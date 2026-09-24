/**
 * Caller binding: signing a request as the agent, and checking on the other
 * side that the call came from the agent a passport describes.
 *
 * The first test is an interoperability check against RFC 9421's own ed25519
 * example (Appendix B.1.4 and B.2.6), so the signature base is measured
 * against the standard rather than against this implementation.
 */

import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  authorize,
  buildSignatureBase,
  checkExecution,
  dnsTxtRecord,
  draftAgentPassport,
  memoryNonceStore,
  requestKeyEntry,
  signAgentPassport,
  signAgentRequest,
  verifyAgentCaller,
  verifyAgentPassport,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const cli = resolve(here, "../bin/agent-passport.mjs");
const codes = (list) => (list ?? []).map((e) => e.code);
const now = () => new Date("2026-06-10T00:00:00Z");

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

// RFC 9421 Appendix B.1.4 (test-key-ed25519) and B.2.6 (signing a request).
const RFC_PUBLIC_KEY_SPKI = "MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=";
const RFC_SIGNATURE =
  "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==";
const RFC_COMPONENTS = ["date", "@method", "@path", "@authority", "content-type", "content-length"];
const RFC_BASE = [
  '"date": Tue, 20 Apr 2021 02:07:55 GMT',
  '"@method": POST',
  '"@path": /foo',
  '"@authority": example.com',
  '"content-type": application/json',
  '"content-length": 18',
  '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
].join("\n");
const RFC_REQUEST = {
  method: "POST",
  url: "https://example.com/foo?param=Value&Pet=dog",
  headers: {
    date: "Tue, 20 Apr 2021 02:07:55 GMT",
    "content-type": "application/json",
    "content-length": "18",
  },
};

test("RFC 9421 interop: the signature base matches the spec's ed25519 example", async () => {
  const base = buildSignatureBase(RFC_REQUEST, RFC_COMPONENTS, {
    created: 1618884473,
    keyid: "test-key-ed25519",
  });
  assert.equal(base, RFC_BASE);

  // The RFC's own signature verifies over the base this implementation built.
  const key = await crypto.subtle.importKey(
    "spki",
    Buffer.from(RFC_PUBLIC_KEY_SPKI, "base64"),
    { name: "Ed25519" },
    true,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "Ed25519",
    key,
    Buffer.from(RFC_SIGNATURE, "base64"),
    new TextEncoder().encode(base),
  );
  assert.equal(valid, true);

  // And a base that differs by one character does not verify, so the check can fail.
  const tampered = RFC_BASE.replace('"@path": /foo', '"@path": /bar');
  assert.equal(
    await crypto.subtle.verify("Ed25519", key, Buffer.from(RFC_SIGNATURE, "base64"), new TextEncoder().encode(tampered)),
    false,
  );
});

function newKey(keyId) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = new Uint8Array(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url"));
  return {
    keyId,
    raw,
    b64url: Buffer.from(raw).toString("base64url"),
    pkcs8: new Uint8Array(privateKey.export({ type: "pkcs8", format: "der" })),
    txt: dnsTxtRecord({ keyId, publicKeyRaw: raw }),
  };
}

/** An issued passport that publishes one request-signing key. */
async function issuedPassport({ requestKeys } = {}) {
  const signingKey = newKey("acme-2026-q3");
  const requestKey = newKey("acme-2026-q3-request");
  const draft = draftAgentPassport({
    domain: "acme.example",
    legalName: "Acme Corporation",
    agentName: "Acme Procurement Agent",
    role: "procurement",
    purpose: "Buys software licences for Acme within budget.",
    endpoints: { rest: "https://agents.acme.example/api/procurement" },
    scopes: ["procurement.purchase"],
    spendCeiling: 50_000,
    humanAbove: 10_000,
    escalation: "procurement-team@acme.example",
    keyId: signingKey.keyId,
    now: new Date("2026-06-01T00:00:00Z"),
    requestKeys:
      requestKeys ?? [requestKeyEntry({ keyId: requestKey.keyId, publicKeyRaw: requestKey.raw })],
  });
  return { passport: await signAgentPassport(draft, signingKey.pkcs8), signingKey, requestKey };
}

const callRequest = (body = { sku: "sku-123", quantity: 20 }) => ({
  method: "POST",
  url: "https://api.globex.example/orders?channel=agent",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
});

async function signedCall(requestKey, overrides = {}) {
  const request = { ...callRequest(), ...overrides };
  const headers = await signAgentRequest(request, {
    keyId: requestKey.keyId,
    privateKey: requestKey.pkcs8,
    created: now(),
  });
  return { ...request, headers: { ...request.headers, ...headers } };
}

test("a request signed by the agent verifies against the key in its passport", async () => {
  const { passport, requestKey } = await issuedPassport();
  const received = await signedCall(requestKey);
  const result = await verifyAgentCaller(received, passport, { now });
  assert.deepEqual(result, { ok: true, keyId: requestKey.keyId, nonce: result.nonce });
  assert.equal(result.keyId, "acme-2026-q3-request");
});

test("changing the body, method, path or query after signing is caught", async () => {
  const { passport, requestKey } = await issuedPassport();
  const received = await signedCall(requestKey);

  const swappedBody = { ...received, body: JSON.stringify({ sku: "sku-999", quantity: 20 }) };
  assert.deepEqual(codes((await verifyAgentCaller(swappedBody, passport, { now })).errors), [
    "httpsig.digest-mismatch",
  ]);

  for (const change of [
    { method: "DELETE" },
    { url: "https://api.globex.example/orders/99?channel=agent" },
    { url: "https://api.globex.example/orders?channel=human" },
    { url: "https://api.evil.example/orders?channel=agent" },
  ]) {
    const result = await verifyAgentCaller({ ...received, ...change }, passport, { now });
    assert.deepEqual(codes(result.errors), ["httpsig.invalid"], JSON.stringify(change));
  }
});

test("a signature outside its window, or replayed, is refused", async () => {
  const { passport, requestKey } = await issuedPassport();
  const received = await signedCall(requestKey);
  const at = (seconds) => ({ now: () => new Date(now().getTime() + seconds * 1000) });

  assert.deepEqual(codes((await verifyAgentCaller(received, passport, at(120))).errors), ["httpsig.expired"]);
  assert.deepEqual(codes((await verifyAgentCaller(received, passport, at(-60))).errors), [
    "httpsig.created-in-future",
  ]);

  const nonceStore = memoryNonceStore({ now });
  assert.equal((await verifyAgentCaller(received, passport, { now, nonceStore })).ok, true);
  assert.deepEqual(codes((await verifyAgentCaller(received, passport, { now, nonceStore })).errors), [
    "httpsig.replayed",
  ]);
});

test("a key the passport does not publish is refused, as is a passport with no keys", async () => {
  const { passport } = await issuedPassport();
  const strangerKey = newKey("stranger-1");
  const received = await signedCall(strangerKey);
  assert.deepEqual(codes((await verifyAgentCaller(received, passport, { now })).errors), [
    "httpsig.unknown-key",
  ]);

  const { passport: bare, requestKey } = await issuedPassport({ requestKeys: [] });
  const honest = await signedCall(requestKey);
  const result = await verifyAgentCaller(honest, bare, { now });
  assert.deepEqual(codes(result.errors), ["caller.no-request-keys"]);
  assert.match(result.errors[0].hint, /mutual TLS/);
});

test("an unsigned request, and one signed without the tag, are refused", async () => {
  const { passport, requestKey } = await issuedPassport();
  assert.deepEqual(codes((await verifyAgentCaller(callRequest(), passport, { now })).errors), [
    "httpsig.missing",
  ]);

  const { signHttpRequest } = await import("../dist/http-signature.js");
  const request = callRequest();
  const headers = await signHttpRequest(request, {
    keyId: requestKey.keyId,
    privateKey: requestKey.pkcs8,
    created: now(),
  });
  const untagged = { ...request, headers: { ...request.headers, ...headers } };
  assert.deepEqual(codes((await verifyAgentCaller(untagged, passport, { now })).errors), ["httpsig.missing"]);
});

test("a signature that leaves the body or the target uncovered is refused", async () => {
  const { passport, requestKey } = await issuedPassport();
  const { signHttpRequest } = await import("../dist/http-signature.js");
  const request = callRequest();

  const weak = await signHttpRequest(request, {
    keyId: requestKey.keyId,
    privateKey: requestKey.pkcs8,
    created: now(),
    tag: "agent-passport",
    components: ["@method", "@authority"],
  });
  const result = await verifyAgentCaller({ ...request, headers: { ...request.headers, ...weak } }, passport, { now });
  assert.equal(result.ok, false);
  assert.deepEqual(codes(result.errors), ["httpsig.weak-coverage"]);
  assert.match(result.errors[0].message, /@path, @query, content-digest/);
});

test("the whole chain: passport, caller, authority, execution", async () => {
  const { passport, signingKey, requestKey } = await issuedPassport();
  globalThis.fetch = async (input) => {
    const url = String(input);
    if (url.startsWith("https://acme.example/.well-known/agent-passport.json")) {
      return new Response(JSON.stringify(passport), { headers: { "content-type": "application/json" } });
    }
    if (url.startsWith("https://cloudflare-dns.com/dns-query")) {
      return new Response(
        JSON.stringify({ Status: 0, AD: true, Answer: [{ name: "x", type: 16, TTL: 300, data: `"${signingKey.txt}"` }] }),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (url.endsWith("revoked-passports.json")) {
      return new Response("[]", { headers: { "content-type": "application/json" } });
    }
    throw new Error(`unexpected fetch: ${url}`);
  };

  // 1. The passport verifies, so we know what Acme authorised.
  const verification = await verifyAgentPassport({ domain: "acme.example", now });
  assert.equal(verification.ok, true, JSON.stringify(verification.errors));

  // 2. The caller proves it is Acme's agent, not someone quoting a public file.
  const received = await signedCall(requestKey);
  const caller = await verifyAgentCaller(received, verification.passport, { now });
  assert.equal(caller.ok, true);

  // 3. The action falls inside the authority, bound to these exact values.
  const request = {
    scope: "procurement.purchase",
    amount: { amount: 4_000, currency: "USD" },
    counterpartyDomain: "globex.example",
    action: { tool: "orders.create", target: "sku-123", args: { quantity: 20 } },
  };
  const decision = await authorize(verification, request, { now });
  assert.equal(decision.decision, "allow");

  // 4. Nothing changed between the decision and the side effect.
  assert.deepEqual(await checkExecution(decision, request, { now }), { ok: true });
});

test("the CLI prints a request-key entry, and init can publish one", async () => {
  const dir = mkdtempSync(join(tmpdir(), "agent-passport-caller-"));
  try {
    const run = (...args) => execFileSync(process.execPath, [cli, ...args], { cwd: dir, encoding: "utf8" });
    const keyPath = join(dir, "request.pem");
    run("keygen", "--kid", "acme-2026-q3-request", "--out", keyPath);
    const entry = JSON.parse(run("request-key", "--key", keyPath, "--kid", "acme-2026-q3-request"));
    assert.equal(entry.alg, "ed25519");
    assert.match(entry.publicKey, /^[A-Za-z0-9_-]{43}$/);

    run(
      "init", "--yes",
      "--domain", "initech.example",
      "--legal-name", "Initech LLC",
      "--purpose", "Answers partner support requests and issues small refunds.",
      "--endpoint", "https://agents.initech.example/mcp",
      "--scope", "support.refund",
      "--escalation", "support@initech.example",
      "--key-out", join(dir, "keys", "initech.pem"),
      "--request-key",
    );
    const passport = JSON.parse(readFileSync(join(dir, ".well-known", "agent-passport.json"), "utf8"));
    assert.equal(passport.agent.requestKeys.length, 1);
    assert.match(passport.agent.requestKeys[0].keyId, /-request$/);
    assert.match(passport.agent.requestKeys[0].publicKey, /^[A-Za-z0-9_-]{43}$/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
