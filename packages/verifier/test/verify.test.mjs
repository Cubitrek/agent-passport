import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

import {
  dnsTxtRecord,
  signAgentPassport,
  validate,
  verifyAgentPassport,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const now = () => new Date("2026-06-01T00:00:00Z");

const DOH = "https://cloudflare-dns.com/dns-query";
const WELL_KNOWN = "https://acme.example/.well-known/agent-passport.json";
const REVOCATION = "https://acme.example/.well-known/revoked-passports.json";

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

function loadExample(name) {
  return JSON.parse(readFileSync(resolve(repoRoot, `examples/${name}`), "utf8"));
}

function newKey(keyId) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = new Uint8Array(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url"));
  return {
    keyId,
    raw,
    spkiB64: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    pkcs8: new Uint8Array(privateKey.export({ type: "pkcs8", format: "der" })),
    txt: dnsTxtRecord({ keyId, publicKeyRaw: raw }),
  };
}

async function signedAcme(key, mutate = () => {}) {
  const passport = loadExample("acme.agent-passport.json");
  passport.signature.keyId = key.keyId;
  mutate(passport);
  return signAgentPassport(passport, key.pkcs8);
}

const json = (body, init = {}) =>
  new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json", ...init.headers },
  });

const dohTxt =
  (records, { ad = true } = {}) =>
  () =>
    json({
      Status: 0,
      AD: ad,
      Answer: records.map((data) => ({ name: "x", type: 16, TTL: 300, data: `"${data}"` })),
    });

/** Route fetch by URL prefix. Unrouted URLs throw, which the verifier reports as a fetch failure. */
function network(routes) {
  const calls = [];
  globalThis.fetch = async (input) => {
    const url = String(input);
    calls.push(url);
    for (const [prefix, respond] of Object.entries(routes)) {
      if (url.startsWith(prefix)) return respond(url);
    }
    throw new Error(`unexpected fetch: ${url}`);
  };
  return calls;
}

const codes = (list) => (list ?? []).map((e) => e.code);
const pinned = (key) => ({ publicKeyB64: key.spkiB64 });

test("a signed passport verifies end to end: fetch, DNS key by kid, signature, revocation", async () => {
  const key = newKey("acme-2026-q2");
  const passport = await signedAcme(key);
  const calls = network({
    [WELL_KNOWN]: () => json(passport),
    [`${DOH}?name=_agent-passport.acme.example`]: dohTxt([newKey("acme-2026-q1").txt, key.txt]),
    [REVOCATION]: () => json([]),
  });
  const result = await verifyAgentPassport({ domain: "acme.example", now });
  assert.deepEqual(codes(result.errors), []);
  assert.deepEqual(codes(result.warnings), []);
  assert.equal(result.ok, true);
  assert.equal(calls.length, 3);
});

test("changing a signed field after signing fails the signature", async () => {
  const key = newKey("acme-2026-q2");
  const passport = await signedAcme(key);
  passport.authority.spendCeiling.amount = 5_000_000;
  const result = await verifyAgentPassport({
    passport,
    resolveSignerPublicKey: pinned(key),
    checkRevocation: false,
    now,
  });
  assert.deepEqual(codes(result.errors), ["signature.invalid"]);
});

test("rejects a passport whose signing key is published outside issuer.domain", async () => {
  // The forgery this check exists for: name a victim as issuer, publish your
  // own key in a zone you control, sign. Verifier 0.1.1 returned ok: true.
  const attacker = newKey("evil-1");
  const forged = await signedAcme(attacker, (p) => {
    p.issuer.signingKeyDns = "_agent-passport.attacker.example";
  });
  const calls = network({ [DOH]: dohTxt([attacker.txt]) });
  const result = await verifyAgentPassport({ passport: forged, checkRevocation: false, now });
  assert.equal(result.ok, false);
  assert.deepEqual(codes(result.errors), ["issuer.signing-key-outside-domain"]);
  assert.equal(calls.length, 0, "must not query a zone the issuer does not control");
});

test("a look-alike zone that only ends with the issuer's name is rejected", async () => {
  const key = newKey("acme-2026-q2");
  const passport = await signedAcme(key, (p) => {
    p.issuer.signingKeyDns = "_agent-passport.notacme.example";
  });
  network({ [DOH]: dohTxt([key.txt]) });
  const result = await verifyAgentPassport({ passport, checkRevocation: false, now });
  assert.deepEqual(codes(result.errors), ["issuer.signing-key-outside-domain"]);
});

test("a signing key on a name inside the issuer zone is accepted", async () => {
  const key = newKey("acme-2026-q2");
  const passport = await signedAcme(key, (p) => {
    p.issuer.signingKeyDns = "_agent-passport.keys.acme.example";
  });
  network({ [`${DOH}?name=_agent-passport.keys.acme.example`]: dohTxt([key.txt]) });
  const result = await verifyAgentPassport({ passport, checkRevocation: false, now });
  assert.equal(result.ok, true);
});

test("a malformed signature returns ok:false instead of throwing", async () => {
  const key = newKey("acme-2026-q2");
  const passport = await signedAcme(key);
  passport.signature.value = "a";
  const result = await verifyAgentPassport({
    passport,
    resolveSignerPublicKey: pinned(key),
    checkRevocation: false,
    now,
  });
  assert.deepEqual(codes(result.errors), ["signature.invalid"]);
});

test("an expired passport is rejected", async () => {
  const key = newKey("acme-2026-q2");
  const passport = await signedAcme(key);
  const result = await verifyAgentPassport({
    passport,
    resolveSignerPublicKey: pinned(key),
    checkRevocation: false,
    now: () => new Date("2026-08-01T00:00:00Z"),
  });
  assert.deepEqual(codes(result.errors), ["time.expired"]);
});

test("a revoked agent.id is rejected", async () => {
  const key = newKey("acme-2026-q2");
  const passport = await signedAcme(key);
  network({ [REVOCATION]: () => json([passport.agent.id]) });
  const result = await verifyAgentPassport({ passport, resolveSignerPublicKey: pinned(key), now });
  assert.deepEqual(codes(result.errors), ["revocation.revoked"]);
});

test("an unreachable revocation list warns by default and fails closed on request", async () => {
  const key = newKey("acme-2026-q2");
  const passport = await signedAcme(key);
  network({ [REVOCATION]: () => json({ error: "down" }, { status: 503 }) });
  const opts = { passport, resolveSignerPublicKey: pinned(key), now };

  const open = await verifyAgentPassport(opts);
  assert.equal(open.ok, true);
  assert.deepEqual(codes(open.warnings), ["revocation.fetch-non-2xx"]);

  const closed = await verifyAgentPassport({ ...opts, revocationFailure: "error" });
  assert.equal(closed.ok, false);
  assert.deepEqual(codes(closed.errors), ["revocation.fetch-non-2xx"]);
});

test("passport fetches do not follow redirects", async () => {
  network({
    [WELL_KNOWN]: () =>
      new Response(null, { status: 302, headers: { location: "https://evil.example/passport.json" } }),
  });
  const result = await verifyAgentPassport({ domain: "acme.example", now });
  assert.deepEqual(codes(result.errors), ["fetch.redirect"]);
});

test("an oversized passport response is refused", async () => {
  network({ [WELL_KNOWN]: () => new Response("x".repeat(300 * 1024)) });
  const result = await verifyAgentPassport({ domain: "acme.example", now });
  assert.deepEqual(codes(result.errors), ["fetch.too-large"]);
});

test("domain comparison ignores case and a trailing dot", async () => {
  const key = newKey("acme-2026-q2");
  const passport = await signedAcme(key);
  network({
    [WELL_KNOWN]: () => json(passport),
    [DOH]: dohTxt([key.txt]),
    [REVOCATION]: () => json([]),
  });
  const result = await verifyAgentPassport({ domain: "ACME.example.", now });
  assert.equal(result.ok, true);
});

test("a domain argument that is not a bare hostname is refused before any fetch", async () => {
  const calls = network({});
  const result = await verifyAgentPassport({ domain: "acme.example/evil?", now });
  assert.deepEqual(codes(result.errors), ["args.invalid-domain"]);
  assert.equal(calls.length, 0);
});

test("raw and SPKI public keys, in base64 or base64url, all verify", async () => {
  const key = newKey("acme-2026-q2");
  const passport = await signedAcme(key);
  const forms = [
    key.spkiB64,
    Buffer.from(key.raw).toString("base64"),
    Buffer.from(key.raw).toString("base64url"),
  ];
  for (const publicKeyB64 of forms) {
    const result = await verifyAgentPassport({
      passport,
      resolveSignerPublicKey: { publicKeyB64 },
      checkRevocation: false,
      now,
    });
    assert.equal(result.ok, true, publicKeyB64);
  }
});

test("a DNS answer without DNSSEC validation passes with a dns.unauthenticated warning", async () => {
  const key = newKey("acme-2026-q2");
  const passport = await signedAcme(key);
  network({ [DOH]: dohTxt([key.txt], { ad: false }) });
  const result = await verifyAgentPassport({ passport, checkRevocation: false, now });
  assert.equal(result.ok, true);
  assert.deepEqual(codes(result.warnings), ["dns.unauthenticated"]);
});

test("a human-in-the-loop threshold above the spend ceiling raises a warning", async () => {
  const key = newKey("acme-2026-q2");
  const passport = await signedAcme(key, (p) => {
    p.authority.humanInLoop.above.amount = 60_000;
  });
  const result = await verifyAgentPassport({
    passport,
    resolveSignerPublicKey: pinned(key),
    checkRevocation: false,
    now,
  });
  assert.equal(result.ok, true);
  assert.deepEqual(codes(result.warnings), ["authority.hil-above-ceiling"]);
});

test("Cubitrek's published passport verifies against its DNS key while it was valid", async () => {
  // Pins canonicalisation against a passport signed by a real issuer, and the
  // base64url key decoding fixed in 0.1.1. The key is the pk= value at
  // _agent-passport.cubitrek.com; update both together when the example is re-issued.
  const result = await verifyAgentPassport({
    passport: loadExample("cubitrek.agent-passport.json"),
    resolveSignerPublicKey: { publicKeyB64: "M-_7mbiIxdhKF3h-xbqWjorcUfXhcuo_bqoLkzlADnA" },
    checkRevocation: false,
    now: () => new Date("2026-05-01T00:00:00Z"),
  });
  assert.equal(result.ok, true);
});

test("schema requires {engagementId} in authority.decisionAudit", () => {
  const passport = loadExample("acme.agent-passport.json");
  passport.authority.decisionAudit = "https://agents.acme.example/audit";
  assert.equal(validate(passport).ok, false);
});

test("CLI keygen and sign produce a passport the verifier accepts", async () => {
  const dir = mkdtempSync(join(tmpdir(), "agent-passport-"));
  try {
    const cli = resolve(here, "../bin/agent-passport.mjs");
    const keyPath = join(dir, "acme.pem");
    const keygen = execFileSync(
      process.execPath,
      [cli, "keygen", "--kid", "acme-2026-q3", "--out", keyPath],
      { encoding: "utf8" },
    );
    const record = keygen.split("\n").find((line) => line.startsWith("v=ap1;"));
    assert.ok(record, keygen);
    assert.equal(statSync(keyPath).mode & 0o777, 0o600);

    const signed = JSON.parse(
      execFileSync(
        process.execPath,
        [cli, "sign", resolve(repoRoot, "examples/acme.agent-passport.json"), "--key", keyPath, "--kid", "acme-2026-q3"],
        { encoding: "utf8" },
      ),
    );
    assert.equal(signed.signature.keyId, "acme-2026-q3");

    network({ [DOH]: dohTxt([record]) });
    const result = await verifyAgentPassport({ passport: signed, checkRevocation: false, now });
    assert.equal(result.ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
