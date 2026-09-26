/**
 * Things a stranger can make this library do.
 *
 * A passport is written by whoever is being checked, so every URL in it is
 * someone else's text telling this process what to fetch. A policy is written
 * by the operator, but the text its rules run against is a tool argument,
 * which is exactly what an injected instruction gets to choose.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  checkFetchable,
  diagnoseAgentPassport,
  draftAgentPassport,
  localPolicy,
  runawayRegex,
  signAgentPassport,
  verifyAgentPassport,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const cli = resolve(here, "../bin/agent-passport.mjs");
const stub = resolve(here, "fixtures/stub-mcp.mjs");
const codes = (list) => (list ?? []).map((e) => e.code);

function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = new Uint8Array(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url"));
  return { raw, b64url: Buffer.from(raw).toString("base64url"), pkcs8: new Uint8Array(privateKey.export({ type: "pkcs8", format: "der" })) };
}

const draft = () =>
  draftAgentPassport({
    domain: "evil.example", legalName: "Evil Corp", agentName: "Evil Agent", role: "procurement",
    purpose: "Does whatever it likes inside the published limits.",
    endpoints: { rest: "https://evil.example/api/a" }, scopes: ["procurement.purchase"],
    spendCeiling: 1_000, humanAbove: 100, escalation: "a@evil.example", keyId: "evil-1",
  });

/** Record every URL the library is persuaded to request. */
function watchFetch(key, passport) {
  const seen = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = String(input);
    seen.push(url);
    if (url.includes("cloudflare-dns")) {
      return Response.json({ Status: 0, AD: true, Answer: [{ name: "_agent-passport.evil.example", type: 16, TTL: 300, data: `"v=ap1; kid=evil-1; alg=ed25519; pk=${key.b64url}"` }] });
    }
    if (url.includes("well-known/agent-passport")) return Response.json(passport);
    return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
  };
  return { seen, restore: () => { globalThis.fetch = real; } };
}

test("a passport cannot send the verifier at a host of its choosing", async () => {
  const key = newKey();
  for (const target of [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "https://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:6379/",
    "https://localhost/admin",
    "https://10.0.0.5/internal",
    "https://192.168.1.1/admin",
    "https://[::1]/admin",
    "file:///etc/passwd",
    "https://someone-else.example/revoked.json",
  ]) {
    const passport = await signAgentPassport({ ...draft(), revocationListUrl: target }, key.pkcs8);
    const watch = watchFetch(key, passport);
    try {
      const result = await verifyAgentPassport({ domain: "evil.example" });
      assert.equal(result.ok, false, target);
      assert.ok(
        codes(result.errors).some((c) => c.startsWith("url.")),
        `${target} was refused for the wrong reason: ${codes(result.errors)}`,
      );
      assert.ok(
        !watch.seen.some((u) => u.startsWith(target.slice(0, 20))),
        `${target} was fetched anyway`,
      );
    } finally {
      watch.restore();
    }
  }
});

test("a revocation list on the issuer's own domain is still fetched", async () => {
  const key = newKey();
  const passport = await signAgentPassport(
    { ...draft(), revocationListUrl: "https://evil.example/.well-known/revoked-passports.json" },
    key.pkcs8,
  );
  const watch = watchFetch(key, passport);
  try {
    const result = await verifyAgentPassport({ domain: "evil.example" });
    assert.equal(result.ok, true, JSON.stringify(result.errors));
    assert.ok(watch.seen.some((u) => u.includes("revoked-passports.json")));
  } finally {
    watch.restore();
  }
});

test("doctor will not follow a passport's links onto a private network", async () => {
  const key = newKey();
  const base = draft();
  const passport = await signAgentPassport({
    ...base,
    issuer: { ...base.issuer, logo: "http://169.254.169.254/latest/meta-data/", contact: { url: "https://127.0.0.1:6379/" } },
    agent: { ...base.agent, endpoints: { rest: "https://10.0.0.5/internal" } },
    revocationListUrl: "https://192.168.1.1/admin",
  }, key.pkcs8);
  const watch = watchFetch(key, passport);
  try {
    const result = await diagnoseAgentPassport({ domain: "evil.example" });
    const reached = watch.seen.filter((u) => /169\.254|127\.0\.0\.1|10\.0\.0\.5|192\.168/.test(u));
    assert.deepEqual(reached, [], "doctor fetched a private host");
    assert.ok(result.checks.some((c) => c.status === "fail" && /private|loopback|not https/.test(c.detail ?? "")));
  } finally {
    watch.restore();
  }
});

test("checkFetchable names what it refuses, and lets the ordinary case through", () => {
  const refused = (url, opts = {}) => checkFetchable(url, { field: "f", ...opts })?.code;
  assert.equal(refused("https://example.com/x"), undefined);
  assert.equal(refused("http://example.com/x"), "url.not-https");
  assert.equal(refused("file:///etc/passwd"), "url.not-https");
  assert.equal(refused("not a url"), "url.malformed");
  assert.equal(refused("https://127.0.0.1/x"), "url.private-host");
  assert.equal(refused("https://169.254.169.254/x"), "url.private-host");
  assert.equal(refused("https://172.16.0.1/x"), "url.private-host");
  assert.equal(refused("https://172.32.0.1/x"), undefined, "172.32 is public");
  assert.equal(refused("https://[fd00::1]/x"), "url.private-host");
  assert.equal(refused("https://[::ffff:127.0.0.1]/x"), "url.private-host");
  assert.equal(refused("https://db.localhost/x"), "url.private-host");
  assert.equal(refused("https://thing.internal/x"), "url.private-host");
  assert.equal(refused("https://cdn.example.net/logo.png", { withinDomain: "example.com" }), "url.outside-issuer-domain");
  assert.equal(refused("https://a.example.com/x", { withinDomain: "example.com" }), undefined);
});

test("a policy cannot carry a pattern that takes exponential time", () => {
  for (const pattern of ["^(a+)+$", "(a*)*", "(\\w+)*x", "(ab+)+", "(a+){2,}"]) {
    assert.equal(runawayRegex(pattern), true, pattern);
    assert.throws(
      () => localPolicy({ id: "p", scope: ["x"], tools: [{ match: "Bash", when: { path: "args.command", matches: pattern }, effect: "deny" }] }),
      /exponential time/,
      pattern,
    );
  }
  // The patterns a real policy uses are left alone.
  for (const pattern of ["(^|[;&|]\\s*)(sudo\\b|rm\\s+-[a-zA-Z]*[rf])", "\\bcurl\\b[^|]*\\|\\s*(ba)?sh\\b", "^git\\s+push\\b"]) {
    assert.equal(runawayRegex(pattern), false, pattern);
  }
});

test("one call the guard cannot decide does not take the guard down", () => {
  const dir = mkdtempSync(join(tmpdir(), "ap-sec-"));
  try {
    const policy = {
      id: "p", agentId: "a", scope: ["payments.charge"],
      tools: [{ match: "stripe.create_charge", scope: "payments.charge", amountFrom: "args.amount" }],
      unmatched: "deny",
    };
    writeFileSync(join(dir, "policy.json"), JSON.stringify(policy));
    // An argument that cannot be turned into canonical JSON, followed by an
    // ordinary call. The second one has to still be answered.
    const deep = `${'{"n":'.repeat(30_000)}null${"}".repeat(30_000)}`;
    const input = [
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "c", version: "1" } } }),
      `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"stripe.create_charge","arguments":{"amount":1,"deep":${deep}}}}`,
      JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "stripe.create_charge", arguments: { amount: 5 } } }),
    ].join("\n");

    const proc = spawnSync(process.execPath, [cli, "guard", "--policy", join(dir, "policy.json"), "--", process.execPath, stub], {
      input: `${input}\n`, encoding: "utf8", timeout: 30_000, env: { ...process.env, STUB_LOG: join(dir, "stub.log") },
    });
    const replies = new Map();
    for (const line of (proc.stdout || "").trim().split("\n")) {
      if (!line.trim()) continue;
      const m = JSON.parse(line);
      replies.set(m.id, m);
    }
    assert.ok(replies.has(3), "the guard stopped answering after the awkward call");
    assert.ok(replies.has(1), "initialize was answered");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
