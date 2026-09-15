import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  authorize,
  describePassport,
  diagnoseAgentPassport,
  dnsTxtRecord,
  draftAgentPassport,
  signAgentPassport,
  validate,
  verifyAgentPassport,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const cli = resolve(here, "../bin/agent-passport.mjs");
const DAY = 24 * 60 * 60 * 1000;

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

const loadExample = (name) =>
  JSON.parse(readFileSync(resolve(repoRoot, `examples/${name}`), "utf8"));
const verified = (passport) => ({ ok: true, passport, warnings: [] });
const codes = (list) => (list ?? []).map((e) => e.code);

function newKey(keyId) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = new Uint8Array(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url"));
  return {
    raw,
    b64url: Buffer.from(raw).toString("base64url"),
    pkcs8: new Uint8Array(privateKey.export({ type: "pkcs8", format: "der" })),
    txt: dnsTxtRecord({ keyId, publicKeyRaw: raw }),
  };
}

const json = (body, init = {}) =>
  new Response(JSON.stringify(body), { ...init, headers: { "content-type": "application/json", ...init.headers } });

function network(routes) {
  globalThis.fetch = async (input) => {
    const url = String(input);
    for (const [prefix, respond] of Object.entries(routes)) {
      if (url.startsWith(prefix)) return respond(url);
    }
    throw new Error(`unexpected fetch: ${url}`);
  };
}

const dohTxt = (record, ad = true) => () =>
  json({ Status: 0, AD: ad, Answer: [{ name: "x", type: 16, TTL: 300, data: `"${record}"` }] });

// authorize()

test("authorize allows a request inside the envelope", () => {
  const result = authorize(verified(loadExample("acme.agent-passport.json")), {
    scope: "procurement.purchase",
    amount: { amount: 5_000, currency: "USD" },
    counterpartyDomain: "globex.example",
  });
  assert.equal(result.decision, "allow");
  assert.equal(result.allow, true);
  assert.deepEqual(codes(result.reasons), ["authority.within-envelope"]);
  assert.equal(result.escalation, undefined);
});

test("authorize escalates between the human threshold and the ceiling, naming the issuer's human", () => {
  const result = authorize(verified(loadExample("acme.agent-passport.json")), {
    scope: "procurement.purchase",
    amount: { amount: 42_000, currency: "USD" },
    counterpartyDomain: "globex.example",
  });
  assert.equal(result.decision, "escalate");
  assert.deepEqual(codes(result.reasons), ["amount.above-human-threshold"]);
  assert.deepEqual(result.escalation, { to: "procurement-team@acme.example", slaHours: 4 });
});

test("authorize denies above the ceiling and outside scope, reporting both", () => {
  const result = authorize(verified(loadExample("acme.agent-passport.json")), {
    scope: "sales.discount",
    amount: { amount: 60_000, currency: "USD" },
    counterpartyDomain: "globex.example",
  });
  assert.equal(result.decision, "deny");
  assert.deepEqual(codes(result.reasons), ["scope.not-granted", "amount.above-ceiling"]);
});

test("authorize denies an unverified passport whatever it claims", () => {
  const result = authorize(
    { ok: false, errors: [{ code: "time.expired", message: "expired" }], warnings: [] },
    { scope: "procurement.purchase" },
  );
  assert.equal(result.decision, "deny");
  assert.deepEqual(codes(result.reasons), ["passport.unverified"]);
});

test("authorize applies counterparty rules", () => {
  const passport = loadExample("acme.agent-passport.json");
  const ask = (req) => authorize(verified(passport), { scope: "procurement.rfx", ...req }).reasons;

  assert.deepEqual(codes(ask({ counterpartyDomain: "globex.example", counterpartyHasPassport: false })), [
    "counterparty.passport-required",
  ]);
  passport.counterparties = { openTo: "allowlist-only", allowlist: ["globex.example"], blocklist: ["evil.example"] };
  assert.deepEqual(codes(ask({ counterpartyDomain: "GLOBEX.example" })), ["authority.within-envelope"]);
  assert.deepEqual(codes(ask({ counterpartyDomain: "initech.example" })), ["counterparty.not-allowlisted"]);
  assert.deepEqual(codes(ask({ counterpartyDomain: "evil.example" })), [
    "counterparty.blocked",
    "counterparty.not-allowlisted",
  ]);
});

test("authorize checks region and data classification", () => {
  const passport = loadExample("acme.agent-passport.json");
  const ask = (req) => codes(authorize(verified(passport), { scope: "procurement.rfx", ...req }).reasons);
  assert.deepEqual(ask({ region: "us" }), ["authority.within-envelope"]);
  assert.deepEqual(ask({ region: "FR" }), ["region.not-cleared"]);
  assert.deepEqual(ask({ dataClassification: "internal" }), ["authority.within-envelope"]);
  assert.deepEqual(ask({ dataClassification: "regulated-pii" }), ["data.classification-exceeds"]);
});

test("authorize handles cumulative ceilings and foreign currencies", () => {
  const passport = loadExample("acme.agent-passport.json");
  passport.authority.spendCeiling.perEngagement = false;
  const ask = (req) => codes(authorize(verified(passport), { scope: "procurement.purchase", ...req }).reasons);
  const usd = (amount) => ({ amount, currency: "USD" });
  assert.deepEqual(ask({ amount: usd(5_000) }), ["amount.cumulative-unknown"]);
  assert.deepEqual(ask({ amount: usd(5_000), priorSpend: 48_000 }), ["amount.above-ceiling"]);
  assert.deepEqual(ask({ amount: usd(5_000), priorSpend: 1_000 }), ["authority.within-envelope"]);
  assert.deepEqual(ask({ amount: { amount: 10, currency: "EUR" } }), ["amount.currency-unsupported"]);
});

// draftAgentPassport() and describePassport()

test("a drafted passport is schema-valid, signs and verifies", async () => {
  const issued = new Date("2026-06-01T00:00:00Z");
  const draft = draftAgentPassport({
    domain: "Acme.example",
    legalName: "Acme Corporation",
    agentName: "Acme Procurement Agent",
    role: "Procurement",
    purpose: "Buys software licences for Acme within budget.",
    endpoints: { mcp: "https://agents.acme.example/mcp" },
    scopes: ["procurement.purchase", " procurement.purchase", "procurement.negotiate"],
    spendCeiling: 50_000,
    humanAbove: 10_000,
    escalation: "procurement@acme.example",
    now: issued,
  });
  assert.equal(validate(draft).ok, true);
  assert.equal(draft.agent.id, "acme.example:procurement-v1");
  assert.equal(draft.issuer.signingKeyDns, "_agent-passport.acme.example");
  assert.equal(draft.signature.keyId, "acme-2026-q2");
  assert.deepEqual(draft.authority.scope, ["procurement.purchase", "procurement.negotiate"]);
  assert.equal(Date.parse(draft.expiresAt) - Date.parse(draft.issuedAt), 90 * DAY);

  const key = newKey(draft.signature.keyId);
  const signed = await signAgentPassport(draft, key.pkcs8);
  const result = await verifyAgentPassport({
    passport: signed,
    resolveSignerPublicKey: { publicKeyB64: key.b64url },
    checkRevocation: false,
    now: () => issued,
  });
  assert.equal(result.ok, true);
});

test("describePassport reads as plain English", () => {
  const text = describePassport(loadExample("acme.agent-passport.json"), new Date("2026-07-20T00:00:00Z"));
  assert.match(text, /Spending: commits up to 50,000 USD per engagement\. Above 10,000 USD a human confirms first/);
  assert.match(text, /Valid until 2026-07-27 \(7 days left\)/);
  const expired = describePassport(loadExample("acme.agent-passport.json"), new Date("2026-08-01T00:00:00Z"));
  assert.match(expired, /EXPIRED on 2026-07-27/);
});

// diagnoseAgentPassport()

async function publishAcme({ passportHeaders, ad = true, logo } = {}) {
  const key = newKey("acme-2026-q2");
  const passport = loadExample("acme.agent-passport.json");
  passport.signature.keyId = "acme-2026-q2";
  const signed = await signAgentPassport(passport, key.pkcs8);
  network({
    "https://acme.example/.well-known/agent-passport.json": () =>
      new Response(JSON.stringify(signed), {
        headers: passportHeaders ?? {
          "content-type": "application/json",
          "access-control-allow-origin": "*",
          "cache-control": "max-age=300",
        },
      }),
    "https://acme.example/.well-known/revoked-passports.json": () => json([]),
    "https://cloudflare-dns.com/dns-query": dohTxt(key.txt, ad),
    "https://acme.example/logo.svg": () =>
      logo ?? new Response("<svg/>", { headers: { "content-type": "image/svg+xml" } }),
    "https://acme.example/legal/": () => new Response("ok", { headers: { "content-type": "text/html" } }),
    "https://agents.acme.example/": () => json({}),
  });
}

test("doctor passes a healthy passport on every check", async () => {
  await publishAcme();
  const result = await diagnoseAgentPassport({ domain: "acme.example", now: () => new Date("2026-06-01T00:00:00Z") });
  const notPassing = result.checks.filter((c) => c.status !== "pass").map((c) => `${c.id}:${c.status}:${c.detail}`);
  assert.deepEqual(notPassing, []);
  assert.equal(result.ok, true);
});

test("doctor turns the usual deployment mistakes into specific fixes", async () => {
  await publishAcme({
    passportHeaders: { "content-type": "application/json", "cache-control": "s-maxage=1, stale-while-revalidate=2592000" },
    ad: false,
    logo: new Response("not found", { status: 404 }),
  });
  const result = await diagnoseAgentPassport({ domain: "acme.example", now: () => new Date("2026-08-01T00:00:00Z") });
  const status = Object.fromEntries(result.checks.map((c) => [c.id, c.status]));
  assert.equal(result.ok, false);
  assert.equal(status["validity.window"], "fail");
  assert.equal(status["http.cache"], "warn");
  assert.equal(status["http.cors"], "warn");
  assert.equal(status["dns.dnssec"], "warn");
  assert.equal(status["link.logo"], "warn");
  assert.equal(status.signature, "pass");
  assert.match(result.checks.find((c) => c.id === "http.cache").detail, /30 days/);
  assert.ok(result.checks.filter((c) => c.status !== "pass").every((c) => c.hint || c.id === "dns.dnssec" || c.detail));
});

test("doctor stops at a redirect and says why", async () => {
  network({
    "https://acme.example/.well-known/agent-passport.json": () =>
      new Response(null, { status: 301, headers: { location: "https://www.acme.example/.well-known/agent-passport.json" } }),
  });
  const result = await diagnoseAgentPassport({ domain: "acme.example" });
  assert.equal(result.ok, false);
  assert.deepEqual(result.checks.map((c) => `${c.id}:${c.status}`), ["http.reachable:fail"]);
  assert.match(result.checks[0].hint, /do not follow redirects/);
});

// CLI

function tempDir() {
  return mkdtempSync(join(tmpdir(), "agent-passport-"));
}

test("init --yes writes a signed passport, a revocation list and a private key outside the public folder", async () => {
  const dir = tempDir();
  try {
    const out = execFileSync(
      process.execPath,
      [cli, "init", "--yes", "--domain", "acme.example", "--legal-name", "Acme Corporation", "--role", "procurement",
        "--purpose", "Buys software licences for Acme within budget.", "--endpoint", "https://agents.acme.example/mcp",
        "--scope", "procurement.purchase,procurement.negotiate", "--ceiling", "50000", "--human-above", "10000",
        "--escalation", "procurement@acme.example", "--key-out", join(dir, "keys", "acme.pem")],
      { cwd: dir, encoding: "utf8" },
    );
    const record = out.split("\n").map((l) => l.trim()).find((l) => l.startsWith("Value:"))?.slice("Value:".length).trim();
    assert.match(record ?? "", /^v=ap1; kid=acme-\d{4}-q[1-4]; alg=ed25519; pk=/);

    const passport = JSON.parse(readFileSync(join(dir, ".well-known/agent-passport.json"), "utf8"));
    assert.equal(validate(passport).ok, true);
    assert.deepEqual(passport.agent.endpoints, { mcp: "https://agents.acme.example/mcp" });
    assert.equal(readFileSync(join(dir, ".well-known/revoked-passports.json"), "utf8"), "[]\n");
    assert.equal(statSync(join(dir, "keys", "acme.pem")).mode & 0o777, 0o600);

    network({ "https://cloudflare-dns.com/dns-query": dohTxt(record) });
    const result = await verifyAgentPassport({ passport, checkRevocation: false });
    assert.equal(result.ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("init without a terminal lists the missing answers instead of hanging", () => {
  const run = spawnSync(process.execPath, [cli, "init", "--domain", "acme.example"], { encoding: "utf8", input: "" });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /Missing: --legal-name --purpose --endpoint --scope --escalation/);
});

async function signedFile(dir, key, mutate = () => {}) {
  const passport = loadExample("acme.agent-passport.json");
  passport.issuedAt = new Date(Date.now() - DAY).toISOString().replace(/\.\d{3}Z$/, "Z");
  passport.expiresAt = new Date(Date.now() + 30 * DAY).toISOString().replace(/\.\d{3}Z$/, "Z");
  mutate(passport);
  const file = join(dir, "agent-passport.json");
  writeFileSync(file, JSON.stringify(await signAgentPassport(passport, key.pkcs8), null, 2));
  return file;
}

test("renew --offline re-dates and re-signs the passport in place", async () => {
  const dir = tempDir();
  try {
    const keyPath = join(dir, "acme.pem");
    execFileSync(process.execPath, [cli, "keygen", "--kid", "acme-2026-q2", "--out", keyPath]);
    const file = join(dir, "agent-passport.json");
    writeFileSync(file, readFileSync(resolve(repoRoot, "examples/acme.agent-passport.json")));
    execFileSync(process.execPath, [cli, "renew", file, "--key", keyPath, "--days", "30", "--offline"], { encoding: "utf8" });

    const renewed = JSON.parse(readFileSync(file, "utf8"));
    const lifetime = Date.parse(renewed.expiresAt) - Date.parse(renewed.issuedAt);
    assert.equal(lifetime, 30 * DAY);
    assert.ok(Math.abs(Date.parse(renewed.issuedAt) - Date.now()) < 60_000);

    const pub = execFileSync(process.execPath, ["-e", `const c=require("node:crypto");process.stdout.write(c.createPublicKey(c.createPrivateKey(require("node:fs").readFileSync(${JSON.stringify(keyPath)}))).export({format:"jwk"}).x)`], { encoding: "utf8" });
    const result = await verifyAgentPassport({ passport: renewed, resolveSignerPublicKey: { publicKeyB64: pub }, checkRevocation: false });
    assert.equal(result.ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("authorize CLI exits 0 to allow, 2 to escalate, 1 to deny", async () => {
  const dir = tempDir();
  try {
    const key = newKey("acme-2026-q2");
    const file = await signedFile(dir, key);
    const run = (...extra) =>
      spawnSync(process.execPath, [cli, "authorize", file, "--public-key", key.b64url, "--no-revocation", ...extra], { encoding: "utf8" });
    const allow = run("--scope", "procurement.purchase", "--amount", "500");
    assert.equal(allow.status, 0, allow.stdout + allow.stderr);
    assert.match(allow.stdout, /^ALLOW/);
    assert.equal(run("--scope", "procurement.purchase", "--amount", "20000").status, 2);
    assert.equal(run("--scope", "sales.discount").status, 1);
    const asJson = JSON.parse(run("--scope", "procurement.purchase", "--amount", "20000", "--json").stdout);
    assert.equal(asJson.decision, "escalate");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// MCP

function mcpSession(messages) {
  return new Promise((resolveSession, reject) => {
    const child = spawn(process.execPath, [cli, "mcp"], { stdio: ["pipe", "pipe", "inherit"] });
    const expected = messages.filter((m) => m.id !== undefined).length;
    const replies = new Map();
    let buffer = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      buffer += chunk;
      let newline;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (line.trim()) {
          const message = JSON.parse(line);
          replies.set(message.id, message);
        }
      }
      if (replies.size === expected) child.stdin.end();
    });
    child.on("error", reject);
    child.on("exit", () => resolveSession(replies));
    for (const m of messages) child.stdin.write(`${JSON.stringify(m)}\n`);
  });
}

test("MCP server negotiates, lists four tools, drafts offline and rejects unknown tools", { timeout: 15_000 }, async () => {
  const replies = await mcpSession([
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } } },
    { jsonrpc: "2.0", method: "notifications/initialized" },
    { jsonrpc: "2.0", id: 2, method: "tools/list" },
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "draft_agent_passport",
        arguments: {
          domain: "acme.example",
          legal_name: "Acme Corporation",
          agent_name: "Acme Sales Agent",
          purpose: "Quotes and books meetings for Acme.",
          endpoint: "https://acme.example/.well-known/agent-card.json",
          scopes: ["sales.quote"],
          escalation: "sales@acme.example",
        },
      },
    },
    { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "no_such_tool", arguments: {} } },
  ]);

  const init = replies.get(1).result;
  assert.equal(init.protocolVersion, "2025-06-18");
  assert.ok(init.capabilities.tools);
  assert.match(init.instructions, /authorize_agent_action/);

  assert.deepEqual(replies.get(2).result.tools.map((t) => t.name), [
    "verify_agent_passport",
    "authorize_agent_action",
    "check_agent_passport_health",
    "draft_agent_passport",
  ]);

  const draft = replies.get(3).result;
  assert.equal(draft.isError, false);
  assert.equal(draft.structuredContent.valid, true);
  assert.deepEqual(draft.structuredContent.passport.agent.endpoints, {
    a2a: "https://acme.example/.well-known/agent-card.json",
  });

  assert.equal(replies.get(4).error.code, -32602);
});

test("doctor describes cache lifetimes with correct plurals", async () => {
  await publishAcme({
    passportHeaders: { "content-type": "application/json", "access-control-allow-origin": "*", "cache-control": "max-age=86400" },
  });
  const result = await diagnoseAgentPassport({ domain: "acme.example", now: () => new Date("2026-06-01T00:00:00Z") });
  assert.equal(result.checks.find((c) => c.id === "http.cache").detail, "max-age=86400 (1 day)");
});
