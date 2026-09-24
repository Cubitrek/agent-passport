/**
 * Whole-flow tests for use cases other than the buyer/seller example in the
 * spec: a support agent refunding against a cumulative ceiling, a data export
 * with no money attached, a payment whose arguments are swapped after
 * approval, an escalation a person confirms, and an issuer's first run through
 * the CLI. Network calls are stubbed; signing uses freshly generated keys.
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
  checkExecution,
  dnsTxtRecord,
  draftAgentPassport,
  memoryNonceStore,
  signAgentPassport,
  verifyAgentPassport,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const cli = resolve(here, "../bin/agent-passport.mjs");
const ISSUED = new Date("2026-06-01T00:00:00Z");
const now = () => new Date("2026-06-10T00:00:00Z");
const codes = (list) => (list ?? []).map((e) => e.code);

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
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

const dohTxt = (record) => () =>
  json({ Status: 0, AD: true, Answer: [{ name: "x", type: 16, TTL: 300, data: `"${record}"` }] });

/** Issue a passport, publish it and its key, and verify it the way a counterparty would. */
async function publishAndVerify(domain, draftInput) {
  const key = newKey(`${domain.split(".")[0]}-2026-q3`);
  const signed = await signAgentPassport(
    draftAgentPassport({ domain, keyId: key.keyId, now: ISSUED, ...draftInput }),
    key.pkcs8,
  );
  network({
    [`https://${domain}/.well-known/agent-passport.json`]: () => json(signed),
    [`https://${domain}/.well-known/revoked-passports.json`]: () => json([]),
    "https://cloudflare-dns.com/dns-query": dohTxt(key.txt),
  });
  const verification = await verifyAgentPassport({ domain, now });
  assert.equal(verification.ok, true, JSON.stringify(verification.errors));
  return { key, verification };
}

test("scenario: a support agent refunding a customer against a cumulative ceiling", async () => {
  const { verification } = await publishAndVerify("globex.example", {
    legalName: "Globex Software, Inc.",
    agentName: "Globex Support Agent",
    role: "support",
    purpose: "Refunds customers inside the published limits and hands larger cases to a person.",
    endpoints: { rest: "https://agents.globex.example/api/support" },
    scopes: ["support.refund", "support.credit"],
    spendCeiling: 5_000,
    perEngagement: false,
    humanAbove: 500,
    escalation: "support-leads@globex.example",
    slaHours: 2,
    dataClassification: "regulated-pii",
    regions: ["US", "GB"],
  });

  const refund = (amount, priorSpend, reason) => ({
    scope: "support.refund",
    amount: { amount, currency: "USD" },
    priorSpend,
    counterpartyDomain: "acme.example",
    region: "US",
    dataClassification: "regulated-pii",
    action: { tool: "billing.refund", target: "invoice_8831", args: { reason } },
  });

  const small = await authorize(verification, refund(120, 4_800, "late delivery"), { now });
  assert.equal(small.decision, "allow");
  assert.deepEqual(await checkExecution(small, refund(120, 4_800, "late delivery"), { now }), { ok: true });

  const overCeiling = await authorize(verification, refund(300, 4_800, "late delivery"), { now });
  assert.deepEqual(codes(overCeiling.reasons), ["amount.above-ceiling"]);

  const needsPerson = await authorize(verification, refund(900, 1_000, "duplicate charge"), { now });
  assert.equal(needsPerson.decision, "escalate");
  assert.equal(needsPerson.escalation.to, "support-leads@globex.example");

  const wrongScope = await authorize(verification, { ...refund(50, 0, "goodwill"), scope: "support.delete-account" }, { now });
  assert.deepEqual(codes(wrongScope.reasons), ["scope.not-granted"]);
});

test("scenario: a data export with no money attached", async () => {
  const { verification } = await publishAndVerify("initech.example", {
    legalName: "Initech LLC",
    agentName: "Initech Analytics Agent",
    role: "analytics",
    purpose: "Exports aggregate reporting data for partners inside agreed limits.",
    endpoints: { mcp: "https://agents.initech.example/mcp" },
    scopes: ["data.export"],
    escalation: "data-team@initech.example",
    dataClassification: "internal",
    regions: ["US", "DE"],
  });

  const exportRows = (overrides = {}) => ({
    scope: "data.export",
    counterpartyDomain: "acme.example",
    region: "DE",
    dataClassification: "internal",
    action: { tool: "warehouse.export", target: "orders", args: { rows: 5_000, columns: ["id", "total"] } },
    ...overrides,
  });

  const approved = await authorize(verification, exportRows(), { now });
  assert.equal(approved.decision, "allow", JSON.stringify(approved.reasons));
  assert.deepEqual(await checkExecution(approved, exportRows(), { now }), { ok: true });

  const biggerPull = exportRows({
    action: { tool: "warehouse.export", target: "orders", args: { rows: 5_000_000, columns: ["id", "total"] } },
  });
  assert.deepEqual(codes((await checkExecution(approved, biggerPull, { now })).errors), ["execution.request-changed"]);

  assert.deepEqual(codes((await authorize(verification, exportRows({ region: "FR" }), { now })).reasons), [
    "region.not-cleared",
  ]);
  assert.deepEqual(
    codes((await authorize(verification, exportRows({ dataClassification: "regulated-pii" }), { now })).reasons),
    ["data.classification-exceeds"],
  );
});

test("scenario: a payment whose destination is swapped between approval and execution", async () => {
  const { verification } = await publishAndVerify("umbrella.example", {
    legalName: "Umbrella Logistics",
    agentName: "Umbrella Treasury Agent",
    role: "treasury",
    purpose: "Pays approved supplier invoices inside the published limits.",
    endpoints: { rest: "https://agents.umbrella.example/api/treasury" },
    scopes: ["payments.transfer"],
    spendCeiling: 10_000,
    humanAbove: 2_000,
    escalation: "finance@umbrella.example",
  });

  const payment = (iban) => ({
    scope: "payments.transfer",
    amount: { amount: 400, currency: "USD" },
    counterpartyDomain: "acme.example",
    action: { tool: "payments.create_transfer", target: "supplier_412", args: { iban, amount: 400, reference: "INV-2291" } },
  });

  const approved = payment("GB33BUKB20201555555555");
  const decision = await authorize(verification, approved, { now });
  assert.equal(decision.decision, "allow");

  // The executor receives an account number nobody approved.
  const swapped = payment("GB94BARC10201530093459");
  assert.deepEqual(codes((await checkExecution(decision, swapped, { now })).errors), ["execution.request-changed"]);

  // The approved payment runs once, and only once.
  const store = memoryNonceStore({ now });
  assert.deepEqual(await checkExecution(decision, approved, { now, nonceStore: store }), { ok: true });
  assert.deepEqual(codes((await checkExecution(decision, approved, { now, nonceStore: store })).errors), [
    "execution.replayed",
  ]);
});

test("scenario: a person confirms an escalation, inside and outside the response window", async () => {
  const { verification } = await publishAndVerify("acme.example", {
    legalName: "Acme Corporation",
    agentName: "Acme Procurement Agent",
    role: "procurement",
    purpose: "Buys software licences for Acme within budget.",
    endpoints: { mcp: "https://agents.acme.example/mcp" },
    scopes: ["procurement.purchase"],
    spendCeiling: 50_000,
    humanAbove: 10_000,
    escalation: "procurement-team@acme.example",
    slaHours: 4,
  });

  const t0 = now();
  const order = {
    scope: "procurement.purchase",
    amount: { amount: 42_000, currency: "USD" },
    counterpartyDomain: "globex.example",
    action: { tool: "orders.create", target: "quote_77", args: { seats: 200, term: "12m" } },
  };
  const decision = await authorize(verification, order, { now: () => t0 });
  assert.equal(decision.decision, "escalate");

  const at = (hours) => ({ now: () => new Date(t0.getTime() + hours * 3600 * 1000) });
  assert.deepEqual(codes((await checkExecution(decision, order, at(1.5))).errors), ["execution.needs-human"]);
  assert.deepEqual(await checkExecution(decision, order, { ...at(1.5), humanApproved: true }), { ok: true });

  // The person's confirmation does not survive past the issuer's own window.
  assert.deepEqual(codes((await checkExecution(decision, order, { ...at(5), humanApproved: true })).errors), [
    "execution.expired",
  ]);
});

test("scenario: an issuer's first run through the CLI, from init to a bound decision", async () => {
  const dir = mkdtempSync(join(tmpdir(), "agent-passport-scenario-"));
  try {
    const run = (...args) => execFileSync(process.execPath, [cli, ...args], { cwd: dir, encoding: "utf8" });
    const keyPath = join(dir, "keys", "initech.pem");
    const out = run(
      "init", "--yes",
      "--domain", "initech.example",
      "--legal-name", "Initech LLC",
      "--role", "support",
      "--purpose", "Answers partner support requests and issues small refunds.",
      "--endpoint", "https://agents.initech.example/mcp",
      "--scope", "support.refund,support.credit",
      "--ceiling", "2000",
      "--human-above", "250",
      "--escalation", "support@initech.example",
      "--key-out", keyPath,
    );
    const record = out.split("\n").map((l) => l.trim()).find((l) => l.startsWith("Value:"))?.slice(6).trim();
    const publicKey = record.split("pk=")[1];
    const passportPath = join(dir, ".well-known", "agent-passport.json");

    // The issuer checks its own file the way a counterparty will.
    const verified = run("verify", passportPath, "--public-key", publicKey, "--no-revocation");
    assert.match(verified, /Verified/);

    // A counterparty decides on a concrete action, and the decision is bound to it.
    const decision = JSON.parse(
      run("authorize", passportPath, "--public-key", publicKey, "--no-revocation",
        "--scope", "support.refund", "--amount", "100",
        "--tool", "billing.refund", "--target", "invoice_1", "--args", '{"reason":"duplicate"}', "--json"),
    );
    assert.equal(decision.decision, "allow");
    assert.match(decision.binding.digest, /^sha256:[0-9a-f]{64}$/);

    const check = await checkExecution(decision, {
      scope: "support.refund",
      amount: { amount: 100, currency: "USD" },
      action: { tool: "billing.refund", target: "invoice_1", args: { reason: "duplicate" } },
    });
    assert.deepEqual(check, { ok: true });

    // Renewal keeps the file valid and still verifiable with the same key.
    run("renew", passportPath, "--key", keyPath, "--days", "30", "--offline");
    const renewed = JSON.parse(readFileSync(passportPath, "utf8"));
    assert.equal(renewed.signature.keyId, decision.keyId);
    assert.match(run("verify", passportPath, "--public-key", publicKey, "--no-revocation"), /Verified/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
