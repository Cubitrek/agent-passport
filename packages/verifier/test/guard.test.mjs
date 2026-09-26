/**
 * The guard kernel: authority from somewhere other than a passport, ceilings
 * that are counted rather than asserted, and receipts that prove what
 * happened without carrying what was in the request.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  checkAndHold,
  checkExecution,
  decide,
  guardedCall,
  intersect,
  localPolicy,
  memoryNonceStore,
  memoryReceiptSink,
  memorySpendLedger,
  passportAuthority,
  signReceipt,
  verifyReceipt,
} from "../dist/index.js";
import { fileSpendLedger } from "../dist/ledger-node.js";

const NOW = new Date("2026-06-10T09:00:00Z");
const now = () => NOW;
const codes = (list) => (list ?? []).map((e) => e.code);

const policy = (over = {}) =>
  localPolicy({
    id: "treasury-local",
    agentId: "ops-bot",
    label: "the local treasury policy",
    scope: ["payments.transfer", "invoices.read"],
    limits: [{ amount: 1_000, currency: "USD", window: "day", label: "your daily cap" }],
    humanInLoop: { above: { amount: 500, currency: "USD" }, escalation: "finance@local", slaHours: 4 },
    counterparties: { openTo: "any" },
    ...over,
  });

const transfer = (amount, over = {}) => ({
  scope: "payments.transfer",
  amount: { amount, currency: "USD" },
  action: {
    tool: "payments.create_transfer",
    target: "supplier_412",
    args: { iban: "GB33BUKB20201555555555", amount, reference: "INV-2291" },
  },
  ...over,
});

function sink() {
  const effects = [];
  return {
    effects,
    run(request) {
      return () => {
        effects.push(request.action);
        return { id: `tx_${effects.length}` };
      };
    },
  };
}

test("a local policy grants authority with no passport anywhere in sight", async () => {
  const ledger = memorySpendLedger();
  const allowed = await decide(policy(), transfer(100), { now, ledger });
  assert.equal(allowed.decision, "allow");
  assert.deepEqual(allowed.origin, [
    { kind: "policy", id: "treasury-local", label: "the local treasury policy" },
  ]);
  assert.equal(allowed.subject.agentId, "ops-bot");
  assert.equal(allowed.subject.issuerDomain, undefined);
  assert.match(allowed.binding.digest, /^sha256:[0-9a-f]{64}$/);

  assert.deepEqual(codes((await decide(policy(), transfer(600), { now, ledger })).reasons), [
    "amount.above-human-threshold",
  ]);
  assert.deepEqual(codes((await decide(policy(), transfer(5_000), { now, ledger })).reasons), [
    "amount.above-ceiling",
  ]);
  assert.deepEqual(
    codes(
      (await decide(policy(), { ...transfer(10), scope: "payments.refund" }, { now, ledger }))
        .reasons,
    ),
    ["scope.not-granted"],
  );
});

test("intersecting two authorities grants only what both grant", async () => {
  const broad = localPolicy({
    id: "broad",
    scope: ["payments.transfer", "invoices.read", "contracts.sign"],
    limits: [{ amount: 10_000, currency: "USD", window: "total" }],
    humanInLoop: { above: { amount: 5_000, currency: "USD" }, escalation: "cfo@local", slaHours: 24 },
    counterparties: { allowlist: ["globex.example", "initech.example"], openTo: "allowlist-only" },
    compliance: { dataClassification: "confidential-business", regions: ["US", "GB", "DE"] },
  });
  const tight = localPolicy({
    id: "tight",
    scope: ["payments.transfer", "invoices.read"],
    limits: [{ amount: 900, currency: "USD", window: "day" }],
    humanInLoop: { above: { amount: 250, currency: "USD" }, escalation: "ops@local", slaHours: 2 },
    counterparties: { allowlist: ["globex.example"], blocklist: ["evil.example"] },
    compliance: { dataClassification: "internal", regions: ["US", "GB"] },
  });
  const both = intersect(broad, tight);

  assert.deepEqual(both.scope, ["payments.transfer", "invoices.read"]);
  assert.equal(both.ceilings.length, 2);
  assert.deepEqual(both.humanInLoop, {
    above: { amount: 250, currency: "USD" },
    escalation: "ops@local",
    slaHours: 2,
  });
  assert.deepEqual(both.counterparties.allowlist, ["globex.example"]);
  assert.deepEqual(both.counterparties.blocklist, ["evil.example"]);
  assert.equal(both.counterparties.openTo, "allowlist-only");
  assert.equal(both.compliance.dataClassification, "internal");
  assert.deepEqual(both.compliance.regions, ["US", "GB"]);

  const ledger = memorySpendLedger();
  const ask = async (req) => codes((await decide(both, req, { now, ledger })).reasons);
  assert.deepEqual(await ask({ ...transfer(100), counterpartyDomain: "globex.example" }), [
    "authority.within-envelope",
  ]);
  // Allowed by the broad policy's scope, absent from the tight one.
  assert.deepEqual(
    await ask({ ...transfer(100), scope: "contracts.sign", counterpartyDomain: "globex.example" }),
    ["scope.not-granted"],
  );
  // Inside the broad ceiling, over the tight daily cap.
  assert.deepEqual(await ask({ ...transfer(950), counterpartyDomain: "globex.example" }), [
    "amount.above-ceiling",
  ]);
  // Allowlisted by the broad policy, not by the tight one.
  assert.deepEqual(await ask({ ...transfer(100), counterpartyDomain: "initech.example" }), [
    "counterparty.not-allowlisted",
  ]);
});

test("an unverified passport intersected with a local policy still grants nothing", async () => {
  const unverified = passportAuthority({
    ok: false,
    errors: [{ code: "time.expired", message: "expired" }],
    warnings: [],
  });
  const combined = intersect(unverified, policy());
  const result = await decide(combined, transfer(1), { now });
  assert.equal(result.decision, "deny");
  assert.deepEqual(codes(result.reasons), ["passport.unverified"]);
  assert.equal(result.agentId, undefined);
});

test("a ledger counts spend, so a daily cap holds across separate decisions", async () => {
  const ledger = memorySpendLedger();
  const receipts = memoryReceiptSink();
  const provider = sink();
  const spend = async (amount) => {
    const request = transfer(amount);
    const decision = await decide(policy(), request, { now, ledger });
    return guardedCall(decision, request, provider.run(request), { now, ledger, receipts });
  };

  assert.equal((await spend(400)).outcome, "executed");
  assert.equal((await spend(400)).outcome, "executed");
  const third = await spend(400);
  assert.equal(third.outcome, "blocked");
  assert.deepEqual(third.reasons.map((r) => r.code), ["execution.denied"]);
  assert.equal(provider.effects.length, 2);

  assert.equal(
    await ledger.committed({ subject: "ops-bot", currency: "USD", window: "day", at: NOW }),
    800,
  );
  // The next UTC day starts from zero.
  const tomorrow = new Date("2026-06-11T00:30:00Z");
  assert.equal(
    await ledger.committed({ subject: "ops-bot", currency: "USD", window: "day", at: tomorrow }),
    0,
  );
  assert.deepEqual(
    receipts.receipts.map((r) => r.outcome),
    ["executed", "executed", "blocked"],
  );
});

test("two decisions taken before either executes cannot both spend the cap", async () => {
  const request = transfer(700);
  // Without a ledger, both callers see the same prior total and both pass.
  const blind = [
    await decide(policy(), request, { now }),
    await decide(policy(), request, { now }),
  ];
  assert.deepEqual(
    blind.map((d) => d.decision),
    ["escalate", "escalate"],
  );

  // With one, the first decision holds the money and the second cannot fit.
  const ledger = memorySpendLedger();
  const small = transfer(600);
  const first = await decide(policy({ humanInLoop: undefined }), small, { now, ledger });
  const second = await decide(policy({ humanInLoop: undefined }), small, { now, ledger });
  assert.equal(first.decision, "allow");
  assert.equal(first.charge.reserved, true);
  assert.equal(second.decision, "deny");
  assert.deepEqual(codes(second.reasons), ["amount.above-ceiling"]);
  assert.match(second.reasons[0].hint, /600 USD is already committed or held/);
});

test("a blocked execution gives the held amount back", async () => {
  const ledger = memorySpendLedger();
  const request = transfer(900);
  const decision = await decide(policy({ humanInLoop: undefined }), request, { now, ledger });
  assert.equal(decision.charge.reserved, true);
  assert.equal(
    await ledger.outstanding({ subject: "ops-bot", currency: "USD", window: "day", at: NOW }),
    900,
  );

  const mutated = { ...request, action: { ...request.action, target: "supplier_999" } };
  const result = await guardedCall(decision, mutated, () => assert.fail("must not run"), { now, ledger });
  assert.equal(result.outcome, "blocked");
  assert.deepEqual(result.reasons.map((r) => r.code), ["execution.request-changed"]);
  assert.equal(
    await ledger.outstanding({ subject: "ops-bot", currency: "USD", window: "day", at: NOW }),
    0,
  );
  // The headroom really came back: the same amount can be spent again.
  const retry = await decide(policy({ humanInLoop: undefined }), transfer(900), { now, ledger });
  assert.equal(retry.decision, "allow");
});

test("an effect whose result is lost counts as spent unless told otherwise", async () => {
  const run = async (onUnknown) => {
    const ledger = memorySpendLedger();
    const request = transfer(300);
    const decision = await decide(policy({ humanInLoop: undefined }), request, { now, ledger });
    const result = await guardedCall(
      decision,
      request,
      () => {
        throw new Error("socket hang up");
      },
      { now, ledger, onUnknown },
    );
    assert.equal(result.outcome, "unknown");
    assert.equal(result.receipt.outcome, "unknown");
    assert.deepEqual(result.receipt.blockedBecause, ["execution.result-unknown"]);
    return ledger.committed({ subject: "ops-bot", currency: "USD", window: "day", at: NOW });
  };
  assert.equal(await run(undefined), 300, "the default assumes the money moved");
  assert.equal(await run("release"), 0);
});

test("an escalation reserves when the person confirms, not when it is decided", async () => {
  const ledger = memorySpendLedger();
  const request = transfer(600);
  const escalated = await decide(policy(), request, { now, ledger });
  assert.equal(escalated.decision, "escalate");
  assert.equal(escalated.charge.reserved, false);
  assert.deepEqual(escalated.escalation, { to: "finance@local", slaHours: 4 });
  // Nothing is held while it waits, so other work is not blocked meanwhile.
  assert.equal(
    await ledger.outstanding({ subject: "ops-bot", currency: "USD", window: "day", at: NOW }),
    0,
  );

  // Someone else spends most of the cap while the person is deciding.
  const other = transfer(800);
  const meanwhile = await decide(policy({ humanInLoop: undefined }), other, { now, ledger });
  await guardedCall(meanwhile, other, () => "done", { now, ledger });

  const confirmed = await guardedCall(escalated, request, () => assert.fail("must not run"), {
    now,
    ledger,
    humanApproved: true,
  });
  assert.equal(confirmed.outcome, "blocked");
  assert.deepEqual(confirmed.reasons.map((r) => r.code), ["amount.above-ceiling"]);

  // Without the confirmation it does not run either.
  const unconfirmed = await guardedCall(escalated, request, () => assert.fail("must not run"), {
    now,
    ledger,
  });
  assert.deepEqual(unconfirmed.reasons.map((r) => r.code), ["execution.needs-human"]);
});

test("a receipt records the call without carrying what was in it", async () => {
  const canary = "GB33BUKB20201555555555";
  const request = transfer(100);
  assert.ok(JSON.stringify(request).includes(canary), "the request does carry the account number");

  const receipts = memoryReceiptSink();
  const ledger = memorySpendLedger();
  const decision = await decide(policy(), request, { now, ledger });
  const result = await guardedCall(decision, request, () => "ok", { now, ledger, receipts });
  assert.equal(result.outcome, "executed");

  const [receipt] = receipts.receipts;
  const serialised = JSON.stringify(receipt);
  assert.ok(!serialised.includes(canary), "the receipt must not carry the account number");
  assert.ok(!serialised.includes("supplier_412"), "the receipt must not carry the target");
  assert.equal(receipt.request.tool, "payments.create_transfer");
  assert.equal(receipt.request.scope, "payments.transfer");
  assert.deepEqual(receipt.request.amount, { amount: 100, currency: "USD" });
  assert.equal(receipt.decision, "allow");
  assert.equal(receipt.binding.digest, decision.binding.digest);
  assert.deepEqual(receipt.reasons, ["authority.within-envelope"]);
});

test("a signed receipt verifies, and any edit to it does not", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = new Uint8Array(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url"));
  const pkcs8 = new Uint8Array(privateKey.export({ type: "pkcs8", format: "der" }));

  const receipts = memoryReceiptSink();
  const request = transfer(100);
  const decision = await decide(policy(), request, { now, ledger: memorySpendLedger() });
  await guardedCall(decision, request, () => "ok", {
    now,
    receipts,
    signReceiptsWith: { keyId: "receipts-2026-q3", privateKey: pkcs8 },
  });
  const [receipt] = receipts.receipts;
  assert.equal(receipt.signature.keyId, "receipts-2026-q3");
  assert.deepEqual(await verifyReceipt(receipt, raw), { ok: true });

  for (const edit of [
    { outcome: "blocked" },
    { decision: "deny" },
    { request: { ...receipt.request, amount: { amount: 1, currency: "USD" } } },
    { binding: { ...receipt.binding, digest: "sha256:0" } },
    { subject: { agentId: "someone-else" } },
  ]) {
    const tampered = { ...receipt, ...edit };
    const check = await verifyReceipt(tampered, raw);
    assert.equal(check.ok, false, JSON.stringify(edit));
    assert.deepEqual(codes(check.errors), ["receipt.signature-invalid"]);
  }

  const unsigned = { ...receipt, signature: undefined };
  assert.deepEqual(codes((await verifyReceipt(unsigned, raw)).errors), ["receipt.unsigned"]);
  const other = generateKeyPairSync("ed25519");
  const otherRaw = new Uint8Array(Buffer.from(other.publicKey.export({ format: "jwk" }).x, "base64url"));
  assert.equal((await verifyReceipt(receipt, otherRaw)).ok, false);
});

test("an unsigned receipt round-trips through signReceipt without changing what it says", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pkcs8 = new Uint8Array(privateKey.export({ type: "pkcs8", format: "der" }));
  const raw = new Uint8Array(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url"));
  const receipts = memoryReceiptSink();
  const request = transfer(100);
  const decision = await decide(policy(), request, { now, ledger: memorySpendLedger() });
  await guardedCall(decision, request, () => "ok", { now, receipts });
  const plain = receipts.receipts[0];
  const signed = await signReceipt(plain, { keyId: "k1", privateKey: pkcs8 });
  assert.deepEqual({ ...signed, signature: undefined }, { ...plain, signature: undefined });
  assert.equal((await verifyReceipt(signed, raw)).ok, true);
});

test("checkAndHold is the same gate, one step at a time", async () => {
  const ledger = memorySpendLedger();
  const nonceStore = memoryNonceStore({ now });
  const request = transfer(200);
  const decision = await decide(policy(), request, { now, ledger });

  const gate = await checkAndHold(decision, request, { now, ledger, nonceStore });
  assert.equal(gate.ok, true);
  const receipt = await gate.hold.commit();
  assert.equal(receipt.outcome, "executed");
  assert.equal(
    await ledger.committed({ subject: "ops-bot", currency: "USD", window: "day", at: NOW }),
    200,
  );

  const replay = await checkAndHold(decision, request, { now, ledger, nonceStore });
  assert.equal(replay.ok, false);
  assert.deepEqual(replay.reasons.map((r) => r.code), ["execution.replayed"]);
  // Settling is idempotent: the replay must not claw back the first, real spend.
  assert.equal(
    await ledger.committed({ subject: "ops-bot", currency: "USD", window: "day", at: NOW }),
    200,
  );
  await ledger.release(decision.binding.nonce);
  assert.equal(
    await ledger.committed({ subject: "ops-bot", currency: "USD", window: "day", at: NOW }),
    200,
  );
});

test("a file ledger survives a restart and keeps the whole trail", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ap-ledger-"));
  const path = join(dir, "spend", "ledger.jsonl");
  try {
    const request = transfer(700);
    const first = await decide(policy({ humanInLoop: undefined }), request, {
      now,
      ledger: fileSpendLedger(path),
    });
    await guardedCall(first, request, () => "ok", { now, ledger: fileSpendLedger(path) });

    // A brand new process, reading the same file.
    const restarted = fileSpendLedger(path);
    assert.equal(
      await restarted.committed({ subject: "ops-bot", currency: "USD", window: "day", at: NOW }),
      700,
    );
    const second = await decide(policy({ humanInLoop: undefined }), transfer(700), {
      now,
      ledger: restarted,
    });
    assert.equal(second.decision, "deny");
    assert.deepEqual(codes(second.reasons), ["amount.above-ceiling"]);

    const lines = readFileSync(path, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(lines.map((l) => l.state), ["reserved", "committed"]);
    assert.equal(lines[0].amount, 700);
    const entries = await restarted.entries();
    assert.equal(entries.length, 1);
    assert.equal(entries[0].state, "committed");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("monthly and total windows count over their own period", async () => {
  const ledger = memorySpendLedger();
  const monthly = localPolicy({
    id: "monthly",
    agentId: "ops-bot",
    scope: ["payments.transfer"],
    limits: [{ amount: 1_500, currency: "USD", window: "month" }],
  });
  const spend = async (at, amount) => {
    const request = transfer(amount);
    const decision = await decide(monthly, request, { now: () => at, ledger });
    return guardedCall(decision, request, () => "ok", { now: () => at, ledger });
  };

  assert.equal((await spend(new Date("2026-06-02T00:00:00Z"), 1_000)).outcome, "executed");
  assert.equal((await spend(new Date("2026-06-28T00:00:00Z"), 1_000)).outcome, "blocked");
  assert.equal((await spend(new Date("2026-07-01T00:00:00Z"), 1_000)).outcome, "executed");
  assert.equal(
    await ledger.committed({
      subject: "ops-bot",
      currency: "USD",
      window: "total",
      at: new Date("2026-07-01T00:00:00Z"),
    }),
    2_000,
  );
});

test("a cap in another currency escalates instead of being compared", async () => {
  const eur = localPolicy({
    id: "eur",
    agentId: "ops-bot",
    scope: ["payments.transfer"],
    limits: [{ amount: 1_000, currency: "EUR", window: "day" }],
  });
  const result = await decide(eur, transfer(10), { now, ledger: memorySpendLedger() });
  assert.equal(result.decision, "escalate");
  assert.deepEqual(codes(result.reasons), ["amount.currency-unsupported"]);
});

test("a cap that nothing is counting escalates rather than passing quietly", async () => {
  // The whole point of a daily cap is the running total. With no ledger and
  // no priorSpend, nobody has one, so this is a question for a person.
  const result = await decide(policy(), transfer(100), { now });
  assert.equal(result.decision, "escalate");
  assert.deepEqual(codes(result.reasons), ["amount.cumulative-unknown"]);
  assert.match(result.reasons[0].message, /pass a ledger or priorSpend/);

  const total = localPolicy({
    id: "total-cap",
    agentId: "ops-bot",
    scope: ["payments.transfer"],
    limits: [{ amount: 1_000, currency: "USD", window: "total" }],
  });
  assert.deepEqual(codes((await decide(total, transfer(100), { now })).reasons), [
    "amount.cumulative-unknown",
  ]);
});

/**
 * A ceiling is enforced in two places: when the decision is made, so the
 * refusal can say why, and inside the ledger's reservation, which is the
 * atomic one a shared store has to implement. Each of the next two tests
 * isolates one of them, so neither can quietly stop working behind the
 * other.
 */

test("a cap that is already used up denies rather than asking a person", async () => {
  const ledger = memorySpendLedger();
  const warmup = transfer(900);
  const opening = await decide(policy({ humanInLoop: undefined }), warmup, { now, ledger });
  await guardedCall(opening, warmup, () => "ok", { now, ledger });

  // 600 is over the 500 human threshold, and also past the 100 that is left
  // of the daily cap. Reading the running total at decision time is what
  // separates "ask someone" from "there is no room for this".
  const result = await decide(policy(), transfer(600), { now, ledger });
  assert.equal(result.decision, "deny");
  assert.deepEqual(codes(result.reasons), ["amount.above-ceiling"]);
  assert.match(result.reasons[0].message, /1,500 USD for this day exceeds 1,000 USD/);
});

test("the ledger itself refuses a reservation that would break a ceiling", async () => {
  const ledger = memorySpendLedger();
  const ceilings = [{ amount: 1_000, currency: "USD", window: "day", label: "your daily cap" }];
  const base = {
    subject: "ops-bot",
    currency: "USD",
    ceilings,
    at: NOW,
    expiresAt: "2026-06-10T09:01:00Z",
  };

  assert.deepEqual(await ledger.reserve({ ...base, amount: 700, nonce: "n1" }), { ok: true });
  const refused = await ledger.reserve({ ...base, amount: 700, nonce: "n2" });
  assert.equal(refused.ok, false);
  assert.equal(refused.prior, 700);
  assert.equal(refused.wouldBe, 1_400);
  assert.equal(refused.ceiling.label, "your daily cap");

  // A held amount stops counting once the decision holding it has expired.
  const later = new Date("2026-06-10T09:05:00Z");
  assert.deepEqual(await ledger.reserve({ ...base, amount: 700, nonce: "n3", at: later }), {
    ok: true,
  });

  // A ceiling in another currency is not this ledger's business to compare.
  const eur = [{ amount: 1, currency: "EUR", window: "day", label: "a euro cap" }];
  assert.deepEqual(
    await ledger.reserve({ ...base, ceilings: eur, amount: 5_000, nonce: "n4", at: later }),
    { ok: true },
  );
});

/* The same three sources of authority, reached from a shell. */

import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { draftAgentPassport, dnsTxtRecord, signAgentPassport } from "../dist/index.js";

const cli = resolve(dirname(fileURLToPath(import.meta.url)), "../bin/agent-passport.mjs");
const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
const runJson = (...args) => {
  const out = run(...args, "--json");
  assert.ok(out.stdout, `no output from: ${args.join(" ")}\n${out.stderr}`);
  return { ...JSON.parse(out.stdout), status: out.status };
};

function tempPolicy(dir, body) {
  const path = resolve(dir, "policy.json");
  writeFileSync(path, JSON.stringify(body));
  return path;
}

test("the CLI decides against a policy file with no passport anywhere", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ap-cli-"));
  try {
    const policyPath = tempPolicy(dir, {
      id: "treasury-local",
      agentId: "ops-bot",
      label: "our treasury policy",
      scope: ["payments.transfer"],
      limits: [{ amount: 1_000, currency: "USD", window: "day" }],
      humanInLoop: { above: { amount: 500, currency: "USD" }, escalation: "finance@local" },
    });
    // --prior-spend says what has already gone against the cap. Without it,
    // and without a --ledger, nothing is counting the day, which is a
    // question for a person rather than a quiet yes.
    const unchecked = runJson("authorize", "--policy", policyPath, "--scope", "payments.transfer", "--amount", "100");
    assert.equal(unchecked.decision, "escalate");
    assert.deepEqual(unchecked.reasons.map((r) => r.code), ["amount.cumulative-unknown"]);

    const ask = (amount) =>
      runJson("authorize", "--policy", policyPath, "--scope", "payments.transfer",
        "--amount", String(amount), "--prior-spend", "0");

    assert.equal(ask(100).decision, "allow");
    assert.equal(ask(100).status, 0);
    assert.equal(ask(600).decision, "escalate");
    assert.equal(ask(600).status, 2);
    assert.equal(ask(9_000).decision, "deny");
    assert.equal(ask(9_000).status, 1);
    assert.equal(
      runJson("authorize", "--policy", policyPath, "--scope", "payments.refund", "--amount", "1",
        "--prior-spend", "0").reasons[0].code,
      "scope.not-granted",
    );
    assert.match(run("authorize", "--scope", "payments.transfer").stderr, /authorize \[<domain/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the CLI keeps a running total in a ledger file, and settle closes it out", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ap-cli-"));
  try {
    const policyPath = tempPolicy(dir, {
      id: "treasury-local",
      agentId: "ops-bot",
      scope: ["payments.transfer"],
      limits: [{ amount: 1_000, currency: "USD", window: "day" }],
    });
    const ledger = resolve(dir, "spend.jsonl");
    const ask = (amount) =>
      runJson("authorize", "--policy", policyPath, "--ledger", ledger, "--scope", "payments.transfer", "--amount", String(amount));

    const first = ask(400);
    assert.equal(first.decision, "allow");
    assert.equal(first.charge.reserved, true);
    assert.deepEqual(runJson("settle", first.binding.nonce, "--ledger", ledger, "--commit"), {
      nonce: first.binding.nonce,
      was: "reserved",
      now: "committed",
      amount: 400,
      currency: "USD",
      status: 0,
    });

    const second = ask(400);
    assert.equal(second.decision, "allow");
    run("settle", second.binding.nonce, "--ledger", ledger, "--commit");

    // 800 is committed, so the third does not fit and holds nothing.
    const third = ask(400);
    assert.equal(third.decision, "deny");
    assert.deepEqual(third.reasons.map((r) => r.code), ["amount.above-ceiling"]);
    assert.equal(third.charge.reserved, false);

    // Releasing one of the committed ones gives the room back.
    assert.equal(runJson("settle", first.binding.nonce, "--ledger", ledger, "--release").now, "committed");
    assert.equal(ask(400).decision, "deny", "a committed amount is not released");

    assert.equal(run("settle", "no-such-nonce", "--ledger", ledger, "--commit").status, 1);
    assert.equal(run("settle", first.binding.nonce, "--ledger", ledger, "--commit", "--release").status, 1);
    assert.equal(run("settle", first.binding.nonce, "--commit").status, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the CLI intersects a counterparty's passport with your own policy", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ap-cli-"));
  try {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const raw = new Uint8Array(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url"));
    const draft = draftAgentPassport({
      domain: "acme.example",
      legalName: "Acme Corporation",
      agentName: "Acme Treasury Agent",
      role: "treasury",
      purpose: "Pays approved supplier invoices inside the published limits.",
      endpoints: { rest: "https://agents.acme.example/api/treasury" },
      scopes: ["payments.transfer", "contracts.sign"],
      spendCeiling: 10_000,
      humanAbove: 2_000,
      escalation: "finance@acme.example",
      keyId: "acme-2026-q3",
    });
    const passportPath = resolve(dir, "passport.json");
    writeFileSync(
      passportPath,
      JSON.stringify(await signAgentPassport(draft, new Uint8Array(privateKey.export({ type: "pkcs8", format: "der" })))),
    );
    assert.match(dnsTxtRecord({ keyId: "acme-2026-q3", publicKeyRaw: raw }), /^v=ap1;/);

    const policyPath = tempPolicy(dir, {
      id: "ours",
      label: "our own limits",
      scope: ["payments.transfer"],
      limits: [{ amount: 900, currency: "USD", window: "day" }],
    });
    const key = Buffer.from(raw).toString("base64url");
    const ask = (args) =>
      runJson("authorize", passportPath, ...args, "--public-key", key, "--no-revocation",
        "--prior-spend", "0", "--scope", "payments.transfer");

    // The passport alone allows 5,000; our own cap does not.
    assert.equal(ask(["--amount", "5000"]).decision, "escalate");
    const combined = ask(["--amount", "5000", "--policy", policyPath]);
    assert.equal(combined.decision, "deny");
    assert.deepEqual(combined.reasons.map((r) => r.code), ["amount.above-ceiling"]);
    assert.deepEqual(
      combined.origin.map((o) => o.kind),
      ["passport", "policy"],
    );

    // A scope the passport grants but our policy does not.
    const scoped = runJson("authorize", passportPath, "--policy", policyPath, "--public-key", key,
      "--no-revocation", "--prior-spend", "0", "--scope", "contracts.sign", "--amount", "10");
    assert.deepEqual(scoped.reasons.map((r) => r.code), ["scope.not-granted"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/* The MCP server, with a policy its operator set and the model cannot widen. */

function mcpCalls(args, calls) {
  const messages = [
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } },
    { jsonrpc: "2.0", id: 2, method: "tools/list" },
    ...calls.map((c, i) => ({ jsonrpc: "2.0", id: 10 + i, method: "tools/call", params: { name: "authorize_agent_action", arguments: c } })),
  ];
  const out = spawnSync(process.execPath, [cli, "mcp", ...args], {
    input: `${messages.map((m) => JSON.stringify(m)).join("\n")}\n`,
    encoding: "utf8",
    timeout: 30_000,
  });
  const replies = new Map();
  for (const line of out.stdout.trim().split("\n")) {
    if (!line) continue;
    const reply = JSON.parse(line);
    replies.set(reply.id, reply);
  }
  return replies;
}

test("the MCP server enforces its operator's policy and the model cannot widen it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ap-mcp-"));
  try {
    const policyPath = tempPolicy(dir, {
      id: "assistant-limits",
      agentId: "claude-code",
      label: "this machine's assistant limits",
      scope: ["payments.transfer"],
      limits: [{ amount: 200, currency: "USD", window: "day" }],
    });

    const replies = mcpCalls(["--policy", policyPath], [
      // 500 is over the operator's 200 cap.
      { scope: "payments.transfer", amount: 500, prior_spend: 0, tool: "payments.create_transfer" },
      // The same call, with a policy of the model's own invention attached.
      {
        scope: "payments.transfer",
        amount: 500,
        prior_spend: 0,
        tool: "payments.create_transfer",
        policy: { id: "mine", scope: ["payments.transfer"], limits: [{ amount: 999_999, currency: "USD" }] },
      },
      // A scope the operator's policy does not grant.
      { scope: "contracts.sign", amount: 1, prior_spend: 0 },
    ]);

    // With a policy in force, a counterparty domain is no longer required.
    const listed = replies.get(2).result.tools.find((t) => t.name === "authorize_agent_action");
    assert.deepEqual(listed.inputSchema.required, ["scope"]);
    assert.match(replies.get(1).result.instructions, /You cannot change or widen it/);

    const decision = (id) => replies.get(id).result.structuredContent;
    assert.equal(decision(10).decision, "deny");
    assert.deepEqual(decision(10).reasons.map((r) => r.code), ["amount.above-ceiling"]);

    // The model's own policy changes nothing: same verdict, same reason.
    assert.equal(decision(11).decision, "deny");
    assert.deepEqual(decision(11).reasons.map((r) => r.code), ["amount.above-ceiling"]);
    assert.deepEqual(
      decision(11).origin,
      [{ kind: "policy", id: "assistant-limits", label: "this machine's assistant limits" }],
    );

    assert.deepEqual(decision(12).reasons.map((r) => r.code), ["scope.not-granted"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("without a policy the MCP server still requires a counterparty domain", async () => {
  const replies = mcpCalls([], [{ scope: "payments.transfer", amount: 10 }]);
  const listed = replies.get(2).result.tools.find((t) => t.name === "authorize_agent_action");
  assert.deepEqual(listed.inputSchema.required, ["domain", "scope"]);
  assert.equal(replies.get(10).result.isError, true);
  assert.match(replies.get(10).result.content[0].text, /domain is required/);
});

/**
 * The package advertises that it runs in Cloudflare Workers and browsers, and
 * dns.ts goes out of its way to use DNS-over-HTTPS rather than node:dns to
 * keep that true. Anything reachable from the main entry has to hold the same
 * line, so the on-disk ledger sits behind the "/node" subpath instead.
 */
test("nothing reachable from the main entry imports a Node built-in", async () => {
  const dist = resolve(dirname(fileURLToPath(import.meta.url)), "../dist");
  const seen = new Set();
  const leaks = [];
  const walk = (file) => {
    if (seen.has(file)) return;
    seen.add(file);
    const source = readFileSync(resolve(dist, file), "utf8");
    for (const m of source.matchAll(/from "(\.\/[^"]+)"/g)) walk(m[1].slice(2));
    for (const m of source.matchAll(/from "(node:[^"]+)"/g)) leaks.push(`${file} imports ${m[1]}`);
  };
  walk("index.js");

  assert.deepEqual(leaks, []);
  assert.ok(seen.size > 5, `only walked ${seen.size} files, so the check proved nothing`);
  assert.ok(seen.has("authorize.js") && seen.has("ledger.js"), "the walk did not reach the new modules");
  assert.ok(!seen.has("ledger-node.js"), "the on-disk ledger must not be reachable from the main entry");

  // And the subpath that is allowed to use them really does.
  const nodeOnly = readFileSync(resolve(dist, "ledger-node.js"), "utf8");
  assert.match(nodeOnly, /from "node:fs"/);
});

/* Inputs a caller can actually send, including the ones they should not. */

test("a negative amount is refused, and an unrepresentable one is a programming error", async () => {
  const ledger = memorySpendLedger();
  for (const opts of [{ now }, { now, ledger }]) {
    const result = await decide(policy(), transfer(-100), opts);
    assert.equal(result.decision, "deny");
    assert.deepEqual(codes(result.reasons), ["amount.invalid"]);
    assert.equal(result.charge?.reserved, false);
  }
  // Letting one through would subtract from the running total, so check that
  // nothing was recorded against the ceiling either way.
  assert.equal(
    await ledger.outstanding({ subject: "ops-bot", currency: "USD", window: "day", at: NOW }),
    0,
  );

  for (const bad of [Number.NaN, Infinity, -Infinity]) {
    await assert.rejects(decide(policy(), transfer(bad), { now }), {
      name: "TypeError",
      message: /amount\.amount must be a finite number/,
    });
  }
  assert.equal((await decide(policy(), transfer(0), { now, ledger })).decision, "allow");
});

test("a policy cannot set a ceiling over a window that does not exist", () => {
  const withWindow = (window) =>
    localPolicy({ id: "w", scope: ["x"], limits: [{ amount: 1, currency: "USD", window }] });
  for (const window of ["engagement", "day", "month", "total"]) {
    assert.equal(withWindow(window).ceilings[0].window, window);
  }
  // "fortnight" used to be accepted and then quietly enforced as a total.
  for (const window of ["fortnight", "DAY", "week", "", null]) {
    assert.throws(() => withWindow(window), { name: "TypeError", message: /use one of/ }, String(window));
  }
  // An omitted window still means "total".
  assert.equal(localPolicy({ id: "w", scope: ["x"], limits: [{ amount: 1, currency: "USD" }] }).ceilings[0].window, "total");
});

test("a file ledger survives an interrupted append but refuses a corrupted one", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ap-ledger-"));
  const at = new Date("2026-09-26T10:00:00Z");
  const entry = (nonce, amount) =>
    JSON.stringify({ nonce, subject: "s", amount, currency: "USD", at: "2026-09-26T00:00:00Z", expiresAt: "2126-01-01T00:00:00Z", state: "committed" });
  const query = { subject: "s", currency: "USD", window: "day", at };
  try {
    // A crash mid-append leaves a partial last line. That record never landed,
    // so the rest of the ledger still has to be readable.
    const cut = join(dir, "cut.jsonl");
    writeFileSync(cut, `${entry("n1", 50)}\n{"nonce":"n2","sub`);
    assert.equal(await fileSpendLedger(cut).committed(query), 50);
    // And it keeps working: a new entry appends cleanly after the partial one.
    const after = fileSpendLedger(cut);
    assert.deepEqual(
      await after.reserve({ subject: "s", amount: 10, currency: "USD", ceilings: [], nonce: "n3", expiresAt: "2126-01-01T00:00:00Z", at }),
      { ok: true },
    );
    await after.commit("n3");
    assert.equal(await after.committed(query), 60);

    // Corruption anywhere else is not something to guess past: skipping the
    // line would drop committed spend and hand back headroom.
    const rotten = join(dir, "rotten.jsonl");
    writeFileSync(rotten, `${entry("n1", 50)}\nnot json at all\n${entry("n2", 10)}\n`);
    await assert.rejects(fileSpendLedger(rotten).committed(query), {
      message: /line 2 is not JSON/,
    });

    const nameless = join(dir, "nameless.jsonl");
    writeFileSync(nameless, `${entry("n1", 50)}\n{"amount":10}\n`);
    await assert.rejects(fileSpendLedger(nameless).committed(query), { message: /line 2 has no nonce/ });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("decisions taken in parallel cannot both spend the same headroom", async () => {
  const ledger = memorySpendLedger();
  const ask = () => decide(policy({ humanInLoop: undefined }), transfer(600), { now, ledger });
  const [a, b] = await Promise.all([ask(), ask()]);
  assert.deepEqual([a.decision, b.decision].sort(), ["allow", "deny"]);

  const more = await Promise.all(Array.from({ length: 5 }, ask));
  assert.deepEqual(new Set(more.map((d) => d.decision)), new Set(["deny"]));
  assert.equal(
    await ledger.outstanding({ subject: "ops-bot", currency: "USD", window: "day", at: NOW }),
    600,
    "the running total must never exceed what was actually allowed",
  );
});

test("a decision survives the trip through JSON that the CLI and MCP put it through", async () => {
  const request = transfer(100);
  const decision = await decide(policy(), request, { now, ledger: memorySpendLedger() });
  const overTheWire = JSON.parse(JSON.stringify(decision));

  assert.deepEqual(await checkExecution(overTheWire, request, { now }), { ok: true });
  // Key order is not part of the request; values are.
  const reordered = { ...request, action: { args: request.action.args, target: request.action.target, tool: request.action.tool } };
  assert.deepEqual(await checkExecution(overTheWire, reordered, { now }), { ok: true });
  assert.deepEqual(
    codes((await checkExecution(overTheWire, { ...request, amount: { amount: 101, currency: "USD" } }, { now })).errors),
    ["execution.request-changed"],
  );
});

test("a target or arguments without a tool name is refused, not quietly dropped", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ap-cli-"));
  try {
    const policyPath = tempPolicy(dir, {
      id: "p",
      agentId: "s",
      scope: ["x"],
      limits: [{ amount: 100, currency: "USD", window: "day" }],
    });
    const base = ["authorize", "--policy", policyPath, "--scope", "x", "--amount", "10", "--prior-spend", "0"];

    for (const extra of [["--args", '{"q":1}'], ["--target", "acct-1"], ["--target", "a", "--args", "{}"]]) {
      const out = run(...base, ...extra);
      assert.equal(out.status, 1, extra.join(" "));
      assert.match(out.stderr, /they need --tool as well/);
    }
    assert.equal(runJson(...base, "--tool", "t", "--args", '{"q":1}').decision, "allow");

    // With --tool the arguments really are bound, which is the point.
    const a = runJson(...base, "--tool", "t", "--args", '{"q":1}').binding.digest;
    const b = runJson(...base, "--tool", "t", "--args", '{"q":2}').binding.digest;
    assert.notEqual(a, b);

    // The MCP tool refuses the same shape.
    const replies = mcpCalls(["--policy", policyPath], [
      { scope: "x", amount: 10, prior_spend: 0, target: "acct-1" },
      { scope: "x", amount: 10, prior_spend: 0, tool: "t", target: "acct-1" },
    ]);
    assert.equal(replies.get(10).result.isError, true);
    assert.match(replies.get(10).result.content[0].text, /tool is required as well/);
    assert.equal(replies.get(11).result.isError, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
