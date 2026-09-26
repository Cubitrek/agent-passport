/**
 * The approval channel.
 *
 * The property everything rests on: an approval buys one exact call. What ties
 * the two together is the decision digest, which comes from the subject, the
 * authority and the request and from nothing else, so changing the amount, the
 * target or an argument makes the approval stop matching. None of that depends
 * on trusting whatever is asking.
 *
 * The second property is who may answer. An agent that can run a shell can run
 * the approve command, so a policy that names approvers takes only signed
 * answers from those keys.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const cli = resolve(here, "../bin/agent-passport.mjs");
const stub = resolve(here, "fixtures/stub-mcp.mjs");
const temp = () => mkdtempSync(join(tmpdir(), "ap-approve-"));

const POLICY = {
  id: "treasury-local",
  agentId: "claude-code",
  scope: ["payments.charge"],
  limits: [{ amount: 50_000, currency: "USD", window: "day", label: "your daily cap" }],
  humanInLoop: { above: { amount: 1_000, currency: "USD" }, escalation: "finance@example.test", slaHours: 8 },
  tools: [{ match: "stripe.create_charge", scope: "payments.charge", amountFrom: "args.amount", amountUnit: "minor", targetFrom: "args.customer" }],
  unmatched: "deny",
};

function charge(dir, { amount = 250_000, customer = "cus_7", policy = POLICY } = {}) {
  writeFileSync(join(dir, "policy.json"), JSON.stringify(policy));
  const messages = [
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "c", version: "1" } } },
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "stripe.create_charge", arguments: { amount, customer } } },
  ];
  const proc = spawnSync(process.execPath, [
    cli, "guard", "--policy", join(dir, "policy.json"),
    "--ledger", join(dir, "spend.jsonl"), "--approvals", join(dir, "approvals.jsonl"),
    "--", process.execPath, stub,
  ], {
    input: `${messages.map((m) => JSON.stringify(m)).join("\n")}\n`,
    encoding: "utf8",
    timeout: 30_000,
    env: { ...process.env, STUB_LOG: join(dir, "stub.log") },
  });
  let reply;
  for (const line of (proc.stdout || "").trim().split("\n")) {
    if (!line.trim()) continue;
    const m = JSON.parse(line);
    if (m.id === 2) reply = m;
  }
  let received = 0;
  try {
    received = readFileSync(join(dir, "stub.log"), "utf8").trim().split("\n").filter(Boolean).length;
  } catch {}
  return {
    blocked: reply?.result?.isError === true,
    text: reply?.result?.content?.[0]?.text ?? "",
    received,
  };
}

const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
const waiting = (dir) =>
  JSON.parse(run("approvals", "--approvals", join(dir, "approvals.jsonl"), "--json").stdout)
    .filter((s) => s.status === "pending");

function approverKey(dir) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const path = join(dir, "approver.pem");
  writeFileSync(path, pem, { mode: 0o600 });
  return {
    path,
    entry: {
      keyId: "approver-2026",
      alg: "ed25519",
      publicKey: Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url").toString("base64url"),
    },
  };
}

test("an escalated call leaves a request behind, and the same call goes through once it is answered", () => {
  const dir = temp();
  try {
    const first = charge(dir);
    assert.equal(first.blocked, true);
    assert.equal(first.received, 0, "the server must not see a call that is waiting");
    assert.match(first.text, /Waiting for a person/);

    const [pending] = waiting(dir);
    assert.ok(pending, "a request should be recorded");
    assert.match(first.text, new RegExp(`approve ${pending.request.id}`));
    // A person cannot approve what they cannot see, so unlike a receipt this
    // carries the arguments.
    assert.equal(pending.request.request.action.target, "cus_7");
    assert.deepEqual(pending.request.request.action.args, { amount: 250_000, customer: "cus_7" });
    assert.equal(pending.request.request.amount.amount, 2_500);

    const answered = run("approve", pending.request.id, "--approvals", join(dir, "approvals.jsonl"), "--by", "faizan");
    assert.equal(answered.status, 0);
    assert.match(answered.stdout, /Approved/);

    const second = charge(dir);
    assert.equal(second.blocked, false, "the approved call should now go through");
    assert.equal(second.received, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an approval is good once", () => {
  const dir = temp();
  try {
    charge(dir);
    run("approve", waiting(dir)[0].request.id, "--approvals", join(dir, "approvals.jsonl"));
    assert.equal(charge(dir).blocked, false);

    const again = charge(dir);
    assert.equal(again.blocked, true);
    assert.match(again.text, /has already been used/);
    assert.equal(again.received, 1, "only the first one reached the server");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an approval buys the exact call it was given, and no other", () => {
  const dir = temp();
  try {
    charge(dir, { amount: 250_000, customer: "cus_7" });
    run("approve", waiting(dir)[0].request.id, "--approvals", join(dir, "approvals.jsonl"));

    // Same shape, one thing changed each time. None of these are what was approved.
    for (const change of [{ amount: 250_001 }, { amount: 900_000 }, { customer: "cus_other" }]) {
      const other = charge(dir, { amount: 250_000, customer: "cus_7", ...change });
      assert.equal(other.blocked, true, JSON.stringify(change));
      assert.equal(other.received, 0, JSON.stringify(change));
    }

    // And the call that was approved still works.
    assert.equal(charge(dir, { amount: 250_000, customer: "cus_7" }).blocked, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a declined request stays declined", () => {
  const dir = temp();
  try {
    charge(dir);
    const id = waiting(dir)[0].request.id;
    run("decline", id, "--approvals", join(dir, "approvals.jsonl"), "--by", "faizan", "--note", "wrong supplier");

    const after = charge(dir);
    assert.equal(after.blocked, true);
    assert.match(after.text, /was declined by faizan/);
    assert.equal(after.received, 0);

    // It cannot be talked round afterwards.
    const retry = run("approve", id, "--approvals", join(dir, "approvals.jsonl"));
    assert.equal(retry.status, 1);
    assert.match(retry.stderr, /already declined/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a policy that names approvers takes answers from nobody else", () => {
  const dir = temp();
  try {
    const approver = approverKey(dir);
    const rogue = generateKeyPairSync("ed25519");
    writeFileSync(join(dir, "rogue.pem"), rogue.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    const policy = { ...POLICY, approvers: [approver.entry] };
    const approvals = join(dir, "approvals.jsonl");

    // Unsigned: refused, which is the case that matters. An agent that can run
    // a shell can run the approve command, and this is what stops it.
    charge(dir, { policy });
    run("approve", waiting(dir)[0].request.id, "--approvals", approvals, "--by", "the agent itself");
    let out = charge(dir, { policy });
    assert.equal(out.blocked, true);
    assert.match(out.text, /approved without a signature/);
    assert.equal(out.received, 0);

    // Signed by a key the policy does not name: also refused.
    run("approve", waiting(dir)[0].request.id, "--approvals", approvals, "--key", join(dir, "rogue.pem"), "--kid", "rogue");
    out = charge(dir, { policy });
    assert.equal(out.blocked, true);
    assert.match(out.text, /signed by "rogue", which this policy does not name/);
    assert.equal(out.received, 0);

    // Signed by the named key: through.
    run("approve", waiting(dir)[0].request.id, "--approvals", approvals, "--key", approver.path, "--kid", approver.entry.keyId);
    out = charge(dir, { policy });
    assert.equal(out.blocked, false);
    assert.equal(out.received, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a signature that was edited afterwards does not pass", () => {
  const dir = temp();
  try {
    const approver = approverKey(dir);
    const policy = { ...POLICY, approvers: [approver.entry] };
    const approvals = join(dir, "approvals.jsonl");

    charge(dir, { policy });
    const id = waiting(dir)[0].request.id;
    run("approve", id, "--approvals", approvals, "--key", approver.path, "--kid", approver.entry.keyId, "--by", "faizan");

    // Rewrite the trail, changing who approved it while keeping the signature.
    const lines = readFileSync(approvals, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    const edited = lines.map((e) => (e.kind === "answer" && e.id === id ? { ...e, by: "somebody else" } : e));
    writeFileSync(approvals, `${edited.map((e) => JSON.stringify(e)).join("\n")}\n`);

    const out = charge(dir, { policy });
    assert.equal(out.blocked, true);
    assert.match(out.text, /does not check out/);
    assert.equal(out.received, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("approvals lists what is waiting, and what was answered", () => {
  const dir = temp();
  try {
    charge(dir);
    const plain = run("approvals", "--approvals", join(dir, "approvals.jsonl"));
    assert.match(plain.stdout, /WAITING/);
    assert.match(plain.stdout, /stripe\.create_charge\s+2,500 USD/);
    assert.match(plain.stdout, /on cus_7/);
    assert.match(plain.stdout, /1 shown, 1 waiting/);

    run("approve", waiting(dir)[0].request.id, "--approvals", join(dir, "approvals.jsonl"), "--by", "faizan");
    assert.match(run("approvals", "--approvals", join(dir, "approvals.jsonl")).stdout, /Nothing is waiting/);
    const all = run("approvals", "--approvals", join(dir, "approvals.jsonl"), "--all");
    assert.match(all.stdout, /APPROVED/);
    assert.match(all.stdout, /by faizan/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("without --approvals an escalation is still simply refused", () => {
  const dir = temp();
  try {
    writeFileSync(join(dir, "policy.json"), JSON.stringify(POLICY));
    const messages = [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "c", version: "1" } } },
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "stripe.create_charge", arguments: { amount: 250_000, customer: "c" } } },
    ];
    const proc = spawnSync(process.execPath, [
      cli, "guard", "--policy", join(dir, "policy.json"), "--ledger", join(dir, "spend.jsonl"),
      "--", process.execPath, stub,
    ], { input: `${messages.map((m) => JSON.stringify(m)).join("\n")}\n`, encoding: "utf8", timeout: 30_000, env: { ...process.env, STUB_LOG: join(dir, "stub.log") } });
    const reply = (proc.stdout || "").trim().split("\n").map((l) => JSON.parse(l)).find((m) => m.id === 2);
    assert.equal(reply.result.isError, true);
    assert.match(reply.result.content[0].text, /A person must confirm this: finance@example\.test/);
    assert.doesNotMatch(reply.result.content[0].text, /agent-passport approve/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
