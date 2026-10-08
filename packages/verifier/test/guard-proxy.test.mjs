/**
 * The guard as an agent actually meets it: a real child process, speaking MCP
 * over stdio, in front of a server that records every call it receives.
 *
 * The property under test is not "the guard returned an error". It is "the
 * upstream server never heard about it", which is the only version that means
 * anything. Every case checks the stub's log, not just the reply.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const cli = resolve(here, "../bin/agent-passport.mjs");
const stub = resolve(here, "fixtures/stub-mcp.mjs");

const BASE_POLICY = {
  id: "treasury-local",
  agentId: "claude-code",
  scope: ["payments.charge", "payments.read"],
  limits: [{ amount: 5_000, currency: "USD", window: "day", label: "your daily cap" }],
  humanInLoop: { above: { amount: 2_000, currency: "USD" }, escalation: "finance@yourcompany.example" },
  tools: [
    { match: "stripe.create_charge", scope: "payments.charge", amountFrom: "args.amount", amountUnit: "minor", targetFrom: "args.customer" },
    { match: "stripe.list_*", scope: "payments.read" },
  ],
  unmatched: "escalate",
};

const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } };
const call = (id, name, args = {}) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });

/** Run the guard once, with a given policy and a given set of client messages. */
function runGuard(dir, { policy = BASE_POLICY, messages, ledger, receipts, reset = false } = {}) {
  const policyPath = join(dir, "policy.json");
  writeFileSync(policyPath, JSON.stringify(policy));
  const log = join(dir, "stub.log");
  if (reset) rmSync(log, { force: true });

  const args = [cli, "guard", "--policy", policyPath];
  if (ledger) args.push("--ledger", join(dir, ledger));
  if (receipts) args.push("--receipts", join(dir, receipts));
  args.push("--", process.execPath, stub);

  const proc = spawnSync(process.execPath, args, {
    input: `${[init, ...messages].map((m) => JSON.stringify(m)).join("\n")}\n`,
    encoding: "utf8",
    timeout: 30_000,
    env: { ...process.env, STUB_LOG: log },
  });

  const replies = new Map();
  for (const line of (proc.stdout || "").trim().split("\n")) {
    if (!line.trim()) continue;
    const m = JSON.parse(line);
    replies.set(m.id, m);
  }
  const received = existsSync(log)
    ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))
    : [];
  return { replies, received, stderr: proc.stderr || "", status: proc.status };
}

const blocked = (reply) => reply.result?.isError === true;
const text = (reply) => reply.result?.content?.[0]?.text ?? "";
const temp = () => mkdtempSync(join(tmpdir(), "ap-guard-"));

test("a call the policy refuses never reaches the server", () => {
  const dir = temp();
  try {
    const { replies, received } = runGuard(dir, {
      messages: [
        call(10, "stripe.create_charge", { amount: 150_000, customer: "cus_1" }), // 1,500 USD
        call(11, "stripe.create_charge", { amount: 900_000, customer: "cus_2" }), // 9,000 USD, over the cap
        call(12, "stripe.create_charge", { amount: 250_000, customer: "cus_3" }), // 2,500 USD, over the human threshold
      ],
      ledger: "spend.jsonl",
      reset: true,
    });

    assert.equal(blocked(replies.get(10)), false, "the allowed charge should go through");
    assert.equal(blocked(replies.get(11)), true);
    assert.equal(blocked(replies.get(12)), true);
    assert.match(text(replies.get(11)), /amount\.above-ceiling/);
    assert.match(text(replies.get(12)), /amount\.above-human-threshold/);
    assert.match(text(replies.get(12)), /finance@yourcompany\.example/);

    // The point of the whole exercise.
    assert.deepEqual(received.map((r) => r.args.customer), ["cus_1"]);
    assert.equal(received.length, 1, "the server must not have seen the refused calls");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the daily cap holds across calls, and across separate runs", () => {
  const dir = temp();
  try {
    const charge = (id, major) => call(id, "stripe.create_charge", { amount: major * 100, customer: `cus_${id}` });
    // 1,900 each: under the 2,000 human threshold, so each one is allowed on
    // its own, and together they run out the 5,000 daily cap.
    const first = runGuard(dir, { messages: [charge(10, 1_900), charge(11, 1_900)], ledger: "spend.jsonl", reset: true });
    assert.equal(blocked(first.replies.get(10)), false);
    assert.equal(blocked(first.replies.get(11)), false);
    assert.equal(first.received.length, 2);

    // A brand new process, reading the same ledger.
    const second = runGuard(dir, { messages: [charge(12, 1_900)], ledger: "spend.jsonl" });
    assert.equal(blocked(second.replies.get(12)), true, "5,700 would be over the 5,000 cap");
    assert.match(text(second.replies.get(12)), /amount\.above-ceiling/);
    assert.equal(second.received.length, 2, "still only the first two reached the server");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a tool no rule covers is handled by unmatched, whichever way it is set", () => {
  for (const [unmatched, expectBlocked] of [["escalate", true], ["deny", true], ["allow", false]]) {
    const dir = temp();
    try {
      const { replies, received } = runGuard(dir, {
        policy: { ...BASE_POLICY, unmatched },
        messages: [call(10, "stripe.refund", { charge: "ch_1" })],
        ledger: "spend.jsonl",
        reset: true,
      });
      // The stub always fails stripe.refund, so isError alone cannot say who
      // refused it. Whether the server saw it can.
      assert.equal(received.length, expectBlocked ? 0 : 1, `unmatched: ${unmatched}`);
      if (expectBlocked) {
        assert.equal(blocked(replies.get(10)), true, `unmatched: ${unmatched}`);
        assert.match(text(replies.get(10)), /no rule in the local policy covers/);
      } else {
        assert.doesNotMatch(text(replies.get(10)), /local policy/, "allow means the guard says nothing");
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("a value the rule cannot read is refused, not waved through unpriced", () => {
  const dir = temp();
  try {
    const { replies, received } = runGuard(dir, {
      messages: [
        call(10, "stripe.create_charge", { customer: "cus_1" }), // no amount at all
        call(11, "stripe.create_charge", { amount: "not a number", customer: "cus_2" }),
        call(12, "stripe.create_charge", { amount: 100_000, customer: "cus_3" }), // fine
      ],
      ledger: "spend.jsonl",
      reset: true,
    });
    for (const id of [10, 11]) {
      assert.equal(blocked(replies.get(id)), true, `id ${id}`);
      assert.match(text(replies.get(id)), /cannot be read cannot be held to a spending limit/);
    }
    assert.equal(blocked(replies.get(12)), false);
    assert.equal(received.length, 1, "only the priced call reached the server");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("minor units are converted, so 250000 is 2,500 and not 250,000", () => {
  const dir = temp();
  try {
    // In minor units this is 2,500 USD: over the human threshold, under the cap.
    const asMinor = runGuard(dir, { messages: [call(10, "stripe.create_charge", { amount: 250_000, customer: "c" })], ledger: "minor.jsonl", reset: true });
    assert.match(text(asMinor.replies.get(10)), /2,500 USD is above the 2,000 USD threshold/);

    // Read as major units the same number would be 250,000 and over the ceiling.
    const major = { ...BASE_POLICY, tools: [{ ...BASE_POLICY.tools[0], amountUnit: "major" }, BASE_POLICY.tools[1]] };
    const asMajor = runGuard(dir, { policy: major, messages: [call(10, "stripe.create_charge", { amount: 250_000, customer: "c" })], ledger: "major.jsonl", reset: true });
    assert.match(text(asMajor.replies.get(10)), /amount\.above-ceiling/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a server that says it did not act gives the money back", () => {
  const dir = temp();
  try {
    // stripe.refund is mapped here, and the stub always fails it.
    const policy = {
      ...BASE_POLICY,
      tools: [...BASE_POLICY.tools, { match: "stripe.refund", scope: "payments.charge", amountFrom: "args.amount", amountUnit: "minor" }],
    };
    const { replies, received } = runGuard(dir, {
      policy,
      messages: [call(10, "stripe.refund", { amount: 100_000 })],
      ledger: "spend.jsonl",
      reset: true,
    });
    assert.equal(received.length, 1, "the call was allowed, so the server did see it");
    assert.equal(blocked(replies.get(10)), true, "the server itself refused it");

    const entries = readFileSync(join(dir, "spend.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(entries.map((e) => e.state), ["reserved", "released"]);

    // And the headroom really came back: the full cap is still available.
    const after = runGuard(dir, { policy, messages: [call(11, "stripe.create_charge", { amount: 190_000, customer: "c" })], ledger: "spend.jsonl" });
    assert.equal(blocked(after.replies.get(11)), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the model is told which tools are governed, and which will be refused", () => {
  const dir = temp();
  try {
    const { replies } = runGuard(dir, { messages: [{ jsonrpc: "2.0", id: 2, method: "tools/list" }], ledger: "spend.jsonl", reset: true });
    const tools = Object.fromEntries(replies.get(2).result.tools.map((t) => [t.name, t.description]));

    assert.match(tools["stripe.create_charge"], /Governed by local policy as "payments\.charge"/);
    assert.match(tools["stripe.create_charge"], /Limits: 5,000 USD per day/);
    assert.match(tools["stripe.list_charges"], /Governed by local policy as "payments\.read"/);
    // A tool with no value cannot be held to a spending limit, so it is not told about one.
    assert.doesNotMatch(tools["stripe.list_charges"], /Limits:/);
    assert.match(tools["stripe.refund"], /will be refused/);
    // The server's own description survives.
    assert.match(tools["stripe.create_charge"], /^Charge a customer\./);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("everything that is not a tool call passes through untouched", () => {
  const dir = temp();
  try {
    const { replies } = runGuard(dir, {
      messages: [{ jsonrpc: "2.0", id: 5, method: "ping" }, { jsonrpc: "2.0", method: "notifications/initialized" }],
      ledger: "spend.jsonl",
      reset: true,
    });
    assert.equal(replies.get(1).result.serverInfo.name, "stub", "initialize reached the server");
    assert.ok(replies.has(5), "ping was answered by the server");
    assert.equal(replies.size, 2, "a notification draws no reply");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a policy whose tool rule uses an ungranted scope refuses to start", () => {
  const dir = temp();
  try {
    const bad = { ...BASE_POLICY, tools: [{ match: "x", scope: "payments.wire" }] };
    const { status, stderr } = runGuard(dir, { policy: bad, messages: [], ledger: "spend.jsonl", reset: true });
    assert.equal(status, 1);
    assert.match(stderr, /uses scope "payments\.wire", which the policy does not grant/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the receipt trail records every decision, and log reads it back", () => {
  const dir = temp();
  try {
    runGuard(dir, {
      messages: [
        call(10, "stripe.create_charge", { amount: 150_000, customer: "cus_1" }),
        call(11, "stripe.create_charge", { amount: 900_000, customer: "cus_2" }),
      ],
      ledger: "spend.jsonl",
      receipts: "receipts.jsonl",
      reset: true,
    });

    const out = spawnSync(process.execPath, [cli, "log", "--receipts", join(dir, "receipts.jsonl"), "--json"], { encoding: "utf8" });
    const receipts = JSON.parse(out.stdout);
    assert.equal(receipts.length, 2);
    assert.deepEqual(new Set(receipts.map((r) => r.outcome)), new Set(["executed", "blocked"]));

    // A receipt names the tool and the amount, and never the payload.
    const wire = JSON.stringify(receipts);
    assert.ok(wire.includes("stripe.create_charge"));
    assert.ok(!wire.includes("cus_1"), "the receipt must not carry the customer");

    const human = spawnSync(process.execPath, [cli, "log", "--receipts", join(dir, "receipts.jsonl")], { encoding: "utf8" });
    assert.match(human.stdout, /amount\.above-ceiling/);
    assert.match(human.stdout, /1,500 committed/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a policy with limits and no ledger says so at startup, not at the first call", () => {
  const dir = temp();
  try {
    const { status, stderr, received } = runGuard(dir, {
      messages: [call(10, "stripe.create_charge", { amount: 100, customer: "c" })],
      reset: true,
    });
    assert.equal(status, 1);
    assert.match(stderr, /nothing is counting against/);
    assert.match(stderr, /Add --ledger/);
    assert.equal(received.length, 0, "the upstream server was never started against");

    // A policy with no limits at all is a pure allowlist and needs no ledger.
    const allowlist = { id: "a", agentId: "x", scope: ["payments.read"], tools: [{ match: "stripe.list_*", scope: "payments.read" }], unmatched: "deny" };
    const ok = runGuard(dir, { policy: allowlist, messages: [call(11, "stripe.list_charges")], reset: true });
    assert.equal(blocked(ok.replies.get(11)), false);
    assert.equal(ok.received.length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a server that asks for more input did not act, so nothing counts until the retry runs", () => {
  const dir = temp();
  try {
    // MCP 2026-07-28 lets a server answer tools/call with resultType
    // "input_required" instead of acting. The client then retries the same
    // call under a new id, carrying inputResponses and requestState. The first
    // attempt moved no money, so it must not be counted; the retry is a call
    // of its own and is decided afresh.
    const ask = { amount: 190_000, customer: "cus_ask", ask: true }; // 1,900 USD
    const retry = {
      jsonrpc: "2.0", id: 11, method: "tools/call",
      params: { name: "stripe.create_charge", arguments: ask, inputResponses: { confirm: { action: "accept", content: { ok: true } } }, requestState: "stub-state" },
    };
    const first = runGuard(dir, {
      messages: [call(10, "stripe.create_charge", ask), retry],
      ledger: "spend.jsonl",
      receipts: "receipts.jsonl",
      reset: true,
    });
    assert.equal(first.replies.get(10).result?.resultType, "input_required", "the ask reaches the client untouched");
    assert.equal(first.replies.get(10).result?.requestState, "stub-state");
    assert.equal(blocked(first.replies.get(11)), false, "the answered retry goes through");
    assert.deepEqual(first.received.map((r) => r.args.customer), ["cus_ask", "cus_ask"]);

    // One reservation was handed back, one was kept.
    const entries = readFileSync(join(dir, "spend.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(entries.map((e) => e.state).sort(), ["committed", "released", "reserved", "reserved"]);

    // The trail says so: the first attempt did not run, and names why.
    const receipts = JSON.parse(spawnSync(process.execPath, [cli, "log", "--receipts", join(dir, "receipts.jsonl"), "--json"], { encoding: "utf8" }).stdout);
    assert.deepEqual(receipts.map((r) => r.outcome).sort(), ["blocked", "executed"]);
    assert.deepEqual(receipts.find((r) => r.outcome === "blocked").blockedBecause, ["execution.input-required"]);

    // And only 1,900 of the 5,000 is gone: a second 1,900 fits, a third does not.
    const second = runGuard(dir, {
      messages: [
        call(12, "stripe.create_charge", { amount: 190_000, customer: "cus_3" }), // 3,800 so far
        call(13, "stripe.create_charge", { amount: 190_000, customer: "cus_4" }), // 5,700: over the cap
      ],
      ledger: "spend.jsonl",
    });
    assert.equal(blocked(second.replies.get(12)), false, "the attempt that did not run must not have been counted");
    assert.equal(blocked(second.replies.get(13)), true, "and the cap still holds once the money is really spent");
    assert.match(text(second.replies.get(13)), /amount\.above-ceiling/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a refusal carries resultType only when the client speaks MCP 2026-07-28", () => {
  const dir = temp();
  try {
    // From 2026-07-28 every request names its protocol revision in _meta and
    // every result carries resultType. An older client has never seen the
    // field, so a refusal to it keeps the shape it knows.
    const meta = {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": { name: "t", version: "1" },
      "io.modelcontextprotocol/clientCapabilities": {},
    };
    const newer = { jsonrpc: "2.0", id: 20, method: "tools/call", params: { name: "stripe.create_charge", arguments: { amount: 900_000, customer: "c" }, _meta: meta } };
    const older = call(21, "stripe.create_charge", { amount: 900_000, customer: "c" });
    const { replies, received } = runGuard(dir, { messages: [newer, older], ledger: "spend.jsonl", reset: true });
    assert.equal(received.length, 0, "both are over the cap and never reach the server");
    assert.equal(blocked(replies.get(20)), true);
    assert.equal(replies.get(20).result.resultType, "complete");
    assert.equal(blocked(replies.get(21)), true);
    assert.equal("resultType" in replies.get(21).result, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
