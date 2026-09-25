#!/usr/bin/env node
/**
 * Execution-boundary harness.
 *
 * One synthetic action, authorized once, then executed several ways:
 *
 *   1. control              the exact action that was authorized
 *   2. mutate-target        the target changes after authorization
 *   3. mutate-arguments     an argument changes after authorization
 *   4. mutate-amount        the value changes after authorization
 *   5. replay               the same approved decision is used twice
 *   6. expired              the decision is used after its window
 *   7. reauthorize-B        B is authorized fresh, on its own merits
 *   8. over-budget          on its own merits, but past the running cap
 *   9. concurrent           two decisions taken before either executes
 *  10. in-transit-body      the request body changes between signing and receipt
 *
 * Each case runs against a stub provider that records every side effect it
 * performs, so the result is not "the library said no" but "the provider
 * observed nothing".
 *
 * The same cases run against two sources of authority, which is the point of
 * the file: the rules are one engine, and where the permission came from
 * does not change what reaches the provider.
 *
 *   --authority passport   a counterparty's published, verified passport
 *   --authority policy     a policy file on this machine, no passport at all
 *   --authority both       run each in turn (default)
 *
 * Cases 1 to 9 sit at the authorization boundary. Case 10 sits at the
 * transport boundary, where the caller's signature is checked, and needs a
 * published request key, so it runs in passport mode only.
 *
 * Usage, from the repository root:
 *
 *   cd packages/verifier && npm install && npm run build && cd ../..
 *   node examples/execution-boundary/harness.mjs
 *   node examples/execution-boundary/harness.mjs --authority policy
 *   node examples/execution-boundary/harness.mjs --json
 *
 * Exit code is 0 when every case matched its expectation, 1 otherwise.
 */

import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  decide,
  draftAgentPassport,
  guardedCall,
  localPolicy,
  memoryNonceStore,
  memoryReceiptSink,
  memorySpendLedger,
  intersect,
  passportAuthority,
  requestKeyEntry,
  signAgentPassport,
  signAgentRequest,
  verifyAgentCaller,
  verifyAgentPassport,
} from "../../packages/verifier/dist/index.js";

const VERSION = JSON.parse(
  readFileSync(new URL("../../packages/verifier/package.json", import.meta.url), "utf8"),
).version;

const ISSUED = new Date("2026-06-01T00:00:00Z");
const NOW = new Date("2026-06-10T00:00:00Z");
const now = () => NOW;

/** A stub payment provider. The only thing that counts as "an effect happened". */
function provider() {
  const effects = [];
  return {
    effects,
    execute(action) {
      effects.push({ tool: action.tool, target: action.target, args: action.args });
      return { id: `tx_${effects.length}` };
    },
  };
}

/**
 * What an integrator is expected to write: the provider is only ever reached
 * through the library's guard, with the values that are about to be executed.
 */
async function guardedExecute(decision, finalRequest, sink, opts = {}) {
  const result = await guardedCall(
    decision,
    finalRequest,
    () => sink.execute(finalRequest.action),
    { now, ...opts },
  );
  return {
    executed: result.outcome === "executed",
    reason:
      result.outcome === "blocked" ? result.reasons.map((e) => e.code).join(", ") : null,
    receipt: result.receipt,
  };
}

function newKey(keyId) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = new Uint8Array(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url"));
  return {
    keyId,
    raw,
    b64url: Buffer.from(raw).toString("base64url"),
    pkcs8: new Uint8Array(privateKey.export({ type: "pkcs8", format: "der" })),
  };
}

/** Issue a passport for a fictional issuer and verify it as a counterparty would. */
async function passportSetup() {
  const signingKey = newKey("acme-2026-q3");
  const requestKey = newKey("acme-2026-q3-request");
  const passport = await signAgentPassport(
    draftAgentPassport({
      domain: "acme.example",
      legalName: "Acme Corporation",
      agentName: "Acme Treasury Agent",
      role: "treasury",
      purpose: "Pays approved supplier invoices inside the published limits.",
      endpoints: { rest: "https://agents.acme.example/api/treasury" },
      scopes: ["payments.transfer"],
      spendCeiling: 10_000,
      humanAbove: 2_000,
      escalation: "finance@acme.example",
      keyId: signingKey.keyId,
      now: ISSUED,
      requestKeys: [requestKeyEntry({ keyId: requestKey.keyId, publicKeyRaw: requestKey.raw })],
    }),
    signingKey.pkcs8,
  );

  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = String(input);
    if (url.startsWith("https://acme.example/.well-known/agent-passport.json")) {
      return Response.json(passport);
    }
    if (url.startsWith("https://cloudflare-dns.com/dns-query")) {
      return Response.json({
        Status: 0,
        AD: true,
        Answer: [
          {
            name: "_agent-passport.acme.example",
            type: 16,
            TTL: 300,
            data: `"v=ap1; kid=${signingKey.keyId}; alg=ed25519; pk=${signingKey.b64url}"`,
          },
        ],
      });
    }
    if (url.endsWith("revoked-passports.json")) return Response.json([]);
    return realFetch(input);
  };

  const verification = await verifyAgentPassport({ domain: "acme.example", now });
  if (!verification.ok) {
    throw new Error(`passport did not verify: ${JSON.stringify(verification.errors)}`);
  }
  return { verification, passport: verification.passport, requestKey };
}

/**
 * The same envelope, written locally instead of published: the operator's own
 * rules for an agent running on their own machine. Nothing is fetched and
 * there is no counterparty.
 */
function treasuryPolicy(cap) {
  return localPolicy({
    id: "treasury-local",
    agentId: "acme-treasury-local",
    label: `the local treasury policy (${cap.toLocaleString("en-US")} USD cap)`,
    scope: ["payments.transfer"],
    limits: [{ amount: cap, currency: "USD", window: "total", label: "your own total cap" }],
    humanInLoop: { above: { amount: 2_000, currency: "USD" }, escalation: "finance@local", slaHours: 4 },
    counterparties: { openTo: "any" },
  });
}

/**
 * The three sources of authority the same engine runs on.
 *
 *  - passport:  what a counterparty published and this side verified
 *  - policy:    what this side decided locally, with no counterparty at all
 *  - combined:  both, where the tighter of the two always binds
 */
async function setupFor(mode) {
  if (mode === "policy") return { mode, authority: treasuryPolicy(10_000) };
  const issued = await passportSetup();
  const published = passportAuthority(issued.verification);
  return {
    mode,
    authority: mode === "combined" ? intersect(published, treasuryPolicy(3_000)) : published,
    passport: issued.passport,
    requestKey: issued.requestKey,
  };
}

/** Action A: the transfer that gets authorized. */
const actionA = {
  scope: "payments.transfer",
  amount: { amount: 400, currency: "USD" },
  counterpartyDomain: "globex.example",
  action: {
    tool: "payments.create_transfer",
    target: "supplier_412",
    args: { iban: "GB33BUKB20201555555555", amount: 400, reference: "INV-2291" },
  },
};

/** Action B: the same call with one thing changed. */
const mutate = (change) => ({
  ...actionA,
  ...change,
  action: { ...actionA.action, ...(change.action ?? {}) },
});

const amountOf = (n) =>
  mutate({
    amount: { amount: n, currency: "USD" },
    action: { args: { iban: "GB33BUKB20201555555555", amount: n, reference: "INV-2291" } },
  });

async function run(setup) {
  const { authority, mode } = setup;
  const results = [];
  // A fresh ledger per case, except where a case is about the running total.
  const fresh = () => memorySpendLedger();
  const record = (name, expectation, outcome, sink, detail) =>
    results.push({
      case: name,
      expected: expectation,
      executed: outcome.executed,
      blockedBecause: outcome.reason,
      providerEffects: sink.effects.length,
      matchedExpectation:
        expectation === "executes" ? outcome.executed === true : outcome.executed === false,
      ...(detail ? { detail } : {}),
    });

  // 1. Positive control: the exact action that was authorized.
  {
    const sink = provider();
    const ledger = fresh();
    const decision = await decide(authority, actionA, { now, ledger });
    const outcome = await guardedExecute(decision, actionA, sink, { ledger });
    record("control", "executes", outcome, sink, `decision=${decision.decision}`);
  }

  // 2 to 4. Authorize A, execute B.
  const mutations = [
    ["mutate-target", mutate({ action: { target: "supplier_999" } })],
    [
      "mutate-arguments",
      mutate({ action: { args: { iban: "GB94BARC10201530093459", amount: 400, reference: "INV-2291" } } }),
    ],
    ["mutate-amount", amountOf(9_000)],
  ];
  for (const [name, actionB] of mutations) {
    const sink = provider();
    const ledger = fresh();
    const decision = await decide(authority, actionA, { now, ledger });
    const outcome = await guardedExecute(decision, actionB, sink, { ledger });
    record(name, "blocked", outcome, sink);
  }

  // 5. Replay: the same approved decision used a second time.
  {
    const sink = provider();
    const ledger = fresh();
    const nonceStore = memoryNonceStore({ now });
    const decision = await decide(authority, actionA, { now, ledger });
    const first = await guardedExecute(decision, actionA, sink, { ledger, nonceStore });
    const second = await guardedExecute(decision, actionA, sink, { ledger, nonceStore });
    record("replay", "blocked", second, sink, `first attempt executed=${first.executed}`);
  }

  // 6. Expired: used after the decision's window.
  {
    const sink = provider();
    const ledger = fresh();
    const decision = await decide(authority, actionA, { now, ledger, ttlSeconds: 30 });
    const later = () => new Date(NOW.getTime() + 60_000);
    const outcome = await guardedExecute(decision, actionA, sink, { ledger, now: later });
    record("expired", "blocked", outcome, sink);
  }

  // 7. Re-authorization: B is authorized fresh, on its own merits. The point of
  //    the case is that B does not inherit A's approval; here the larger amount
  //    lands above the human threshold, so it still does not execute.
  {
    const sink = provider();
    const ledger = fresh();
    const actionB = amountOf(9_000);
    const decision = await decide(authority, actionB, { now, ledger });
    const outcome = await guardedExecute(decision, actionB, sink, { ledger });
    record(
      "reauthorize-B",
      "blocked",
      outcome,
      sink,
      `decision=${decision.decision}, escalates to ${decision.escalation?.to}`,
    );
  }

  // Both ledger cases below run inside one engagement, because a ceiling a
  // passport publishes per engagement only binds when the receiver says which
  // engagement this is. A local cap over a day or a month does not need it.
  const engagementId = "harness-run";

  // 8. Over budget: every single action is inside the per-action limits, and
  //    the run as a whole is not. Only a running total can see this.
  {
    const sink = provider();
    const ledger = fresh();
    let executed = 0;
    let last = { executed: false, reason: "never ran" };
    for (let i = 0; i < 12; i++) {
      const action = amountOf(1_500);
      const decision = await decide(authority, action, { now, ledger, engagementId });
      last = await guardedExecute(decision, action, sink, { ledger, engagementId });
      if (!last.executed) break;
      executed += 1;
    }
    record("over-budget", "blocked", last, sink, `${executed} transfers of 1,500 USD went through first`);
  }

  // 9. Concurrency: two decisions taken while there is room for only one of
  //    them, both made before either executes. Without a running total both
  //    see the same headroom and both spend it.
  {
    const sink = provider();
    const ledger = fresh();
    // The tightest ceiling is the one that binds, whichever source set it.
    const cap = Math.min(...authority.ceilings.filter((c) => c.currency === "USD").map((c) => c.amount));
    const headroom = cap - 2_600;
    const filler = amountOf(Math.max(0, headroom));
    if (headroom > 0) {
      const d = await decide(authority, filler, { now, ledger, engagementId });
      await guardedExecute(d, filler, sink, { ledger, engagementId, humanApproved: true });
    }
    const action = amountOf(1_500);
    const first = await decide(authority, action, { now, ledger, engagementId });
    const second = await decide(authority, action, { now, ledger, engagementId });
    await guardedExecute(first, action, sink, { ledger, engagementId });
    const outcome = await guardedExecute(second, action, sink, { ledger, engagementId });
    record(
      "concurrent",
      "blocked",
      outcome,
      sink,
      `first decision=${first.decision}, second decision=${second.decision}`,
    );
  }

  // 10. Transport boundary: the body changes between signing and receipt.
  if (setup.passport) {
    const sink = provider();
    const body = JSON.stringify({ iban: "GB33BUKB20201555555555", amount: 400 });
    const request = {
      method: "POST",
      url: "https://api.globex.example/transfers",
      headers: { "content-type": "application/json" },
      body,
    };
    const headers = await signAgentRequest(request, {
      keyId: setup.requestKey.keyId,
      privateKey: setup.requestKey.pkcs8,
      created: NOW,
    });
    const received = {
      ...request,
      headers: { ...request.headers, ...headers },
      body: JSON.stringify({ iban: "GB94BARC10201530093459", amount: 400 }),
    };
    const caller = await verifyAgentCaller(received, setup.passport, { now });
    const outcome = caller.ok
      ? (sink.execute(actionA.action), { executed: true, reason: null })
      : { executed: false, reason: caller.errors.map((e) => e.code).join(", ") };
    record("in-transit-body", "blocked", outcome, sink);
  }

  return results;
}

/** Every refusal should also leave a receipt, and no receipt should carry the payload. */
async function receiptCheck(setup) {
  const receipts = memoryReceiptSink();
  const ledger = memorySpendLedger();
  const sink = provider();
  const decision = await decide(setup.authority, actionA, { now, ledger });
  await guardedExecute(decision, actionA, sink, { ledger, receipts });
  const mutated = mutate({ action: { target: "supplier_999" } });
  const blocked = await decide(setup.authority, actionA, { now, ledger });
  await guardedExecute(blocked, mutated, sink, { ledger, receipts });

  const serialised = JSON.stringify(receipts.receipts);
  return {
    receipts: receipts.receipts.length,
    outcomes: receipts.receipts.map((r) => r.outcome),
    carriesTarget: serialised.includes("supplier_412") || serialised.includes("supplier_999"),
    carriesArguments: serialised.includes("GB33BUKB20201555555555"),
  };
}

const argv = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? fallback : argv[i + 1];
};
const KNOWN = ["passport", "policy", "combined"];
const which = flag("authority", "all");
const modes = which === "all" ? KNOWN : [which];
if (!modes.every((m) => KNOWN.includes(m))) {
  console.error(`unknown --authority ${which}; expected ${KNOWN.join(", ")} or all`);
  process.exit(2);
}

const runs = [];
for (const mode of modes) {
  const setup = await setupFor(mode);
  runs.push({
    authority: mode,
    origin: setup.authority.origin.map((o) => o.label),
    results: await run(setup),
    receipts: await receiptCheck(setup),
  });
}

const failures = runs.flatMap((r) =>
  r.results.filter((c) => !c.matchedExpectation).map((c) => ({ authority: r.authority, ...c })),
);
const leaks = runs.filter((r) => r.receipts.carriesTarget || r.receipts.carriesArguments);

if (argv.includes("--json")) {
  console.log(
    JSON.stringify(
      {
        subject: "agent-passport",
        version: VERSION,
        generatedAt: new Date().toISOString(),
        runs,
        allMatched: failures.length === 0 && leaks.length === 0,
      },
      null,
      2,
    ),
  );
} else {
  const pad = (s, n) => String(s).padEnd(n);
  for (const r of runs) {
    console.log(`\nauthority: ${r.authority} (${r.origin.join(", ")})`);
    console.log(`${pad("case", 18)}${pad("expected", 10)}${pad("executed", 10)}${pad("effects", 9)}blocked because`);
    console.log("-".repeat(92));
    for (const c of r.results) {
      console.log(
        `${pad(c.case, 18)}${pad(c.expected, 10)}${pad(c.executed, 10)}${pad(c.providerEffects, 9)}${c.blockedBecause ?? ""}`,
      );
    }
    console.log(
      `receipts: ${r.receipts.receipts} written (${r.receipts.outcomes.join(", ")}), ` +
        `target in receipt: ${r.receipts.carriesTarget}, arguments in receipt: ${r.receipts.carriesArguments}`,
    );
  }
  console.log(
    `\n${
      failures.length === 0 && leaks.length === 0
        ? "All cases matched expectation, under every authority, and no receipt carried the payload."
        : `${failures.length} case(s) did not match expectation; ${leaks.length} run(s) leaked the payload into a receipt.`
    }`,
  );
}

process.exit(failures.length === 0 && leaks.length === 0 ? 0 : 1);
