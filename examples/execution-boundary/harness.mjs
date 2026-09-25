#!/usr/bin/env node
/**
 * Execution-boundary harness.
 *
 * One synthetic action, authorized once, then executed eight ways:
 *
 *   1. control              the exact action that was authorized
 *   2. mutate-target        the target changes after authorization
 *   3. mutate-arguments     an argument changes after authorization
 *   4. mutate-amount        the value changes after authorization
 *   5. replay               the same approved decision is used twice
 *   6. expired              the decision is used after its window
 *   7. reauthorize-B        B is authorized fresh, on its own merits
 *   8. in-transit-body      the request body changes between signing and receipt
 *
 * Each case runs against a stub provider that records every side effect it
 * performs, so the result is not "the library said no" but "the provider
 * observed nothing". Cases 1 to 7 sit at the authorization boundary; case 8
 * sits at the transport boundary, where the caller's signature is checked.
 *
 * Usage, from the repository root:
 *
 *   cd packages/verifier && npm install && npm run build && cd ../..
 *   node examples/execution-boundary/harness.mjs          # table
 *   node examples/execution-boundary/harness.mjs --json   # machine-readable
 *
 * Exit code is 0 when every case matched its expectation, 1 otherwise.
 */

import { generateKeyPairSync } from "node:crypto";

import {
  authorize,
  checkExecution,
  draftAgentPassport,
  memoryNonceStore,
  requestKeyEntry,
  signAgentPassport,
  signAgentRequest,
  verifyAgentCaller,
  verifyAgentPassport,
} from "../../packages/verifier/dist/index.js";

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
 * What an integrator is expected to write: never call the provider without
 * checking the decision against the values about to be executed.
 */
async function guardedExecute(decision, finalRequest, sink, opts = {}) {
  const check = await checkExecution(decision, finalRequest, { now, ...opts });
  if (!check.ok) return { executed: false, reason: check.errors.map((e) => e.code).join(", ") };
  sink.execute(finalRequest.action);
  return { executed: true, reason: null };
}

function newKey(keyId) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    keyId,
    raw: new Uint8Array(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url")),
    b64url: Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url").toString("base64url"),
    pkcs8: new Uint8Array(privateKey.export({ type: "pkcs8", format: "der" })),
  };
}

/** Issue a passport for a fictional issuer and verify it as a counterparty would. */
async function setup() {
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
  if (!verification.ok) throw new Error(`passport did not verify: ${JSON.stringify(verification.errors)}`);
  return { verification, requestKey, passport };
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

async function run() {
  const { verification, requestKey } = await setup();
  const results = [];
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
    const decision = await authorize(verification, actionA, { now });
    const outcome = await guardedExecute(decision, actionA, sink);
    record("control", "executes", outcome, sink, `decision=${decision.decision}`);
  }

  // 2 to 4. Authorize A, execute B.
  const mutations = [
    ["mutate-target", mutate({ action: { target: "supplier_999" } })],
    [
      "mutate-arguments",
      mutate({ action: { args: { iban: "GB94BARC10201530093459", amount: 400, reference: "INV-2291" } } }),
    ],
    [
      "mutate-amount",
      mutate({
        amount: { amount: 9_000, currency: "USD" },
        action: { args: { iban: "GB33BUKB20201555555555", amount: 9_000, reference: "INV-2291" } },
      }),
    ],
  ];
  for (const [name, actionB] of mutations) {
    const sink = provider();
    const decision = await authorize(verification, actionA, { now });
    const outcome = await guardedExecute(decision, actionB, sink);
    record(name, "blocked", outcome, sink);
  }

  // 5. Replay: the same approved decision used a second time.
  {
    const sink = provider();
    const nonceStore = memoryNonceStore({ now });
    const decision = await authorize(verification, actionA, { now });
    const first = await guardedExecute(decision, actionA, sink, { nonceStore });
    const second = await guardedExecute(decision, actionA, sink, { nonceStore });
    record("replay", "blocked", second, sink, `first attempt executed=${first.executed}`);
  }

  // 6. Expired: used after the decision's window.
  {
    const sink = provider();
    const decision = await authorize(verification, actionA, { now, ttlSeconds: 30 });
    const later = () => new Date(NOW.getTime() + 60_000);
    const check = await checkExecution(decision, actionA, { now: later });
    const outcome = check.ok
      ? (sink.execute(actionA.action), { executed: true, reason: null })
      : { executed: false, reason: check.errors.map((e) => e.code).join(", ") };
    record("expired", "blocked", outcome, sink);
  }

  // 7. Re-authorization: B is authorized fresh, on its own merits. The point of
  //    the case is that B does not inherit A's approval; here the larger amount
  //    lands above the issuer's human threshold, so it still does not execute.
  {
    const sink = provider();
    const actionB = mutate({
      amount: { amount: 9_000, currency: "USD" },
      action: { args: { iban: "GB33BUKB20201555555555", amount: 9_000, reference: "INV-2291" } },
    });
    const decision = await authorize(verification, actionB, { now });
    const outcome = await guardedExecute(decision, actionB, sink);
    record("reauthorize-B", "blocked", outcome, sink, `decision=${decision.decision}, escalates to ${decision.escalation?.to}`);
  }

  // 8. Transport boundary: the body changes between signing and receipt.
  {
    const sink = provider();
    const body = JSON.stringify({ iban: "GB33BUKB20201555555555", amount: 400 });
    const request = {
      method: "POST",
      url: "https://api.globex.example/transfers",
      headers: { "content-type": "application/json" },
      body,
    };
    const headers = await signAgentRequest(request, {
      keyId: requestKey.keyId,
      privateKey: requestKey.pkcs8,
      created: NOW,
    });
    const received = {
      ...request,
      headers: { ...request.headers, ...headers },
      body: JSON.stringify({ iban: "GB94BARC10201530093459", amount: 400 }),
    };
    const caller = await verifyAgentCaller(received, verification.passport, { now });
    const outcome = caller.ok
      ? (sink.execute(actionA.action), { executed: true, reason: null })
      : { executed: false, reason: caller.errors.map((e) => e.code).join(", ") };
    record("in-transit-body", "blocked", outcome, sink);
  }

  return results;
}

const results = await run();
const failures = results.filter((r) => !r.matchedExpectation);

if (process.argv.includes("--json")) {
  console.log(
    JSON.stringify(
      {
        subject: "agent-passport",
        version: "0.1.2",
        generatedAt: new Date().toISOString(),
        results,
        allMatched: failures.length === 0,
      },
      null,
      2,
    ),
  );
} else {
  const pad = (s, n) => String(s).padEnd(n);
  console.log(`${pad("case", 18)}${pad("expected", 10)}${pad("executed", 10)}${pad("effects", 9)}blocked because`);
  console.log("-".repeat(86));
  for (const r of results) {
    console.log(
      `${pad(r.case, 18)}${pad(r.expected, 10)}${pad(r.executed, 10)}${pad(r.providerEffects, 9)}${r.blockedBecause ?? ""}`,
    );
  }
  console.log(
    `\n${failures.length === 0 ? "All cases matched expectation." : `${failures.length} case(s) did not match expectation.`}`,
  );
}

process.exit(failures.length === 0 ? 0 : 1);
