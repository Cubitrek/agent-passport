/**
 * A type-level test. Everything here is what a TypeScript consumer would
 * actually write, checked against the declaration files the package ships.
 * The rest of the suite is .mjs, so without this a broken .d.ts goes unnoticed
 * until someone installs the package.
 */

import {
  decide,
  guardedCall,
  intersect,
  localPolicy,
  memoryNonceStore,
  memoryReceiptSink,
  memorySpendLedger,
  passportAuthority,
  signAgentRequest,
  signReceipt,
  verifyAgentCaller,
  verifyAgentPassport,
  verifyReceipt,
  type Authority,
  type AuthorizationRequest,
  type Receipt,
  type SpendLedger,
} from "../../dist/index.js";
import { fileSpendLedger } from "../../dist/ledger-node.js";

declare const privateKey: Uint8Array;
declare const publicKeyRaw: Uint8Array;

async function surface(): Promise<void> {
  // Authority from a policy, from a passport, and from both.
  const mine: Authority = localPolicy({
    id: "treasury-local",
    agentId: "ops-bot",
    scope: ["payments.transfer"],
    limits: [{ amount: 5_000, currency: "USD", window: "day" }],
    humanInLoop: { above: { amount: 500, currency: "USD" }, escalation: "finance@example.test" },
  });
  const theirs = passportAuthority(await verifyAgentPassport({ domain: "acme.example" }));
  const both: Authority = intersect(theirs, mine);

  // Both ledgers satisfy the same interface, from their two entry points.
  const memory: SpendLedger = memorySpendLedger();
  const onDisk: SpendLedger = fileSpendLedger(".agent-passport/spend.jsonl");
  const committed: number = await onDisk.committed({
    subject: "ops-bot",
    currency: "USD",
    window: "day",
    at: new Date(),
  });
  void committed;

  const request: AuthorizationRequest = {
    scope: "payments.transfer",
    amount: { amount: 400, currency: "USD" },
    action: { tool: "payments.create_transfer", target: "supplier_412", args: { ref: "INV-1" } },
  };
  const decision = await decide(both, request, { ledger: memory, engagementId: "inv-1" });
  const receipts = memoryReceiptSink();

  const result = await guardedCall(decision, request, () => ({ id: "tx_1" }), {
    ledger: memory,
    nonceStore: memoryNonceStore(),
    receipts,
    signReceiptsWith: { keyId: "receipts-2026-q3", privateKey },
  });

  // The result narrows on `outcome`, and every branch carries a receipt.
  const receipt: Receipt = result.receipt;
  if (result.outcome === "executed") {
    const id: string = result.value.id;
    void id;
  } else if (result.outcome === "blocked") {
    const codes: string[] = result.reasons.map((r) => r.code);
    void codes;
  } else {
    const error: unknown = result.error;
    void error;
  }

  const signed = await signReceipt(receipt, { keyId: "k", privateKey });
  const checked = await verifyReceipt(signed, publicKeyRaw);
  if (!checked.ok) void checked.errors.map((e) => e.code);

  // Signing a request and then verifying it is one continuous flow.
  const headers = await signAgentRequest(
    { method: "POST", url: "https://api.example.test/orders", body: "{}" },
    { keyId: "req-1", privateKey },
  );
  void (await verifyAgentCaller(
    { method: "POST", url: "https://api.example.test/orders", headers, body: "{}" },
    (await verifyAgentPassport({ domain: "acme.example" })).passport!,
    {},
  ));
  void (await verifyAgentCaller(
    {
      method: "POST",
      url: "https://api.example.test/orders",
      headers: { "content-type": "application/json", ...headers },
      body: "{}",
    },
    (await verifyAgentPassport({ domain: "acme.example" })).passport!,
    {},
  ));
}

void surface;
