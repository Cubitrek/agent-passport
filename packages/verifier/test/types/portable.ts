/**
 * The consumer-side half of the portability promise: a project with no Node
 * types at all, importing only the main entry, must typecheck. The import-graph
 * test covers the runtime side; this covers what a Worker or browser project
 * sees from the declaration files.
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
  type Receipt,
  type SpendLedger,
} from "../../dist/index.js";

declare const privateKey: Uint8Array;

async function portable(): Promise<Receipt> {
  const mine: Authority = localPolicy({
    id: "edge", scope: ["x.do"],
    limits: [{ amount: 100, currency: "USD", window: "day" }],
  });
  const both = intersect(mine, passportAuthority(await verifyAgentPassport({ domain: "acme.example" })));
  const ledger: SpendLedger = memorySpendLedger();
  const request = { scope: "x.do", amount: { amount: 10, currency: "USD" } };
  const decision = await decide(both, request, { ledger });

  const headers = await signAgentRequest(
    { method: "POST", url: "https://api.example.test/x", body: "{}" },
    { keyId: "k", privateKey },
  );
  void (await verifyAgentCaller(
    { method: "POST", url: "https://api.example.test/x", headers, body: "{}" },
    (await verifyAgentPassport({ domain: "acme.example" })).passport!,
    { nonceStore: memoryNonceStore() },
  ));

  const result = await guardedCall(decision, request, () => 1, {
    ledger, receipts: memoryReceiptSink(),
  });
  void (await verifyReceipt(await signReceipt(result.receipt, { keyId: "k", privateKey }), privateKey));
  return result.receipt;
}

void portable;
