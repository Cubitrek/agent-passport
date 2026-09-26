#!/usr/bin/env node
/**
 * End to end: two companies, one purchase, the whole chain.
 *
 * Acme runs a procurement agent and publishes a passport. Globex sells, and
 * receives a signed call from that agent. Nothing is stubbed except the
 * network: real Ed25519 keys, real signatures, real DNS records, the real
 * library. Every link is checked, and then each link is broken in turn to
 * confirm the chain actually depends on it.
 *
 * This exists because the unit suite tests each layer and the harness tests
 * the guard boundary, and neither tests the joins: a passport that verifies
 * but whose authority is read wrongly, a caller bound to the wrong passport,
 * a receipt that cannot be checked by the party it is written for. Those only
 * show up when the whole thing runs in one go.
 *
 * Usage, from the repository root:
 *
 *   cd packages/verifier && npm install && npm run build && cd ../..
 *   node examples/end-to-end/scenario.mjs
 *
 * Exit code is 0 when every link holds and every break is caught.
 */
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const D = new URL("../../packages/verifier/dist/", import.meta.url).href;
const {
  decide, draftAgentPassport, dnsTxtRecord, guardedCall, intersect, localPolicy,
  memoryNonceStore, memoryReceiptSink, memorySpendLedger, passportAuthority,
  requestKeyEntry, signAgentPassport, signAgentRequest, signReceipt,
  verifyAgentCaller, verifyAgentPassport, verifyReceipt,
} = await import(`${D}index.js`);
const { fileSpendLedger } = await import(`${D}ledger-node.js`);

const ok = (label, pass, detail = "") =>
  console.log(`  ${pass ? "PASS" : "FAIL"}  ${label.padEnd(56)}${detail}`);
let failures = 0;
const check = (label, pass, detail) => { if (!pass) failures++; ok(label, pass, detail); };

const newKey = (keyId) => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = new Uint8Array(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url"));
  return { keyId, raw, b64url: Buffer.from(raw).toString("base64url"),
           pkcs8: new Uint8Array(privateKey.export({ type: "pkcs8", format: "der" })) };
};

// ---------------------------------------------------------------- Acme issues
console.log("\n1. Acme issues a passport and publishes its key in DNS");
const signingKey = newKey("acme-2026-q3");
const requestKey = newKey("acme-2026-q3-request");
const receiptKey = newKey("globex-receipts-2026-q3");

const passport = await signAgentPassport(
  draftAgentPassport({
    domain: "acme.example", legalName: "Acme Corporation",
    agentName: "Acme Procurement Agent", role: "procurement",
    purpose: "Buys software licences for Acme inside the published limits.",
    endpoints: { rest: "https://agents.acme.example/api/procurement" },
    scopes: ["procurement.purchase", "contracts.sign"],
    spendCeiling: 50_000, humanAbove: 10_000, escalation: "procurement@acme.example",
    keyId: signingKey.keyId,
    requestKeys: [requestKeyEntry({ keyId: requestKey.keyId, publicKeyRaw: requestKey.raw })],
  }),
  signingKey.pkcs8,
);
const txt = dnsTxtRecord({ keyId: signingKey.keyId, publicKeyRaw: signingKey.raw });
check("passport signed, key id matches the DNS record",
  passport.signature.value.length > 0 && txt.includes(signingKey.keyId), txt.slice(0, 44) + "...");

// The only thing faked: the network Acme would publish on.
const realFetch = globalThis.fetch;
let dnsKey = signingKey.b64url;
let served = passport;
globalThis.fetch = async (input, init) => {
  const url = String(input);
  if (url.startsWith("https://acme.example/.well-known/agent-passport.json")) return Response.json(served);
  if (url.startsWith("https://cloudflare-dns.com/dns-query"))
    return Response.json({ Status: 0, AD: true, Answer: [{ name: "_agent-passport.acme.example", type: 16, TTL: 300,
      data: `"v=ap1; kid=${signingKey.keyId}; alg=ed25519; pk=${dnsKey}"` }] });
  if (url.endsWith("revoked-passports.json")) return Response.json([]);
  return realFetch(input, init);
};

// ------------------------------------------------------- Globex verifies Acme
console.log("\n2. Globex verifies the passport the way any counterparty would");
const verification = await verifyAgentPassport({ domain: "acme.example" });
check("fetch, DNS key by kid, signature, expiry, revocation", verification.ok,
  verification.ok ? `agent ${verification.passport.agent.id}` : JSON.stringify(verification.errors));
check("DNSSEC-validated lookup leaves no warning",
  !verification.warnings.some((w) => w.code === "dns.unauthenticated"));

// ------------------------------------------------- Globex binds who is calling
console.log("\n3. Globex ties the live caller to that passport");
const body = JSON.stringify({ sku: "sku-7741", quantity: 40, unitPrice: 200 });
const outgoing = { method: "POST", url: "https://api.globex.example/orders?channel=agent",
                   headers: { "content-type": "application/json" }, body };
const signed = await signAgentRequest(outgoing, { keyId: requestKey.keyId, privateKey: requestKey.pkcs8 });
const received = { ...outgoing, headers: { ...outgoing.headers, ...signed } };
const callerNonces = memoryNonceStore();
const caller = await verifyAgentCaller(received, verification.passport, { nonceStore: callerNonces });
check("RFC 9421 signature verifies against agent.requestKeys", caller.ok, caller.ok ? `key ${caller.keyId}` : JSON.stringify(caller.errors));

// ---------------------------------------- Globex applies both sets of limits
console.log("\n4. Globex decides, under Acme's envelope and its own policy");
const globexPolicy = localPolicy({
  id: "globex-inbound", label: "Globex's own limits on inbound agents",
  scope: ["procurement.purchase"],
  limits: [{ amount: 20_000, currency: "USD", window: "day", label: "Globex's daily exposure cap" }],
  humanInLoop: { above: { amount: 8_000, currency: "USD" }, escalation: "sales-ops@globex.example", slaHours: 4 },
});
const authority = intersect(passportAuthority(verification), globexPolicy);
check("intersection drops the scope only Acme granted", !authority.scope.includes("contracts.sign"), `scopes: ${authority.scope.join(", ")}`);
check("both ceilings are carried, the tighter one binds", authority.ceilings.length === 2,
  authority.ceilings.map((c) => `${c.amount} ${c.currency}/${c.window}`).join(" + "));

const dir = mkdtempSync(join(tmpdir(), "ap-e2e-"));
const ledger = fileSpendLedger(join(dir, "spend.jsonl"));
const receipts = memoryReceiptSink();
const nonces = memoryNonceStore();
const order = {
  scope: "procurement.purchase", amount: { amount: 8_000, currency: "USD" },
  counterpartyDomain: "globex.example", counterpartyHasPassport: true,
  action: { tool: "orders.create", target: "sku-7741", args: { quantity: 40, unitPrice: 200 } },
};
const decision = await decide(authority, order, { ledger, engagementId: "po-8891" });
check("an 8,000 USD order is allowed", decision.decision === "allow", `reasons: ${decision.reasons.map((r) => r.code)}`);
check("the amount is held against the ledger", decision.charge?.reserved === true);

// --------------------------------------------- Globex executes under the guard
console.log("\n5. Globex performs the side effect, once, through the guard");
const fulfilled = [];
const result = await guardedCall(decision, order, () => { fulfilled.push(order.action); return { orderId: "ord_1" }; },
  { ledger, nonceStore: nonces, receipts, engagementId: "po-8891",
    signReceiptsWith: { keyId: receiptKey.keyId, privateKey: receiptKey.pkcs8 } });
check("the order executes exactly once", result.outcome === "executed" && fulfilled.length === 1, `orderId ${result.value?.orderId}`);
check("spend is committed, not merely reserved",
  (await ledger.committed({ subject: decision.subject.agentId, currency: "USD", window: "day", at: new Date() })) === 8_000);

// ------------------------------------------------- A third party checks the receipt
console.log("\n6. An auditor checks the receipt holding only the public key");
const receipt = receipts.receipts[0];
const audited = await verifyReceipt(receipt, receiptKey.raw);
check("the signed receipt verifies", audited.ok);
check("it names the agent, the authority and the outcome",
  receipt.subject.agentId === verification.passport.agent.id && receipt.origin.length === 2 && receipt.outcome === "executed",
  `${receipt.origin.map((o) => o.kind).join("+")} / ${receipt.outcome}`);
const wire = JSON.stringify(receipt);
// Distinctive values only: a bare "40" also matches inside a uuid.
const payload = ["sku-7741", "unitPrice", "quantity", "orders.create:"];
const leaked = payload.filter((v) => wire.includes(v));
check("it carries no payload", leaked.length === 0, leaked.length ? `leaked ${leaked}` : "target and args absent");
check("but it does name the tool and the amount",
  receipt.request.tool === "orders.create" && receipt.request.amount.amount === 8_000);
check("the digest still ties it to the original request", receipt.binding.digest === decision.binding.digest);

// ------------------------------------------------------- Break each link in turn
console.log("\n7. Break each link and confirm the chain depends on it");
const tamper = { ...passport, authority: { ...passport.authority, spendCeiling: { ...passport.authority.spendCeiling, amount: 5_000_000 } } };
served = tamper;
check("a passport edited after signing fails", !(await verifyAgentPassport({ domain: "acme.example" })).ok);
served = passport;

dnsKey = newKey("x").b64url;
check("a DNS key that is not the signer fails", !(await verifyAgentPassport({ domain: "acme.example" })).ok);
dnsKey = signingKey.b64url;

// The forgery the whole scheme exists to stop: name someone else as issuer,
// publish your own key in a zone you control, sign, and present it.
{
  const attacker = newKey("attacker-1");
  const forged = await signAgentPassport(
    { ...structuredClone(passport), issuer: { ...passport.issuer, signingKeyDns: "_agent-passport.attacker.example" },
      signature: { ...passport.signature, keyId: attacker.keyId, value: "" } },
    attacker.pkcs8,
  );
  const result = await verifyAgentPassport({ passport: forged, checkRevocation: false });
  const codes = (result.errors ?? []).map((e) => e.code);
  check("a signing key published outside the issuer's zone fails",
    !result.ok && codes.length === 1 && codes[0] === "issuer.signing-key-outside-domain", codes.join(","));
}

const strayKey = newKey("stranger");
const strayCall = { ...outgoing, headers: { ...outgoing.headers,
  ...(await signAgentRequest(outgoing, { keyId: strayKey.keyId, privateKey: strayKey.pkcs8 })) } };
check("a caller using an unpublished key is refused", !(await verifyAgentCaller(strayCall, passport)).ok);
check("the same signed call replayed is refused",
  !(await verifyAgentCaller(received, verification.passport, { nonceStore: callerNonces })).ok);

const swapped = { ...order, action: { ...order.action, target: "sku-9999" } };
const d2 = await decide(authority, order, { ledger, engagementId: "po-8891" });
const r2 = await guardedCall(d2, swapped, () => { fulfilled.push(swapped.action); return {}; },
  { ledger, nonceStore: nonces, receipts, engagementId: "po-8891" });
check("an action swapped after approval never reaches fulfilment",
  r2.outcome === "blocked" && fulfilled.length === 1, r2.reasons?.map((r) => r.code).join(","));

const replay = await guardedCall(decision, order, () => { fulfilled.push(order.action); return {}; },
  { ledger, nonceStore: nonces, receipts, engagementId: "po-8891" });
check("the first decision cannot be used twice", replay.outcome === "blocked" && fulfilled.length === 1,
  replay.reasons?.map((r) => r.code).join(","));

const big = { ...order, amount: { amount: 13_000, currency: "USD" } };
const d3 = await decide(authority, big, { ledger, engagementId: "po-8891" });
check("a second order past Globex's daily cap is denied", d3.decision === "deny", d3.reasons.map((r) => r.code).join(","));

const forged = { ...receipt, outcome: "blocked" };
check("an edited receipt fails verification", !(await verifyReceipt(forged, receiptKey.raw)).ok);

check("the ledger recorded every attempt, and only one commit",
  (await ledger.entries()).filter((e) => e.state === "committed").length === 1,
  (await ledger.entries()).map((e) => e.state).join(","));

rmSync(dir, { recursive: true, force: true });
globalThis.fetch = realFetch;
console.log(`\n${failures === 0 ? "Every link holds, and every break is caught." : `${failures} check(s) failed.`}`);
process.exit(failures === 0 ? 0 : 1);
