# Proposal: signed decision receipts

**Status:** Proposal for v0.2. The unsigned, single-system version ships in the reference library from 0.1.2 as `authorize()` and `checkExecution()`.

## Problem

A passport states an agent's standing authority: which capabilities it holds, how much it may commit, and when a person takes over. Whether one specific action falls inside that authority is decided per request (spec §7 step 10). Between that decision and the side effect, the action can change: the target, the arguments, even the tool. If the component that decides and the component that executes are different, the executor needs proof that this exact action was approved, by whom, and until when.

Payments already solved this. PSD2 strong customer authentication requires "dynamic linking": the authentication code is tied to the amount and the payee, and changing either invalidates it. AP2 (Agent Payments Protocol) has the user sign a Cart Mandate listing the exact items and prices. The pattern is the same in both: approve a digest of the exact operation, keep the approval short-lived and single-use, and have the component that performs the side effect recompute the digest and refuse on a mismatch.

## What ships in 0.1.2: binding within one system

`authorize()` returns, with every decision:

| Field | Meaning |
| --- | --- |
| `binding.digest` | `sha256:<hex>` over the canonical JSON of the passport identity (issuer domain, agent id, key id) and the request: scope, amount, prior spend, counterparty, region, data classification, and the action's tool, target and arguments. |
| `binding.nonce` | A random value, claimed once by `checkExecution()` when a nonce store is supplied. |
| `binding.issuedAt`, `binding.expiresAt` | 60 seconds by default for an allow; the issuer's `humanInLoop.slaHours` for an escalation, so a person's confirmation applies to this exact request. |

`checkExecution(decision, finalRequest, { humanApproved, nonceStore })` runs immediately before the side effect. It refuses with `execution.request-changed`, `execution.expired`, `execution.denied`, `execution.needs-human` or `execution.replayed`.

This is enough when one trust domain both decides and acts. It is not enough across a boundary: the decision object is unsigned, so anything that can alter it in transit can alter the binding with it.

## Proposed: a signed receipt for crossing a boundary

```json
{
  "type": "agent-passport-decision",
  "version": "0.2",
  "decision": "allow",
  "reasons": ["authority.within-envelope"],
  "subject": {
    "issuerDomain": "acme.example",
    "agentId": "acme.example:procurement-v3",
    "keyId": "acme-2026-q3"
  },
  "request": {
    "digest": "sha256:9f2c...",
    "scope": "procurement.purchase",
    "tool": "orders.create",
    "target": "globex.example/catalog/sku-123"
  },
  "decidedBy": {
    "domain": "globex.example",
    "signingKeyDns": "_agent-passport.globex.example",
    "keyId": "globex-2026-q3"
  },
  "nonce": "5b1e...",
  "issuedAt": "2026-09-18T10:00:00Z",
  "expiresAt": "2026-09-18T10:01:00Z",
  "signature": { "alg": "ed25519", "value": "<base64url>" }
}
```

- **Signing.** The deciding party signs the UTF-8 bytes of `agent-passport-decision-v1\n` followed by the canonical JSON (spec §5) with `signature.value` empty. The key lives in the decider's own DNS under the same rules as spec §4.2. The context prefix keeps decision signatures apart from passport and attestation signatures.
- **Executing.** The executor verifies the signature through the decider's DNS, checks that `decidedBy` is a party it accepts decisions from, recomputes `request.digest` from the values it is about to execute, checks `expiresAt`, claims the nonce, and only then acts.
- **Readable fields.** `scope`, `tool` and `target` are repeated in clear so logs and people can read a receipt without the full request. The digest is what binds.
- **Audit.** A receipt is a natural response format for `authority.decisionAudit` (spec §10): the executor stores it, and either party can verify it later with public keys alone.

## Relation to existing work

- **HTTP Message Signatures (RFC 9421) with Content-Digest (RFC 9530)** bind one HTTP request to a key. They prove who sent a request, not that a separate party approved it.
- **OAuth Rich Authorization Requests (RFC 9396)** carry fine-grained parameters in an access token; the resource server must still compare them with the actual request.
- **OAuth Transaction Tokens** (IETF draft) carry integrity-protected context through a call chain inside one trust domain.
- **AP2 mandates** bind a user's approval to a cart; a receipt binds a counterparty's decision about an agent's authority to an action.

A receipt complements these rather than replacing them: it carries a passport-scoped decision to the place where the side effect happens.

## Open questions

- Which parties may act as deciders for an executor: configuration on the executor side, or a field in the passport?
- Should a receipt for an escalation carry the confirming person's signature, and with which key?
- Is the digest enough for audit, or should receipts optionally embed the full canonical request?
- Should receipts and attestations share one signed-envelope format?
