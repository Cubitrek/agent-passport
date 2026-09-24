# Proposal: caller binding with signed requests

**Status:** Proposal for v0.2. Implemented in the reference library from 0.1.2 as `agent.requestKeys`, `signAgentRequest()` and `verifyAgentCaller()`. Under v0.1 the field is an unknown property, which verifiers ignore.

## Problem

A passport is a public file. Verifying one proves that the issuer published this authority for this agent. It does not prove that the party sending you a message is that agent: anyone can fetch `acme.example/.well-known/agent-passport.json` and claim to be its subject. Spec §7 says this plainly and leaves the binding to the transport, which in practice means every receiver invents its own answer.

## Shape

An optional `agent.requestKeys` array. The issuer already signs the passport, so listing the agent's request-signing keys there binds them without publishing anything else:

```json
"agent": {
  "id": "acme.example:procurement-v3",
  "requestKeys": [
    {
      "keyId": "acme-2026-q3-request",
      "alg": "ed25519",
      "publicKey": "2ib2Yj3Xd1dzjWXBiz_Hu98_DAsLYEabhoSYgObSDgs"
    }
  ]
}
```

`publicKey` is the raw 32-byte Ed25519 public key, base64url, unpadded. At most eight keys, so rotation can overlap.

The trust chain becomes:

```
issuer's DNS key -> passport signature -> agent request key -> this request
```

A request-signing key is used on every call, so it must not be the passport signing key, which issues authority and belongs offline or in an HSM (threat model §4). Rotating a request key means re-issuing the passport, which is already a short-lived document.

## Signing profile

The agent signs each request with HTTP Message Signatures (RFC 9421), the same primitive the IETF Web Bot Auth drafts use:

- **Covered components:** `("@method" "@authority" "@path" "@query")`, plus `"content-digest"` whenever there is a body. A verifier rejects a signature that covers less.
- **Parameters:** `created`, `expires` (300 seconds or less), `keyid` matching an entry in `agent.requestKeys`, `alg="ed25519"`, a `nonce`, and `tag="agent-passport"`.
- **Body integrity:** `Content-Digest: sha-256=:...:` per RFC 9530, recomputed by the verifier.
- **Single use:** the verifier claims the nonce in a store shared by everything that accepts these requests.

The `tag` lets a receiver pick out the Agent Passport signature when proxies or gateways have added signatures of their own.

## Verification order

1. Verify the passport (spec §7).
2. Verify the request signature against `agent.requestKeys`. Now the caller is bound to the passport.
3. Decide the action against `authority` (spec §7 step 10), bound to the exact tool, target and arguments.
4. Re-check that binding immediately before the side effect.

Each step answers a different question: what was authorised, who is calling, may this action proceed, and is this still the same action.

## Alternatives that remain valid

Mutual TLS with a certificate for the agent's host, or an OAuth client registered to the issuer, bind a caller just as well where both parties already run that infrastructure. This proposal is for the case the passport is aimed at: two companies with no shared platform, no accounts with each other, and nothing but public DNS between them.

## Open questions

- Should a passport be allowed to point at a key directory URL instead of listing keys inline, as Web Bot Auth does? It adds a fetch and a second thing to keep alive.
- Should responses be signed as well, so an agent can prove what it was told?
- How should sub-agents present themselves: their own keys inside the parent's passport, or the `delegation` field open question in spec §10?
- Is a 300 second ceiling on signature lifetime right for slow or queued transports?
