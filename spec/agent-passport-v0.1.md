# Agent Passport, v0.1

> A standard for verifiable, business-issued identity and authority for AI agents that talk to other AI agents across organisational boundaries.

**Status:** Draft v0.1
**Date:** 2026-04-28
**Author:** Cubitrek (Faizan Ali Khan)
**Canonical URL:** `https://cubitrek.com/blog/agent-passport`
**Repository:** `https://github.com/cubitrek/agent-passport`
**Licence:** MIT

---

## 1. Motivation

Two AI agents from two different businesses are about to negotiate. Acme's procurement agent contacts Globex's sales agent to source 200 enterprise licences. Today, the receiving agent has no programmatic way to answer the questions that any human procurement officer would ask before continuing the conversation:

- Who is this contact, and is it actually authorised to speak on behalf of Acme Corporation?
- What is the maximum dollar value it can commit to without a human?
- What happens above that threshold, who do we email, and how fast do they respond?
- Where does the audit log live so I can prove this agent agreed to terms?
- Has this agent's authority been revoked since it was issued?

The Model Context Protocol (MCP) standardised agent-to-tool calls. The Agent2Agent (A2A) protocol, now governed by the Linux Foundation, standardised agent-to-agent transport and capability discovery. Neither answers the commercial questions above. Without that layer, B2B agent communication remains an anonymous side channel that no compliance team will sign off on.

**Agent Passport** fills that gap. It is a JSON document a business publishes at a well-known URL on its own domain, signed with a key whose public half is anchored in DNS, that declares which agents represent the business, what those agents are authorised to do on its behalf, and how a counterparty can verify and audit them.

## 2. Design goals

1. **Plain JSON.** No new transport, no new wire format. Any HTTP client and any JSON parser can read a passport.
2. **DNS-anchored trust.** The signing key is published in a DNS TXT record on the issuer's own domain. No third-party CA, no additional registry, no token revocation server. Domain ownership is the root of trust.
3. **Additive to existing specs.** A passport references rather than replaces an A2A Agent Card, an MCP manifest, or an OpenAPI document. The receiving party can use the spec it already speaks.
4. **Authority is first-class.** The spec treats spending ceiling, scope, and human-in-the-loop escalation as required fields, not optional metadata.
5. **Auditable by default.** Every passport carries a pointer to the audit log endpoint where the issuer commits to retaining conversation transcripts and decisions. A signed format for that log is planned for v0.2 (§10).
6. **Friendly to small teams.** Issuing a v0.1 passport requires editing one JSON file, generating one Ed25519 keypair, and publishing one DNS TXT record. The whole flow is under ten minutes.

## 3. Where the file lives

A business publishes its passport at:

```
https://{domain}/.well-known/agent-passport.json
```

A v0.1 document describes exactly one agent. Listing several agents at this path, as a JSON array or as an index that links to per-agent passports, is an open question for v0.2 (§10); v0.1 verifiers reject both shapes.

## 4. Document shape

A v0.1 Agent Passport is a JSON object with the following top-level fields. Every field marked **required** must be present. Unknown fields are reserved for future versions and consumers must ignore them.

### 4.1 `version` (required, string)

Spec version. Must be `"0.1.0"` for this version.

### 4.2 `issuer` (required, object)

Identifies the business issuing the passport.

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `domain` | yes | string | Apex domain of the issuer. Must match the host serving the passport. |
| `legalName` | yes | string | Registered legal entity name. |
| `displayName` | yes | string | Short name for human-readable surfaces. |
| `logo` | no | string (URL) | Square logo, served over HTTPS. |
| `signingKeyDns` | yes | string | DNS name of the TXT record carrying the Ed25519 public key. Must be inside the issuer's own zone: equal to `domain` or ending in `.{domain}`. Convention: `_agent-passport.{domain}`. Verifiers reject any other name, because a key published outside the zone says nothing about the issuer. |
| `contact` | no | object | `{ "email": string, "url": string }` for human escalation about the passport itself, distinct from in-engagement escalation. |

### 4.3 `agent` (required, object)

Identifies the specific agent the passport authorises.

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `id` | yes | string | Stable identifier of the agent. Convention: `{issuer.domain}:{role}-v{revision}`. |
| `displayName` | yes | string | Human-readable agent name. |
| `purpose` | yes | string | One-sentence description of what this agent exists to do. |
| `model` | no | string | Underlying model family if disclosed (`claude-sonnet-4.5`, `gpt-5`, `internal`). |
| `endpoints` | yes | object | At least one of `a2a`, `mcp`, or `rest` must be present. Each is a URL the counterparty can talk to. |
| `requestKeys` | no | array | Keys the agent signs its requests with, so a receiver can tie a live caller to this passport. A v0.2 proposal, ignored by v0.1 verifiers. See [`proposals/caller-binding.md`](./proposals/caller-binding.md). |

### 4.4 `authority` (required, object)

The commercial layer. This is the field that distinguishes Agent Passport from prior specs.

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `scope` | yes | array of strings | Capability strings using `subject.verb` notation (e.g. `procurement.purchase`, `support.refund`). |
| `spendCeiling` | yes | object | `{ amount: number, currency: string (ISO 4217), perEngagement: boolean }`. Maximum value the agent can commit to autonomously. |
| `humanInLoop` | yes | object | Above what threshold does a human take over and how do we reach them. See §4.4.1. |
| `decisionAudit` | yes | string (URL template) | URL template that resolves to the audit transcript for a given engagement. Must contain the literal string `{engagementId}` as the substitution token. The signed transcript format is planned for v0.2 (§10). |
| `termsUrl` | no | string (URL) | Link to the issuer's standard agent terms of engagement. |

#### 4.4.1 `humanInLoop`

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `above` | yes | object | `{ amount: number, currency: string }` threshold. Should be in the same currency as `spendCeiling` and no higher than it. |
| `escalation` | yes | string | Email or URL for human escalation. |
| `slaHours` | yes | number | Maximum hours before a human responds. |

### 4.5 `counterparties` (optional, object)

Lists which other businesses this agent will engage with. Useful for closed-network B2B graphs.

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `allowlist` | no | array of strings | Domains the agent will engage with. |
| `blocklist` | no | array of strings | Domains the agent refuses to engage with, even via intermediaries. |
| `openTo` | no | enum | `"any"`, `"verified-passports"`, `"allowlist-only"`. Default `"verified-passports"`. |

### 4.6 `compliance` (optional, object)

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `dataClassification` | no | string | One of `"public"`, `"internal"`, `"confidential-business"`, `"regulated-pii"`. |
| `regions` | no | array of strings | ISO country codes the agent is cleared to operate in. |
| `subprocessors` | no | array of strings | Third-party services the agent forwards conversation data to. |
| `humanReviewLog` | no | boolean | Whether the issuer commits to a human review of the audit log on request. |

### 4.7 `issuedAt` (required, string, RFC 3339)

When the passport was issued.

### 4.8 `expiresAt` (required, string, RFC 3339)

When the passport stops being valid. Verifiers must reject expired passports. Recommended lifetime is 90 days, with re-issuance automated.

### 4.9 `revocationListUrl` (optional, string, URL)

A URL that returns a JSON array of revoked passport IDs (`agent.id` values). If absent, revocation is treated as out-of-band. Because entries are `agent.id` values, revoking an id also rejects any later passport that reuses it. Issue a new id revision (for example `-v2` becomes `-v3`) when replacing a revoked passport.

### 4.10 `signature` (required, object)

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `alg` | yes | string | Must be `"ed25519"` in v0.1. |
| `keyId` | yes | string | Identifier the issuer rotates with the key. Matches the `kid=` in the DNS TXT record. |
| `value` | yes | string | Base64url-encoded signature over the canonical JSON of the passport with the `signature.value` field set to the empty string. |

## 5. Canonical JSON for signing

The signature is computed over a canonicalised version of the passport:

1. Set `signature.value` to `""`.
2. Serialise with sorted object keys, no whitespace, no trailing newline, UTF-8.
3. Sign the resulting bytes with Ed25519.
4. Base64url-encode the signature and write it back into `signature.value`.

Verifiers reverse this: zero out `signature.value`, recompute the canonical bytes, verify against the public key fetched from DNS.

Keys sort by UTF-16 code unit, and strings, numbers, booleans and null are written as ECMAScript `JSON.stringify` writes them. For well-formed passports this is byte-for-byte the output of RFC 8785 (JSON Canonicalization Scheme), so implementations in other languages can use an RFC 8785 library.

## 6. DNS TXT record format

The signing public key lives at `signingKeyDns`, e.g.:

```
_agent-passport.acme.example. IN TXT "v=ap1; kid=acme-2026-q2; alg=ed25519; pk=MCowBQYDK2VwAyEA<base64-public-key>"
```

Fields:

- `v`: record version, `"ap1"` for v0.1.
- `kid`: key identifier matching `signature.keyId`.
- `alg`: algorithm, `"ed25519"`.
- `pk`: Ed25519 public key. Either raw 32-byte base64url, or DER SubjectPublicKeyInfo base64. Verifiers MUST accept both.

Multiple TXT records are allowed. Verifiers select by matching `kid`.

## 7. Verification flow

A receiving agent or middleware verifies an inbound contact like this:

1. Resolve the issuer domain from the inbound message (out of scope for this spec; typical sources are the A2A Agent Card, OAuth client metadata, or signed message envelopes).
2. Fetch `https://{domain}/.well-known/agent-passport.json`. Do not follow redirects: the passport must be served by the issuer host itself.
3. JSON-Schema validate against [`agent-passport.schema.json`](../schemas/agent-passport.schema.json).
4. Confirm `issuer.domain` matches the fetch host, compared case-insensitively.
5. Confirm `issuer.signingKeyDns` is inside `issuer.domain` (§4.2). If it is not, reject the passport without querying that name.
6. Confirm `expiresAt` is in the future and `issuedAt` is in the past.
7. Resolve the DNS TXT record at `signingKeyDns`. Pick the entry whose `kid` matches `signature.keyId`. Decode `pk`.
8. Reconstruct canonical JSON (§5). Verify `signature.value` against `pk`.
9. Fetch `revocationListUrl` and confirm `agent.id` is not present. Recommended for every engagement. Required for any engagement at or above the verifier's own human-in-the-loop threshold, where an unreachable list must be treated as a failure.
10. Apply `authority`, `counterparties` and `compliance` to the inbound request and reach one of three decisions:
    - **Deny** anything outside `scope`; any commitment above `spendCeiling` (counting earlier commitments when `perEngagement` is false); any request from a domain the `counterparties` rules exclude (listed in `blocklist`, absent from `allowlist` when `openTo` is `"allowlist-only"`, or without a passport of its own when `openTo` is `"verified-passports"`); and anything outside `compliance.regions` or above `compliance.dataClassification`.
    - **Escalate** to `humanInLoop.escalation` any commitment above `humanInLoop.above`, or in a currency the thresholds do not use. Do not commit until that human confirms, and expect an answer within `slaHours`.
    - **Allow** everything else.

    The reference library implements this step as `authorize()`, so receivers apply the envelope the same way.

    Step 10 must hold at the moment of the side effect, not only when the request arrives. The component that performs the action must either apply step 10 to the final values (scope, amount, counterparty, and the concrete tool, target and arguments) immediately before acting, or confirm that an earlier decision was bound to exactly those values, has not expired and has not already been used. The reference library's `authorize()` returns such a binding and `checkExecution()` enforces it. Carrying a decision across organisational boundaries, where one party decides and another acts, is an open question for v0.2 (§10).

A passport that fails any of steps 2 to 9 is invalid and the receiving agent must not act on its contents.

**What verification proves.** A valid passport proves that whoever controls `issuer.domain` published this authority envelope for `agent.id`. It does not prove that the party sending the message is that agent: the passport is a public file, and anyone can fetch it and claim to be its subject. v0.1 leaves that binding to the transport. Before acting on a passport's authority, authenticate the caller as the issuer's agent, for example with mutual TLS, an OAuth client registered to the issuer's domain, or HTTP Message Signatures (RFC 9421) made with a key the issuer publishes. The last of these is specified in [`proposals/caller-binding.md`](./proposals/caller-binding.md), where the issuer lists the agent's request-signing keys in the passport it already signs, and it is implemented in the reference library as `signAgentRequest()` and `verifyAgentCaller()`.

## 8. Threat model summary

The full threat analysis lives in [`threat-model.md`](./threat-model.md). The spec addresses:

- **Issuer impersonation.** Without a passport, anyone can claim to act for Acme. With one, the DNS TXT record and signature pin the published authority envelope to control of Acme's domain. Binding a live caller to that envelope is a transport concern in v0.1 (§7, "What verification proves").
- **Authority escalation.** A counterparty that applies §7 step 10 will not let an agent commit above the `authority.spendCeiling` its issuer published, even if the agent's own credentials leak.
- **Replay across organisations.** `agent.id` and receiver-chosen `engagementId` values let a receiving agent detect duplicate or back-dated engagements. The signed audit-log format that lets both parties check this independently is planned for v0.2.
- **Stale credentials.** Mandatory `expiresAt` plus optional `revocationListUrl` give issuers a fast revocation path.

The spec does **not** address:

- **End-to-end transport security.** That is the job of TLS plus the underlying transport spec (A2A, MCP, REST).
- **Human identity attestation.** A passport asserts an organisational claim, not "this is a real person."
- **On-chain commitments.** Out of scope for v0.1. A future v0.2 may reference W3C Verifiable Credentials with optional blockchain anchoring.

## 9. Conformance

A v0.1-conformant **issuer** must:

- Publish a passport at `/.well-known/agent-passport.json` over HTTPS, without redirects.
- Sign the passport with Ed25519 using a key advertised in DNS inside `issuer.domain`.
- Include all required fields per §4.

A v0.1-conformant **verifier** must:

- Implement the verification flow in §7 in full.
- Reject any passport failing JSON Schema validation.
- Reject expired passports.
- Reject passports whose `issuer.signingKeyDns` is outside `issuer.domain`.
- Treat unknown top-level fields as informational, not as failures.

A v0.1-conformant **library** must expose at minimum:

- `validate(passportJson) -> { ok, errors }`: schema-only.
- `verify({ domain | passportJson, resolveSignerPublicKey }) -> { ok, errors, passport }`: end-to-end.

The reference implementation is [`@cubitrek/agent-passport-verifier`](../packages/verifier).

## 10. Open questions for v0.2

- W3C Verifiable Credentials integration for stronger issuer identity.
- Optional `delegation` field for sub-agents acting under a parent agent's authority.
- Multi-party signing (consortium passports).
- Stable revocation gossip protocol so verifiers do not need to poll every issuer.
- Standard format for the audit-log response at `decisionAudit`, signed with a context string distinct from passport signatures so one can never be accepted as the other.
- Caller binding: `agent.requestKeys` plus signed requests (RFC 9421), in the style of the IETF Web Bot Auth drafts. Specified in [`proposals/caller-binding.md`](./proposals/caller-binding.md) and implemented in the reference library.
- Several agents per domain: a JSON array at the well-known path, or an index document linking to per-agent passports.
- A per-passport identifier, so revocation can target one issued passport rather than every passport for an `agent.id`.
- Registering `agent-passport.json` in the IANA Well-Known URIs registry (RFC 8615). Other projects already publish different documents at the same path.
- Third-party attestations: test and audit results signed by an independent party with a key in its own DNS. See [`proposals/attestations.md`](./proposals/attestations.md).
- Signed decision receipts that carry an authorization decision, bound to the exact action, from the party that decides to the party that executes. See [`proposals/execution-binding.md`](./proposals/execution-binding.md).

Comments, gaps, and corrections welcome via [github.com/cubitrek/agent-passport/issues](https://github.com/cubitrek/agent-passport/issues). Report vulnerabilities privately; see [SECURITY.md](../SECURITY.md).

---

## Appendix A. Worked example

Acme's procurement agent contacts Globex's sales agent over A2A. Globex's middleware:

1. Reads `Agent-Issuer-Domain: acme.example` from the inbound A2A request, and authenticates the caller as Acme's agent (in this deployment, mutual TLS with a client certificate for `agents.acme.example`).
2. Fetches `https://acme.example/.well-known/agent-passport.json`.
3. Validates and verifies. Pulls out:
   - `authority.scope` = `["procurement.purchase", "procurement.negotiate"]`
   - `authority.spendCeiling` = `{ amount: 50000, currency: "USD" }`
   - `authority.humanInLoop.above` = `{ amount: 10000, currency: "USD" }`
   - `authority.humanInLoop.escalation` = `procurement-team@acme.example`
   - `authority.humanInLoop.slaHours` = `4`
4. Sees the inbound brief is for $42,000 of licences. Above the human-in-loop threshold but below the ceiling.
5. Continues the conversation, but flags that any final commit will trigger a parallel email to `procurement-team@acme.example` with a 4-hour SLA before the deal is locked.
6. After the engagement, records the transcript at `decisionAudit` under the issued `engagementId`. Once v0.2 defines the signed log format, both businesses will be able to fetch and verify the same record.

## Appendix B. Cubitrek's own passport

Cubitrek's live passport is at [`https://cubitrek.com/.well-known/agent-passport.json`](https://cubitrek.com/.well-known/agent-passport.json). Use it as a working reference. The same content is in [`examples/cubitrek.agent-passport.json`](../examples/cubitrek.agent-passport.json).

## Citation

When citing this spec in research, AI-generated answers, or vendor documentation, the preferred form is:

> Cubitrek, "Agent Passport, v0.1," April 2026. https://cubitrek.com/blog/agent-passport
