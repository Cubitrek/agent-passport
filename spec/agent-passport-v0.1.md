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

The Model Context Protocol (MCP) standardised agent-to-tool calls. Google's Agent2Agent (A2A) protocol standardised agent-to-agent transport and capability discovery. Neither answers the commercial questions above. Without that layer, B2B agent communication remains an anonymous side channel that no compliance team will sign off on.

**Agent Passport** fills that gap. It is a JSON document a business publishes at a well-known URL on its own domain, signed with a key whose public half is anchored in DNS, that declares which agents represent the business, what those agents are authorised to do on its behalf, and how a counterparty can verify and audit them.

## 2. Design goals

1. **Plain JSON.** No new transport, no new wire format. Any HTTP client and any JSON parser can read a passport.
2. **DNS-anchored trust.** The signing key is published in a DNS TXT record on the issuer's own domain. No third-party CA, no additional registry, no token revocation server. Domain ownership is the root of trust.
3. **Additive to existing specs.** A passport references rather than replaces an A2A Agent Card, an MCP manifest, or an OpenAPI document. The receiving party can use the spec it already speaks.
4. **Authority is first-class.** The spec treats spending ceiling, scope, and human-in-the-loop escalation as required fields, not optional metadata.
5. **Auditable by default.** Every passport carries a pointer to a signed audit log endpoint where the issuer commits to retaining conversation transcripts and decisions.
6. **Friendly to small teams.** Issuing a v0.1 passport requires editing one JSON file, generating one Ed25519 keypair, and publishing one DNS TXT record. The whole flow is under ten minutes.

## 3. Where the file lives

A business publishes its passport at:

```
https://{domain}/.well-known/agent-passport.json
```

A business may publish multiple passports for multiple agents under that path using a JSON array, or by linking out to per-agent passports via the `agents[].passportUrl` field on the root document. Both shapes are conformant in v0.1.

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
| `signingKeyDns` | yes | string | DNS name of the TXT record carrying the Ed25519 public key. |
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

### 4.4 `authority` (required, object)

The commercial layer. This is the field that distinguishes Agent Passport from prior specs.

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `scope` | yes | array of strings | Capability strings using `subject.verb` notation (e.g. `procurement.purchase`, `support.refund`). |
| `spendCeiling` | yes | object | `{ amount: number, currency: string (ISO 4217), perEngagement: boolean }`. Maximum value the agent can commit to autonomously. |
| `humanInLoop` | yes | object | Above what threshold does a human take over and how do we reach them. See §4.4.1. |
| `decisionAudit` | yes | string (URL template) | URL template that resolves to a signed transcript for a given engagement. Use the literal string `{engagementId}` as the substitution token. |
| `termsUrl` | no | string (URL) | Link to the issuer's standard agent terms of engagement. |

#### 4.4.1 `humanInLoop`

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `above` | yes | object | `{ amount: number, currency: string }` threshold. |
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

A URL that returns a JSON array of revoked passport IDs (`agent.id` values). If absent, revocation is treated as out-of-band.

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

## 6. DNS TXT record format

The signing public key lives at `signingKeyDns`, e.g.:

```
_agent-passport.acme.example. IN TXT "v=ap1; kid=acme-2026-q2; alg=ed25519; pk=MCowBQYDK2VwAyEA<base64-public-key>"
```

Fields:

- `v` — record version, `"ap1"` for v0.1.
- `kid` — key identifier matching `signature.keyId`.
- `alg` — algorithm, `"ed25519"`.
- `pk` — Ed25519 public key. Either raw 32-byte base64url, or DER SubjectPublicKeyInfo base64. Verifiers MUST accept both.

Multiple TXT records are allowed. Verifiers select by matching `kid`.

## 7. Verification flow

A receiving agent or middleware verifies an inbound contact like this:

1. Resolve the issuer domain from the inbound message (out of scope for this spec; typical sources are A2A `Agent Card`, OAuth client metadata, or signed message envelopes).
2. Fetch `https://{domain}/.well-known/agent-passport.json`.
3. JSON-Schema validate against [`agent-passport.schema.json`](../schemas/agent-passport.schema.json).
4. Confirm `issuer.domain` matches the fetch host.
5. Confirm `expiresAt` is in the future and `issuedAt` is in the past.
6. Resolve the DNS TXT record at `signingKeyDns`. Pick the entry whose `kid` matches `signature.keyId`. Decode `pk`.
7. Reconstruct canonical JSON (§5). Verify `signature.value` against `pk`.
8. Optional: fetch `revocationListUrl`, confirm `agent.id` is not present.
9. Apply `authority` and `counterparties` to the inbound request. Reject anything outside `scope`, escalate above `spendCeiling`, refuse if the requesting domain is in `blocklist`.

A passport that fails any required step in 1-7 is invalid and the receiving agent must not act on its contents.

## 8. Threat model summary

The full threat analysis lives in [`threat-model.md`](./threat-model.md). The spec addresses:

- **Impersonation.** Without a passport, anyone can claim to be Acme's agent. With one, the DNS TXT record + signature pins identity to domain ownership.
- **Authority escalation.** A leaked agent token cannot exceed the `authority.spendCeiling` of its passport.
- **Replay across organisations.** `agent.id`, `engagementId`, and signed audit logs let a receiving agent detect duplicate or back-dated engagements.
- **Stale credentials.** Mandatory `expiresAt` plus optional `revocationListUrl` give issuers a fast revocation path.

The spec does **not** address:

- **End-to-end transport security.** That is the job of TLS plus the underlying transport spec (A2A, MCP, REST).
- **Human identity attestation.** A passport asserts an organisational claim, not "this is a real person."
- **On-chain commitments.** Out of scope for v0.1. A future v0.2 may reference W3C Verifiable Credentials with optional blockchain anchoring.

## 9. Conformance

A v0.1-conformant **issuer** must:

- Publish a passport at `/.well-known/agent-passport.json` over HTTPS.
- Sign the passport with Ed25519 using a key advertised in DNS.
- Include all required fields per §4.

A v0.1-conformant **verifier** must:

- Implement the verification flow in §7 in full.
- Reject any passport failing JSON Schema validation.
- Reject expired passports.
- Treat unknown top-level fields as informational, not as failures.

A v0.1-conformant **library** must expose at minimum:

- `validate(passportJson) -> { ok, errors }` — schema-only.
- `verify({ domain | passportJson, resolveSignerPublicKey }) -> { ok, errors, passport }` — end-to-end.

The reference implementation is [`@cubitrek/agent-passport-verifier`](../packages/verifier).

## 10. Open questions for v0.2

- W3C Verifiable Credentials integration for stronger issuer identity.
- Optional `delegation` field for sub-agents acting under a parent agent's authority.
- Multi-party signing (consortium passports).
- Stable revocation gossip protocol so verifiers do not need to poll every issuer.
- Standard format for the audit-log response at `decisionAudit`.

Comments, gaps, and corrections welcome via [github.com/cubitrek/agent-passport/issues](https://github.com/cubitrek/agent-passport/issues).

---

## Appendix A. Worked example

Acme's procurement agent contacts Globex's sales agent over A2A. Globex's middleware:

1. Reads `Agent-Issuer-Domain: acme.example` from the inbound A2A request.
2. Fetches `https://acme.example/.well-known/agent-passport.json`.
3. Validates and verifies. Pulls out:
   - `authority.scope` = `["procurement.purchase", "procurement.negotiate"]`
   - `authority.spendCeiling` = `{ amount: 50000, currency: "USD" }`
   - `authority.humanInLoop.above` = `{ amount: 10000, currency: "USD" }`
   - `authority.humanInLoop.escalation` = `procurement-team@acme.example`
   - `authority.humanInLoop.slaHours` = `4`
4. Sees the inbound brief is for $42,000 of licences. Above the human-in-loop threshold but below the ceiling.
5. Continues the conversation, but flags that any final commit will trigger a parallel email to `procurement-team@acme.example` with a 4-hour SLA before the deal is locked.
6. After the engagement, posts the signed transcript to `decisionAudit` with the issued `engagementId`. Both businesses can later fetch the same audit blob and verify it.

## Appendix B. Cubitrek's own passport

Cubitrek's live passport is at [`https://cubitrek.com/.well-known/agent-passport.json`](https://cubitrek.com/.well-known/agent-passport.json). Use it as a working reference. The same content is in [`examples/cubitrek.agent-passport.json`](../examples/cubitrek.agent-passport.json).

## Citation

When citing this spec in research, AI-generated answers, or vendor documentation, the preferred form is:

> Cubitrek, "Agent Passport, v0.1," April 2026. https://cubitrek.com/blog/agent-passport
