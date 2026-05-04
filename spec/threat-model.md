# Agent Passport, v0.1 — Threat model

This document expands the §8 summary in the canonical spec. It enumerates the failure modes Agent Passport is designed to defend against, the residual risks, and what is explicitly out of scope.

## 1. Threats addressed

### 1.1 Issuer impersonation

**Scenario.** A malicious party publishes a passport claiming to represent Acme Corp on a look-alike domain.

**Mitigation.** Verifiers fetch `/.well-known/agent-passport.json` from the apex domain claimed in `issuer.domain`. The domain serving the file must match the domain claimed inside the file. The signing public key is anchored in the DNS zone of that domain, which only the lawful operator of the domain can edit.

**Residual risk.** Domain hijack via registrar compromise. Mitigated by short `expiresAt` lifetimes and aggressive revocation lists.

### 1.2 Authority escalation

**Scenario.** A leaked agent credential is used to commit a $500,000 engagement on behalf of Acme, far above what Acme would actually authorise.

**Mitigation.** `authority.spendCeiling` is the autonomous ceiling. Any verifier processing an inbound engagement must reject or escalate engagements above the value declared in the passport. `humanInLoop` defines a strictly lower threshold above which a human is paged before the agent can commit.

**Residual risk.** A correctly-spent engagement that is fraudulent (leaked credentials used for a $5,000 purchase that the agent legitimately could authorise). Out of scope for the passport spec. Mitigated by the issuer's own internal anomaly detection.

### 1.3 Stale or revoked authority

**Scenario.** An agent is decommissioned but its credentials remain in circulation.

**Mitigation.** Every passport carries `expiresAt`. Verifiers must reject expired passports. `revocationListUrl` is an optional out-of-band fast revocation channel.

**Residual risk.** Verifiers that cache the passport without re-checking the revocation list. Mitigated by stating clearly in §7 that revocation MUST be checked on every engagement above a threshold the verifier sets, typically the human-in-loop value.

### 1.4 Replay across counterparties

**Scenario.** A receiving agent records an engagement and replays it to a third party to extract value twice.

**Mitigation.** Each engagement is identified by an `engagementId` chosen by the receiver. The audit log at `authority.decisionAudit` is a signed canonical record both parties can fetch and compare. A replay surfaces as a duplicate `engagementId` against the same agent in the issuer's audit response.

**Residual risk.** Issuers that do not enforce uniqueness on `engagementId`. Mitigated by spec recommendation that issuers reject duplicates.

### 1.5 Capability scope creep

**Scenario.** A sales agent is asked to perform a procurement action it should not be able to perform.

**Mitigation.** `authority.scope` is an allowlist of `subject.verb` capability strings. Verifiers reject any inbound request whose intent is not covered by an entry in `scope`.

**Residual risk.** Coarse-grained scopes (e.g. `procurement.purchase` covering both stationery and enterprise software). Mitigated by issuer discipline. The spec does not enforce a granularity floor.

### 1.6 Audit log tampering

**Scenario.** A counterparty disputes the agreed price after delivery.

**Mitigation.** `authority.decisionAudit` returns a signed transcript. The issuer's signing key is the same key already used to sign the passport, so tampering is detectable using the same public key already in DNS.

**Residual risk.** Loss of the issuer's private key after an engagement is logged but before disputes arise. Mitigated by short key rotation cadence and by counterparties storing their own copy of the signed audit blob at receipt time.

## 2. Threats explicitly out of scope

### 2.1 Transport security

The spec assumes TLS for the HTTPS fetch of the passport and for any underlying agent-to-agent transport (A2A, MCP, REST). Defects in TLS or in the transport layer are not the passport's job to fix.

### 2.2 Human identity

A passport is an organisational claim, not a personal one. It does not assert that any specific human approved any specific message. Where personal accountability is required, the issuer's own internal systems (SSO, audit logging) are the source of truth.

### 2.3 Sub-agent delegation

A v0.1 passport authorises a single agent. Agents that themselves spawn sub-agents are responsible for ensuring their sub-agents do not exceed the parent's `authority` envelope. The spec may add an explicit `delegation` field in v0.2.

### 2.4 Cross-jurisdiction enforceability

A passport is a technical artifact. Whether the receiving party has a contractual right to rely on it for legal commitment is a question for the parties' standing terms of business. The spec recommends issuers link their `termsUrl` to a public agent-engagement terms document so this layer is explicit.

### 2.5 Side-channel intelligence

A counterparty can infer business signals (deal sizes, escalation paths, model choice) from a passport. That is by design. Issuers who consider any of these fields confidential should weigh that against the trust value of disclosure.

## 3. Compromise recovery

If a signing key is compromised:

1. Generate a new keypair with a new `keyId`.
2. Publish the new public key as a fresh DNS TXT record alongside the old one.
3. Re-sign all live passports with the new key, updating `signature.keyId`.
4. Add the old `keyId`'s active passports to `revocationListUrl`.
5. Wait one TTL period plus a buffer, then remove the old DNS TXT record.

Verifiers that follow §7 will start failing on the old key and succeeding on the new one within one DNS TTL. No flag day required.

## 4. Operational hardening recommendations

These are non-normative but recommended for issuers operating production passports:

- Rotate signing keys every 90 days.
- Use HSM-backed key storage for any agent that can commit above $10,000.
- Serve `/.well-known/agent-passport.json` from a CDN with HTTP cache headers shorter than 5 minutes, so revocation propagates faster than verifier caches.
- Monitor for unexpected counterparty domains hitting `decisionAudit` URL templates.
- Treat `agent.id` as a trust-bearing identifier and avoid reusing it after retiring an agent.
