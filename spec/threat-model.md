# Agent Passport, v0.1: Threat model

This document expands the §8 summary in the canonical spec. It enumerates the failure modes Agent Passport is designed to defend against, the residual risks, and what is explicitly out of scope.

## 1. Threats addressed

### 1.1 Issuer impersonation

**Scenario.** A malicious party publishes a passport claiming to represent Acme Corp on a look-alike domain.

**Mitigation.** Verifiers fetch `/.well-known/agent-passport.json` from the apex domain claimed in `issuer.domain`. The domain serving the file must match the domain claimed inside the file. The signing public key is anchored in the DNS zone of that domain, which only the lawful operator of the domain can edit, and `issuer.signingKeyDns` must sit inside that zone (see 1.8).

**Residual risk.** Domain hijack via registrar compromise. Mitigated by short `expiresAt` lifetimes and aggressive revocation lists. A valid passport also does not, on its own, bind a live caller to the agent it describes (see 1.7).

### 1.2 Authority escalation

**Scenario.** A leaked agent credential is used to commit a $500,000 engagement on behalf of Acme, far above what Acme would actually authorise.

**Mitigation.** `authority.spendCeiling` is the autonomous ceiling. Any verifier processing an inbound engagement must reject or escalate engagements above the value declared in the passport. `humanInLoop` defines a strictly lower threshold above which a human is paged before the agent can commit.

**Residual risk.** A correctly-spent engagement that is fraudulent (leaked credentials used for a $5,000 purchase that the agent legitimately could authorise). Out of scope for the passport spec. Mitigated by the issuer's own internal anomaly detection.

### 1.3 Stale or revoked authority

**Scenario.** An agent is decommissioned but its credentials remain in circulation.

**Mitigation.** Every passport carries `expiresAt`. Verifiers must reject expired passports. `revocationListUrl` is an optional out-of-band fast revocation channel.

**Residual risk.** Verifiers that cache the passport without re-checking the revocation list, or that pass when the list is unreachable. Spec §7 step 9 requires a revocation check for any engagement at or above the verifier's human-in-the-loop threshold, with an unreachable list treated as a failure. The reference verifier does this with `revocationFailure: "error"`.

### 1.4 Replay across counterparties

**Scenario.** A receiving agent records an engagement and replays it to a third party to extract value twice.

**Mitigation.** Each engagement is identified by an `engagementId` chosen by the receiver. A replay surfaces as a duplicate `engagementId` against the same agent in the issuer's audit response. v0.1 does not yet define that response's format or signature (spec §10), so today the check depends on each issuer's own records.

**Residual risk.** Issuers that do not enforce uniqueness on `engagementId`. Mitigated by spec recommendation that issuers reject duplicates.

### 1.5 Capability scope creep

**Scenario.** A sales agent is asked to perform a procurement action it should not be able to perform.

**Mitigation.** `authority.scope` is an allowlist of `subject.verb` capability strings. Verifiers reject any inbound request whose intent is not covered by an entry in `scope`.

**Residual risk.** Coarse-grained scopes (e.g. `procurement.purchase` covering both stationery and enterprise software). Mitigated by issuer discipline. The spec does not enforce a granularity floor.

### 1.6 Audit log tampering

**Scenario.** A counterparty disputes the agreed price after delivery.

**Mitigation.** Partial in v0.1. `authority.decisionAudit` names where the issuer keeps the transcript, but the spec does not yet define the response format or how it is signed (spec §10). Until it does, a transcript is only as trustworthy as the issuer's own system, and counterparties should keep their own copy of every agreed term at receipt time. When the format lands, audit signatures should use a context string distinct from passport signatures, so a signature made for one can never be accepted as the other.

**Residual risk.** Disputes that rest on the issuer's record alone. Once audit signing exists, loss of the issuer's private key after an engagement is logged but before a dispute arises; mitigated by short key rotation and by counterparties storing the signed record at receipt.

### 1.7 Caller impersonation with a genuine passport

**Scenario.** An attacker contacts Globex, claims to be Acme's procurement agent, and points to Acme's real, valid passport at `acme.example`.

**Mitigation.** None inside the passport. The passport is a public file, so verifying it proves what Acme authorised, not who is calling. v0.1 requires the verifier to authenticate the caller as Acme's agent through the transport (spec §7, "What verification proves"): mutual TLS, an OAuth client registered to Acme's domain, or HTTP Message Signatures (RFC 9421) with a key Acme publishes.

**Residual risk.** High for any deployment that treats "passport verified" as "caller verified". Request signing bound to the passport is planned for v0.2.

### 1.8 Signing key published outside the issuer's zone

**Scenario.** An attacker writes a passport naming `acme.example` as issuer, sets `issuer.signingKeyDns` to `_agent-passport.attacker.example`, publishes their own key there, signs, and presents the passport directly in an inbound message.

**Mitigation.** `signingKeyDns` must be inside `issuer.domain` (spec §4.2), and verifiers reject the passport before querying any other name (spec §7 step 5). The reference verifier enforces this from 0.1.2 with the error `issuer.signing-key-outside-domain`. Versions 0.1.1 and earlier accepted such passports.

**Residual risk.** Third-party verifiers written against the earlier spec text, which implied the check without stating it. Spec §9 now lists it as a conformance requirement.

### 1.9 Action substitution between authorization and execution

**Scenario.** A request is authorized for one action, say 20 units of SKU 123 for $4,000, and the target or arguments change before the side effect happens: a bug, a race, an injected prompt that edits the tool call, or a compromised component between the check and the executor.

**Mitigation.** Spec §7 step 10 applies at the moment of the side effect. The reference library binds each decision to a SHA-256 digest of the exact request (scope, amount, counterparty, tool, target and arguments) and of the passport identity it was checked against, with a nonce and an expiry: 60 seconds by default, or the issuer's response window for an escalation. `checkExecution()` recomputes the digest from the final values and refuses on any change, after expiry, for a deny, for an escalation no person confirmed, and on reuse when given a nonce store.

**Residual risk.** The binding is unsigned, so it protects only where the component that decides and the component that acts trust each other, usually within one system. Carrying a decision across a boundary needs a signed receipt (proposal: [`proposals/execution-binding.md`](./proposals/execution-binding.md)). Single use is only as strong as the nonce store: a per-process store does not cover executors spread across machines.

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
2. Publish the new public key as a fresh DNS TXT record alongside the old one, and wait one TTL so resolvers see it.
3. Re-issue every live passport under a new `agent.id` revision (for example `-v2` becomes `-v3`), signed with the new key.
4. Add the old `agent.id` values to `revocationListUrl`. Revocation is keyed on `agent.id`, so re-signing under the old id and then revoking it would revoke the replacement as well.
5. Remove the old DNS TXT record. Anything signed with the compromised key stops verifying once cached answers expire, including at verifiers that skip the revocation list.

Verifiers that follow §7 fail on the old passports and succeed on the new ones within one DNS TTL. No flag day required.

## 4. Operational hardening recommendations

These are non-normative but recommended for issuers operating production passports:

- Rotate signing keys every 90 days.
- Use HSM-backed key storage for any agent that can commit above $10,000.
- Serve `/.well-known/agent-passport.json` from a CDN with HTTP cache headers shorter than 5 minutes, so revocation propagates faster than verifier caches. Keep `stale-while-revalidate` short too: a long value lets a CDN keep serving a superseded passport long after `max-age` has passed.
- Enable DNSSEC on the issuer zone. Without it the key lookup is only as trustworthy as the resolver's path to your nameservers; the reference verifier warns with `dns.unauthenticated`.
- Monitor your own passport: run `agent-passport verify <your-domain>` on a schedule and alert on a non-zero exit well before `expiresAt`.
- Monitor for unexpected counterparty domains hitting `decisionAudit` URL templates.
- Treat `agent.id` as a trust-bearing identifier and avoid reusing it after retiring an agent.
