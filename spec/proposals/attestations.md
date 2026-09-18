# Proposal: third-party attestations

**Status:** Proposal for v0.2. Not part of v0.1. Under v0.1 an `attestations` field is an unknown top-level field, which verifiers ignore.

## Problem

A passport tells a counterparty what the issuer authorised. It says nothing about whether the agent behind it has been tested: whether it resists prompt injection, leaks data, or brings in a human when it should. Enterprise buyers now ask for exactly that. Workday's Agent Passport (announced June 2026) records results from independent testing partners against OWASP LLM Top 10, NIST AI RMF and MITRE ATLAS, inside Workday's own system of record.

This proposal brings the same idea to an open, self-hosted passport. The tester signs its result with a key anchored in the tester's own DNS, using the same mechanism the issuer already uses. Nobody has to trust a central registry.

## Shape

An optional top-level `attestations` array. Each entry:

```json
{
  "type": "security-test",
  "standard": "OWASP-LLM-TOP-10-2025",
  "claim": "No successful prompt injection or system prompt extraction across the tester's published suite.",
  "result": "pass",
  "evidenceUrl": "https://tester.example/reports/acme-procurement-v3",
  "subject": { "issuerDomain": "acme.example", "agentId": "acme.example:procurement-v3" },
  "attester": {
    "domain": "tester.example",
    "legalName": "Tester Ltd",
    "signingKeyDns": "_agent-passport.tester.example",
    "keyId": "tester-2026-q3"
  },
  "issuedAt": "2026-09-01T00:00:00Z",
  "expiresAt": "2026-12-01T00:00:00Z",
  "signature": { "alg": "ed25519", "value": "<base64url>" }
}
```

| Field | Required | Notes |
| --- | --- | --- |
| `type` | yes | `security-test`, `compliance-audit`, `performance-benchmark`, `bias-evaluation`, or another agreed value. |
| `standard` | yes | Identifier of the public standard or test suite the claim is measured against. |
| `claim` | yes | One testable sentence. |
| `result` | yes | `pass`, `partial` or `fail`. |
| `evidenceUrl` | no | Where the full report lives. May require authentication. |
| `subject` | yes | Binds the attestation to one agent. Verifiers reject it when `issuerDomain` or `agentId` differ from the passport. |
| `attester` | yes | Same key rules as the issuer: `signingKeyDns` must be inside `attester.domain` (spec §4.2). |
| `issuedAt`, `expiresAt` | yes | Attestations expire on their own schedule; 90 days or less forces regular re-testing. |
| `signature` | yes | The attester's Ed25519 signature, described below. |

## Signing

1. Set `signature.value` to `""`.
2. Canonicalise the entry exactly as spec §5 does for a passport.
3. Sign the UTF-8 bytes of `agent-passport-attestation-v1\n` followed by the canonical JSON.

The context prefix means an attestation signature can never be accepted as a passport signature or the reverse, even when one party signs both (threat model §1.6).

The issuer then adds the entry to its passport and re-signs. The issuer's signature covers the array, so a signed copy cannot have an attestation added or removed without the issuer's key.

## Verification

For each entry, a verifier:

1. Confirms `subject` matches the passport's `issuer.domain` and `agent.id`.
2. Confirms `attester.signingKeyDns` is inside `attester.domain`.
3. Resolves the attester's TXT record and picks the entry matching `attester.keyId`.
4. Verifies the signature over the prefixed canonical bytes.
5. Checks `issuedAt` and `expiresAt`.

Each attestation is reported separately as verified, expired or invalid. A bad attestation never invalidates the passport itself. The receiver's policy decides what to require, for example `authorize()` gaining a `requireAttestations: ["OWASP-LLM-TOP-10-2025"]` option that escalates when a verified, unexpired `pass` is missing.

## Continuous monitoring

An attestation is a point-in-time result. Pair it with monitoring of the live passport: `agent-passport doctor` on a schedule, or the repository's GitHub Action, fails loudly on expiry, key or signature problems before counterparties notice.

## Open questions

- A shared registry of `standard` identifiers, or free text with conventions?
- Should `fail` results be publishable, or only omitted?
- Should attesters publish their own revocation list for withdrawn results?
- How should an attestation bound to `agent.id` carry over when the id is bumped after a key compromise?
