# Changelog

Covers the spec text, the JSON Schema, and `@cubitrek/agent-passport-verifier`.

## 0.1.2 (unreleased)

### Security

- **The verifier now rejects passports whose `issuer.signingKeyDns` is outside `issuer.domain`** (`issuer.signing-key-outside-domain`). Earlier versions fetched the key from whatever DNS name the passport gave. Anyone could write a passport naming any company as issuer, publish a key in a zone they control, sign it, and get `ok: true`. The spec already made domain ownership the root of trust (§2, threat model §1.1); §4.2 and §7 now state the requirement explicitly.
- A malformed `signature.value` now returns `signature.invalid` instead of throwing.
- Passport fetches no longer follow redirects (`fetch.redirect`), are capped at 256 KB (`fetch.too-large`), and every network call times out after 10 seconds by default (`timeoutMs`).

### Added

- `signAgentPassport()` and `dnsTxtRecord()` for issuers, and an `agent-passport` CLI.
- `agent-passport init`: answer a few questions (or pass flags) and get a signed passport, an empty revocation list, a private key stored outside the public folder, and the exact DNS record to add.
- `agent-passport renew`: re-date and re-sign a passport in place, and confirm DNS carries the key.
- `agent-passport doctor` and `diagnoseAgentPassport()`: up to 21 health checks on a published passport (delivery, CORS, caching, DNS key, DNSSEC, signature, expiry runway, lifetime, thresholds, revocation list, linked URLs), each problem with a fix.
- `agent-passport authorize` and `authorize()`: allow, escalate or deny one request against the authority envelope (scope, spend ceiling and human threshold, cumulative ceilings, counterparty rules, regions, data classification), with the issuer's human contact on anything but allow. Exit codes 0, 2 and 1.
- Caller binding. An issuer can publish its agent's request-signing keys in the passport (`agent.requestKeys`); the agent signs each request with HTTP Message Signatures (RFC 9421) through `signAgentRequest()`, and the receiver checks it with `verifyAgentCaller()` before acting. Signatures cover method, authority, path, query and the body digest, expire in 60 seconds by default, and can be made single-use. The CLI gains `request-key` and `init --request-key`. The signature base is checked against RFC 9421's own ed25519 example in the tests. See `spec/proposals/caller-binding.md`.
- Execution binding. `authorize()` returns a `binding` with every decision: a SHA-256 digest of the exact request (scope, amount, counterparty, and the concrete tool, target and arguments) and of the passport identity, plus a nonce and an expiry (60 seconds by default, the issuer's response window for an escalation). `checkExecution()` runs immediately before the side effect and refuses if anything changed, the decision expired, it was a deny, an escalation lacks a person's confirmation, or (with a nonce store) it was already used. `memoryNonceStore()` gives single use within one process. `authorize()` is now async. The CLI takes `--tool`, `--target`, `--args` and `--ttl`; the MCP tool takes `tool`, `target` and `arguments`.
- `describePassport()`: a plain-English reading of a passport, now the default output of `verify`.
- `draftAgentPassport()`: a complete, schema-valid passport from plain answers.
- `agent-passport mcp`: an MCP server over stdio with four tools (`verify_agent_passport`, `authorize_agent_action`, `check_agent_passport_health`, `draft_agent_passport`). No dependencies; tested against the official MCP SDK client 1.30.0. It never handles private keys.
- `--public-key` on `verify` and `authorize` to pin an issuer key instead of using DNS.
- A GitHub Action (`action.yml`) that runs the health check on a schedule and writes a job summary.
- Spec: §7 step 10 now defines the allow, escalate and deny outcomes and must hold at the moment of the side effect; threat model §1.9 covers action substitution; new proposals for third-party attestations (`spec/proposals/attestations.md`) and signed decision receipts (`spec/proposals/execution-binding.md`).
- `revocationFailure: "error"` to fail closed when the revocation list cannot be read.
- Warnings: `dns.unauthenticated` (key lookup not DNSSEC-validated), `time.lifetime-exceeds-recommended` (over 90 days), `authority.hil-above-ceiling`, `authority.currency-mismatch`.
- End-to-end tests for signing, tampering, key-zone forgery, expiry, revocation, redirects, oversized responses and the CLI.
- `SECURITY.md`, this changelog, Dependabot, and a tag-driven npm release workflow with provenance.

### Changed

- Domain comparison ignores case and a trailing dot.
- Canonical JSON, used for signing and for request digests, refuses values with no unambiguous JSON form (Dates, NaN, bigints) instead of writing them as `{}` or `null`.
- Schema: `authority.decisionAudit` must contain `{engagementId}`, as the spec already required.
- DNS-over-HTTPS answers with a failing RCODE are reported as `dns.rcode`.
- The revocation list is only fetched once every other check has passed.
- Spec: v0.1 is one agent per document (the schema never accepted the array form §3 described); revocation is required at or above the verifier's human-in-the-loop threshold; the compromise-recovery steps now issue new `agent.id` values, since revoking an id also revokes its re-signed passport; new threat-model entries for caller binding and key-zone forgery; A2A examples use `/.well-known/agent-card.json`.

## 0.1.1 (git only, not published to npm)

- Decode the DNS `pk` value as base64url.

## 0.1.0 (git only, not published to npm)

- Initial spec draft, JSON Schema and reference verifier.
