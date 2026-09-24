# @cubitrek/agent-passport-verifier

Library, CLI and MCP server for the [Agent Passport spec, v0.1](https://github.com/Cubitrek/agent-passport/blob/main/spec/agent-passport-v0.1.md).

- **Verify** a passport: schema, the signing key inside the issuer's own DNS zone, the Ed25519 signature, the validity window and the revocation list.
- **Authorize** one request against it: allow, escalate to the issuer's human, or deny.
- **Issue and renew** passports without hand-editing JSON.
- **Health-check** a published passport, with a fix for every problem.
- **Connect AI assistants** through a four-tool MCP server.

The library is pure ESM and runs in Node 20+, Cloudflare Workers and modern browsers. The CLI and MCP server need Node.

```bash
npm install @cubitrek/agent-passport-verifier
```

> **Not on npm yet.** 0.1.2 publishes when the release workflow runs. Until then, clone this repository and run `npm install && npm run build` in `packages/verifier`, and call the CLI as `node packages/verifier/bin/agent-passport.mjs`.

## CLI

| Command | What it does |
| --- | --- |
| `agent-passport init` | Asks a few questions (or takes flags) and writes a signed passport, an empty revocation list and a private key, then prints the DNS record to add |
| `agent-passport renew <file> --key <pem>` | Re-dates and re-signs a passport, and confirms DNS carries the key |
| `agent-passport doctor <domain>` | Health check with fixes; exits 1 on any failure |
| `agent-passport verify <domain or file>` | Verifies and explains a passport in plain English |
| `agent-passport authorize <domain or file> --scope <s> [--amount <n>] [--tool <t> --target <id> --args <json>]` | Allow, escalate or deny, bound to the exact action; exits 0, 2 or 1 |
| `agent-passport keygen --kid <id> --out <pem>` | Generates a signing key and prints its TXT record |
| `agent-passport sign <file> --key <pem>` | Signs a passport file |
| `agent-passport mcp` | Runs the MCP server on stdio |

`agent-passport help <command>` lists every flag. `doctor`, `verify` and `authorize` take `--json`.

## Verify, then authorize

```typescript
import { authorize, checkExecution, memoryNonceStore, verifyAgentPassport } from "@cubitrek/agent-passport-verifier";

const verification = await verifyAgentPassport({ domain: "acme.example" });

const decision = await authorize(verification, {
  scope: "procurement.purchase",
  amount: { amount: 42_000, currency: "USD" },
  counterpartyDomain: "yourcompany.example",
  action: { tool: "orders.create", target: "sku-123", args: { quantity: 20 } },
});
// decision.decision is "allow", "escalate" or "deny".
// decision.reasons explains it; decision.escalation names the issuer's human.

// Immediately before the side effect, with the values about to be executed:
const nonceStore = memoryNonceStore(); // one per process; share one across machines
const check = await checkExecution(decision, finalRequest, { nonceStore });
if (!check.ok) throw new Error(check.errors.map((e) => e.code).join(", "));
```

### Bind the decision to the action

`authorize()` binds every decision to the exact request: a SHA-256 digest over the scope, amount, counterparty and the concrete tool, target and arguments, plus the passport identity, with a nonce and an expiry. Allow decisions last 60 seconds by default (`ttlSeconds`); an escalation lasts for the issuer's response window so the person's confirmation applies to this exact request.

`checkExecution()` recomputes the digest from the final values and refuses if anything changed, the decision expired, it was a deny, an escalation has no confirmation (`humanApproved`), or it was already used (with a `nonceStore`). `memoryNonceStore()` covers one process; executors on several machines need a shared store with an atomic insert, such as Redis `SET NX`.

The binding is unsigned, so it protects where the component that decides and the component that acts trust each other. Carrying a decision across organisations is a [v0.2 proposal](https://github.com/Cubitrek/agent-passport/blob/main/spec/proposals/execution-binding.md).

### What `verifyAgentPassport` proves

The business that controls `issuer.domain` published this authority envelope for `agent.id`, and it has not expired or been revoked. It does **not** prove that whoever is messaging you is that agent: the passport is a public file anyone can point to. Authenticate the caller as the issuer's agent through your transport (mutual TLS, an OAuth client registered to the issuer, or HTTP Message Signatures per RFC 9421) before acting on the passport's authority.

### Other ways to supply the passport and key

```typescript
// A passport you already have, with a pinned key instead of DNS.
await verifyAgentPassport({
  passport: parsedJson,
  resolveSignerPublicKey: { publicKeyB64: "MCowBQYDK2VwAyEA..." },
});

// Your own key source: a cache, a registry, an allow-list.
await verifyAgentPassport({
  domain: "acme.example",
  resolveSignerPublicKey: async ({ issuerDomain, keyId }) => myKeyCache.get(`${issuerDomain}:${keyId}`),
});

// Fail closed when the revocation list cannot be read.
await verifyAgentPassport({ domain: "acme.example", revocationFailure: "error" });
```

## Issue a passport from code

```typescript
import { draftAgentPassport, signAgentPassport, dnsTxtRecord } from "@cubitrek/agent-passport-verifier";

const draft = draftAgentPassport({
  domain: "acme.example",
  legalName: "Acme Corporation",
  agentName: "Acme Procurement Agent",
  role: "procurement",
  purpose: "Buys software licences for Acme within budget.",
  endpoints: { mcp: "https://agents.acme.example/mcp" },
  scopes: ["procurement.purchase", "procurement.negotiate"],
  spendCeiling: 50_000,
  humanAbove: 10_000,
  escalation: "procurement@acme.example",
});
const signed = await signAgentPassport(draft, privateKey); // CryptoKey or PKCS#8 DER bytes
const record = dnsTxtRecord({ keyId: draft.signature.keyId, publicKeyRaw }); // raw 32-byte public key
```

## Health-check a published passport

```typescript
import { diagnoseAgentPassport } from "@cubitrek/agent-passport-verifier";

const report = await diagnoseAgentPassport({ domain: "acme.example", warnDays: 14 });
for (const check of report.checks) {
  if (check.status !== "pass") console.log(check.status, check.title, check.detail, check.hint);
}
```

Checks: delivery without redirects, content type, CORS, cache lifetimes, schema, `issuer.domain`, key zone, DNS key, DNSSEC, signature, validity window and expiry runway, lifetime, spending thresholds, revocation list, and the logo, terms, contact and endpoint URLs. `report.ok` is false when any check fails; warnings do not change it.

## MCP server

```bash
claude mcp add agent-passport -- npx -y -p @cubitrek/agent-passport-verifier agent-passport mcp
```

| Tool | What it does |
| --- | --- |
| `verify_agent_passport` | Verifies a company's passport and explains it |
| `authorize_agent_action` | Allow, escalate or deny one request from that company's agent |
| `check_agent_passport_health` | Runs the health check |
| `draft_agent_passport` | Drafts a passport; never handles private keys |

Speaks MCP protocol versions 2024-11-05 through 2025-11-25 over stdio, with no dependencies.

## API

| Function | Returns |
| --- | --- |
| `verifyAgentPassport(options)` | `{ ok: true, passport, warnings }` or `{ ok: false, errors, warnings, passport? }`. A malformed passport produces errors, never an exception. |
| `authorize(verification, request, options?)` | Promise of `{ decision, allow, reasons, escalation?, agentId, issuerDomain, keyId, evaluatedAt, binding }` |
| `checkExecution(decision, finalRequest, options?)` | Promise of `{ ok: true }` or `{ ok: false, errors }` |
| `memoryNonceStore()` | A single-process `NonceStore` for `checkExecution` |
| `diagnoseAgentPassport(options)` | `{ ok, domain, url, checks, passport?, verification? }` |
| `describePassport(passport, now?)` | Plain-English summary |
| `draftAgentPassport(input)` | An unsigned, schema-valid passport |
| `signAgentPassport(passport, privateKey)` | A copy with `signature.value` set; set `signature.keyId` first |
| `dnsTxtRecord({ keyId, publicKeyRaw })` | The TXT record value |
| `validate(value)` | JSON Schema result only |
| `canonicalize(passport)`, `canonicalBytes(passport)` | The bytes that are signed (spec §5) |
| `fetchSigningKeys({ signingKeyDns })` | Parsed `v=ap1` records and whether DNSSEC validated them |
| `daysUntilExpiry(passport, now?)`, `defaultKeyId(domain)`, `guessEndpointType(url)`, `isoSeconds(date)` | Helpers |

`verifyAgentPassport` options: `domain` or `passport`; `resolveSignerPublicKey` (`"dns"`, `{ publicKeyB64 }` or a function); `checkRevocation` (default true); `revocationFailure` (`"warn"` or `"error"`); `timeoutMs` (default 10000); `signal`; `now`.

`authorize` request: `scope`; optional `amount`, `priorSpend`, `counterpartyDomain`, `counterpartyHasPassport`, `region`, `dataClassification`, and `action` (`tool`, `target`, `args`). Options: `ttlSeconds` (default 60), `now`.

`checkExecution` options: `humanApproved`, `nonceStore`, `now`.

## Result codes

Verification errors:

| Code | Meaning |
| --- | --- |
| `args.missing`, `args.invalid-domain` | Neither `domain` nor `passport` was given, or `domain` is not a bare hostname. |
| `fetch.failed`, `fetch.non-2xx`, `fetch.redirect`, `fetch.too-large` | The passport could not be fetched. Redirects are refused; the size limit is 256 KB. |
| `schema.*` | JSON Schema validation failed. |
| `issuer.domain-mismatch` | `issuer.domain` differs from the host the passport came from. |
| `issuer.signing-key-outside-domain` | `issuer.signingKeyDns` is not inside `issuer.domain`. |
| `time.issued-in-future`, `time.expired`, `time.window-inverted`, `time.unparseable` | The validity window is wrong. |
| `dns.fetch-failed`, `dns.fetch-non-2xx`, `dns.rcode`, `dns.no-records` | The key lookup failed. |
| `signer-key.no-matching-kid`, `signer-key.resolver-empty` | No key matches `signature.keyId`. |
| `signature.invalid` | The signature is malformed or does not verify. |
| `revocation.revoked` | `agent.id` is on the issuer's revocation list. |

Verification warnings (`ok` stays true):

| Code | Meaning |
| --- | --- |
| `dns.unauthenticated` | The key lookup was not DNSSEC-validated. |
| `time.lifetime-exceeds-recommended` | Valid for more than the recommended 90 days. |
| `authority.hil-above-ceiling` | `humanInLoop.above` exceeds `spendCeiling`, so no autonomous commitment ever reaches a human. |
| `authority.currency-mismatch` | The two thresholds use different currencies. |
| `revocation.fetch-failed`, `revocation.fetch-non-2xx`, `revocation.malformed` | The revocation list could not be read. Errors under `revocationFailure: "error"`. |

Authorization reasons:

| Code | Decision |
| --- | --- |
| `authority.within-envelope` | allow |
| `amount.above-human-threshold`, `amount.currency-unsupported`, `amount.cumulative-unknown` | escalate |
| `passport.unverified`, `scope.not-granted`, `amount.above-ceiling`, `counterparty.blocked`, `counterparty.not-allowlisted`, `counterparty.passport-required`, `region.not-cleared`, `data.classification-exceeds` | deny |

Execution checks (`checkExecution`):

| Code | Meaning |
| --- | --- |
| `execution.request-changed` | The final request differs from the one authorized: scope, amount, counterparty, tool, target or arguments. |
| `execution.expired` | The decision is past `binding.expiresAt`. Authorize the final request again. |
| `execution.denied` | The decision was a deny. |
| `execution.needs-human` | An escalation without `humanApproved`. |
| `execution.replayed` | The nonce store has already seen this decision. |
| `execution.unbound` | The decision has no binding. |

## Behaviour notes

- **DNS lookups** use Cloudflare's DNS-over-HTTPS by default, so verification works in Workers and browsers without `node:dns`.
- **Public key formats:** raw 32-byte Ed25519 or DER SubjectPublicKeyInfo, in base64 or base64url.
- **Canonical JSON** sorts keys by UTF-16 code unit with no whitespace and writes scalars as `JSON.stringify` does, which matches RFC 8785 (JCS) for well-formed passports.
- **Network calls:** `validate`, `authorize`, `describePassport` and `draftAgentPassport` make none. `verifyAgentPassport` makes at most three, each with a timeout.

## Versioning

`0.1.x` of this package targets spec v0.1. See the [changelog](https://github.com/Cubitrek/agent-passport/blob/main/CHANGELOG.md).

## Licence

MIT. See [LICENSE](./LICENSE).
