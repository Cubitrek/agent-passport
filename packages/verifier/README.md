# @cubitrek/agent-passport-verifier

Reference verifier for the [Agent Passport spec, v0.1](https://cubitrek.com/blog/agent-passport).

Validates the JSON Schema, fetches the issuer's DNS-anchored Ed25519 public key, verifies the canonical-JSON signature, checks expiry, and consults the optional revocation list. Pure ESM, runs in Node 20+, Cloudflare Workers, and modern browsers.

## Install

```bash
npm install @cubitrek/agent-passport-verifier
```

## Usage

### Verify by domain

```typescript
import { verifyAgentPassport } from "@cubitrek/agent-passport-verifier";

const result = await verifyAgentPassport({
  domain: "acme.example",
});

if (!result.ok) {
  // Reject the inbound agent. The errors array describes why.
  console.error(result.errors);
  return;
}

const { passport } = result;

if (engagementValueUSD > passport.authority.spendCeiling.amount) {
  throw new Error("Engagement value exceeds passport spendCeiling, refuse.");
}

if (engagementValueUSD > passport.authority.humanInLoop.above.amount) {
  // Trigger your own human escalation, then notify the issuer's escalation
  // address with the agreed terms before locking the deal.
}
```

### Validate without verifying signatures (lint mode)

```typescript
import { validate } from "@cubitrek/agent-passport-verifier";

const passport = JSON.parse(file);
const result = validate(passport);

if (!result.ok) {
  console.error("Schema errors:", result.errors);
}
```

### Pass a parsed passport directly

```typescript
const result = await verifyAgentPassport({
  passport: parsedJson,
  resolveSignerPublicKey: { publicKeyB64: "MCowBQYDK2VwAyEA..." },
});
```

### Custom key resolver (cache, alternate registry, mTLS allow-list)

```typescript
const result = await verifyAgentPassport({
  domain: "acme.example",
  resolveSignerPublicKey: async ({ issuerDomain, keyId }) => {
    return await myKeyCache.get(`${issuerDomain}:${keyId}`);
  },
});
```

## API

### `verifyAgentPassport(options)`

Performs the full verification flow per spec §7.

```typescript
interface VerifyOptions {
  /** Either a domain (we fetch /.well-known/agent-passport.json) or a parsed passport object. */
  domain?: string;
  passport?: unknown;
  /** How to resolve the issuer's Ed25519 public key. Default "dns". */
  resolveSignerPublicKey?: SignerKeyResolver;
  /** Whether to fetch and check revocationListUrl. Default true. */
  checkRevocation?: boolean;
  /** AbortSignal forwarded to fetch calls. */
  signal?: AbortSignal;
  /** Override `now` for tests. */
  now?: () => Date;
}
```

Returns `{ ok: true, passport, warnings }` on success or `{ ok: false, errors, warnings, passport? }` on failure. Warnings cover non-fatal conditions (e.g. revocation list unreachable).

### `validate(value)`

JSON Schema validation only. Returns `{ ok: true, passport }` or `{ ok: false, errors }`. Does not check signature, expiry, or revocation.

### `canonicalize(passport)`

Returns the canonical UTF-8 bytes (and string) used for signing. Useful for issuers building a passport.

## Behaviour notes

- **DNS lookups** use Cloudflare's DNS-over-HTTPS by default so the verifier works in Cloudflare Workers and browsers without `node:dns`. Override by passing a custom `resolveSignerPublicKey` function.
- **Public key formats** accepted: raw 32-byte Ed25519 (base64) or DER SubjectPublicKeyInfo (base64). The verifier wraps raw keys to SPKI before calling `crypto.subtle.importKey`.
- **Canonical JSON** uses sorted-keys serialisation with no whitespace, matching the spec. Numbers, strings, booleans, and nulls are emitted as `JSON.stringify` does. The signing flow temporarily zeroes `signature.value` and restores it after.
- **No external network calls** are made by `validate()`. `verifyAgentPassport` makes at most three: the passport fetch, the DNS-over-HTTPS lookup, and the optional revocation list fetch.

## Versioning

Tracks the spec major.minor: `0.1.x` of this package targets spec v0.1. Major bumps will track spec major bumps.

## Licence

MIT. See [the repository LICENSE](https://github.com/cubitrek/agent-passport/blob/main/LICENSE).
