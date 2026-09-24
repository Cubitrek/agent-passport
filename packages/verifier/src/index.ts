/**
 * @cubitrek/agent-passport-verifier
 *
 * Reference verifier for the Agent Passport spec, v0.1.
 *
 *   import { verifyAgentPassport, validate } from "@cubitrek/agent-passport-verifier";
 *
 *   const result = await verifyAgentPassport({
 *     domain: "acme.example",
 *     resolveSignerPublicKey: "dns",
 *   });
 *
 *   if (!result.ok) console.error(result.errors);
 */

export { validate } from "./schema.js";
export { canonicalize, canonicalBytes } from "./canonical.js";
export { fetchSigningKeys } from "./dns.js";
export type { SigningKeyLookup, SigningKeyRecord } from "./dns.js";
export { dnsTxtRecord, signAgentPassport } from "./sign.js";
export { authorize, checkExecution, memoryNonceStore } from "./authorize.js";
export type {
  AuthorizationRequest,
  AuthorizationResult,
  AuthorizedAction,
  AuthorizeOptions,
  DataClassification,
  Decision,
  DecisionBinding,
  ExecutionCheckOptions,
  ExecutionCheckResult,
  NonceStore,
} from "./authorize.js";
export { daysUntilExpiry, describePassport } from "./describe.js";
export { defaultKeyId, draftAgentPassport, guessEndpointType, isoSeconds } from "./draft.js";
export type { EndpointType, PassportDraftInput } from "./draft.js";
export { diagnoseAgentPassport } from "./doctor.js";
export type {
  CheckStatus,
  DiagnoseOptions,
  DiagnoseResult,
  HealthCheck,
} from "./doctor.js";
export type * from "./types.js";

import type {
  AgentPassport,
  VerificationError,
  VerifyOptions,
  VerifyResult,
} from "./types.js";
import { validate } from "./schema.js";
import { canonicalBytes } from "./canonical.js";
import { fetchSigningKeys } from "./dns.js";
import { base64ToBytes } from "./encoding.js";
import { BodyTooLargeError, readJsonCapped, withTimeout } from "./http.js";

const WELL_KNOWN_PATH = "/.well-known/agent-passport.json";
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_PASSPORT_BYTES = 256 * 1024;
const MAX_REVOCATION_LIST_BYTES = 1024 * 1024;
const RECOMMENDED_MAX_LIFETIME_MS = 90 * 24 * 60 * 60 * 1000;
const HOSTNAME =
  /^(?=.{1,253}$)_?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\._?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

export async function verifyAgentPassport(
  opts: VerifyOptions,
): Promise<VerifyResult> {
  const errors: VerificationError[] = [];
  const warnings: VerificationError[] = [];
  const now = (opts.now ?? (() => new Date()))().getTime();
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  let fetchHost: string | undefined;
  if (opts.domain !== undefined) {
    const host = normalizeHost(opts.domain);
    if (!host) {
      return failure({
        code: "args.invalid-domain",
        message: `domain must be a bare hostname, got "${opts.domain}"`,
      });
    }
    fetchHost = host;
  }

  // 1. Get the passport JSON.
  let passportJson: unknown;
  if (opts.passport !== undefined) {
    passportJson = opts.passport;
  } else if (fetchHost) {
    const url = `https://${fetchHost}${WELL_KNOWN_PATH}`;
    try {
      const res = await fetch(url, {
        headers: { accept: "application/json" },
        redirect: "manual",
        signal: withTimeout(opts.signal, timeoutMs),
      });
      if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
        return failure({
          code: "fetch.redirect",
          message: `${url} redirected. The passport must be served directly by the issuer host.`,
          hint: res.headers.get("location") ?? undefined,
        });
      }
      if (!res.ok) {
        return failure({
          code: "fetch.non-2xx",
          message: `${url} returned HTTP ${res.status}`,
        });
      }
      passportJson = await readJsonCapped(res, MAX_PASSPORT_BYTES);
    } catch (err) {
      return failure({
        code: err instanceof BodyTooLargeError ? "fetch.too-large" : "fetch.failed",
        message: `Failed to fetch ${url}`,
        hint: errorMessage(err),
      });
    }
  } else {
    return failure({
      code: "args.missing",
      message: "Either domain or passport must be supplied",
    });
  }

  // 2. Schema validate.
  const v = validate(passportJson);
  if (!v.ok) {
    return { ok: false, errors: v.errors, warnings };
  }
  const passport: AgentPassport = v.passport;
  const issuerHost = normalizeHost(passport.issuer.domain);

  // 3. Issuer domain must match the host we fetched from, if we fetched.
  if (fetchHost && fetchHost !== issuerHost) {
    errors.push({
      code: "issuer.domain-mismatch",
      message: `Passport issuer.domain "${passport.issuer.domain}" does not match fetch host "${fetchHost}".`,
    });
  }

  // 4. The signing key must sit inside the issuer's own DNS zone. Without this
  //    anyone can name any issuer, publish a key in a zone they control, and sign.
  const keyHost = normalizeHost(passport.issuer.signingKeyDns);
  const keyInIssuerZone =
    issuerHost !== null &&
    keyHost !== null &&
    (keyHost === issuerHost || keyHost.endsWith(`.${issuerHost}`));
  if (!keyInIssuerZone) {
    errors.push({
      code: "issuer.signing-key-outside-domain",
      message: `issuer.signingKeyDns "${passport.issuer.signingKeyDns}" is not inside issuer.domain "${passport.issuer.domain}".`,
      hint: `Publish the key at _agent-passport.${passport.issuer.domain}`,
    });
  }

  // 5. Validity window.
  const issuedAt = Date.parse(passport.issuedAt);
  const expiresAt = Date.parse(passport.expiresAt);
  if (Number.isNaN(issuedAt) || Number.isNaN(expiresAt)) {
    errors.push({
      code: "time.unparseable",
      message: "Passport issuedAt or expiresAt cannot be parsed as a date.",
    });
  } else {
    if (issuedAt > now) {
      errors.push({
        code: "time.issued-in-future",
        message: `Passport issuedAt is in the future (${passport.issuedAt}).`,
      });
    }
    if (expiresAt <= now) {
      errors.push({
        code: "time.expired",
        message: `Passport expired at ${passport.expiresAt}.`,
      });
    }
    if (expiresAt <= issuedAt) {
      errors.push({
        code: "time.window-inverted",
        message: "Passport expiresAt is not after issuedAt.",
      });
    } else if (expiresAt - issuedAt > RECOMMENDED_MAX_LIFETIME_MS) {
      warnings.push({
        code: "time.lifetime-exceeds-recommended",
        message: "Passport lifetime exceeds the recommended 90 days (spec §4.8).",
      });
    }
  }

  // 6. Authority envelope consistency. Warnings, because the schema cannot express these.
  const { spendCeiling, humanInLoop } = passport.authority;
  if (humanInLoop.above.currency !== spendCeiling.currency) {
    warnings.push({
      code: "authority.currency-mismatch",
      message: `humanInLoop.above is in ${humanInLoop.above.currency} but spendCeiling is in ${spendCeiling.currency}, so the thresholds cannot be compared.`,
    });
  } else if (humanInLoop.above.amount > spendCeiling.amount) {
    warnings.push({
      code: "authority.hil-above-ceiling",
      message: "humanInLoop.above exceeds spendCeiling, so no autonomous commitment ever reaches a human.",
    });
  }

  // 7. Resolve the signer's key and verify the signature. Skipped when the key
  //    name is outside the issuer zone, so we never query a zone the issuer
  //    does not control.
  if (keyInIssuerZone) {
    const pk = await resolvePublicKey(passport, opts, timeoutMs, warnings);
    if (typeof pk !== "string") {
      errors.push(...pk);
    } else if (!(await verifyEd25519(passport, pk))) {
      errors.push({
        code: "signature.invalid",
        message: "Ed25519 signature does not verify against the resolved public key.",
        hint: "Confirm canonical-JSON serialisation matches the issuer's. Field order must be sorted; signature.value must be empty during signing.",
      });
    }
  }

  // 8. Revocation, once every other check has passed.
  if (errors.length === 0 && opts.checkRevocation !== false && passport.revocationListUrl) {
    const report = opts.revocationFailure === "error" ? errors : warnings;
    try {
      const res = await fetch(passport.revocationListUrl, {
        headers: { accept: "application/json" },
        signal: withTimeout(opts.signal, timeoutMs),
      });
      if (!res.ok) {
        report.push({
          code: "revocation.fetch-non-2xx",
          message: `revocationListUrl returned HTTP ${res.status}`,
        });
      } else {
        const list = await readJsonCapped(res, MAX_REVOCATION_LIST_BYTES);
        if (!Array.isArray(list)) {
          report.push({
            code: "revocation.malformed",
            message: "revocationListUrl did not return a JSON array",
          });
        } else if (list.includes(passport.agent.id)) {
          errors.push({
            code: "revocation.revoked",
            message: `Passport agent.id ${passport.agent.id} is on the issuer's revocation list.`,
          });
        }
      }
    } catch (err) {
      report.push({
        code: "revocation.fetch-failed",
        message: "Failed to fetch revocationListUrl",
        hint: errorMessage(err),
      });
    }
  }

  if (errors.length) return { ok: false, errors, warnings, passport };
  return { ok: true, passport, warnings };
}

async function resolvePublicKey(
  passport: AgentPassport,
  opts: VerifyOptions,
  timeoutMs: number,
  warnings: VerificationError[],
): Promise<string | VerificationError[]> {
  const strategy = opts.resolveSignerPublicKey ?? "dns";
  if (typeof strategy === "object" && "publicKeyB64" in strategy) {
    return strategy.publicKeyB64;
  }
  if (typeof strategy === "function") {
    const k = await strategy({
      issuerDomain: passport.issuer.domain,
      signingKeyDns: passport.issuer.signingKeyDns,
      keyId: passport.signature.keyId,
    });
    if (!k) {
      return [
        {
          code: "signer-key.resolver-empty",
          message: "Custom signer-key resolver returned null",
        },
      ];
    }
    return k;
  }
  // strategy === "dns"
  const lookup = await fetchSigningKeys({
    signingKeyDns: passport.issuer.signingKeyDns,
    signal: opts.signal,
    timeoutMs,
  });
  if (lookup.errors.length) return lookup.errors;
  const match = lookup.records.find(
    (r) => r.kid === passport.signature.keyId && r.alg === passport.signature.alg,
  );
  if (!match) {
    return [
      {
        code: "signer-key.no-matching-kid",
        message: `No DNS TXT record matches keyId="${passport.signature.keyId}" alg="${passport.signature.alg}"`,
      },
    ];
  }
  if (!lookup.authenticated) {
    warnings.push({
      code: "dns.unauthenticated",
      message: `The DNS answer for ${passport.issuer.signingKeyDns} was not DNSSEC-validated.`,
      hint: "Without DNSSEC the key is only as trustworthy as the resolver's path to the issuer's nameservers. Issuers should enable DNSSEC.",
    });
  }
  return match.pk;
}

async function verifyEd25519(
  passport: AgentPassport,
  publicKeyB64: string,
): Promise<boolean> {
  try {
    // Signatures and DNS keys are base64url per the spec; function resolvers
    // may return standard base64. base64ToBytes accepts both and throws on
    // anything else, which lands in the catch below.
    const sig = base64ToBytes(passport.signature.value);
    if (sig.length !== 64) return false;
    const key = await importEd25519PublicKey(base64ToBytes(publicKeyB64));
    // Cast to BufferSource: TS 5.7 distinguishes Uint8Array<ArrayBuffer> vs
    // <ArrayBufferLike>, but both arrays here are backed by fresh ArrayBuffers.
    return await crypto.subtle.verify(
      "Ed25519",
      key,
      sig as unknown as BufferSource,
      canonicalBytes(passport) as unknown as BufferSource,
    );
  } catch {
    return false;
  }
}

async function importEd25519PublicKey(bytes: Uint8Array): Promise<CryptoKey> {
  // A 32-byte value is a raw Ed25519 key and gets wrapped as SPKI; anything
  // else is treated as DER SubjectPublicKeyInfo.
  const data = bytes.length === 32 ? wrapEd25519Raw(bytes) : bytes;
  return crypto.subtle.importKey(
    "spki",
    data as unknown as BufferSource,
    { name: "Ed25519" },
    true,
    ["verify"],
  );
}

function wrapEd25519Raw(raw: Uint8Array): Uint8Array {
  // SubjectPublicKeyInfo prefix for Ed25519:
  //   30 2a 30 05 06 03 2b 65 70 03 21 00 <32 bytes>
  const prefix = new Uint8Array([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
  ]);
  const out = new Uint8Array(prefix.length + raw.length);
  out.set(prefix, 0);
  out.set(raw, prefix.length);
  return out;
}

function normalizeHost(value: string): string | null {
  const host = value.trim().toLowerCase().replace(/\.$/, "");
  return HOSTNAME.test(host) ? host : null;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function failure(error: VerificationError): VerifyResult {
  return { ok: false, errors: [error], warnings: [] };
}
