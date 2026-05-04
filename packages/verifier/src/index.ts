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

const WELL_KNOWN_PATH = "/.well-known/agent-passport.json";

export async function verifyAgentPassport(
  opts: VerifyOptions,
): Promise<VerifyResult> {
  const errors: VerificationError[] = [];
  const warnings: VerificationError[] = [];
  const now = (opts.now ?? (() => new Date()))();

  // 1. Get the passport JSON.
  let passportJson: unknown;
  if (opts.passport !== undefined) {
    passportJson = opts.passport;
  } else if (opts.domain) {
    const url = `https://${opts.domain}${WELL_KNOWN_PATH}`;
    try {
      const res = await fetch(url, { signal: opts.signal });
      if (!res.ok) {
        return failure(errors, [
          {
            code: "fetch.non-2xx",
            message: `${url} returned HTTP ${res.status}`,
          },
        ]);
      }
      passportJson = await res.json();
    } catch (err) {
      return failure(errors, [
        {
          code: "fetch.failed",
          message: `Failed to fetch ${url}`,
          hint: err instanceof Error ? err.message : String(err),
        },
      ]);
    }
  } else {
    return failure(errors, [
      {
        code: "args.missing",
        message: "Either domain or passport must be supplied",
      },
    ]);
  }

  // 2. Schema validate.
  const v = validate(passportJson);
  if (!v.ok) {
    return { ok: false, errors: v.errors, warnings };
  }
  const passport: AgentPassport = v.passport;

  // 3. Issuer domain must match the host we fetched from, if we fetched.
  if (opts.domain && opts.domain !== passport.issuer.domain) {
    errors.push({
      code: "issuer.domain-mismatch",
      message: `Passport issuer.domain "${passport.issuer.domain}" does not match fetch host "${opts.domain}".`,
    });
  }

  // 4. Validity window.
  const issuedAt = new Date(passport.issuedAt);
  const expiresAt = new Date(passport.expiresAt);
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

  // 5. Resolve the signer's public key.
  const pk = await resolvePublicKey(passport, opts);
  if (typeof pk === "string") {
    // 6. Verify the signature.
    const sigOk = await verifyEd25519(passport, pk);
    if (!sigOk) {
      errors.push({
        code: "signature.invalid",
        message: "Ed25519 signature does not verify against the resolved public key.",
        hint: "Confirm canonical-JSON serialisation matches the issuer's. Field order must be sorted; signature.value must be empty during signing.",
      });
    }
  } else {
    errors.push(...pk);
  }

  // 7. Optional: revocation check.
  const checkRevocation = opts.checkRevocation !== false;
  if (
    checkRevocation &&
    passport.revocationListUrl &&
    !errors.some((e) => e.code === "signature.invalid")
  ) {
    try {
      const r = await fetch(passport.revocationListUrl, { signal: opts.signal });
      if (r.ok) {
        const list = (await r.json()) as unknown;
        if (Array.isArray(list) && list.includes(passport.agent.id)) {
          errors.push({
            code: "revocation.revoked",
            message: `Passport agent.id ${passport.agent.id} is on the issuer's revocation list.`,
          });
        }
      } else {
        warnings.push({
          code: "revocation.fetch-non-2xx",
          message: `revocationListUrl returned ${r.status}; skipping`,
        });
      }
    } catch (err) {
      warnings.push({
        code: "revocation.fetch-failed",
        message: "Failed to fetch revocationListUrl; skipping",
        hint: err instanceof Error ? err.message : String(err),
      });
    }
  }

  if (errors.length) return { ok: false, errors, warnings, passport };
  return { ok: true, passport, warnings };
}

async function resolvePublicKey(
  passport: AgentPassport,
  opts: VerifyOptions,
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
  const { records, errors } = await fetchSigningKeys({
    signingKeyDns: passport.issuer.signingKeyDns,
    signal: opts.signal,
  });
  if (errors.length) return errors;
  const match = records.find(
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
  return match.pk;
}

async function verifyEd25519(
  passport: AgentPassport,
  publicKeyB64: string,
): Promise<boolean> {
  const bytes = canonicalBytes(passport);
  const sig = base64UrlDecode(passport.signature.value);
  if (sig.length === 0) return false;
  try {
    const pkBytes = base64ToBytes(publicKeyB64);
    const key = await importEd25519PublicKey(pkBytes);
    // Cast to BufferSource: TS 5.7 distinguishes Uint8Array<ArrayBuffer> vs
    // <ArrayBufferLike>, but at runtime any TypedArray over an ArrayBuffer
    // satisfies the WebCrypto API. The arrays here are always backed by
    // fresh ArrayBuffers (canonicalBytes via TextEncoder, base64UrlDecode
    // via new Uint8Array(...)).
    return await crypto.subtle.verify(
      "Ed25519",
      key,
      sig as unknown as BufferSource,
      bytes as unknown as BufferSource,
    );
  } catch {
    return false;
  }
}

async function importEd25519PublicKey(bytes: Uint8Array): Promise<CryptoKey> {
  // Accept either a raw 32-byte Ed25519 public key or a DER SubjectPublicKeyInfo.
  // We try SPKI first (more common in production), fall back to raw.
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

function base64UrlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  return base64ToBytes(b64);
}

function base64ToBytes(s: string): Uint8Array {
  const cleaned = s.replace(/\s+/g, "");
  if (typeof atob === "function") {
    const bin = atob(cleaned);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return Uint8Array.from(Buffer.from(cleaned, "base64"));
}

function failure(
  errors: VerificationError[],
  added: VerificationError[],
): VerifyResult {
  return { ok: false, errors: [...errors, ...added], warnings: [] };
}
