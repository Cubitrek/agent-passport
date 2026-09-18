/**
 * Issuer-side helpers: sign a passport, and format the DNS TXT record that
 * publishes its public key.
 */

import type { AgentPassport } from "./types.js";
import { canonicalBytes } from "./canonical.js";
import { bytesToBase64Url } from "./encoding.js";

/**
 * Sign a passport per spec §5 and return a copy with `signature.value` set.
 * `privateKey` is a WebCrypto Ed25519 CryptoKey or PKCS#8 DER bytes.
 * Set `signature.keyId` first: it is covered by the signature.
 */
export async function signAgentPassport(
  passport: AgentPassport,
  privateKey: CryptoKey | Uint8Array,
): Promise<AgentPassport> {
  const key =
    privateKey instanceof Uint8Array
      ? await crypto.subtle.importKey(
          "pkcs8",
          privateKey as unknown as BufferSource,
          { name: "Ed25519" },
          false,
          ["sign"],
        )
      : privateKey;
  const sig = await crypto.subtle.sign(
    "Ed25519",
    key,
    canonicalBytes(passport) as unknown as BufferSource,
  );
  const signed = structuredClone(passport) as AgentPassport;
  signed.signature = {
    ...signed.signature,
    value: bytesToBase64Url(new Uint8Array(sig)),
  };
  return signed;
}

/** TXT record value (spec §6) for a raw 32-byte Ed25519 public key. */
export function dnsTxtRecord(args: {
  keyId: string;
  publicKeyRaw: Uint8Array;
}): string {
  if (args.publicKeyRaw.length !== 32) {
    throw new TypeError("publicKeyRaw must be the raw 32-byte Ed25519 public key");
  }
  if (!args.keyId || /[;\s"]/.test(args.keyId)) {
    throw new TypeError("keyId must be non-empty with no spaces, quotes or semicolons");
  }
  return `v=ap1; kid=${args.keyId}; alg=ed25519; pk=${bytesToBase64Url(args.publicKeyRaw)}`;
}
