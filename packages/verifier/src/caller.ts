/**
 * Caller binding: tie the party making a request to the agent a passport
 * describes.
 *
 * A passport is public, so verifying one proves what a company authorised,
 * not who is calling. The issuer closes that gap by listing the agent's
 * request-signing keys in the passport it already signs
 * (`agent.requestKeys`). The agent signs every request with one of those
 * keys, and the receiver checks the signature against the list.
 *
 *   issuer's DNS key -> passport signature -> agent request key -> request
 *
 * Nothing extra has to be published: the chain hangs off the passport, which
 * is already anchored in the issuer's DNS.
 */

import type { AgentPassport, PassportRequestKey, VerificationError } from "./types.js";
import type { NonceStore } from "./authorize.js";
import {
  signHttpRequest,
  verifyHttpRequest,
  type SignableRequest,
  type SignedRequestHeaders,
} from "./http-signature.js";
import { bytesToBase64Url } from "./encoding.js";

/** Signatures made for Agent Passport carry this tag, so a receiver can tell them apart. */
export const CALLER_SIGNATURE_TAG = "agent-passport";

/** Method, authority, path and query are always covered; a body adds content-digest. */
export const CALLER_REQUIRED_COMPONENTS = ["@method", "@authority", "@path", "@query"];

export interface SignAgentRequestOptions {
  keyId: string;
  /** PKCS#8 DER bytes or a WebCrypto Ed25519 private key. Never the passport signing key. */
  privateKey: Uint8Array | CryptoKey;
  /** Default 60. Keep it short: the signature is per request. */
  expiresInSeconds?: number;
  created?: Date;
  nonce?: string;
}

export interface VerifyAgentCallerOptions {
  now?: () => Date;
  /** Enforces single use of each signed request. */
  nonceStore?: NonceStore;
  /** Longest signature lifetime accepted, in seconds. Default 300. */
  maxAgeSeconds?: number;
  clockSkewSeconds?: number;
}

export type AgentCallerResult =
  | { ok: true; keyId: string; nonce?: string }
  | { ok: false; errors: VerificationError[] };

/**
 * Sign an outgoing request as the agent. Returns the headers to send:
 * `Signature-Input`, `Signature`, and `Content-Digest` when there is a body.
 */
export function signAgentRequest(
  request: SignableRequest,
  opts: SignAgentRequestOptions,
): Promise<SignedRequestHeaders> {
  return signHttpRequest(request, {
    keyId: opts.keyId,
    privateKey: opts.privateKey,
    expiresInSeconds: opts.expiresInSeconds,
    created: opts.created,
    nonce: opts.nonce,
    tag: CALLER_SIGNATURE_TAG,
  });
}

/**
 * Check that an inbound request was signed by one of the keys this passport
 * publishes. Run it after verifying the passport and before authorizing the
 * action.
 */
export async function verifyAgentCaller(
  request: SignableRequest,
  passport: AgentPassport,
  opts: VerifyAgentCallerOptions = {},
): Promise<AgentCallerResult> {
  const keys = passport.agent.requestKeys ?? [];
  if (!keys.length) {
    return {
      ok: false,
      errors: [
        {
          code: "caller.no-request-keys",
          message: `${passport.agent.id} publishes no request-signing keys, so an inbound call cannot be tied to it.`,
          hint: "Ask the issuer to add agent.requestKeys to its passport, or bind the caller another way, such as mutual TLS or an OAuth client registered to the issuer.",
        },
      ],
    };
  }

  const result = await verifyHttpRequest(request, {
    resolveKey: (keyId, alg) =>
      keys.find((k) => k.keyId === keyId && k.alg === alg)?.publicKey ?? null,
    requireTag: CALLER_SIGNATURE_TAG,
    requiredComponents: CALLER_REQUIRED_COMPONENTS,
    now: opts.now,
    nonceStore: opts.nonceStore,
    maxAgeSeconds: opts.maxAgeSeconds,
    clockSkewSeconds: opts.clockSkewSeconds,
  });
  if (!result.ok) return result;
  return { ok: true, keyId: result.keyId, nonce: result.nonce };
}

/** The entry an issuer puts in `agent.requestKeys` for a raw 32-byte public key. */
export function requestKeyEntry(args: {
  keyId: string;
  publicKeyRaw: Uint8Array;
}): PassportRequestKey {
  if (args.publicKeyRaw.length !== 32) {
    throw new TypeError("publicKeyRaw must be the raw 32-byte Ed25519 public key");
  }
  if (!args.keyId || /[\s"]/.test(args.keyId)) {
    throw new TypeError("keyId must be non-empty with no spaces or quotes");
  }
  return { keyId: args.keyId, alg: "ed25519", publicKey: bytesToBase64Url(args.publicKeyRaw) };
}
