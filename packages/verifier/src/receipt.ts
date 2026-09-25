/**
 * Receipts: a durable, signable record that a decision was made and what
 * became of it.
 *
 * A receipt deliberately carries no payload. The tool name, the scope and
 * the amount are in it; the target and the arguments are not. What ties the
 * receipt to one exact call is the binding digest, which already covers all
 * of them. So a receipt can be handed to an auditor, a counterparty or a
 * customer without disclosing the account number that was paid or the
 * contents of the request, and anyone holding the original request can still
 * prove it is the one the receipt refers to by recomputing the digest.
 *
 * That is the property to keep when extending this type: nothing goes in a
 * receipt that the operator would not publish.
 */

import type { AuthorityOrigin, AuthoritySubject } from "./authority.js";
import type { AuthorizationRequest, AuthorizationResult, Decision } from "./authorize.js";
import type { VerificationError } from "./types.js";
import { canonicalJson } from "./canonical.js";
import { base64ToBytes, bytesToBase64Url } from "./encoding.js";

export const RECEIPT_CONTEXT = "agent-passport-receipt-v1";

export type ReceiptOutcome =
  /** The side effect ran and returned. */
  | "executed"
  /** The side effect did not run. */
  | "blocked"
  /** The side effect was attempted and the result was lost. */
  | "unknown";

export interface Receipt {
  version: "0.1.0";
  context: typeof RECEIPT_CONTEXT;
  id: string;
  at: string;
  subject: AuthoritySubject;
  origin: AuthorityOrigin[];
  request: {
    scope: string;
    /** The tool or operation name. Never its arguments or its target. */
    tool?: string;
    amount?: { amount: number; currency: string };
    counterpartyDomain?: string;
    region?: string;
    dataClassification?: string;
  };
  decision: Decision;
  /** Reason codes only, so a receipt cannot leak a value through prose. */
  reasons: string[];
  binding: { digest: string; nonce: string; expiresAt: string };
  outcome: ReceiptOutcome;
  /** Reason codes for a receipt whose outcome is not "executed". */
  blockedBecause?: string[];
  signature?: { alg: "ed25519"; keyId: string; value: string };
}

/** Somewhere receipts are kept: a file, a log, a queue, a table. */
export interface ReceiptSink {
  record(receipt: Receipt): void | Promise<void>;
}

export interface BuildReceiptOptions {
  outcome: ReceiptOutcome;
  /** The request this decision covered, for the scope and the tool name. */
  request: AuthorizationRequest;
  blockedBecause?: VerificationError[];
  now?: () => Date;
  id?: string;
}

/** A receipt for one decision and what became of it. */
export function buildReceipt(
  decision: AuthorizationResult,
  opts: BuildReceiptOptions,
): Receipt {
  const now = (opts.now ?? (() => new Date()))();
  const charge = decision.charge;
  return {
    version: "0.1.0",
    context: RECEIPT_CONTEXT,
    id: opts.id ?? crypto.randomUUID(),
    at: now.toISOString(),
    subject: decision.subject,
    origin: decision.origin,
    request: {
      scope: opts.request.scope,
      tool: opts.request.action?.tool,
      amount: charge ? { amount: charge.amount, currency: charge.currency } : undefined,
      counterpartyDomain: opts.request.counterpartyDomain,
      region: opts.request.region,
      dataClassification: opts.request.dataClassification,
    },
    decision: decision.decision,
    reasons: decision.reasons.map((r) => r.code),
    binding: {
      digest: decision.binding.digest,
      nonce: decision.binding.nonce,
      expiresAt: decision.binding.expiresAt,
    },
    outcome: opts.outcome,
    blockedBecause: opts.blockedBecause?.length
      ? opts.blockedBecause.map((r) => r.code)
      : undefined,
  };
}

function receiptBytes(receipt: Receipt): Uint8Array {
  const unsigned = { ...receipt, signature: receipt.signature ? { ...receipt.signature, value: "" } : undefined };
  return new TextEncoder().encode(canonicalJson(unsigned));
}

/** Sign a receipt with an Ed25519 key. The signature covers every field. */
export async function signReceipt(
  receipt: Receipt,
  signer: { keyId: string; privateKey: CryptoKey | Uint8Array },
): Promise<Receipt> {
  const key =
    signer.privateKey instanceof Uint8Array
      ? await crypto.subtle.importKey(
          "pkcs8",
          signer.privateKey as unknown as BufferSource,
          { name: "Ed25519" },
          false,
          ["sign"],
        )
      : signer.privateKey;
  const unsigned: Receipt = { ...receipt, signature: { alg: "ed25519", keyId: signer.keyId, value: "" } };
  const sig = await crypto.subtle.sign(
    "Ed25519",
    key,
    receiptBytes(unsigned) as unknown as BufferSource,
  );
  return { ...unsigned, signature: { alg: "ed25519", keyId: signer.keyId, value: bytesToBase64Url(new Uint8Array(sig)) } };
}

export type ReceiptVerification = { ok: true } | { ok: false; errors: VerificationError[] };

/** Check a receipt's signature against a raw 32-byte Ed25519 public key. */
export async function verifyReceipt(
  receipt: Receipt,
  publicKeyRaw: Uint8Array,
): Promise<ReceiptVerification> {
  if (!receipt.signature?.value) {
    return { ok: false, errors: [{ code: "receipt.unsigned", message: "The receipt carries no signature." }] };
  }
  if (receipt.context !== RECEIPT_CONTEXT) {
    return {
      ok: false,
      errors: [{ code: "receipt.wrong-context", message: `Not a receipt: context is ${String(receipt.context)}.` }],
    };
  }
  let signature: Uint8Array;
  try {
    signature = base64ToBytes(receipt.signature.value);
    if (signature.length !== 64) throw new Error("length");
  } catch {
    return {
      ok: false,
      errors: [{ code: "receipt.signature-malformed", message: "The signature is not 64 base64url bytes." }],
    };
  }
  const key = await crypto.subtle.importKey(
    "raw",
    publicKeyRaw as unknown as BufferSource,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "Ed25519",
    key,
    signature as unknown as BufferSource,
    receiptBytes(receipt) as unknown as BufferSource,
  );
  return valid
    ? { ok: true }
    : {
        ok: false,
        errors: [{ code: "receipt.signature-invalid", message: "The receipt was changed after it was signed." }],
      };
}
