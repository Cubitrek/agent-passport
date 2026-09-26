/**
 * The approval channel: how an escalation stops being a dead end.
 *
 * Until now a decision that needed a person could only be refused, with a name
 * attached. That is fine for an assistant someone is watching and useless for
 * anything running on its own. Here a refused call leaves a request behind, a
 * person answers it out of band, and the same call goes through next time.
 *
 * What ties the two halves together is the decision digest, which is derived
 * from the subject, the authority and the exact request, and from nothing
 * else. Two runs of the same call produce the same digest; changing the
 * amount, the target or an argument produces a different one. So an approval
 * is for one exact call and cannot be spent on a different one, and none of
 * that relies on trusting whatever is asking.
 *
 * Who may approve is the other half, and the reason signatures are here. An
 * agent that can run a shell can also run the approve command, so on anything
 * unattended the answer has to be something the agent does not hold. A policy
 * that names `approvers` accepts only approvals signed by one of those keys.
 */

import type { AuthorityOrigin, AuthoritySubject } from "./authority.js";
import type { AuthorizationRequest, AuthorizationResult } from "./authorize.js";
import type { VerificationError } from "./types.js";
import { canonicalJson } from "./canonical.js";
import { base64ToBytes, bytesToBase64Url } from "./encoding.js";

export const APPROVAL_CONTEXT = "agent-passport-approval-v1";

/** A public key allowed to answer. Named in the policy, never in the file. */
export interface ApproverKey {
  keyId: string;
  alg: "ed25519";
  /** Raw 32-byte Ed25519 public key, base64url, unpadded. */
  publicKey: string;
}

/**
 * A call that stopped and is waiting for an answer.
 *
 * Unlike a receipt this does carry the request in full, arguments and all.
 * Nobody can approve what they cannot see, and this file is local to the
 * operator rather than something handed to a counterparty.
 */
export interface ApprovalRequest {
  context: typeof APPROVAL_CONTEXT;
  kind: "request";
  id: string;
  digest: string;
  subject: AuthoritySubject;
  origin: AuthorityOrigin[];
  request: AuthorizationRequest;
  reasons: string[];
  escalation?: { to: string; slaHours: number };
  at: string;
  /** After this the answer is stale and the call has to be decided again. */
  expiresAt: string;
}

export interface ApprovalAnswer {
  context: typeof APPROVAL_CONTEXT;
  kind: "answer";
  id: string;
  digest: string;
  status: "approved" | "declined" | "used";
  at: string;
  by?: string;
  note?: string;
  signature?: { alg: "ed25519"; keyId: string; value: string };
}

export type ApprovalEntry = ApprovalRequest | ApprovalAnswer;

export interface ApprovalState {
  request: ApprovalRequest;
  status: "pending" | "approved" | "declined" | "used";
  answer?: ApprovalAnswer;
}

/** Short, and meant to be read out or typed rather than copied. */
export function approvalId(random: () => string = () => crypto.randomUUID()): string {
  return random().replace(/-/g, "").slice(0, 8);
}

export function buildApprovalRequest(
  decision: AuthorizationResult,
  request: AuthorizationRequest,
  opts: { id?: string; now?: () => Date } = {},
): ApprovalRequest {
  const now = (opts.now ?? (() => new Date()))();
  return {
    context: APPROVAL_CONTEXT,
    kind: "request",
    id: opts.id ?? approvalId(),
    digest: decision.binding.digest,
    subject: decision.subject,
    origin: decision.origin,
    request,
    reasons: decision.reasons.map((r) => r.code),
    escalation: decision.escalation,
    at: now.toISOString(),
    expiresAt: decision.binding.expiresAt,
  };
}

/** Fold an append-only trail into where each request currently stands. */
export function foldApprovals(entries: ApprovalEntry[]): Map<string, ApprovalState> {
  const state = new Map<string, ApprovalState>();
  for (const entry of entries) {
    if (entry.kind === "request") {
      if (!state.has(entry.id)) state.set(entry.id, { request: entry, status: "pending" });
      continue;
    }
    const current = state.get(entry.id);
    if (!current) continue;
    // Declined is final, and used is final. Nothing reopens either.
    if (current.status === "declined" || current.status === "used") continue;
    current.status = entry.status;
    current.answer = entry;
  }
  return state;
}

function answerBytes(answer: ApprovalAnswer): Uint8Array {
  const unsigned = {
    context: answer.context,
    kind: answer.kind,
    id: answer.id,
    digest: answer.digest,
    status: answer.status,
    at: answer.at,
    by: answer.by,
    note: answer.note,
  };
  return new TextEncoder().encode(canonicalJson(unsigned));
}

/** Sign an answer, so a policy naming approvers can tell who gave it. */
export async function signApproval(
  answer: ApprovalAnswer,
  signer: { keyId: string; privateKey: CryptoKey | Uint8Array },
): Promise<ApprovalAnswer> {
  const key =
    signer.privateKey instanceof Uint8Array
      ? await crypto.subtle.importKey("pkcs8", signer.privateKey as unknown as BufferSource, { name: "Ed25519" }, false, ["sign"])
      : signer.privateKey;
  const sig = await crypto.subtle.sign("Ed25519", key, answerBytes(answer) as unknown as BufferSource);
  return { ...answer, signature: { alg: "ed25519", keyId: signer.keyId, value: bytesToBase64Url(new Uint8Array(sig)) } };
}

export type ApprovalCheck = { ok: true; answer: ApprovalAnswer } | { ok: false; errors: VerificationError[] };

/**
 * Is this exact call approved, right now?
 *
 * Every no is a separate reason, because "not approved" and "approved by
 * somebody this policy does not recognise" are very different problems.
 */
export async function checkApproval(
  state: Map<string, ApprovalState>,
  digest: string,
  opts: { approvers?: ApproverKey[]; now?: () => Date } = {},
): Promise<ApprovalCheck> {
  const now = (opts.now ?? (() => new Date()))();
  const errors: VerificationError[] = [];
  const candidates = [...state.values()].filter((s) => s.request.digest === digest);

  if (!candidates.length) {
    return {
      ok: false,
      errors: [{ code: "approval.none", message: "Nobody has been asked about this call yet." }],
    };
  }

  for (const candidate of candidates) {
    const { status, answer, request } = candidate;
    if (status === "pending") {
      errors.push({ code: "approval.pending", message: `Request ${request.id} is still waiting for an answer.` });
      continue;
    }
    if (status === "declined") {
      errors.push({ code: "approval.declined", message: `Request ${request.id} was declined${answer?.by ? ` by ${answer.by}` : ""}.` });
      continue;
    }
    if (status === "used") {
      errors.push({ code: "approval.spent", message: `Request ${request.id} was approved and has already been used.` });
      continue;
    }
    if (Date.parse(request.expiresAt) <= now.getTime()) {
      errors.push({ code: "approval.expired", message: `Request ${request.id} was approved but the window closed at ${request.expiresAt}.` });
      continue;
    }
    if (!answer) continue;

    // A policy that names approvers takes answers from nobody else. Without
    // that list anything in the file counts, which is only safe when the agent
    // cannot write to it.
    if (opts.approvers?.length) {
      const key = opts.approvers.find((k) => k.keyId === answer.signature?.keyId);
      if (!answer.signature) {
        errors.push({ code: "approval.unsigned", message: `Request ${request.id} was approved without a signature, and this policy names approvers.` });
        continue;
      }
      if (!key) {
        errors.push({ code: "approval.unknown-approver", message: `Request ${request.id} was signed by "${answer.signature.keyId}", which this policy does not name.` });
        continue;
      }
      const valid = await verifyAnswerSignature(answer, key);
      if (!valid) {
        errors.push({ code: "approval.signature-invalid", message: `The signature on request ${request.id} does not check out.` });
        continue;
      }
    }
    return { ok: true, answer };
  }
  return { ok: false, errors };
}

async function verifyAnswerSignature(answer: ApprovalAnswer, key: ApproverKey): Promise<boolean> {
  let signature: Uint8Array;
  try {
    signature = base64ToBytes(answer.signature!.value);
    if (signature.length !== 64) return false;
  } catch {
    return false;
  }
  const publicKey = await crypto.subtle.importKey(
    "raw",
    base64ToBytes(key.publicKey) as unknown as BufferSource,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    "Ed25519",
    publicKey,
    signature as unknown as BufferSource,
    answerBytes(answer) as unknown as BufferSource,
  );
}
