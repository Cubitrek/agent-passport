/**
 * The guard: the one place a side effect is allowed to happen.
 *
 * Everything else in this package decides and records. This is the piece an
 * integrator actually wires in, and the contract is narrow on purpose:
 * nothing calls the provider except through here, with the final values.
 *
 * It does three things in order. It checks the decision against the request
 * about to be executed, so a substituted, expired or replayed action never
 * reaches the provider. It settles the money, turning a reservation into
 * spend once the effect has happened. It writes a receipt either way, so a
 * refusal leaves as much of a trail as a success.
 *
 * When the effect throws, the result is genuinely unknown: the provider may
 * have acted before the connection died. The reservation is committed rather
 * than released by default, because over-counting only makes the next
 * decision more cautious, while under-counting quietly raises the ceiling.
 */

import type { AuthorizationRequest, AuthorizationResult, NonceStore } from "./authorize.js";
import { ceilingError, checkExecution } from "./authorize.js";
import type { SpendLedger } from "./ledger.js";
import type { Receipt, ReceiptOutcome, ReceiptSink } from "./receipt.js";
import { buildReceipt, signReceipt } from "./receipt.js";
import type { VerificationError } from "./types.js";

export interface GuardOptions {
  now?: () => Date;
  /** Set when the person named in the escalation confirmed this decision. */
  humanApproved?: boolean;
  /** Enforces single use. Without one, the same decision can pass more than once. */
  nonceStore?: NonceStore;
  /** Settles the amount this decision put at stake. */
  ledger?: SpendLedger;
  /** Where receipts go. */
  receipts?: ReceiptSink;
  /** Signs every receipt before it reaches the sink. */
  signReceiptsWith?: { keyId: string; privateKey: CryptoKey | Uint8Array };
  /** Groups spend for a per-engagement ceiling. Match the decide() call. */
  engagementId?: string;
  /** What happens to the held amount when the effect throws. Default "commit". */
  onUnknown?: "commit" | "release";
}

export type GuardResult<T> =
  | { outcome: "executed"; value: T; receipt: Receipt }
  | { outcome: "blocked"; reasons: VerificationError[]; receipt: Receipt }
  | { outcome: "unknown"; error: unknown; receipt: Receipt };

export interface Hold {
  /** The effect happened. Turns the reservation into spend. */
  commit(): Promise<Receipt>;
  /** The effect did not happen. Gives the headroom back. */
  release(reasons?: VerificationError[]): Promise<Receipt>;
  /** The effect may have happened. Settles per `onUnknown`. */
  unresolved(error: unknown): Promise<Receipt>;
}

export type CheckAndHoldResult =
  | { ok: true; hold: Hold }
  | { ok: false; reasons: VerificationError[]; receipt: Receipt };

/**
 * Check a decision against the final request and hold the money, without
 * performing anything. The caller then settles the hold. Use `guardedCall()`
 * unless the effect cannot be expressed as a single function.
 */
export async function checkAndHold(
  decision: AuthorizationResult,
  finalRequest: AuthorizationRequest,
  opts: GuardOptions = {},
): Promise<CheckAndHoldResult> {
  const now = opts.now ?? (() => new Date());
  const charge = decision.charge;
  const write = async (outcome: ReceiptOutcome, reasons?: VerificationError[]): Promise<Receipt> => {
    let receipt = buildReceipt(decision, {
      outcome,
      request: finalRequest,
      blockedBecause: reasons,
      now,
    });
    if (opts.signReceiptsWith) receipt = await signReceipt(receipt, opts.signReceiptsWith);
    await opts.receipts?.record(receipt);
    return receipt;
  };
  const releaseHeld = async (): Promise<void> => {
    if (opts.ledger && charge?.reserved) await opts.ledger.release(decision.binding.nonce);
  };

  const check = await checkExecution(decision, finalRequest, {
    now,
    humanApproved: opts.humanApproved,
    nonceStore: opts.nonceStore,
  });
  if (!check.ok) {
    await releaseHeld();
    return { ok: false, reasons: check.errors, receipt: await write("blocked", check.errors) };
  }

  // A decision that was escalated reserved nothing when it was made, because
  // it could have waited hours. Now that a person has confirmed it, the
  // ceilings have to hold against whatever else was spent in the meantime.
  let held = charge?.reserved ?? false;
  if (opts.ledger && charge && !held) {
    const reservation = await opts.ledger.reserve({
      subject: decision.subject.agentId,
      amount: charge.amount,
      currency: charge.currency,
      ceilings: charge.ceilings,
      nonce: decision.binding.nonce,
      expiresAt: decision.binding.expiresAt,
      engagementId: opts.engagementId ?? charge.engagementId,
      at: now(),
    });
    if (!reservation.ok) {
      const reasons = [ceilingError(reservation.ceiling, reservation.wouldBe, reservation.prior)];
      return { ok: false, reasons, receipt: await write("blocked", reasons) };
    }
    held = true;
  }

  const settle = async (action: "commit" | "release"): Promise<void> => {
    if (!opts.ledger || !held) return;
    if (action === "commit") await opts.ledger.commit(decision.binding.nonce);
    else await opts.ledger.release(decision.binding.nonce);
  };

  return {
    ok: true,
    hold: {
      async commit() {
        await settle("commit");
        return write("executed");
      },
      async release(reasons) {
        await settle("release");
        return write("blocked", reasons);
      },
      async unresolved(error) {
        await settle(opts.onUnknown === "release" ? "release" : "commit");
        return write("unknown", [
          {
            code: "execution.result-unknown",
            message: "The effect was attempted and the result was lost.",
            hint: error instanceof Error ? error.message : undefined,
          },
        ]);
      },
    },
  };
}

/**
 * Run one side effect under a decision. The effect is called only if the
 * decision covers the exact request being executed; the ledger and the
 * receipt trail are settled whichever way it goes.
 */
export async function guardedCall<T>(
  decision: AuthorizationResult,
  finalRequest: AuthorizationRequest,
  effect: () => T | Promise<T>,
  opts: GuardOptions = {},
): Promise<GuardResult<T>> {
  const gate = await checkAndHold(decision, finalRequest, opts);
  if (!gate.ok) return { outcome: "blocked", reasons: gate.reasons, receipt: gate.receipt };

  let value: T;
  try {
    value = await effect();
  } catch (error) {
    return { outcome: "unknown", error, receipt: await gate.hold.unresolved(error) };
  }
  return { outcome: "executed", value, receipt: await gate.hold.commit() };
}

/** Keeps receipts in an array. For tests, and for a process that ships them elsewhere. */
export function memoryReceiptSink(): ReceiptSink & { receipts: Receipt[] } {
  const receipts: Receipt[] = [];
  return {
    receipts,
    record(receipt) {
      receipts.push(receipt);
    },
  };
}
