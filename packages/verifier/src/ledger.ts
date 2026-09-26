/**
 * A spend ledger: what this subject has already committed, so a ceiling can
 * be enforced rather than merely published.
 *
 * Without one, the caller passes `priorSpend` and is trusted to have counted
 * correctly. Two requests evaluated at the same moment then both see the old
 * total and both pass, which is how a cap gets exceeded while every single
 * check says yes. A ledger closes that by reserving the amount when the
 * decision is made and turning the reservation into a commitment only when
 * the side effect actually happened.
 *
 * Every method takes the current time from the caller rather than reading a
 * clock of its own, so a ledger cannot disagree with the decision it is
 * accounting for.
 *
 * This module stays free of Node built-ins so the package keeps running in
 * Workers and browsers. The on-disk ledger lives in ./ledger-node.ts, behind
 * the "@cubitrek/agent-passport-verifier/node" subpath.
 */

import type { AuthorityCeiling, SpendWindow } from "./authority.js";

export interface LedgerQuery {
  subject: string;
  currency: string;
  window: SpendWindow;
  engagementId?: string;
  at: Date;
}

export interface ReserveRequest {
  subject: string;
  amount: number;
  currency: string;
  /** Every ceiling that must hold. Ceilings in another currency are skipped. */
  ceilings: AuthorityCeiling[];
  /** The decision nonce. Reserving twice under one nonce is not allowed. */
  nonce: string;
  /** When this reservation lapses if it is never committed. */
  expiresAt: string;
  engagementId?: string;
  at: Date;
}

export type ReserveResult =
  | { ok: true }
  | {
      ok: false;
      /** The first ceiling the reservation would break. */
      ceiling: AuthorityCeiling;
      /** Already committed or reserved in that window. */
      prior: number;
      /** What the total would have become. */
      wouldBe: number;
    };

export interface LedgerEntry {
  nonce: string;
  subject: string;
  amount: number;
  currency: string;
  engagementId?: string;
  at: string;
  expiresAt: string;
  state: "reserved" | "committed" | "released";
}

export interface SpendLedger {
  /** Committed spend in this window. Reservations are not included. */
  committed(query: LedgerQuery): Promise<number>;
  /** Committed plus live reservations: what a new request has to fit under. */
  outstanding(query: LedgerQuery): Promise<number>;
  /** Hold `amount` against every ceiling, or refuse and hold nothing. */
  reserve(request: ReserveRequest): Promise<ReserveResult>;
  /**
   * The side effect happened: the reservation becomes spend. Committing an
   * already-committed reservation does nothing, because a decision can be
   * presented twice and only the first presentation settles it.
   */
  commit(nonce: string): Promise<void>;
  /**
   * The side effect did not happen: give the headroom back. Releasing a
   * reservation that was already settled, or one that was never made, does
   * nothing, for the same reason.
   */
  release(nonce: string): Promise<void>;
  /** Every entry, newest last. For reporting and tests. */
  entries(): Promise<LedgerEntry[]>;
}

/** Start of the UTC day or month `at` falls in, as epoch milliseconds. */
export function windowStart(window: SpendWindow, at: Date): number {
  switch (window) {
    case "day":
      return Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), at.getUTCDate());
    case "month":
      return Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), 1);
    default:
      return Number.NEGATIVE_INFINITY;
  }
}

function inWindow(entry: LedgerEntry, query: LedgerQuery): boolean {
  if (entry.subject !== query.subject) return false;
  if (entry.currency !== query.currency) return false;
  if (query.window === "engagement") {
    return !!query.engagementId && entry.engagementId === query.engagementId;
  }
  return Date.parse(entry.at) >= windowStart(query.window, query.at);
}

/** A reservation that was never committed and whose decision has expired. */
function lapsed(entry: LedgerEntry, at: Date): boolean {
  return entry.state === "reserved" && Date.parse(entry.expiresAt) <= at.getTime();
}

export function total(entries: LedgerEntry[], query: LedgerQuery, includeReserved: boolean): number {
  let sum = 0;
  for (const entry of entries) {
    if (!inWindow(entry, query)) continue;
    if (entry.state === "committed") sum += entry.amount;
    else if (includeReserved && entry.state === "reserved" && !lapsed(entry, query.at)) {
      sum += entry.amount;
    }
  }
  return sum;
}

export function checkCeilings(
  entries: LedgerEntry[],
  request: ReserveRequest,
): ReserveResult {
  if (!Number.isFinite(request.amount) || request.amount < 0) {
    throw new TypeError("reserve() needs a non-negative, finite amount");
  }
  for (const ceiling of request.ceilings) {
    if (ceiling.currency !== request.currency) continue;
    if (ceiling.window === "engagement" && !request.engagementId) continue;
    const prior = total(
      entries,
      {
        subject: request.subject,
        currency: request.currency,
        window: ceiling.window,
        engagementId: request.engagementId,
        at: request.at,
      },
      true,
    );
    const wouldBe = prior + request.amount;
    if (wouldBe > ceiling.amount) return { ok: false, ceiling, prior, wouldBe };
  }
  return { ok: true };
}

/**
 * A ledger for one process, held in memory. Executors spread across
 * processes need a shared store whose reserve step is a single atomic
 * operation, such as a Redis transaction or a database row lock.
 */
export function memorySpendLedger(seed: LedgerEntry[] = []): SpendLedger {
  const entries: LedgerEntry[] = seed.map((e) => ({ ...e }));
  const byNonce = new Map<string, LedgerEntry>(entries.map((e) => [e.nonce, e]));
  return {
    async committed(query) {
      return total(entries, query, false);
    },
    async outstanding(query) {
      return total(entries, query, true);
    },
    async reserve(request) {
      if (byNonce.has(request.nonce)) {
        const held = byNonce.get(request.nonce)!;
        if (held.state !== "released") {
          throw new Error(`nonce ${request.nonce} is already in the ledger`);
        }
      }
      const verdict = checkCeilings(entries, request);
      if (!verdict.ok) return verdict;
      const entry: LedgerEntry = {
        nonce: request.nonce,
        subject: request.subject,
        amount: request.amount,
        currency: request.currency,
        engagementId: request.engagementId,
        at: request.at.toISOString(),
        expiresAt: request.expiresAt,
        state: "reserved",
      };
      entries.push(entry);
      byNonce.set(entry.nonce, entry);
      return { ok: true };
    },
    async commit(nonce) {
      const entry = byNonce.get(nonce);
      if (!entry) throw new Error(`no reservation for nonce ${nonce}`);
      if (entry.state === "released") throw new Error(`reservation ${nonce} was released`);
      entry.state = "committed";
    },
    async release(nonce) {
      const entry = byNonce.get(nonce);
      if (!entry || entry.state !== "reserved") return;
      entry.state = "released";
    },
    async entries() {
      return entries.map((e) => ({ ...e }));
    },
  };
}
