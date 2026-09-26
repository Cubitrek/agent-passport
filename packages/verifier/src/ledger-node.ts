/**
 * The on-disk spend ledger.
 *
 * Kept out of the main entry point because it imports node:fs, and the rest
 * of the package deliberately runs unchanged in Workers and browsers. Reach
 * it through the subpath:
 *
 *   import { fileSpendLedger } from "@cubitrek/agent-passport-verifier/node";
 */

import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import type { LedgerEntry, SpendLedger } from "./ledger.js";
import { checkCeilings, total } from "./ledger.js";

/**
 * An append-only ledger on disk, one JSON object per line. State changes are
 * appended rather than rewritten, so the file is also the audit trail: a
 * reservation, then the line that committed or released it.
 *
 * It is for a single process. Two processes appending to one file can both
 * read the same prior total before either writes.
 */
export function fileSpendLedger(path: string): SpendLedger {
  const read = (): LedgerEntry[] => {
    let text: string;
    try {
      text = readFileSync(path, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const state = new Map<string, LedgerEntry>();
    const order: string[] = [];
    const lines = text.split("\n");
    // A file that does not end in a newline had its last append interrupted,
    // so that record never landed. Dropping it is safe in both directions: an
    // unfinished reservation was never counted, and an unfinished commit
    // leaves the entry reserved, which still counts against the ceiling.
    const truncated = text.length > 0 && !text.endsWith("\n");
    for (const [i, line] of lines.entries()) {
      if (!line.trim()) continue;
      if (truncated && i === lines.length - 1) continue;
      let row: LedgerEntry;
      try {
        row = JSON.parse(line) as LedgerEntry;
      } catch {
        // Anything else is corruption. Skipping it would quietly drop
        // committed spend and hand back headroom, so stop and say where.
        throw new Error(
          `${path} is not a readable spend ledger: line ${i + 1} is not JSON. ` +
            `Repair or archive the file; spending cannot be counted until it parses.`,
        );
      }
      if (!row || typeof row.nonce !== "string") {
        throw new Error(`${path} is not a readable spend ledger: line ${i + 1} has no nonce.`);
      }
      if (!state.has(row.nonce)) order.push(row.nonce);
      state.set(row.nonce, { ...state.get(row.nonce), ...row });
    }
    return order.map((nonce) => state.get(nonce)!);
  };
  const append = (row: Partial<LedgerEntry> & { nonce: string }): void => {
    mkdirSync(dirname(path), { recursive: true });
    // If the previous append was interrupted the file ends mid-record. Drop
    // that stump before writing: appending after it would fuse this record
    // onto it, and merely closing the line would leave an unparseable line in
    // the middle of the file, where it can no longer be recognised as a
    // failed write. The stump never landed, so removing it loses nothing.
    try {
      const existing = readFileSync(path, "utf8");
      if (existing.length > 0 && !existing.endsWith("\n")) {
        writeFileSync(path, existing.slice(0, existing.lastIndexOf("\n") + 1), "utf8");
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    appendFileSync(path, `${JSON.stringify(row)}\n`, "utf8");
  };
  return {
    async committed(query) {
      return total(read(), query, false);
    },
    async outstanding(query) {
      return total(read(), query, true);
    },
    async reserve(request) {
      const entries = read();
      const held = entries.find((e) => e.nonce === request.nonce);
      if (held && held.state !== "released") {
        throw new Error(`nonce ${request.nonce} is already in the ledger`);
      }
      const verdict = checkCeilings(entries, request);
      if (!verdict.ok) return verdict;
      append({
        nonce: request.nonce,
        subject: request.subject,
        amount: request.amount,
        currency: request.currency,
        engagementId: request.engagementId,
        at: request.at.toISOString(),
        expiresAt: request.expiresAt,
        state: "reserved",
      });
      return { ok: true };
    },
    async commit(nonce) {
      const entry = read().find((e) => e.nonce === nonce);
      if (!entry) throw new Error(`no reservation for nonce ${nonce}`);
      if (entry.state === "released") throw new Error(`reservation ${nonce} was released`);
      if (entry.state === "committed") return;
      append({ nonce, state: "committed" });
    },
    async release(nonce) {
      const entry = read().find((e) => e.nonce === nonce);
      if (!entry || entry.state !== "reserved") return;
      append({ nonce, state: "released" });
    },
    async entries() {
      return read();
    },
  };
}
