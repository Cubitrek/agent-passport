/**
 * Everything in this package that needs Node.
 *
 * The main entry deliberately touches no Node built-in, so the library keeps
 * running in Workers and browsers. Anything that reaches the file system lives
 * here instead, behind the "@cubitrek/agent-passport-verifier/node" subpath.
 */

import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

import type { Receipt, ReceiptSink } from "./receipt.js";
import type { ApprovalAnswer, ApprovalEntry, ApprovalRequest, ApprovalState } from "./approval.js";
import { foldApprovals } from "./approval.js";

export { fileSpendLedger } from "./ledger-node.js";

/**
 * Append receipts to a file, one JSON object per line.
 *
 * Append-only on purpose: a receipt trail you can rewrite is not a trail. The
 * same file is what `agent-passport log` reads back.
 */
export function fileReceiptSink(path: string): ReceiptSink & { path: string } {
  return {
    path,
    record(receipt: Receipt) {
      mkdirSync(dirname(path), { recursive: true });
      appendFileSync(path, `${JSON.stringify(receipt)}\n`, "utf8");
    },
  };
}

/** Read a receipt trail back. Skips a trailing partial line from an interrupted write. */
export function readReceipts(path: string): Receipt[] {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  const lines = text.split("\n");
  const truncated = text.length > 0 && !text.endsWith("\n");
  const out: Receipt[] = [];
  for (const [i, line] of lines.entries()) {
    if (!line.trim()) continue;
    if (truncated && i === lines.length - 1) continue;
    try {
      out.push(JSON.parse(line) as Receipt);
    } catch {
      throw new Error(`${path} is not a readable receipt trail: line ${i + 1} is not JSON.`);
    }
  }
  return out;
}

/**
 * The approvals trail on disk, append only, one JSON object per line.
 *
 * A request is appended when a call is escalated, and an answer when someone
 * says yes or no. Nothing is ever rewritten, so the file is also the record of
 * who decided what and when.
 */
export interface ApprovalStore {
  path: string;
  /** Record a call that is waiting. */
  ask(request: ApprovalRequest): void;
  /** Record an answer to one. */
  answer(answer: ApprovalAnswer): void;
  /** Where every request currently stands. */
  state(): Map<string, ApprovalState>;
  entries(): ApprovalEntry[];
}

export function fileApprovalStore(path: string): ApprovalStore {
  const append = (entry: ApprovalEntry): void => {
    mkdirSync(dirname(path), { recursive: true });
    appendFileSync(path, `${JSON.stringify(entry)}\n`, "utf8");
  };
  const entries = (): ApprovalEntry[] => {
    let text: string;
    try {
      text = readFileSync(path, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const lines = text.split("\n");
    const truncated = text.length > 0 && !text.endsWith("\n");
    const out: ApprovalEntry[] = [];
    for (const [i, line] of lines.entries()) {
      if (!line.trim()) continue;
      if (truncated && i === lines.length - 1) continue;
      try {
        out.push(JSON.parse(line) as ApprovalEntry);
      } catch {
        throw new Error(`${path} is not a readable approvals trail: line ${i + 1} is not JSON.`);
      }
    }
    return out;
  };
  return {
    path,
    ask: append,
    answer: append,
    entries,
    state: () => foldApprovals(entries()),
  };
}
