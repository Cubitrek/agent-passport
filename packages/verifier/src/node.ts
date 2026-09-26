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
