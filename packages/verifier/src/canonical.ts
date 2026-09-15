/**
 * Canonical JSON for Agent Passport signature computation.
 *
 * Per spec §5:
 *   1. Set signature.value to the empty string.
 *   2. Serialise with sorted object keys, no whitespace, no trailing
 *      newline, UTF-8.
 *   3. Sign the resulting bytes with Ed25519.
 *
 * Keys sort by UTF-16 code unit and scalars are written as JSON.stringify
 * writes them, which matches RFC 8785 (JCS) for well-formed passports.
 * This module produces the canonical bytes for both signers and verifiers.
 */

import type { AgentPassport } from "./types.js";

/**
 * Serialise an object with sorted keys. Recursive across nested objects and
 * arrays. Numbers, strings, booleans, and nulls are emitted as JSON.stringify
 * does. Arrays preserve order.
 */
function stringifySortedKeys(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => stringifySortedKeys(v)).join(",") + "]";
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return (
      "{" +
      entries
        .map(([k, v]) => JSON.stringify(k) + ":" + stringifySortedKeys(v))
        .join(",") +
      "}"
    );
  }
  // undefined / functions / symbols
  return "null";
}

/**
 * The canonical string and UTF-8 bytes for a passport, with signature.value
 * emptied. The input is not mutated.
 */
export function canonicalize(passport: AgentPassport): {
  bytes: Uint8Array;
  text: string;
} {
  const cloned = structuredClone(passport) as AgentPassport;
  cloned.signature = { ...cloned.signature, value: "" };
  const text = stringifySortedKeys(cloned);
  return { text, bytes: new TextEncoder().encode(text) };
}

/**
 * Produce the canonical UTF-8 bytes that the issuer signs and the verifier
 * checks against.
 */
export function canonicalBytes(passport: AgentPassport): Uint8Array {
  return canonicalize(passport).bytes;
}
