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
 * This module produces the canonical bytes for both signers and verifiers,
 * and the request digests that bind authorization decisions.
 */

import type { AgentPassport } from "./types.js";

/**
 * Serialise JSON data with sorted keys and no whitespace. Recursive across
 * nested objects and arrays. Strings, numbers, booleans and null are written
 * as JSON.stringify writes them; object members whose value is undefined are
 * omitted. Anything that is not plain JSON data (a Date, a Map, NaN, a
 * bigint, a function) throws, because it would otherwise serialise to
 * something ambiguous such as {} or null.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError(`Canonical JSON cannot represent ${value}`);
      }
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return (
          "[" +
          value.map((v) => (v === undefined ? "null" : canonicalJson(v))).join(",") +
          "]"
        );
      }
      if (Object.prototype.toString.call(value) !== "[object Object]") {
        throw new TypeError("Canonical JSON accepts plain objects, arrays and scalars only");
      }
      const entries = Object.entries(value as Record<string, unknown>)
        .filter(([, v]) => v !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      return (
        "{" +
        entries.map(([k, v]) => JSON.stringify(k) + ":" + canonicalJson(v)).join(",") +
        "}"
      );
    }
    default:
      throw new TypeError(`Canonical JSON cannot represent a ${typeof value}`);
  }
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
  const text = canonicalJson(cloned);
  return { text, bytes: new TextEncoder().encode(text) };
}

/**
 * Produce the canonical UTF-8 bytes that the issuer signs and the verifier
 * checks against.
 */
export function canonicalBytes(passport: AgentPassport): Uint8Array {
  return canonicalize(passport).bytes;
}
