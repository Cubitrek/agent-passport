/**
 * JSON Schema validation for an Agent Passport, v0.1.
 *
 * Loads the canonical schema from this package and exposes a single
 * validate() function that takes any unknown value and returns a typed
 * result.
 */

import Ajv, { type ErrorObject } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import type {
  AgentPassport,
  ValidateResult,
  VerificationError,
} from "./types.js";
import { schema as schemaJson } from "./schema-data.js";

const ajv = new Ajv({ strict: false, allErrors: true });
addFormats(ajv);

const validateFn = ajv.compile(schemaJson);

export function validate(value: unknown): ValidateResult {
  if (validateFn(value)) {
    return { ok: true, passport: value as AgentPassport };
  }
  const errors: VerificationError[] = (validateFn.errors ?? []).map(
    (e: ErrorObject) => ({
      code: "schema." + (e.keyword ?? "invalid"),
      message: `${e.instancePath || "(root)"} ${e.message ?? "is invalid"}`,
      hint: e.params ? JSON.stringify(e.params) : undefined,
    }),
  );
  return { ok: false, errors };
}
