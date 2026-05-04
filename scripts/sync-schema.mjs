#!/usr/bin/env node
/**
 * Sync the canonical JSON Schema into the verifier package as a
 * TypeScript const. Run after editing schemas/agent-passport.schema.json:
 *
 *   node scripts/sync-schema.mjs
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const schemaPath = resolve(root, "schemas/agent-passport.schema.json");
const targetPath = resolve(
  root,
  "packages/verifier/src/schema-data.ts",
);

const schema = readFileSync(schemaPath, "utf8");

const out = `/**
 * Inlined copy of schemas/agent-passport.schema.json so the published npm
 * package has zero runtime fs dependencies. Regenerate after editing the
 * canonical schema with \`node scripts/sync-schema.mjs\`.
 */

export const schema = ${schema.trimEnd()} as const;
`;

writeFileSync(targetPath, out, "utf8");
console.log(`Wrote ${targetPath}`);
