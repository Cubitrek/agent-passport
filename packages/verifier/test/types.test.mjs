/**
 * Typecheck what a TypeScript consumer writes, against the declaration files
 * this package ships. Everything else in the suite is .mjs, so a broken .d.ts
 * would otherwise reach npm before anyone noticed.
 *
 * Each fixture set has its own tsconfig rather than being named on the command
 * line: TypeScript 7 refuses command-line files while a tsconfig.json is in
 * scope, and a project file behaves the same on both 5 and 7.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const pkg = resolve(here, "..");
const tsc = resolve(pkg, "node_modules/typescript/bin/tsc");

const typecheck = (project) =>
  spawnSync(process.execPath, [tsc, "-p", join(here, "types", project)], {
    cwd: pkg,
    encoding: "utf8",
  });

test("the shipped types hold up for a TypeScript consumer", () => {
  assert.ok(existsSync(tsc), "typescript is not installed, so this proves nothing");
  const result = typecheck("tsconfig.json");
  assert.equal(result.status, 0, `tsc reported:\n${result.stdout}${result.stderr}`);
});

test("the main entry typechecks in a project with no Node types", () => {
  // The counterpart to the import-graph check: a Worker or browser project
  // sees only the declaration files, and must not be asked for @types/node.
  const result = typecheck("tsconfig.portable.json");
  assert.equal(result.status, 0, `tsc reported:\n${result.stdout}${result.stderr}`);
});

test("the typecheck is really running, and can fail", () => {
  // A fixture that must not compile, so the check above cannot be a no-op.
  const result = typecheck("tsconfig.broken.json");
  assert.notEqual(result.status, 0, "tsc accepted a file that does not typecheck");
  assert.match(result.stdout + result.stderr, /error TS/);
});
