/**
 * Typecheck what a TypeScript consumer writes, against the declaration files
 * this package ships. Everything else in the suite is .mjs, so a broken .d.ts
 * would otherwise reach npm before anyone noticed.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const pkg = resolve(here, "..");

function typecheck(...files) {
  return spawnSync(
    process.execPath,
    [
      resolve(pkg, "node_modules/typescript/bin/tsc"),
      "--noEmit", "--strict", "--skipLibCheck",
      "--module", "nodenext", "--moduleResolution", "nodenext",
      "--target", "es2022", "--types", "node",
      ...files,
    ],
    { cwd: pkg, encoding: "utf8" },
  );
}

test("the shipped types hold up for a TypeScript consumer", () => {
  const dir = join(here, "types");
  const fixtures = readdirSync(dir).filter((f) => f.endsWith(".ts") && !f.endsWith(".fixture.ts"));
  assert.ok(fixtures.length >= 2, `only found ${fixtures.length} type fixtures`);

  const result = typecheck(...fixtures.map((f) => join(dir, f)));
  assert.equal(result.status, 0, `tsc reported:\n${result.stdout}${result.stderr}`);
});

test("the typecheck is really running, and can fail", () => {
  // A fixture that must not compile, to prove the check above is not a no-op.
  const broken = join(here, "types", "broken.fixture.ts");
  const result = typecheck(broken);
  assert.notEqual(result.status, 0, "tsc accepted a file that does not typecheck");
  assert.match(result.stdout + result.stderr, /error TS/);
});
