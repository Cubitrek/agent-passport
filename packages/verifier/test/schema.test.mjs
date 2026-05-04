import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { validate, canonicalize } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");

function loadExample(name) {
  return JSON.parse(
    readFileSync(resolve(repoRoot, `examples/${name}`), "utf8"),
  );
}

test("acme example validates against schema", () => {
  const result = validate(loadExample("acme.agent-passport.json"));
  assert.equal(result.ok, true);
});

test("globex example validates against schema", () => {
  const result = validate(loadExample("globex.agent-passport.json"));
  assert.equal(result.ok, true);
});

test("cubitrek example validates against schema", () => {
  const result = validate(loadExample("cubitrek.agent-passport.json"));
  assert.equal(result.ok, true);
});

test("schema rejects passport missing authority.spendCeiling", () => {
  const passport = loadExample("acme.agent-passport.json");
  delete passport.authority.spendCeiling;
  const result = validate(passport);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.ok(
      result.errors.some((e) => e.code.startsWith("schema.")),
      "expected at least one schema.* error",
    );
  }
});

test("schema rejects unknown signature.alg", () => {
  const passport = loadExample("acme.agent-passport.json");
  passport.signature.alg = "rsa-pss";
  const result = validate(passport);
  assert.equal(result.ok, false);
});

test("canonicalize zeros out signature.value", () => {
  const passport = loadExample("acme.agent-passport.json");
  const { text } = canonicalize(passport);
  // Signature.value must be present but empty
  assert.match(text, /"signature":\{"alg":"ed25519","keyId":"[^"]+","value":""\}/);
  // Original passport must not be mutated
  assert.notEqual(passport.signature.value, "");
});

test("canonicalize sorts keys deterministically", () => {
  const passport = loadExample("acme.agent-passport.json");
  const a = canonicalize(passport).text;
  const reordered = JSON.parse(JSON.stringify(passport));
  // shuffle top-level keys by reconstructing in reverse order
  const reshuffled = Object.keys(reordered)
    .reverse()
    .reduce((acc, k) => ({ ...acc, [k]: reordered[k] }), {});
  const b = canonicalize(reshuffled).text;
  assert.equal(a, b);
});
