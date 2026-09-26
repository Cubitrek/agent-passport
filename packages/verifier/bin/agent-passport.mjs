#!/usr/bin/env node
/**
 * agent-passport: issue, check and use Agent Passports from the command line.
 *
 *   agent-passport init
 *   agent-passport doctor acme.example
 *   agent-passport authorize acme.example --scope procurement.purchase --amount 4200
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import {
  decide,
  defaultKeyId,
  describePassport,
  diagnoseAgentPassport,
  dnsTxtRecord,
  draftAgentPassport,
  fetchSigningKeys,
  guessEndpointType,
  intersect,
  isoSeconds,
  localPolicy,
  passportAuthority,
  requestKeyEntry,
  signAgentPassport,
  validate,
  verifyAgentPassport,
} from "../dist/index.js";
import { fileSpendLedger } from "../dist/ledger-node.js";

const here = dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(readFileSync(join(here, "../package.json"), "utf8")).version;
const DAY_MS = 24 * 60 * 60 * 1000;
const DATA_CLASSES = ["public", "internal", "confidential-business", "regulated-pii"];

const USAGE = `agent-passport ${VERSION}

Issue a passport for your agent
  init                      Create, key and sign a passport in one guided step
  keygen                    Generate an Ed25519 signing key and print its DNS record
  sign <passport.json>      Sign (or re-sign) a passport file
  request-key               Print the agent.requestKeys entry for a request-signing key
  renew <passport.json>     Re-issue with fresh dates, optionally with a new key

Check a passport
  doctor <domain>           Health-check a published passport, with fixes
  verify <domain|file>      Verify a passport the way a counterparty does

Decide and guard one action
  authorize [domain|file]   Allow, escalate or deny, against a passport,
                            your own --policy file, or both at once
  settle <nonce>            Commit or release the amount a decision held

Connect an AI client
  mcp                       Run the MCP server on stdio, optionally enforcing
                            a --policy on every decision it makes

Run "agent-passport help <command>" for flags. Add --json to doctor, verify or authorize for machine output.`;

const HELP = {
  init: `agent-passport init [flags]

Prompts for anything you leave out. With --yes, or without a terminal, it lists what is missing instead.
  --domain <acme.example>       --legal-name <Acme Corporation>  --display-name <Acme>
  --agent-name <name>           --role <procurement>             --purpose <one sentence>
  --endpoint <url>              --endpoint-type <a2a|mcp|rest>   --scope <a.b,c.d>
  --currency <USD>              --ceiling <amount>               --human-above <amount>
  --escalation <email|url>      --sla-hours <24>                 --terms-url <url>
  --days <90>                   --kid <keyId>
  --request-key                 Also generate a request-signing key and publish it in the passport
  --request-key-out <path>      Where that key goes. Default beside the signing key
  --key <existing.pem>          Sign with an existing key instead of generating one
  --key-out <path>              Where a new key goes. Default ~/.agent-passport/keys/<kid>.pem
  --out-dir <dir>               Where the public files go. Default ./.well-known
  --force                       Overwrite an existing passport file
  --yes                         Never prompt`,
  keygen: "agent-passport keygen --kid <keyId> --out <private-key.pem>",
  "request-key": `agent-passport request-key --key <private-key.pem> --kid <keyId>

Prints the entry to add to agent.requestKeys in your passport, so receivers can tie
a signed request to this passport. Re-sign the passport afterwards. Use a key kept
separate from the passport signing key.`,
  sign: "agent-passport sign <passport.json> --key <private-key.pem> [--kid <keyId>] [--out <signed.json>]",
  renew: `agent-passport renew <passport.json> --key <private-key.pem> [--kid <new keyId>] [--days 90] [--out <file>] [--offline]

Sets issuedAt to now and expiresAt to now plus --days, re-signs, and rewrites the file unless --out is given.
Unless --offline, it also checks that DNS carries this key under the passport's key id.`,
  doctor: `agent-passport doctor <domain> [--warn-days 14] [--no-links] [--json]

Exits 1 when any check fails.`,
  verify: `agent-passport verify <domain | passport.json> [--public-key <base64>] [--no-revocation] [--json]

--public-key pins the issuer key instead of looking it up in DNS.`,
  authorize: `agent-passport authorize [<domain | passport.json>] --scope <subject.verb>
    [--policy <policy.json>] [--ledger <spend.jsonl>] [--engagement <id>]
    [--amount <n>] [--currency <USD>] [--prior-spend <n>] [--as <your-domain>]
    [--region <CC>] [--data <public|internal|confidential-business|regulated-pii>]
    [--tool <name> [--target <id>] [--args <json>]] [--ttl <seconds>]
    [--public-key <base64>] [--no-revocation] [--json]

Exits 0 for allow, 2 for escalate, 1 for deny. The decision is bound to the exact
request, including --tool, --target and --args, and expires after --ttl seconds
(default 60; escalations last for the response window). Whatever performs the
action must call checkExecution() with the final values before acting.

Authority comes from a counterparty's passport, from your own policy file, or
from both, in which case the tighter of the two binds:

  authorize acme.example --scope payments.transfer --amount 400
  authorize --policy treasury.json --scope payments.transfer --amount 400
  authorize acme.example --policy treasury.json --scope payments.transfer --amount 400

A policy file is the same envelope, written by you rather than published:

  {
    "id": "treasury-local",
    "agentId": "ops-bot",
    "scope": ["payments.transfer"],
    "limits": [{ "amount": 5000, "currency": "USD", "window": "day" }],
    "humanInLoop": { "above": { "amount": 500, "currency": "USD" },
                     "escalation": "finance@yourcompany.example" }
  }

--ledger keeps the running total in a file, so a cap over a day, a month or a
whole engagement is counted rather than merely published. Without one, a cap
wider than a single engagement escalates instead of passing unchecked.`,
  settle: `agent-passport settle <nonce> --ledger <spend.jsonl> [--commit | --release] [--json]

Closes out the amount an authorize decision is holding. Run it after the action
either happened or did not:

  agent-passport settle <nonce> --ledger spend.jsonl --commit    # it happened
  agent-passport settle <nonce> --ledger spend.jsonl --release   # it did not

A hold that is never settled lapses on its own when the decision expires, so a
crashed run frees its own headroom. If the action was attempted and the result
was lost, commit it: counting spend that may not have happened only makes the
next decision more cautious, while not counting spend that did raises the cap.`,
  mcp: `agent-passport mcp [--policy <policy.json>] [--ledger <spend.jsonl>]

Speaks MCP over stdio. To add it to Claude Code:
  claude mcp add agent-passport -- npx -y -p @cubitrek/agent-passport-verifier agent-passport mcp

With --policy, every authorize_agent_action call is decided against that policy
as well as against any counterparty passport, and the tighter of the two binds.
The policy is read once, from this flag. Nothing the model sends can widen it,
and authorize_agent_action no longer needs a domain, so the same server guards
your own agent's actions and inbound ones. Add --ledger to count spend across
calls, so a cap over a day or a month is enforced rather than restated.`,
};

const BOOLEAN_FLAGS = new Set(["json", "yes", "force", "offline", "no-links", "no-revocation", "request-key", "commit", "release", "help"]);

const color = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code) => (s) => (color ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const green = paint("32");
const yellow = paint("33");
const red = paint("31");
const dim = paint("2");
const bold = paint("1");
const STATUS = { pass: green("PASS"), warn: yellow("WARN"), fail: red("FAIL"), skip: dim("SKIP") };

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseArgs(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const eq = arg.indexOf("=");
    const name = eq > 2 ? arg.slice(2, eq) : arg.slice(2);
    if (eq > 2) flags[name] = arg.slice(eq + 1);
    else if (BOOLEAN_FLAGS.has(name)) flags[name] = true;
    else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) flags[name] = argv[++i];
    else fail(`--${name} needs a value`);
  }
  return { flags, positional };
}

const json = (value) => `${JSON.stringify(value, null, 2)}\n`;
const readJson = (file) => JSON.parse(readFileSync(file, "utf8"));
const expandHome = (p) => (p.startsWith("~/") ? join(homedir(), p.slice(2)) : p);
const show = (p) => {
  const r = relative(process.cwd(), p);
  return r && !r.startsWith("..") ? r : p.replace(homedir(), "~");
};
const titleCase = (s) =>
  s.split(/[-_\s]+/).filter(Boolean).map((w) => w[0].toUpperCase() + w.slice(1)).join(" ");

function number(value, name) {
  const n = Number(value);
  if (value === "" || !Number.isFinite(n) || n < 0) fail(`--${name} must be a non-negative number`);
  return n;
}

function jsonFlag(value, name) {
  try {
    return JSON.parse(value);
  } catch {
    fail(`--${name} must be valid JSON`);
  }
}

function keyMaterial(privateKey) {
  if (privateKey.asymmetricKeyType !== "ed25519") fail("The key is not an Ed25519 private key.");
  return {
    pkcs8: new Uint8Array(privateKey.export({ type: "pkcs8", format: "der" })),
    publicRaw: new Uint8Array(Buffer.from(createPublicKey(privateKey).export({ format: "jwk" }).x, "base64url")),
  };
}

const loadKey = (path) => keyMaterial(createPrivateKey(readFileSync(expandHome(path))));

function generateKey(path) {
  const { privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(path, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600, flag: "wx" });
  return keyMaterial(privateKey);
}

function samePublicKey(pk, raw) {
  const bytes = Buffer.from(pk.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  if (bytes.length < 32) return false;
  return Buffer.compare(bytes.subarray(bytes.length - 32), Buffer.from(raw)) === 0;
}

/**
 * A target that is plainly a path, and is not there, gets a path error.
 * Falling through to the domain branch answers a typo with a complaint about
 * hostnames, which sends people looking in the wrong place.
 */
function refusePathTypos(target) {
  const looksLikePath = target.endsWith(".json") || target.includes("/") || target.includes(sep);
  if (looksLikePath && !existsSync(target)) {
    fail(`No such file: ${target}\n\nPass a domain to fetch a published passport, or a path to a local one.`);
  }
}

function targetOptions(target, flags) {
  const opts = { checkRevocation: !flags["no-revocation"] };
  if (typeof flags["public-key"] === "string") opts.resolveSignerPublicKey = { publicKeyB64: flags["public-key"] };
  refusePathTypos(target);
  if (target.endsWith(".json") && existsSync(target)) opts.passport = readJson(target);
  else opts.domain = target;
  return opts;
}

function prompter(flags) {
  const rl = !flags.yes && process.stdin.isTTY ? createInterface({ input: process.stdin, output: process.stdout }) : null;
  const missing = [];
  const ask = async (flag, question, fallback) => {
    if (typeof flags[flag] === "string") return flags[flag];
    if (!rl) {
      if (fallback === undefined) missing.push(`--${flag}`);
      return fallback ?? "";
    }
    for (;;) {
      const answer = (await rl.question(`${question}${fallback ? dim(` [${fallback}]`) : ""}: `)).trim();
      if (answer) return answer;
      if (fallback !== undefined) return fallback;
    }
  };
  return { ask, missing, close: () => rl?.close() };
}

// Issue

async function init(flags) {
  const { ask, missing, close } = prompter(flags);
  if (!flags.yes && process.stdin.isTTY) {
    console.log(bold("Create an Agent Passport"));
    console.log(dim("Press Enter to accept a default in brackets.\n"));
  }
  const domain = (await ask("domain", "Your company's domain (e.g. acme.example)")).trim().toLowerCase();
  const legalName = await ask("legal-name", "Registered legal name");
  const displayName = (await ask("display-name", "Short display name", legalName)) || legalName;
  const role = await ask("role", "Agent role, used in its id (e.g. procurement)", "assistant");
  const agentName = await ask("agent-name", "Agent display name", `${displayName} ${titleCase(role)} Agent`);
  const purpose = await ask("purpose", "What the agent does, in one sentence");
  const endpoint = await ask("endpoint", "URL counterparties use to reach it (A2A card, MCP or REST)");
  const endpointType = await ask("endpoint-type", "Endpoint type: a2a, mcp or rest", endpoint ? guessEndpointType(endpoint) : "rest");
  const scopes = await ask("scope", "Capabilities, comma-separated subject.verb (e.g. sales.quote,sales.book-meeting)");
  const currency = await ask("currency", "Currency", "USD");
  const ceiling = await ask("ceiling", "Most it may commit per engagement", "0");
  const humanAbove = await ask("human-above", "A human confirms anything above", "0");
  const escalation = await ask("escalation", "Email or URL of the human who takes over");
  const slaHours = await ask("sla-hours", "Hours before that human responds", "24");
  const termsUrl = await ask("terms-url", "Agent terms URL (optional)", "");
  close();

  if (missing.length) fail(`Missing: ${missing.join(" ")}\n\n${HELP.init}`);
  if (!["a2a", "mcp", "rest"].includes(endpointType)) fail("--endpoint-type must be a2a, mcp or rest");

  const outDir = resolve(expandHome(flags["out-dir"] ?? ".well-known"));
  const passportPath = join(outDir, "agent-passport.json");
  const revocationPath = join(outDir, "revoked-passports.json");
  if (existsSync(passportPath) && !flags.force) {
    fail(`${show(passportPath)} already exists. Use --force to replace it, or \`agent-passport renew\` to re-issue it.`);
  }

  const kid = flags.kid ?? defaultKeyId(domain);
  const days = number(flags.days ?? "90", "days");

  // A request-signing key is separate from the passport signing key: it is used
  // on every call, so it should never be the key that issues passports.
  let requestKeys;
  let requestKeyPath;
  if (flags["request-key"]) {
    const defaultDir = flags["key-out"]
      ? dirname(resolve(expandHome(flags["key-out"])))
      : join(homedir(), ".agent-passport", "keys");
    requestKeyPath = resolve(expandHome(flags["request-key-out"] ?? join(defaultDir, `${kid}-request.pem`)));
    if (existsSync(requestKeyPath)) fail(`${show(requestKeyPath)} already exists. Pass --request-key-out for a different path.`);
    mkdirSync(dirname(requestKeyPath), { recursive: true, mode: 0o700 });
    const generated = generateKey(requestKeyPath);
    requestKeys = [requestKeyEntry({ keyId: `${kid}-request`, publicKeyRaw: generated.publicRaw })];
  }

  const draft = draftAgentPassport({
    domain,
    legalName,
    displayName,
    agentName,
    role,
    purpose,
    endpoints: { [endpointType]: endpoint },
    scopes: scopes.split(","),
    currency,
    spendCeiling: number(ceiling, "ceiling"),
    humanAbove: number(humanAbove, "human-above"),
    escalation,
    slaHours: number(slaHours, "sla-hours"),
    termsUrl: termsUrl || undefined,
    validDays: days,
    keyId: kid,
    requestKeys,
  });
  const checked = validate(draft);
  if (!checked.ok) fail(`The passport is not valid yet:\n${checked.errors.map((e) => `  - ${e.message}`).join("\n")}`);

  let keyPath;
  let key;
  if (flags.key) {
    keyPath = resolve(expandHome(flags.key));
    key = loadKey(keyPath);
  } else {
    keyPath = resolve(expandHome(flags["key-out"] ?? join(homedir(), ".agent-passport", "keys", `${kid}.pem`)));
    if (keyPath.startsWith(outDir + sep)) fail("Refusing to write the private key inside the public output directory.");
    if (existsSync(keyPath)) fail(`${show(keyPath)} already exists. Pass --key to sign with it, or --kid for a new key id.`);
    mkdirSync(dirname(keyPath), { recursive: true, mode: 0o700 });
    key = generateKey(keyPath);
  }

  const signed = await signAgentPassport(checked.passport, key.pkcs8);
  mkdirSync(outDir, { recursive: true });
  writeFileSync(passportPath, json(signed));
  const newRevocationList = !existsSync(revocationPath);
  if (newRevocationList) writeFileSync(revocationPath, "[]\n");

  const until = signed.expiresAt.slice(0, 10);
  console.log(`${green("✓")} Signed passport  ${show(passportPath)} (valid until ${until})`);
  if (newRevocationList) console.log(`${green("✓")} Revocation list  ${show(revocationPath)}`);
  console.log(`${green("✓")} ${(flags.key ? "Signing key" : "Private key").padEnd(15)}  ${show(keyPath)} ${dim("(keep it secret and backed up; never publish it)")}`);
  if (requestKeyPath) {
    console.log(`${green("✓")} ${"Request key".padEnd(15)}  ${show(requestKeyPath)} ${dim("(the agent signs each request with this; published in the passport)")}`);
  }
  console.log(`\n${bold("Next steps")}`);
  console.log("  1. Add a DNS TXT record");
  console.log(`       Name:   ${signed.issuer.signingKeyDns}`);
  console.log(`       Value:  ${dnsTxtRecord({ keyId: kid, publicKeyRaw: key.publicRaw })}`);
  console.log(`  2. Serve both files at https://${domain}/.well-known/ (directly, no redirects)`);
  console.log(`  3. Check everything:    agent-passport doctor ${domain}`);
  console.log(`  4. Before ${until}:  agent-passport renew ${show(passportPath)} --key ${show(keyPath)}`);
}

function keygen(flags) {
  if (!flags.kid || !flags.out) fail(HELP.keygen);
  if (existsSync(flags.out)) fail(`Refusing to overwrite ${flags.out}`);
  const key = generateKey(flags.out);
  console.log(`Private key written to ${flags.out} (mode 600). Keep it out of version control.`);
  console.log("Publish this TXT record at _agent-passport.<your-domain>:");
  console.log(dnsTxtRecord({ keyId: flags.kid, publicKeyRaw: key.publicRaw }));
}

function requestKey(flags) {
  if (!flags.key || !flags.kid) fail(HELP["request-key"]);
  const entry = requestKeyEntry({ keyId: flags.kid, publicKeyRaw: loadKey(flags.key).publicRaw });
  process.stderr.write("Add this to agent.requestKeys in your passport, then re-sign it:\n");
  process.stdout.write(json(entry));
}

async function sign(flags, [file]) {
  if (!file || !flags.key) fail(HELP.sign);
  const passport = readJson(file);
  if (flags.kid) passport.signature = { ...passport.signature, keyId: flags.kid };
  const checked = validate(passport);
  if (!checked.ok) fail(json(checked.errors));
  const signed = await signAgentPassport(checked.passport, loadKey(flags.key).pkcs8);
  if (flags.out) writeFileSync(flags.out, json(signed));
  else process.stdout.write(json(signed));
}

async function renew(flags, [file]) {
  if (!file || !flags.key) fail(HELP.renew);
  const passport = readJson(file);
  const key = loadKey(flags.key);
  const now = new Date();
  passport.issuedAt = isoSeconds(now);
  passport.expiresAt = isoSeconds(new Date(now.getTime() + number(flags.days ?? "90", "days") * DAY_MS));
  passport.signature = { ...passport.signature, ...(flags.kid ? { keyId: flags.kid } : {}), value: "" };
  const checked = validate(passport);
  if (!checked.ok) fail(`The passport is not valid:\n${checked.errors.map((e) => `  - ${e.message}`).join("\n")}`);

  if (!flags.offline) {
    const lookup = await fetchSigningKeys({ signingKeyDns: passport.issuer.signingKeyDns });
    const record = lookup.records.find((r) => r.kid === passport.signature.keyId);
    if (record && samePublicKey(record.pk, key.publicRaw)) {
      console.log(`${green("✓")} DNS carries this key at ${passport.issuer.signingKeyDns}`);
    } else {
      console.log(`${yellow("!")} DNS does not carry this key yet. Counterparties will reject the passport until you publish:`);
      console.log(`    ${passport.issuer.signingKeyDns}  TXT  ${dnsTxtRecord({ keyId: passport.signature.keyId, publicKeyRaw: key.publicRaw })}`);
    }
  }

  const signed = await signAgentPassport(checked.passport, key.pkcs8);
  const out = flags.out ?? file;
  writeFileSync(out, json(signed));
  console.log(`${green("✓")} Re-issued ${show(resolve(out))}, valid until ${signed.expiresAt.slice(0, 10)}`);
  console.log(`  Deploy it, then run: agent-passport doctor ${signed.issuer.domain}`);
}

// Check

async function doctor(flags, [domain]) {
  if (!domain) fail(HELP.doctor);
  // doctor only checks published passports, so a path is always a mistake.
  refusePathTypos(domain);
  const result = await diagnoseAgentPassport({
    domain,
    warnDays: flags["warn-days"] !== undefined ? number(flags["warn-days"], "warn-days") : undefined,
    checkLinks: !flags["no-links"],
  });
  process.exitCode = result.ok ? 0 : 1;
  if (flags.json) {
    process.stdout.write(json({ ok: result.ok, url: result.url, checks: result.checks }));
    return;
  }
  console.log(`${bold("Agent Passport health check")}  ${result.url}\n`);
  const width = Math.max(...result.checks.map((c) => c.title.length));
  for (const check of result.checks) {
    console.log(`  ${STATUS[check.status]}  ${check.title.padEnd(width)}  ${dim(check.detail ?? "")}`);
    if (check.hint && (check.status === "fail" || check.status === "warn")) console.log(`        ${dim("Fix:")} ${check.hint}`);
  }
  const count = (s) => result.checks.filter((c) => c.status === s).length;
  const summary = `${count("fail")} failed, ${count("warn")} warning${count("warn") === 1 ? "" : "s"}, ${count("pass")} passed`;
  console.log(`\n${result.ok ? green(summary) : red(summary)}`);
}

async function verify(flags, [target]) {
  if (!target) fail(HELP.verify);
  const result = await verifyAgentPassport(targetOptions(target, flags));
  process.exitCode = result.ok ? 0 : 1;
  if (flags.json) {
    process.stdout.write(json({ ok: result.ok, errors: result.errors ?? [], warnings: result.warnings }));
    return;
  }
  const indent = (text) => text.split("\n").map((l) => `  ${l}`).join("\n");
  if (result.ok) {
    console.log(`${green("✓ Verified")}\n${indent(describePassport(result.passport))}`);
  } else {
    console.log(red("✗ Not verified"));
    for (const e of result.errors) console.log(`  ${red(e.code)}  ${e.message}`);
    if (result.passport) console.log(`\n${dim("What it claims (do not rely on it):")}\n${indent(describePassport(result.passport))}`);
  }
  for (const w of result.warnings) console.log(`  ${yellow(w.code)}  ${w.message}`);
}

function policyFromFile(path) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(resolve(path), "utf8"));
  } catch (err) {
    fail(`Could not read the policy at ${path}: ${err instanceof Error ? err.message : String(err)}`);
  }
  return localPolicy(parsed);
}

async function authorizeCommand(flags, [target]) {
  const hasPolicy = typeof flags.policy === "string";
  if ((!target && !hasPolicy) || typeof flags.scope !== "string") fail(HELP.authorize);
  if (flags.data !== undefined && !DATA_CLASSES.includes(flags.data)) fail(`--data must be one of ${DATA_CLASSES.join(", ")}`);
  const currency = (flags.currency ?? "USD").toUpperCase();

  // Authority from the counterparty, from this machine, or from both.
  const published = target ? passportAuthority(await verifyAgentPassport(targetOptions(target, flags))) : undefined;
  const mine = hasPolicy ? policyFromFile(flags.policy) : undefined;
  const authority = published && mine ? intersect(published, mine) : (published ?? mine);

  // --target and --args only mean anything alongside --tool, and a decision
  // that silently ignored them would not be bound to the action the caller
  // thinks they described.
  if (typeof flags.tool !== "string" && (flags.target !== undefined || flags.args !== undefined)) {
    fail("--target and --args describe an action, so they need --tool as well.");
  }
  const action =
    typeof flags.tool === "string"
      ? { tool: flags.tool, target: flags.target, args: flags.args !== undefined ? jsonFlag(flags.args, "args") : undefined }
      : undefined;
  const decision = await decide(
    authority,
    {
      scope: flags.scope,
      amount: flags.amount !== undefined ? { amount: number(flags.amount, "amount"), currency } : undefined,
      priorSpend: flags["prior-spend"] !== undefined ? number(flags["prior-spend"], "prior-spend") : undefined,
      counterpartyDomain: flags.as,
      region: flags.region,
      dataClassification: flags.data,
      action,
    },
    {
      ttlSeconds: flags.ttl !== undefined ? number(flags.ttl, "ttl") : undefined,
      ledger: typeof flags.ledger === "string" ? fileSpendLedger(resolve(flags.ledger)) : undefined,
      engagementId: flags.engagement,
    },
  );
  process.exitCode = { allow: 0, escalate: 2, deny: 1 }[decision.decision];
  if (flags.json) {
    process.stdout.write(json(decision));
    return;
  }
  const label = { allow: green("ALLOW"), escalate: yellow("ESCALATE"), deny: red("DENY") }[decision.decision];
  const what = flags.amount !== undefined ? `${flags.scope} for ${Number(flags.amount).toLocaleString("en-US")} ${currency}` : flags.scope;
  console.log(`${label}  ${what}`);
  for (const r of decision.reasons) console.log(`  ${dim(r.code)}  ${r.message}${r.hint ? dim(` (${r.hint})`) : ""}`);
  if (decision.escalation) {
    console.log(`  Human contact: ${decision.escalation.to}, responds within ${decision.escalation.slaHours}h`);
  }
  console.log(dim(`  Authority: ${decision.origin.map((o) => o.label).join(" and ")}`));
  console.log(dim(`  Bound to ${decision.binding.digest}, valid until ${decision.binding.expiresAt}`));
  if (decision.charge?.reserved) {
    console.log(dim(`  ${decision.charge.amount.toLocaleString("en-US")} ${decision.charge.currency} is held in the ledger until this decision is settled or expires`));
  }
}

async function settle(flags, [nonce]) {
  if (!nonce || typeof flags.ledger !== "string") fail(HELP.settle);
  if (flags.commit === flags.release) fail("Pass exactly one of --commit or --release.");
  const ledger = fileSpendLedger(resolve(flags.ledger));
  const before = (await ledger.entries()).find((e) => e.nonce === nonce);
  if (!before) fail(`No hold with nonce ${nonce} in ${flags.ledger}.`);
  if (flags.commit) await ledger.commit(nonce);
  else await ledger.release(nonce);
  const after = (await ledger.entries()).find((e) => e.nonce === nonce);
  if (flags.json) {
    process.stdout.write(json({ nonce, was: before.state, now: after.state, amount: before.amount, currency: before.currency }));
    return;
  }
  const verb = after.state === before.state ? `was already ${after.state}` : `is now ${after.state}`;
  console.log(`${before.amount.toLocaleString("en-US")} ${before.currency} ${verb}.`);
}

async function mcp(flags) {
  const { runMcpServer } = await import("./mcp.mjs");
  await runMcpServer({
    version: VERSION,
    policy: typeof flags.policy === "string" ? policyFromFile(flags.policy) : undefined,
    ledger: typeof flags.ledger === "string" ? fileSpendLedger(resolve(flags.ledger)) : undefined,
  });
}

const COMMANDS = { init, keygen, "request-key": requestKey, sign, renew, doctor, verify, authorize: authorizeCommand, settle, mcp };

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const { flags, positional } = parseArgs(rest);
  if (!command || ["help", "--help", "-h"].includes(command)) {
    console.log(HELP[positional[0]] ?? USAGE);
    return;
  }
  if (command === "--version" || command === "-v") {
    console.log(VERSION);
    return;
  }
  const run = COMMANDS[command];
  if (!run) fail(`Unknown command: ${command}\n\n${USAGE}`);
  if (flags.help) {
    console.log(HELP[command]);
    return;
  }
  await run(flags, positional);
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err)));
