#!/usr/bin/env node
/**
 * Turn `agent-passport doctor --json` output into GitHub annotations, a job
 * summary table and an `ok` step output. Exits 1 when a check failed, or
 * when any warned and FAIL_ON_WARN is "true". Used by action.yml.
 */

import { appendFileSync, readFileSync } from "node:fs";

const [file] = process.argv.slice(2);
const result = JSON.parse(readFileSync(file, "utf8"));
const icon = { pass: "✅", warn: "⚠️", fail: "❌", skip: "⏭️" };
const cell = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
const escapeData = (s) => String(s ?? "").replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const escapeProperty = (s) => escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");

const summary = [
  `### Agent Passport: ${result.ok ? "healthy" : "problems found"}`,
  "",
  result.url,
  "",
  "| | Check | Detail | Fix |",
  "| --- | --- | --- | --- |",
  ...result.checks.map((c) => `| ${icon[c.status]} | ${cell(c.title)} | ${cell(c.detail)} | ${cell(c.hint)} |`),
  "",
].join("\n");

if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `ok=${result.ok}\n`);

for (const check of result.checks) {
  if (check.status !== "fail" && check.status !== "warn") continue;
  const level = check.status === "fail" ? "error" : "warning";
  const message = [check.detail, check.hint && `Fix: ${check.hint}`].filter(Boolean).join(" ");
  console.log(`::${level} title=${escapeProperty(check.title)}::${escapeData(message || check.title)}`);
}

const warned = result.checks.some((c) => c.status === "warn");
process.exitCode = !result.ok || (process.env.FAIL_ON_WARN === "true" && warned) ? 1 : 0;
