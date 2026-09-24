/**
 * A plain-English reading of a passport, for people and for LLM context.
 */

import type { AgentPassport } from "./types.js";

const DAY_MS = 24 * 60 * 60 * 1000;

export function daysUntilExpiry(passport: AgentPassport, now: Date = new Date()): number {
  return Math.floor((Date.parse(passport.expiresAt) - now.getTime()) / DAY_MS);
}

export function describePassport(passport: AgentPassport, now: Date = new Date()): string {
  const { issuer, agent, authority, counterparties, compliance } = passport;
  const money = (n: number, c: string) => `${n.toLocaleString("en-US")} ${c}`;
  const lines: string[] = [];

  lines.push(`${agent.displayName} (${agent.id})`);
  lines.push(`Issued by ${issuer.legalName} (${issuer.domain})`);
  lines.push(`Purpose: ${agent.purpose}`);
  lines.push(`Can: ${authority.scope.join(", ")}`);

  const ceiling = money(authority.spendCeiling.amount, authority.spendCeiling.currency);
  const per = authority.spendCeiling.perEngagement ? "per engagement" : "in total";
  const hil = authority.humanInLoop;
  lines.push(
    `Spending: commits up to ${ceiling} ${per}. Above ${money(hil.above.amount, hil.above.currency)} a human confirms first (${hil.escalation}, within ${hil.slaHours}h).`,
  );

  const openTo = counterparties?.openTo ?? "verified-passports";
  const talksTo =
    openTo === "any"
      ? "anyone"
      : openTo === "allowlist-only"
        ? `only ${(counterparties?.allowlist ?? []).join(", ") || "(empty allowlist)"}`
        : "counterparties with a valid Agent Passport";
  const blocked = counterparties?.blocklist?.length
    ? `; never ${counterparties.blocklist.join(", ")}`
    : "";
  lines.push(`Engages: ${talksTo}${blocked}`);

  if (compliance) {
    const parts = [
      compliance.dataClassification && `data up to ${compliance.dataClassification}`,
      compliance.regions?.length && `regions ${compliance.regions.join(", ")}`,
      compliance.subprocessors?.length && `shares data with ${compliance.subprocessors.join(", ")}`,
    ].filter(Boolean);
    if (parts.length) lines.push(`Compliance: ${parts.join("; ")}`);
  }

  const endpoints = Object.entries(agent.endpoints)
    .map(([kind, url]) => `${kind.toUpperCase()} ${url}`)
    .join(", ");
  lines.push(`Endpoints: ${endpoints}`);

  const days = daysUntilExpiry(passport, now);
  lines.push(
    days >= 0
      ? `Valid until ${passport.expiresAt.slice(0, 10)} (${days} day${days === 1 ? "" : "s"} left)`
      : `EXPIRED on ${passport.expiresAt.slice(0, 10)} (${-days} day${days === -1 ? "" : "s"} ago)`,
  );

  return lines.join("\n");
}
