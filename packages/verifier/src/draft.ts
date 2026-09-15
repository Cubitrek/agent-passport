/**
 * Build a complete, unsigned passport from plain answers, so issuers never
 * start from a hand-edited example. Used by `agent-passport init` and the
 * MCP `draft_agent_passport` tool; sign the result with signAgentPassport.
 */

import type { AgentPassport, PassportCompliance, PassportCounterparties } from "./types.js";

export type EndpointType = "a2a" | "mcp" | "rest";

export interface PassportDraftInput {
  domain: string;
  legalName: string;
  displayName?: string;
  agentName: string;
  /** Short role slug used in agent.id, e.g. "procurement". Default "assistant". */
  role?: string;
  /** Bump when re-issuing after a revocation. Default 1. */
  revision?: number;
  purpose: string;
  endpoints: Partial<Record<EndpointType, string>>;
  scopes: string[];
  currency?: string;
  spendCeiling?: number;
  perEngagement?: boolean;
  humanAbove?: number;
  escalation: string;
  slaHours?: number;
  termsUrl?: string;
  logo?: string;
  contactEmail?: string;
  contactUrl?: string;
  model?: string;
  decisionAuditUrl?: string;
  /** Pass null to publish without a revocation list (not recommended). */
  revocationListUrl?: string | null;
  openTo?: PassportCounterparties["openTo"];
  dataClassification?: PassportCompliance["dataClassification"];
  regions?: string[];
  subprocessors?: string[];
  keyId?: string;
  /** Default 90, the recommended maximum. */
  validDays?: number;
  now?: Date;
}

const DAY_MS = 24 * 60 * 60 * 1000;

export function draftAgentPassport(input: PassportDraftInput): AgentPassport {
  const now = input.now ?? new Date();
  const domain = input.domain.trim().toLowerCase().replace(/\.$/, "");
  const role = slug(input.role ?? "assistant") || "assistant";
  const currency = (input.currency ?? "USD").toUpperCase();

  const compliance: PassportCompliance = {};
  if (input.dataClassification) compliance.dataClassification = input.dataClassification;
  if (input.regions?.length) compliance.regions = input.regions.map((r) => r.toUpperCase());
  if (input.subprocessors?.length) compliance.subprocessors = input.subprocessors;

  const contact =
    input.contactEmail || input.contactUrl
      ? {
          ...(input.contactEmail ? { email: input.contactEmail } : {}),
          ...(input.contactUrl ? { url: input.contactUrl } : {}),
        }
      : undefined;

  const passport: AgentPassport = {
    version: "0.1.0",
    issuer: {
      domain,
      legalName: input.legalName,
      displayName: input.displayName ?? input.legalName,
      ...(input.logo ? { logo: input.logo } : {}),
      signingKeyDns: `_agent-passport.${domain}`,
      ...(contact ? { contact } : {}),
    },
    agent: {
      id: `${domain}:${role}-v${input.revision ?? 1}`,
      displayName: input.agentName,
      purpose: input.purpose,
      ...(input.model ? { model: input.model } : {}),
      endpoints: Object.fromEntries(
        Object.entries(input.endpoints).filter(([, url]) => !!url),
      ),
    },
    authority: {
      scope: [...new Set(input.scopes.map((s) => s.trim()).filter(Boolean))],
      spendCeiling: {
        amount: input.spendCeiling ?? 0,
        currency,
        perEngagement: input.perEngagement ?? true,
      },
      humanInLoop: {
        above: { amount: input.humanAbove ?? 0, currency },
        escalation: input.escalation,
        slaHours: input.slaHours ?? 24,
      },
      decisionAudit:
        input.decisionAuditUrl ?? `https://${domain}/agent-passport/audit/{engagementId}`,
      ...(input.termsUrl ? { termsUrl: input.termsUrl } : {}),
    },
    counterparties: { openTo: input.openTo ?? "verified-passports" },
    ...(Object.keys(compliance).length ? { compliance } : {}),
    issuedAt: isoSeconds(now),
    expiresAt: isoSeconds(new Date(now.getTime() + (input.validDays ?? 90) * DAY_MS)),
    ...(input.revocationListUrl === null
      ? {}
      : {
          revocationListUrl:
            input.revocationListUrl ?? `https://${domain}/.well-known/revoked-passports.json`,
        }),
    signature: {
      alg: "ed25519",
      keyId: input.keyId ?? defaultKeyId(domain, now),
      value: "",
    },
  };
  return passport;
}

/** e.g. "acme-2026-q3" for acme.example in August 2026. */
export function defaultKeyId(domain: string, now: Date = new Date()): string {
  const label = slug(domain.split(".")[0] ?? "") || "issuer";
  return `${label}-${now.getUTCFullYear()}-q${Math.floor(now.getUTCMonth() / 3) + 1}`;
}

export function guessEndpointType(url: string): EndpointType {
  if (/agent-card\.json$|agent\.json$/i.test(url)) return "a2a";
  if (/(^https?:\/\/mcp\.|\/mcp(\/|$)|\/sse$)/i.test(url)) return "mcp";
  return "rest";
}

/** RFC 3339 without milliseconds. */
export function isoSeconds(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function slug(s: string): string {
  return s.trim().toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "");
}
