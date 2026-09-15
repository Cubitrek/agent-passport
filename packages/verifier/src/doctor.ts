/**
 * Health check for an issuer's published passport. `verifyAgentPassport`
 * answers "may I trust this?"; this answers "what will break for my
 * counterparties, and how do I fix it?" It runs the verifier and adds the
 * operational checks the spec recommends: caching, CORS, DNSSEC, expiry
 * runway, the revocation list, and whether linked URLs load.
 */

import type { AgentPassport, VerificationError, VerifyResult } from "./types.js";
import { verifyAgentPassport } from "./index.js";
import { daysUntilExpiry } from "./describe.js";
import { readJsonCapped, withTimeout } from "./http.js";

export type CheckStatus = "pass" | "warn" | "fail" | "skip";

export interface HealthCheck {
  id: string;
  status: CheckStatus;
  title: string;
  detail?: string;
  hint?: string;
}

export interface DiagnoseOptions {
  domain: string;
  /** Warn when the passport expires within this many days. Default 14. */
  warnDays?: number;
  /** Check that logo, terms, contact and endpoint URLs respond. Default true. */
  checkLinks?: boolean;
  timeoutMs?: number;
  now?: () => Date;
}

export interface DiagnoseResult {
  /** False when any check failed. Warnings do not change it. */
  ok: boolean;
  domain: string;
  url: string;
  checks: HealthCheck[];
  passport?: AgentPassport;
  verification?: VerifyResult;
}

const MAX_CACHE_SECONDS = 300;
const MAX_BODY_BYTES = 256 * 1024;

export async function diagnoseAgentPassport(opts: DiagnoseOptions): Promise<DiagnoseResult> {
  const now = opts.now ?? (() => new Date());
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const warnDays = opts.warnDays ?? 14;
  const domain = opts.domain.trim().toLowerCase().replace(/\.$/, "");
  const url = `https://${domain}/.well-known/agent-passport.json`;
  const checks: HealthCheck[] = [];
  const add = (check: HealthCheck) => checks.push(check);
  const result = (extra: Partial<DiagnoseResult> = {}): DiagnoseResult => ({
    ok: !checks.some((c) => c.status === "fail"),
    domain,
    url,
    checks,
    ...extra,
  });

  const reachable = "Passport is served at /.well-known/agent-passport.json";
  if (!/^[a-z0-9_.-]+$/.test(domain)) {
    add({ id: "http.reachable", status: "fail", title: reachable, detail: `"${opts.domain}" is not a bare hostname.` });
    return result();
  }

  // 1. HTTP delivery.
  let res: Response;
  try {
    res = await fetch(url, {
      headers: { accept: "application/json" },
      redirect: "manual",
      signal: withTimeout(undefined, timeoutMs),
    });
  } catch (err) {
    add({ id: "http.reachable", status: "fail", title: reachable, detail: message(err), hint: `Publish the signed passport at ${url}.` });
    return result();
  }
  if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
    add({
      id: "http.reachable",
      status: "fail",
      title: reachable,
      detail: `HTTP ${res.status} redirect to ${res.headers.get("location") ?? "(no location)"}`,
      hint: "Serve the file from the issuer host itself. Verifiers do not follow redirects.",
    });
    return result();
  }
  if (!res.ok) {
    add({ id: "http.reachable", status: "fail", title: reachable, detail: `HTTP ${res.status}`, hint: `Publish the signed passport at ${url}.` });
    return result();
  }
  add({ id: "http.reachable", status: "pass", title: reachable, detail: `HTTP ${res.status}` });

  const contentType = res.headers.get("content-type") ?? "";
  add(
    contentType.includes("application/json")
      ? { id: "http.content-type", status: "pass", title: "Served as application/json" }
      : {
          id: "http.content-type",
          status: "warn",
          title: "Served as application/json",
          detail: contentType ? `content-type: ${contentType}` : "No content-type header",
          hint: "Set Content-Type: application/json. Some clients refuse to parse anything else.",
        },
  );

  add(
    res.headers.get("access-control-allow-origin")
      ? { id: "http.cors", status: "pass", title: "Readable by browser-based verifiers (CORS)" }
      : {
          id: "http.cors",
          status: "warn",
          title: "Readable by browser-based verifiers (CORS)",
          detail: "No Access-Control-Allow-Origin header",
          hint: "Add Access-Control-Allow-Origin: * so verifiers running in a browser can fetch the passport.",
        },
  );

  add(cacheCheck(res.headers.get("cache-control")));

  let json: unknown;
  try {
    json = await readJsonCapped(res, MAX_BODY_BYTES);
    add({ id: "passport.json", status: "pass", title: "Valid JSON" });
  } catch (err) {
    add({ id: "passport.json", status: "fail", title: "Valid JSON", detail: message(err) });
    return result();
  }

  // 2. Everything the verifier checks.
  const verification = await verifyAgentPassport({
    passport: json,
    domain,
    now,
    timeoutMs,
    checkRevocation: false,
  });
  if (!verification.ok && !verification.passport) {
    add({
      id: "passport.schema",
      status: "fail",
      title: "Matches the v0.1 schema",
      detail: verification.errors.slice(0, 5).map((e) => e.message).join("; "),
      hint: "Run `agent-passport sign` on the file: it validates before signing.",
    });
    return result({ verification });
  }
  add({ id: "passport.schema", status: "pass", title: "Matches the v0.1 schema" });

  const passport = verification.passport as AgentPassport;
  const findings = [...(verification.ok ? [] : verification.errors), ...verification.warnings];
  const having = (prefix: string) => findings.filter((f) => f.code.startsWith(prefix));
  const detail = (list: VerificationError[]) => list.map((f) => f.message).join("; ");

  const domainMismatch = having("issuer.domain-mismatch");
  add({
    id: "issuer.domain",
    status: domainMismatch.length ? "fail" : "pass",
    title: "issuer.domain matches the host",
    detail: domainMismatch.length ? detail(domainMismatch) : undefined,
  });

  const outsideZone = having("issuer.signing-key-outside-domain");
  add({
    id: "key.zone",
    status: outsideZone.length ? "fail" : "pass",
    title: "Signing key is published inside the issuer's zone",
    detail: outsideZone.length ? detail(outsideZone) : passport.issuer.signingKeyDns,
    hint: outsideZone.length ? `Set issuer.signingKeyDns to _agent-passport.${passport.issuer.domain}.` : undefined,
  });

  const keyProblems = [...having("dns."), ...having("signer-key.")].filter((f) => f.code !== "dns.unauthenticated");
  const keyStatus: CheckStatus = outsideZone.length ? "skip" : keyProblems.length ? "fail" : "pass";
  add({
    id: "dns.key",
    status: keyStatus,
    title: "Signing key found in DNS",
    detail: keyProblems.length ? detail(keyProblems) : keyStatus === "pass" ? `kid=${passport.signature.keyId}` : undefined,
    hint: keyProblems.length
      ? `Publish a TXT record at ${passport.issuer.signingKeyDns}: v=ap1; kid=${passport.signature.keyId}; alg=ed25519; pk=<public key>. \`agent-passport keygen\` prints it.`
      : undefined,
  });

  const unauthenticated = having("dns.unauthenticated");
  add({
    id: "dns.dnssec",
    status: keyStatus !== "pass" ? "skip" : unauthenticated.length ? "warn" : "pass",
    title: "DNS answer is DNSSEC-validated",
    hint: unauthenticated.length ? "Enable DNSSEC for the zone at your DNS provider." : undefined,
  });

  const badSignature = having("signature.");
  add({
    id: "signature",
    status: keyStatus !== "pass" ? "skip" : badSignature.length ? "fail" : "pass",
    title: "Signature verifies",
    hint: badSignature.length
      ? "Re-sign after every edit with `agent-passport sign` (or `renew`), using the key whose public half is in DNS."
      : undefined,
  });

  const timeProblems = having("time.").filter((f) => f.code !== "time.lifetime-exceeds-recommended");
  const days = daysUntilExpiry(passport, now());
  add(
    timeProblems.length
      ? {
          id: "validity.window",
          status: "fail",
          title: "Passport is within its validity window",
          detail: detail(timeProblems),
          hint: "Re-issue with `agent-passport renew`, then deploy the new file.",
        }
      : days < warnDays
        ? {
            id: "validity.window",
            status: "warn",
            title: "Passport is within its validity window",
            detail: `Expires in ${days} day${days === 1 ? "" : "s"} (${passport.expiresAt})`,
            hint: "Re-issue now with `agent-passport renew` so counterparties never see it expire.",
          }
        : { id: "validity.window", status: "pass", title: "Passport is within its validity window", detail: `${days} days left` },
  );

  const longLifetime = having("time.lifetime-exceeds-recommended");
  add({
    id: "validity.lifetime",
    status: longLifetime.length ? "warn" : "pass",
    title: "Lifetime is 90 days or less",
    hint: longLifetime.length ? "Shorter lifetimes limit the damage of a leaked key or a hijacked domain." : undefined,
  });

  const authority = having("authority.");
  add({
    id: "authority.consistency",
    status: authority.length ? "warn" : "pass",
    title: "Spending thresholds are consistent",
    detail: authority.length ? detail(authority) : undefined,
  });

  add(await revocationCheck(passport, timeoutMs));

  // 3. Linked URLs.
  if (opts.checkLinks !== false) {
    for (const check of await linkChecks(passport, timeoutMs)) add(check);
  }

  return result({ passport, verification });
}

function cacheCheck(header: string | null): HealthCheck {
  const title = "Cache lifetime is short enough for revocation";
  if (!header) {
    return {
      id: "http.cache",
      status: "warn",
      title,
      detail: "No Cache-Control header, so CDN defaults decide",
      hint: `Send Cache-Control: max-age=${MAX_CACHE_SECONDS}, stale-while-revalidate=${MAX_CACHE_SECONDS} or shorter.`,
    };
  }
  const directives: Record<string, number> = {};
  for (const part of header.split(",")) {
    const [key, value] = part.trim().toLowerCase().split("=");
    if (key && value && /^\d+$/.test(value)) directives[key] = Number(value);
  }
  const tooLong = ["max-age", "s-maxage", "stale-while-revalidate"].filter(
    (d) => (directives[d] ?? 0) > MAX_CACHE_SECONDS,
  );
  if (!tooLong.length) return { id: "http.cache", status: "pass", title, detail: header };
  return {
    id: "http.cache",
    status: "warn",
    title,
    detail: tooLong.map((d) => `${d}=${directives[d]} (${humanSeconds(directives[d] ?? 0)})`).join(", "),
    hint: `Keep every cache directive at ${MAX_CACHE_SECONDS} seconds or less, or a superseded or revoked passport keeps being served.`,
  };
}

async function revocationCheck(passport: AgentPassport, timeoutMs: number): Promise<HealthCheck> {
  const title = "Revocation list is published and the agent is not on it";
  if (!passport.revocationListUrl) {
    return {
      id: "revocation.list",
      status: "warn",
      title,
      detail: "No revocationListUrl",
      hint: "Publish a JSON array (start with []) and set revocationListUrl, or you cannot withdraw this agent before it expires.",
    };
  }
  try {
    const res = await fetch(passport.revocationListUrl, {
      headers: { accept: "application/json" },
      signal: withTimeout(undefined, timeoutMs),
    });
    if (!res.ok) {
      return { id: "revocation.list", status: "warn", title, detail: `HTTP ${res.status} from ${passport.revocationListUrl}` };
    }
    const list = await readJsonCapped(res, 1024 * 1024);
    if (!Array.isArray(list)) {
      return { id: "revocation.list", status: "warn", title, detail: "The revocation list is not a JSON array" };
    }
    if (list.includes(passport.agent.id)) {
      return { id: "revocation.list", status: "fail", title, detail: `${passport.agent.id} is revoked` };
    }
    return { id: "revocation.list", status: "pass", title, detail: `${list.length} revoked id${list.length === 1 ? "" : "s"}` };
  } catch (err) {
    return { id: "revocation.list", status: "warn", title, detail: message(err) };
  }
}

type LinkKind = "image" | "page" | "endpoint";

async function linkChecks(passport: AgentPassport, timeoutMs: number): Promise<HealthCheck[]> {
  const links: Array<{ id: string; title: string; url?: string; kind: LinkKind }> = [
    { id: "link.logo", title: "Logo loads", url: passport.issuer.logo, kind: "image" },
    { id: "link.terms", title: "Terms page loads", url: passport.authority.termsUrl, kind: "page" },
    { id: "link.contact", title: "Contact page loads", url: passport.issuer.contact?.url, kind: "page" },
    { id: "link.endpoint.a2a", title: "A2A endpoint responds", url: passport.agent.endpoints.a2a, kind: "page" },
    { id: "link.endpoint.mcp", title: "MCP endpoint responds", url: passport.agent.endpoints.mcp, kind: "endpoint" },
    { id: "link.endpoint.rest", title: "REST endpoint responds", url: passport.agent.endpoints.rest, kind: "endpoint" },
  ];
  return Promise.all(
    links
      .filter((l): l is { id: string; title: string; url: string; kind: LinkKind } => !!l.url)
      .map(async ({ id, title, url, kind }): Promise<HealthCheck> => {
        try {
          const res = await fetch(url, { signal: withTimeout(undefined, timeoutMs) });
          await res.body?.cancel().catch(() => {});
          const type = res.headers.get("content-type") ?? "";
          const ok =
            kind === "image" ? res.ok && type.startsWith("image/") : kind === "page" ? res.ok : res.status < 500;
          return ok
            ? { id, status: "pass", title, detail: url }
            : {
                id,
                status: "warn",
                title,
                detail: `HTTP ${res.status}${kind === "image" && res.ok ? ` (${type || "no content-type"})` : ""} from ${url}`,
                hint: "Counterparties and registries show or call this URL. Fix it or remove the field, then re-sign.",
              };
        } catch (err) {
          return { id, status: "warn", title, detail: `${url}: ${message(err)}` };
        }
      }),
  );
}

function humanSeconds(seconds: number): string {
  if (seconds >= 86_400) return `${Math.round(seconds / 86_400)} days`;
  if (seconds >= 3_600) return `${Math.round(seconds / 3_600)} hours`;
  if (seconds >= 60) return `${Math.round(seconds / 60)} minutes`;
  return `${seconds} seconds`;
}

function message(err: unknown): string {
  if (err instanceof Error) {
    const cause = (err as Error & { cause?: unknown }).cause;
    return cause instanceof Error ? `${err.message} (${cause.message})` : err.message;
  }
  return String(err);
}
