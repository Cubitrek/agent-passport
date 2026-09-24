/**
 * DNS TXT record lookup for the issuer's Ed25519 public key.
 *
 * Per spec §6, issuers publish:
 *   _agent-passport.{domain}. IN TXT "v=ap1; kid=<kid>; alg=ed25519; pk=<base64url>"
 *
 * We default to Cloudflare's DNS-over-HTTPS so this verifier works in
 * Workers, browsers, and Node without pulling node:dns.
 */

import type { VerificationError } from "./types.js";
import { readJsonCapped, withTimeout } from "./http.js";

const DOH_URL = "https://cloudflare-dns.com/dns-query";
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_DOH_BYTES = 64 * 1024;
const RCODE_NXDOMAIN = 3;
const RCODE_SERVFAIL = 2;

interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DohResponse {
  Status?: number;
  AD?: boolean;
  Answer?: DohAnswer[];
}

export interface SigningKeyRecord {
  v: string;
  kid: string;
  alg: string;
  pk: string;
}

export interface SigningKeyLookup {
  records: SigningKeyRecord[];
  errors: VerificationError[];
  /** True when the resolver reports the answer as DNSSEC-validated (the AD flag). */
  authenticated: boolean;
}

export async function fetchSigningKeys(args: {
  signingKeyDns: string;
  signal?: AbortSignal;
  timeoutMs?: number;
}): Promise<SigningKeyLookup> {
  const url = `${DOH_URL}?name=${encodeURIComponent(args.signingKeyDns)}&type=TXT`;
  const fail = (error: VerificationError): SigningKeyLookup => ({
    records: [],
    errors: [error],
    authenticated: false,
  });

  let body: DohResponse;
  try {
    const res = await fetch(url, {
      headers: { accept: "application/dns-json" },
      signal: withTimeout(args.signal, args.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
    if (!res.ok) {
      return fail({
        code: "dns.fetch-non-2xx",
        message: `DNS-over-HTTPS returned ${res.status} for ${args.signingKeyDns}`,
      });
    }
    body = (await readJsonCapped(res, MAX_DOH_BYTES)) as DohResponse;
    if (!body || typeof body !== "object") throw new Error("DNS-over-HTTPS response is not an object");
  } catch (err) {
    return fail({
      code: "dns.fetch-failed",
      message: `DNS-over-HTTPS request to ${args.signingKeyDns} failed`,
      hint: err instanceof Error ? err.message : String(err),
    });
  }

  if (body.Status && body.Status !== RCODE_NXDOMAIN) {
    return fail({
      code: "dns.rcode",
      message: `DNS lookup for ${args.signingKeyDns} failed with RCODE ${body.Status}`,
      hint:
        body.Status === RCODE_SERVFAIL
          ? "SERVFAIL often means DNSSEC validation failed for the issuer zone."
          : undefined,
    });
  }

  const records: SigningKeyRecord[] = [];
  for (const a of body.Answer ?? []) {
    if (a.type !== 16) continue;
    // TXT data comes back as a quoted string, possibly multiple chunks
    const raw = a.data
      .split(/"\s+"/)
      .map((s) => s.replace(/^"|"$/g, ""))
      .join("");
    const parsed = parseTxt(raw);
    if (parsed) records.push(parsed);
  }
  if (!records.length) {
    return fail({
      code: "dns.no-records",
      message: `No agent-passport TXT records found at ${args.signingKeyDns}`,
      hint: "Issuer must publish a TXT record like: v=ap1; kid=...; alg=ed25519; pk=...",
    });
  }
  return { records, errors: [], authenticated: body.AD === true };
}

function parseTxt(raw: string): SigningKeyRecord | null {
  const fields: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 1) continue;
    const k = trimmed.slice(0, eq).trim().toLowerCase();
    const v = trimmed.slice(eq + 1).trim();
    fields[k] = v;
  }
  if (fields.v !== "ap1" || !fields.kid || !fields.alg || !fields.pk) {
    return null;
  }
  return {
    v: fields.v,
    kid: fields.kid,
    alg: fields.alg,
    pk: fields.pk,
  };
}
