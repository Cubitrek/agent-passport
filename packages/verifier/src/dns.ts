/**
 * DNS TXT record lookup for the issuer's Ed25519 public key.
 *
 * Per spec §6, issuers publish:
 *   _agent-passport.{domain}. IN TXT "v=ap1; kid=<kid>; alg=ed25519; pk=<base64>"
 *
 * We default to Cloudflare's DNS-over-HTTPS so this verifier works in
 * Workers, browsers, and Node without pulling node:dns.
 */

import type { VerificationError } from "./types.js";

const DOH_URL = "https://cloudflare-dns.com/dns-query";

interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface SigningKeyRecord {
  v: string;
  kid: string;
  alg: string;
  pk: string;
}

export async function fetchSigningKeys(args: {
  signingKeyDns: string;
  signal?: AbortSignal;
}): Promise<{ records: SigningKeyRecord[]; errors: VerificationError[] }> {
  const url = `${DOH_URL}?name=${encodeURIComponent(args.signingKeyDns)}&type=TXT`;
  let res: Response;
  try {
    res = await fetch(url, {
      headers: { accept: "application/dns-json" },
      signal: args.signal,
    });
  } catch (err) {
    return {
      records: [],
      errors: [
        {
          code: "dns.fetch-failed",
          message: `DNS-over-HTTPS request to ${args.signingKeyDns} failed`,
          hint: err instanceof Error ? err.message : String(err),
        },
      ],
    };
  }
  if (!res.ok) {
    return {
      records: [],
      errors: [
        {
          code: "dns.fetch-non-2xx",
          message: `DNS-over-HTTPS returned ${res.status} for ${args.signingKeyDns}`,
        },
      ],
    };
  }
  const body = (await res.json()) as { Answer?: DohAnswer[] };
  const answers = body.Answer ?? [];
  const records: SigningKeyRecord[] = [];
  for (const a of answers) {
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
    return {
      records,
      errors: [
        {
          code: "dns.no-records",
          message: `No agent-passport TXT records found at ${args.signingKeyDns}`,
          hint: "Issuer must publish a TXT record like: v=ap1; kid=...; alg=ed25519; pk=...",
        },
      ],
    };
  }
  return { records, errors: [] };
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
