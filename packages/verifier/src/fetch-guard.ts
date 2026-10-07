/**
 * What a stranger's document is allowed to make us fetch.
 *
 * A passport is written by whoever we are checking, and several of its fields
 * are URLs this library then requests: the revocation list, the logo, the
 * terms, the contact page, the agent's endpoints. Left alone that turns every
 * verifier into an errand boy for anyone who can get their passport looked at,
 * and the errands worth running are the ones a server can reach and the
 * internet cannot: cloud metadata, a database on localhost, an admin page on
 * the private network.
 *
 * So a URL out of a passport has to clear this before anything fetches it.
 * The checks are deliberately the portable ones, because the library runs in
 * Workers and browsers where no name resolution is available. A hostname that
 * resolves to a private address still gets through, which is why the docs tell
 * anyone running this server-side to filter egress as well.
 */

import type { VerificationError } from "./types.js";

/** Hosts that are never a legitimate destination for a published URL. */
const BLOCKED_NAMES = new Set(["localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"]);
const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa"];

function isPrivateIPv4(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  const octets = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : Number.NaN));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = octets as [number, number, number, number];
  return (
    a === 0 || // this network
    a === 10 || // private
    a === 127 || // loopback
    (a === 169 && b === 254) || // link local, and cloud metadata
    (a === 172 && b >= 16 && b <= 31) || // private
    (a === 192 && b === 168) || // private
    (a === 100 && b >= 64 && b <= 127) || // carrier grade NAT
    (a === 192 && b === 0) || // IETF protocol assignments
    a === 198 || // benchmarking and test nets
    (a >= 224) // multicast, reserved, broadcast
  );
}

function isPrivateIPv6(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "::1" || h === "::" || h === "0:0:0:0:0:0:0:1") return true;
  if (h.startsWith("fc") || h.startsWith("fd")) return true; // unique local
  if (h.startsWith("fe8") || h.startsWith("fe9") || h.startsWith("fea") || h.startsWith("feb")) return true; // link local
  // An IPv4 address wearing an IPv6 hat. The URL parser rewrites the dotted
  // form into hex, so ::ffff:127.0.0.1 arrives as ::ffff:7f00:1 and both
  // spellings have to be understood.
  const dotted = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(h);
  if (dotted) return isPrivateIPv4(dotted[1]!);
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
  if (hex) {
    const high = Number.parseInt(hex[1]!, 16);
    const low = Number.parseInt(hex[2]!, 16);
    return isPrivateIPv4(`${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`);
  }
  return false;
}

export interface FetchGuardOptions {
  /** Which field this came from, so the refusal says where to look. */
  field: string;
  /** When set, the URL's host has to sit inside this domain. */
  withinDomain?: string;
}

/**
 * Decide whether a URL taken out of someone else's document may be fetched.
 * Returns the reason it may not, or null when it is fine.
 */
export function checkFetchable(raw: string, opts: FetchGuardOptions): VerificationError | null {
  const refuse = (code: string, message: string, hint?: string): VerificationError => ({
    code,
    message: `${opts.field}: ${message}`,
    hint,
  });

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return refuse("url.malformed", `"${raw}" is not a URL.`);
  }

  // https only. http is eavesdroppable, and file, data, gopher and the rest
  // are not destinations a published document has any business naming.
  if (url.protocol !== "https:") {
    return refuse(
      "url.not-https",
      `"${raw}" is not https.`,
      "A published URL has to be https, so that what comes back is the document the issuer meant.",
    );
  }

  const host = url.hostname.toLowerCase();
  if (BLOCKED_NAMES.has(host) || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) {
    return refuse("url.private-host", `"${host}" is a local name, not a public one.`);
  }
  if (isPrivateIPv4(host) || isPrivateIPv6(host)) {
    return refuse(
      "url.private-host",
      `"${host}" is a private or loopback address.`,
      "A passport that names one is asking whoever verifies it to fetch something on their own network.",
    );
  }

  if (opts.withinDomain) {
    const within = opts.withinDomain.trim().toLowerCase().replace(/\.$/, "");
    if (!(host === within || host.endsWith(`.${within}`))) {
      return refuse(
        "url.outside-issuer-domain",
        `"${host}" is outside ${within}.`,
        "This document belongs to the issuer, so it has to be served from the issuer's own domain.",
      );
    }
  }
  return null;
}
