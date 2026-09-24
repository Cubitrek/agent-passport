/**
 * HTTP Message Signatures (RFC 9421) over Ed25519, covering what Agent
 * Passport needs: an agent signs the request it sends, and the receiver
 * checks that signature against a key the issuer published in its passport.
 *
 * This is the piece that ties a live caller to a passport. Verifying a
 * passport proves what a company authorised; verifying the request proves
 * the call came from the agent that passport describes.
 *
 * Scope: Ed25519 only, the derived components an HTTP request needs, and
 * strict parsing of the Signature-Input and Signature fields. Signature
 * bases are built per RFC 9421 §2.5 and are interoperable with other
 * implementations (the tests check against the RFC's own Ed25519 example).
 */

import type { VerificationError } from "./types.js";
import type { NonceStore } from "./authorize.js";
import { base64ToBytes } from "./encoding.js";

export interface SignableRequest {
  method: string;
  /** Absolute URL, for example https://agents.globex.example/orders?x=1 */
  url: string;
  headers?: Headers | Record<string, string | string[]>;
  body?: Uint8Array | string | null;
}

export interface SignatureParams {
  created?: number;
  expires?: number;
  keyid?: string;
  alg?: string;
  nonce?: string;
  tag?: string;
}

export interface SignHttpRequestOptions {
  keyId: string;
  /** PKCS#8 DER bytes or a WebCrypto Ed25519 private key. */
  privateKey: Uint8Array | CryptoKey;
  /** Defaults to method, authority, path, query, and content-digest when there is a body. */
  components?: string[];
  label?: string;
  tag?: string;
  created?: Date;
  /** Default 60. */
  expiresInSeconds?: number;
  nonce?: string;
}

/** Headers to add to the outgoing request. */
export interface SignedRequestHeaders {
  "content-digest"?: string;
  "signature-input": string;
  signature: string;
}

export interface VerifyHttpRequestOptions {
  /** Return the public key for this key id (raw 32-byte or SPKI, base64 or base64url), or null. */
  resolveKey: (keyId: string, alg: string) => string | null | Promise<string | null>;
  now?: () => Date;
  /** Longest signature lifetime accepted, in seconds. Default 300. */
  maxAgeSeconds?: number;
  /** Tolerance for a `created` slightly in the future, in seconds. Default 5. */
  clockSkewSeconds?: number;
  /** Components that must be covered. Defaults to method, authority, path. */
  requiredComponents?: string[];
  /** Only accept signatures carrying this tag parameter. */
  requireTag?: string;
  /** Enforces single use of the nonce parameter. */
  nonceStore?: NonceStore;
}

export type HttpSignatureResult =
  | { ok: true; label: string; keyId: string; nonce?: string }
  | { ok: false; errors: VerificationError[] };

const DEFAULT_MAX_AGE_SECONDS = 300;
const DEFAULT_CLOCK_SKEW_SECONDS = 5;
const DEFAULT_EXPIRES_IN_SECONDS = 60;
const BASE_COMPONENTS = ["@method", "@authority", "@path", "@query"];

interface NormalizedMessage {
  method: string;
  url: URL;
  headers: Headers;
  body: Uint8Array | null;
}

export async function signHttpRequest(
  request: SignableRequest,
  opts: SignHttpRequestOptions,
): Promise<SignedRequestHeaders> {
  const message = normalize(request);
  const headers: SignedRequestHeaders = {
    "signature-input": "",
    signature: "",
  };

  if (message.body && message.body.byteLength > 0) {
    const digest = await contentDigest(message.body);
    headers["content-digest"] = digest;
    message.headers.set("content-digest", digest);
  }

  const components =
    opts.components ??
    (headers["content-digest"] ? [...BASE_COMPONENTS, "content-digest"] : [...BASE_COMPONENTS]);
  const created = Math.floor((opts.created ?? new Date()).getTime() / 1000);
  const params: SignatureParams = {
    created,
    expires: created + (opts.expiresInSeconds ?? DEFAULT_EXPIRES_IN_SECONDS),
    keyid: opts.keyId,
    alg: "ed25519",
    nonce: opts.nonce ?? crypto.randomUUID(),
    ...(opts.tag ? { tag: opts.tag } : {}),
  };

  const serializedParams = serializeParams(components, params);
  const base = buildSignatureBaseFromRaw(message, components, serializedParams);
  const key =
    opts.privateKey instanceof Uint8Array
      ? await crypto.subtle.importKey(
          "pkcs8",
          opts.privateKey as unknown as BufferSource,
          { name: "Ed25519" },
          false,
          ["sign"],
        )
      : opts.privateKey;
  const signature = new Uint8Array(
    await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(base) as unknown as BufferSource),
  );

  const label = opts.label ?? "ap";
  headers["signature-input"] = `${label}=${serializedParams}`;
  headers.signature = `${label}=:${bytesToBase64(signature)}:`;
  return headers;
}

export async function verifyHttpRequest(
  request: SignableRequest,
  opts: VerifyHttpRequestOptions,
): Promise<HttpSignatureResult> {
  const message = normalize(request);
  const now = (opts.now ?? (() => new Date()))().getTime() / 1000;
  const maxAge = opts.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;
  const skew = opts.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;

  const inputHeader = message.headers.get("signature-input");
  const signatureHeader = message.headers.get("signature");
  if (!inputHeader || !signatureHeader) {
    return fail("httpsig.missing", "The request carries no Signature-Input and Signature headers.");
  }

  let inputs: Map<string, { components: string[]; params: SignatureParams; raw: string }>;
  let signatures: Map<string, Uint8Array>;
  try {
    inputs = parseSignatureInput(inputHeader);
    signatures = parseSignature(signatureHeader);
  } catch (err) {
    return fail("httpsig.malformed", `Signature headers could not be parsed: ${message2(err)}`);
  }

  const candidates = [...inputs.entries()].filter(
    ([, input]) => !opts.requireTag || input.params.tag === opts.requireTag,
  );
  if (!candidates.length) {
    return fail(
      "httpsig.missing",
      opts.requireTag
        ? `No signature carries tag="${opts.requireTag}".`
        : "No signature was found on the request.",
    );
  }

  const errors: VerificationError[] = [];
  for (const [label, input] of candidates) {
    const result = await verifyOne(message, label, input, signatures.get(label), { now, maxAge, skew }, opts);
    if (result.ok) return result;
    errors.push(...result.errors);
  }
  return { ok: false, errors };
}

async function verifyOne(
  message: NormalizedMessage,
  label: string,
  input: { components: string[]; params: SignatureParams; raw: string },
  signature: Uint8Array | undefined,
  clock: { now: number; maxAge: number; skew: number },
  opts: VerifyHttpRequestOptions,
): Promise<HttpSignatureResult> {
  const errors: VerificationError[] = [];
  const { components, params } = input;

  if (!signature) {
    return fail("httpsig.malformed", `Signature-Input has label "${label}" but the Signature field does not.`);
  }

  const required = opts.requiredComponents ?? ["@method", "@authority", "@path"];
  const missing = required.filter((c) => !components.includes(c));
  const hasBody = !!message.body && message.body.byteLength > 0;
  if (hasBody && !components.includes("content-digest")) missing.push("content-digest");
  if (missing.length) {
    errors.push({
      code: "httpsig.weak-coverage",
      message: `The signature does not cover ${missing.join(", ")}, so those parts of the request are unprotected.`,
    });
  }

  if (hasBody) {
    const expected = await contentDigest(message.body as Uint8Array);
    const sent = message.headers.get("content-digest");
    if (!sent || !digestMatches(sent, expected)) {
      errors.push({
        code: "httpsig.digest-mismatch",
        message: "Content-Digest does not match the body, so the body changed in transit.",
      });
    }
  }

  if (params.created === undefined) {
    errors.push({ code: "httpsig.malformed", message: "The signature has no created parameter." });
  } else if (params.created > clock.now + clock.skew) {
    errors.push({ code: "httpsig.created-in-future", message: "The signature was created in the future." });
  } else if (params.expires === undefined && clock.now - params.created > clock.maxAge) {
    errors.push({
      code: "httpsig.expired",
      message: `The signature is older than the ${clock.maxAge} seconds allowed.`,
    });
  }
  if (params.expires !== undefined) {
    if (params.expires <= clock.now) {
      errors.push({ code: "httpsig.expired", message: "The signature has expired." });
    } else if (params.created !== undefined && params.expires - params.created > clock.maxAge) {
      errors.push({
        code: "httpsig.lifetime-too-long",
        message: `The signature is valid for longer than the ${clock.maxAge} seconds allowed.`,
      });
    }
  }

  const keyId = params.keyid;
  if (!keyId) {
    errors.push({ code: "httpsig.no-key-id", message: "The signature has no keyid parameter." });
  }
  const alg = params.alg ?? "ed25519";
  if (alg !== "ed25519") {
    errors.push({ code: "httpsig.alg-unsupported", message: `Only ed25519 is supported, not ${alg}.` });
  }

  if (errors.length) return { ok: false, errors };

  const publicKey = await opts.resolveKey(keyId as string, alg);
  if (!publicKey) {
    return fail("httpsig.unknown-key", `No published key matches keyid="${keyId}".`);
  }

  const base = buildSignatureBaseFromRaw(message, components, input.raw);
  let valid = false;
  try {
    const key = await importEd25519PublicKey(base64ToBytes(publicKey));
    valid = await crypto.subtle.verify(
      "Ed25519",
      key,
      signature as unknown as BufferSource,
      new TextEncoder().encode(base) as unknown as BufferSource,
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    return fail(
      "httpsig.invalid",
      "The request signature does not verify: the method, target, headers or body are not what was signed.",
    );
  }

  if (opts.nonceStore) {
    if (!params.nonce) {
      return fail("httpsig.no-nonce", "Single use is required, but the signature has no nonce parameter.");
    }
    const expiresAt = new Date(
      (params.expires ?? (params.created as number) + clock.maxAge) * 1000,
    ).toISOString();
    if (!(await opts.nonceStore.claim(`httpsig:${params.nonce}`, expiresAt))) {
      return fail("httpsig.replayed", "This signed request was already accepted.");
    }
  }

  return { ok: true, label, keyId: keyId as string, nonce: params.nonce };
}

/** The exact bytes that are signed (RFC 9421 §2.5), for tests and for interop work. */
export function buildSignatureBase(
  request: SignableRequest,
  components: string[],
  params: SignatureParams,
): string {
  return buildSignatureBaseFromRaw(normalize(request), components, serializeParams(components, params));
}

function buildSignatureBaseFromRaw(
  message: NormalizedMessage,
  components: string[],
  rawParams: string,
): string {
  const lines = components.map((component) => `"${component}": ${componentValue(message, component)}`);
  lines.push(`"@signature-params": ${rawParams}`);
  return lines.join("\n");
}

function componentValue(message: NormalizedMessage, component: string): string {
  switch (component) {
    case "@method":
      return message.method.toUpperCase();
    case "@authority":
      return message.url.host.toLowerCase();
    case "@path":
      return message.url.pathname || "/";
    case "@query":
      return message.url.search === "" ? "?" : message.url.search;
    case "@target-uri":
      return message.url.toString();
    case "@scheme":
      return message.url.protocol.replace(/:$/, "");
    default: {
      if (component.startsWith("@")) {
        throw new Error(`Unsupported derived component ${component}`);
      }
      const value = message.headers.get(component);
      if (value === null) throw new Error(`The request has no ${component} header`);
      return value
        .split(",")
        .map((part) => part.trim())
        .join(", ");
    }
  }
}

function serializeParams(components: string[], params: SignatureParams): string {
  const list = `(${components.map((c) => `"${c}"`).join(" ")})`;
  const parts: string[] = [];
  if (params.created !== undefined) parts.push(`created=${params.created}`);
  if (params.expires !== undefined) parts.push(`expires=${params.expires}`);
  if (params.keyid !== undefined) parts.push(`keyid="${params.keyid}"`);
  if (params.alg !== undefined) parts.push(`alg="${params.alg}"`);
  if (params.nonce !== undefined) parts.push(`nonce="${params.nonce}"`);
  if (params.tag !== undefined) parts.push(`tag="${params.tag}"`);
  return parts.length ? `${list};${parts.join(";")}` : list;
}

export function parseSignatureInput(
  header: string,
): Map<string, { components: string[]; params: SignatureParams; raw: string }> {
  const out = new Map<string, { components: string[]; params: SignatureParams; raw: string }>();
  for (const entry of splitTopLevel(header)) {
    const eq = entry.indexOf("=");
    if (eq < 1) throw new Error(`bad Signature-Input entry: ${entry}`);
    const label = entry.slice(0, eq).trim();
    const raw = entry.slice(eq + 1).trim();
    const close = raw.indexOf(")");
    if (!raw.startsWith("(") || close < 0) throw new Error(`bad component list for ${label}`);
    const components = (raw.slice(1, close).match(/"[^"]*"/g) ?? []).map((c) => c.slice(1, -1));
    const params: SignatureParams = {};
    for (const part of raw.slice(close + 1).split(";")) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      const split = trimmed.indexOf("=");
      if (split < 1) continue;
      const name = trimmed.slice(0, split).trim();
      const value = trimmed.slice(split + 1).trim();
      const unquoted = value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
      if (name === "created" || name === "expires") {
        const n = Number(unquoted);
        if (!Number.isFinite(n)) throw new Error(`bad ${name} parameter`);
        params[name] = n;
      } else if (name === "keyid" || name === "alg" || name === "nonce" || name === "tag") {
        params[name] = unquoted;
      }
    }
    out.set(label, { components, params, raw });
  }
  return out;
}

export function parseSignature(header: string): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  for (const entry of splitTopLevel(header)) {
    const eq = entry.indexOf("=");
    if (eq < 1) throw new Error(`bad Signature entry: ${entry}`);
    const label = entry.slice(0, eq).trim();
    const value = entry.slice(eq + 1).trim();
    if (!value.startsWith(":") || !value.endsWith(":")) throw new Error(`bad byte sequence for ${label}`);
    out.set(label, base64ToBytes(value.slice(1, -1)));
  }
  return out;
}

/** Split a structured field on top-level commas, ignoring commas inside quotes. */
function splitTopLevel(header: string): string[] {
  const parts: string[] = [];
  let current = "";
  let inQuotes = false;
  for (const char of header) {
    if (char === '"') inQuotes = !inQuotes;
    if (char === "," && !inQuotes) {
      parts.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  if (current.trim()) parts.push(current);
  return parts.map((p) => p.trim()).filter(Boolean);
}

export async function contentDigest(body: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", body as unknown as BufferSource);
  return `sha-256=:${bytesToBase64(new Uint8Array(hash))}:`;
}

function digestMatches(sent: string, expected: string): boolean {
  // A sender may list several algorithms; accept when the sha-256 entry matches.
  return sent
    .split(",")
    .map((part) => part.trim())
    .some((part) => part === expected);
}

function normalize(request: SignableRequest): NormalizedMessage {
  const headers =
    request.headers instanceof Headers
      ? new Headers(request.headers)
      : new Headers(
          Object.entries(request.headers ?? {}).flatMap(([name, value]) =>
            Array.isArray(value) ? value.map((v) => [name, v] as [string, string]) : [[name, value] as [string, string]],
          ),
        );
  const body =
    typeof request.body === "string"
      ? new TextEncoder().encode(request.body)
      : request.body instanceof Uint8Array
        ? request.body
        : null;
  return { method: request.method, url: new URL(request.url), headers, body };
}

async function importEd25519PublicKey(bytes: Uint8Array): Promise<CryptoKey> {
  const prefix = new Uint8Array([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
  ]);
  let data: Uint8Array;
  if (bytes.length === 32) {
    data = new Uint8Array(prefix.length + bytes.length);
    data.set(prefix, 0);
    data.set(bytes, prefix.length);
  } else {
    data = bytes;
  }
  return crypto.subtle.importKey("spki", data as unknown as BufferSource, { name: "Ed25519" }, true, [
    "verify",
  ]);
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function fail(code: string, message: string): HttpSignatureResult {
  return { ok: false, errors: [{ code, message }] };
}

function message2(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
