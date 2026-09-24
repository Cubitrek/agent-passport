/**
 * Base64 helpers that run unchanged in Node 20+, Workers and browsers.
 */

/** Decode base64url or standard base64. Throws on characters outside both alphabets. */
export function base64ToBytes(s: string): Uint8Array {
  const cleaned = s
    .replace(/\s+/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .replace(/=+$/, "");
  if (!/^[A-Za-z0-9+/]*$/.test(cleaned) || cleaned.length % 4 === 1) {
    throw new TypeError("Invalid base64 or base64url input");
  }
  const bin = atob(cleaned + "=".repeat((4 - (cleaned.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Encode bytes as unpadded base64url, the form the spec uses for signatures and DNS keys. */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
