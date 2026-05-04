/**
 * TypeScript types for an Agent Passport, v0.1.
 *
 * These mirror the JSON Schema at schemas/agent-passport.schema.json. The
 * schema is the source of truth, these types are authored to match.
 */

export interface AgentPassport {
  version: "0.1.0";
  issuer: PassportIssuer;
  agent: PassportAgent;
  authority: PassportAuthority;
  counterparties?: PassportCounterparties;
  compliance?: PassportCompliance;
  issuedAt: string;
  expiresAt: string;
  revocationListUrl?: string;
  signature: PassportSignature;
}

export interface PassportIssuer {
  domain: string;
  legalName: string;
  displayName: string;
  logo?: string;
  signingKeyDns: string;
  contact?: { email?: string; url?: string };
}

export interface PassportAgent {
  id: string;
  displayName: string;
  purpose: string;
  model?: string;
  endpoints: { a2a?: string; mcp?: string; rest?: string };
}

export interface PassportAuthority {
  scope: string[];
  spendCeiling: { amount: number; currency: string; perEngagement: boolean };
  humanInLoop: {
    above: { amount: number; currency: string };
    escalation: string;
    slaHours: number;
  };
  decisionAudit: string;
  termsUrl?: string;
}

export interface PassportCounterparties {
  allowlist?: string[];
  blocklist?: string[];
  openTo?: "any" | "verified-passports" | "allowlist-only";
}

export interface PassportCompliance {
  dataClassification?:
    | "public"
    | "internal"
    | "confidential-business"
    | "regulated-pii";
  regions?: string[];
  subprocessors?: string[];
  humanReviewLog?: boolean;
}

export interface PassportSignature {
  alg: "ed25519";
  keyId: string;
  value: string;
}

export type ValidateResult =
  | { ok: true; passport: AgentPassport }
  | { ok: false; errors: VerificationError[] };

export type VerifyResult =
  | {
      ok: true;
      passport: AgentPassport;
      warnings: VerificationError[];
    }
  | {
      ok: false;
      errors: VerificationError[];
      warnings: VerificationError[];
      passport?: AgentPassport;
    };

export interface VerificationError {
  code: string;
  message: string;
  hint?: string;
}

/**
 * Strategy for getting the Ed25519 public key used to sign the passport.
 *
 *  - "dns": fetch the DNS TXT record at issuer.signingKeyDns. Default.
 *  - "trust-on-first-use": call the supplied resolver with the keyId; the
 *    caller can return a cached key.
 *  - { publicKeyB64: string }: provide a key directly. Useful in tests.
 */
export type SignerKeyResolver =
  | "dns"
  | { publicKeyB64: string }
  | ((args: {
      issuerDomain: string;
      signingKeyDns: string;
      keyId: string;
    }) => Promise<string | null>);

export interface VerifyOptions {
  /** Either a domain (we fetch /.well-known/agent-passport.json) or a parsed passport object. */
  domain?: string;
  passport?: unknown;
  /** How to resolve the issuer's Ed25519 public key. Default "dns". */
  resolveSignerPublicKey?: SignerKeyResolver;
  /** Whether to fetch and check revocationListUrl. Default true. */
  checkRevocation?: boolean;
  /** AbortSignal forwarded to fetch calls. */
  signal?: AbortSignal;
  /** Override `now` for tests. */
  now?: () => Date;
}
