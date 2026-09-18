/**
 * Turn a verified passport into a decision about one inbound request:
 * allow, escalate to a human, or deny. This is spec §7 step 10 as code, so
 * every receiver applies the authority envelope the same way.
 *
 * Every decision is bound to the exact request it evaluated: a SHA-256
 * digest over the scope, amount, counterparty details and the concrete
 * action (tool, target, arguments), with a single-use nonce and an expiry.
 * The component that performs the side effect calls checkExecution() with
 * the final values immediately before acting, so an action whose target or
 * arguments changed after authorization is refused.
 */

import type {
  AgentPassport,
  PassportCompliance,
  VerificationError,
  VerifyResult,
} from "./types.js";
import { canonicalJson } from "./canonical.js";

export type DataClassification = NonNullable<PassportCompliance["dataClassification"]>;

/** The concrete operation the agent wants performed. */
export interface AuthorizedAction {
  /** Tool, API operation or MCP tool name, for example "payments.create_transfer". */
  tool: string;
  /** The resource the side effect lands on: an account, a URL, a record id. */
  target?: string;
  /** Arguments exactly as they will be executed. Plain JSON data only. */
  args?: unknown;
}

export interface AuthorizationRequest {
  /** The capability the agent is exercising, in subject.verb form. */
  scope: string;
  /** Value of this commitment. Omit for actions with no monetary value. */
  amount?: { amount: number; currency: string };
  /**
   * Value already committed under this passport, in the same currency.
   * Needed when spendCeiling.perEngagement is false (a cumulative ceiling).
   */
  priorSpend?: number;
  /** Your own domain, checked against the passport's counterparties rules. */
  counterpartyDomain?: string;
  /** Whether you publish a valid passport yourself. */
  counterpartyHasPassport?: boolean;
  /** ISO country code where the engagement happens. */
  region?: string;
  /** Most sensitive data the engagement will expose to the agent. */
  dataClassification?: DataClassification;
  /**
   * The exact action. It does not change the decision; it is bound into the
   * decision digest so checkExecution() can refuse a substituted action.
   */
  action?: AuthorizedAction;
}

export type Decision = "allow" | "escalate" | "deny";

export interface DecisionBinding {
  /** "sha256:<hex>" over the canonical request and the passport identity. */
  digest: string;
  /** Single-use value, claimed by checkExecution() when given a nonceStore. */
  nonce: string;
  issuedAt: string;
  /** checkExecution() refuses after this. */
  expiresAt: string;
}

export interface AuthorizationResult {
  decision: Decision;
  /** True only when decision is "allow". */
  allow: boolean;
  /** Why. Always at least one entry. */
  reasons: VerificationError[];
  /** The issuer's human contact, present whenever the answer is not "allow". */
  escalation?: { to: string; slaHours: number };
  agentId?: string;
  issuerDomain?: string;
  keyId?: string;
  evaluatedAt: string;
  /** Ties this decision to the exact request it evaluated. */
  binding: DecisionBinding;
}

export interface AuthorizeOptions {
  now?: () => Date;
  /**
   * How long an allow decision may be executed, in seconds. Default 60.
   * An escalation stays valid for the issuer's humanInLoop.slaHours (and at
   * least this long), so the person's confirmation applies to this exact
   * request.
   */
  ttlSeconds?: number;
}

/** Records nonces so a decision can be executed once. */
export interface NonceStore {
  /** Atomically record the nonce. Return false if it was already recorded. */
  claim(nonce: string, expiresAt: string): boolean | Promise<boolean>;
}

export interface ExecutionCheckOptions {
  now?: () => Date;
  /** Set when a person at the issuer confirmed an escalated decision. */
  humanApproved?: boolean;
  /** Enforces single use. Without one, the same decision can pass more than once. */
  nonceStore?: NonceStore;
}

export type ExecutionCheckResult =
  | { ok: true }
  | { ok: false; errors: VerificationError[] };

const DIGEST_CONTEXT = "agent-passport-decision-v1";
const DEFAULT_TTL_SECONDS = 60;

const CLASSIFICATION_RANK: Record<DataClassification, number> = {
  public: 0,
  internal: 1,
  "confidential-business": 2,
  "regulated-pii": 3,
};

export async function authorize(
  verification: VerifyResult,
  request: AuthorizationRequest,
  opts: AuthorizeOptions = {},
): Promise<AuthorizationResult> {
  const now = (opts.now ?? (() => new Date()))();
  const evaluatedAt = now.toISOString();
  // Only a verified passport's contents are trusted: an unverified one could
  // name any agent and any escalation contact.
  const passport = verification.ok ? verification.passport : undefined;
  const identity = {
    issuerDomain: passport?.issuer.domain,
    agentId: passport?.agent.id,
    keyId: passport?.signature.keyId,
  };

  let decision: Decision;
  let reasons: VerificationError[];
  if (!verification.ok || !passport) {
    decision = "deny";
    reasons = [
      {
        code: "passport.unverified",
        message: "The passport did not verify, so it grants no authority.",
        hint: verification.ok ? undefined : verification.errors.map((e) => e.code).join(", "),
      },
    ];
  } else {
    const denials: VerificationError[] = [];
    const escalations: VerificationError[] = [];
    checkScope(passport, request, denials);
    checkCounterparty(passport, request, denials);
    checkCompliance(passport, request, denials);
    checkAmount(passport, request, denials, escalations);
    decision = denials.length ? "deny" : escalations.length ? "escalate" : "allow";
    reasons =
      decision === "allow"
        ? [
            {
              code: "authority.within-envelope",
              message: `${request.scope} is within the authority ${passport.issuer.displayName} published for this agent.`,
            },
          ]
        : [...denials, ...escalations];
  }

  const ttl = opts.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  const lifetime =
    decision === "escalate" && passport
      ? Math.max(ttl, passport.authority.humanInLoop.slaHours * 3600)
      : ttl;

  return {
    decision,
    allow: decision === "allow",
    reasons,
    escalation:
      decision === "allow" || !passport
        ? undefined
        : {
            to: passport.authority.humanInLoop.escalation,
            slaHours: passport.authority.humanInLoop.slaHours,
          },
    ...identity,
    evaluatedAt,
    binding: {
      digest: await requestDigest(identity, request),
      nonce: crypto.randomUUID(),
      issuedAt: evaluatedAt,
      expiresAt: new Date(now.getTime() + lifetime * 1000).toISOString(),
    },
  };
}

/**
 * Run immediately before the side effect, with the final values that will
 * be executed. Refuses when the decision was not an allow (or an escalation
 * a person confirmed), has expired, was already used, or was made for a
 * different request: another scope, amount, counterparty, tool, target or
 * arguments.
 */
export async function checkExecution(
  decision: AuthorizationResult,
  request: AuthorizationRequest,
  opts: ExecutionCheckOptions = {},
): Promise<ExecutionCheckResult> {
  if (!decision.binding) {
    return {
      ok: false,
      errors: [{ code: "execution.unbound", message: "The decision carries no binding to check against." }],
    };
  }
  const now = (opts.now ?? (() => new Date()))().getTime();
  const errors: VerificationError[] = [];

  if (decision.decision === "deny") {
    errors.push({ code: "execution.denied", message: "The decision was deny." });
  }
  if (decision.decision === "escalate" && !opts.humanApproved) {
    errors.push({
      code: "execution.needs-human",
      message: `A person at the issuer must confirm first${decision.escalation ? ` (${decision.escalation.to})` : ""}.`,
    });
  }
  if (Date.parse(decision.binding.expiresAt) <= now) {
    errors.push({
      code: "execution.expired",
      message: `The decision expired at ${decision.binding.expiresAt}. Authorize the final request again.`,
    });
  }
  const identity = {
    issuerDomain: decision.issuerDomain,
    agentId: decision.agentId,
    keyId: decision.keyId,
  };
  if ((await requestDigest(identity, request)) !== decision.binding.digest) {
    errors.push({
      code: "execution.request-changed",
      message:
        "This is not the request that was authorized: the scope, amount, counterparty, tool, target or arguments changed.",
    });
  }
  if (errors.length) return { ok: false, errors };

  if (opts.nonceStore && !(await opts.nonceStore.claim(decision.binding.nonce, decision.binding.expiresAt))) {
    return {
      ok: false,
      errors: [{ code: "execution.replayed", message: "This decision was already used." }],
    };
  }
  return { ok: true };
}

/**
 * A nonce store for a single process. Executors spread across processes or
 * machines need a shared store with an atomic insert, such as Redis SET NX.
 */
export function memoryNonceStore(): NonceStore {
  const claimed = new Map<string, number>();
  return {
    claim(nonce, expiresAt) {
      const now = Date.now();
      for (const [n, expiry] of claimed) if (expiry <= now) claimed.delete(n);
      if (claimed.has(nonce)) return false;
      claimed.set(nonce, Date.parse(expiresAt));
      return true;
    },
  };
}

async function requestDigest(
  identity: { issuerDomain?: string; agentId?: string; keyId?: string },
  request: AuthorizationRequest,
): Promise<string> {
  const material = canonicalJson({
    context: DIGEST_CONTEXT,
    passport: identity,
    request: {
      scope: request.scope,
      amount: request.amount
        ? { amount: request.amount.amount, currency: request.amount.currency.toUpperCase() }
        : undefined,
      priorSpend: request.priorSpend,
      counterpartyDomain: request.counterpartyDomain?.trim().toLowerCase().replace(/\.$/, ""),
      counterpartyHasPassport: request.counterpartyHasPassport,
      region: request.region?.toUpperCase(),
      dataClassification: request.dataClassification,
      action: request.action
        ? { tool: request.action.tool, target: request.action.target, args: request.action.args }
        : undefined,
    },
  });
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(material) as unknown as BufferSource,
  );
  return `sha256:${[...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

function checkScope(
  passport: AgentPassport,
  request: AuthorizationRequest,
  denials: VerificationError[],
): void {
  if (!passport.authority.scope.includes(request.scope)) {
    denials.push({
      code: "scope.not-granted",
      message: `The passport does not grant ${request.scope}. Granted: ${passport.authority.scope.join(", ")}.`,
    });
  }
}

function checkCounterparty(
  passport: AgentPassport,
  request: AuthorizationRequest,
  denials: VerificationError[],
): void {
  const rules = passport.counterparties ?? {};
  const openTo = rules.openTo ?? "verified-passports";
  const domain = request.counterpartyDomain?.trim().toLowerCase().replace(/\.$/, "");
  const listed = (list?: string[]) =>
    !!domain && (list ?? []).some((d) => d.toLowerCase() === domain);

  if (listed(rules.blocklist)) {
    denials.push({
      code: "counterparty.blocked",
      message: `${domain} is on this agent's blocklist.`,
    });
  }
  if (openTo === "allowlist-only" && !listed(rules.allowlist)) {
    denials.push({
      code: "counterparty.not-allowlisted",
      message: domain
        ? `This agent only engages allowlisted domains, and ${domain} is not one.`
        : "This agent only engages allowlisted domains; pass counterpartyDomain to check.",
    });
  }
  if (openTo === "verified-passports" && request.counterpartyHasPassport === false) {
    denials.push({
      code: "counterparty.passport-required",
      message: "This agent only engages counterparties that publish a valid Agent Passport.",
    });
  }
}

function checkCompliance(
  passport: AgentPassport,
  request: AuthorizationRequest,
  denials: VerificationError[],
): void {
  const compliance = passport.compliance ?? {};
  if (request.region && compliance.regions) {
    const region = request.region.toUpperCase();
    if (!compliance.regions.includes(region)) {
      denials.push({
        code: "region.not-cleared",
        message: `The agent is not cleared to operate in ${region}. Cleared: ${compliance.regions.join(", ")}.`,
      });
    }
  }
  if (request.dataClassification && compliance.dataClassification) {
    if (
      CLASSIFICATION_RANK[request.dataClassification] >
      CLASSIFICATION_RANK[compliance.dataClassification]
    ) {
      denials.push({
        code: "data.classification-exceeds",
        message: `The engagement involves ${request.dataClassification} data; the agent is cleared for ${compliance.dataClassification} at most.`,
      });
    }
  }
}

function checkAmount(
  passport: AgentPassport,
  request: AuthorizationRequest,
  denials: VerificationError[],
  escalations: VerificationError[],
): void {
  if (!request.amount) return;
  const { amount, currency } = request.amount;
  const { spendCeiling, humanInLoop } = passport.authority;
  const fmt = (n: number, c: string) => `${n.toLocaleString("en-US")} ${c}`;

  if (currency !== spendCeiling.currency) {
    escalations.push({
      code: "amount.currency-unsupported",
      message: `The spend ceiling is in ${spendCeiling.currency}, not ${currency}; a human must confirm the conversion.`,
    });
    return;
  }

  let committed = amount;
  if (!spendCeiling.perEngagement) {
    if (request.priorSpend === undefined) {
      escalations.push({
        code: "amount.cumulative-unknown",
        message: "The spend ceiling is cumulative across engagements; pass priorSpend so it can be checked.",
      });
      return;
    }
    committed += request.priorSpend;
  }

  if (committed > spendCeiling.amount) {
    denials.push({
      code: "amount.above-ceiling",
      message: `${fmt(committed, currency)} exceeds the ${fmt(spendCeiling.amount, currency)} ceiling. Only a human at the issuer can commit to this.`,
    });
  } else if (humanInLoop.above.currency !== currency) {
    escalations.push({
      code: "amount.currency-unsupported",
      message: `The human-in-the-loop threshold is in ${humanInLoop.above.currency}, not ${currency}.`,
    });
  } else if (amount > humanInLoop.above.amount) {
    escalations.push({
      code: "amount.above-human-threshold",
      message: `${fmt(amount, currency)} is above the ${fmt(humanInLoop.above.amount, currency)} threshold, so a human at the issuer must confirm before commitment.`,
    });
  }
}
