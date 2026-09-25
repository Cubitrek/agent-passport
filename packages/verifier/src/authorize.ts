/**
 * Turn an authority into a decision about one request: allow, escalate to a
 * person, or deny.
 *
 * `decide()` is the engine and takes an Authority, so the same rules apply
 * whether the permission came from a counterparty's published passport, from
 * a policy file on this machine, or from both at once. `authorize()` is the
 * passport-shaped front door onto it, and is spec §7 step 10 as code.
 *
 * Every decision is bound to the exact request it evaluated: a SHA-256
 * digest over the subject, the authority it came from, the scope, amount,
 * counterparty details and the concrete action (tool, target, arguments),
 * with a single-use nonce and an expiry. The component that performs the
 * side effect calls checkExecution() with the final values immediately
 * before acting, so an action whose target or arguments changed after
 * authorization is refused.
 */

import type { VerificationError, VerifyResult } from "./types.js";
import type {
  Authority,
  AuthorityCeiling,
  AuthorityOrigin,
  AuthoritySubject,
  DataClassification,
} from "./authority.js";
import { passportAuthority } from "./authority.js";
import type { SpendLedger } from "./ledger.js";
import { canonicalJson } from "./canonical.js";

export type { DataClassification };

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
   * Value already committed against the ceiling, in the same currency. Used
   * when no ledger is supplied; a ledger counts it for you.
   */
  priorSpend?: number;
  /** Your own domain, checked against the authority's counterparty rules. */
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
  /** "sha256:<hex>" over the canonical request, the subject and the authority. */
  digest: string;
  /** Single-use value, claimed by checkExecution() when given a nonceStore. */
  nonce: string;
  issuedAt: string;
  /** checkExecution() refuses after this. */
  expiresAt: string;
}

/** The money this decision puts at stake, and whether it is being held. */
export interface DecisionCharge {
  amount: number;
  currency: string;
  /** The ceilings this amount has to fit under. */
  ceilings: AuthorityCeiling[];
  engagementId?: string;
  /** True when a ledger is already holding the amount for this decision. */
  reserved: boolean;
}

export interface AuthorizationResult {
  decision: Decision;
  /** True only when decision is "allow". */
  allow: boolean;
  /** Why. Always at least one entry. */
  reasons: VerificationError[];
  /** The human contact, present whenever the answer is not "allow". */
  escalation?: { to: string; slaHours: number };
  /** Who is acting, as the authority names them. */
  subject: AuthoritySubject;
  /** Where the authority came from. */
  origin: AuthorityOrigin[];
  agentId?: string;
  issuerDomain?: string;
  keyId?: string;
  evaluatedAt: string;
  /** Ties this decision to the exact request it evaluated. */
  binding: DecisionBinding;
  /** Present when the request carries an amount. */
  charge?: DecisionCharge;
}

export interface DecideOptions {
  now?: () => Date;
  /**
   * How long an allow decision may be executed, in seconds. Default 60.
   * An escalation stays valid for the authority's slaHours (and at least
   * this long), so the person's confirmation applies to this exact request.
   */
  ttlSeconds?: number;
  /**
   * Counts spend and holds it. With one, ceilings are enforced against what
   * was actually committed rather than against a number the caller supplied.
   */
  ledger?: SpendLedger;
  /** Groups spend for a per-engagement ceiling. */
  engagementId?: string;
}

export type AuthorizeOptions = DecideOptions;

/** Records nonces so a decision can be executed once. */
export interface NonceStore {
  /** Atomically record the nonce. Return false if it was already recorded. */
  claim(nonce: string, expiresAt: string): boolean | Promise<boolean>;
}

export interface ExecutionCheckOptions {
  now?: () => Date;
  /** Set when the person named in the escalation confirmed this decision. */
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

/**
 * Decide one request against one authority.
 *
 * With a ledger, an allow also reserves the amount, so a second request
 * evaluated before the first one executes sees the money as already spoken
 * for. The reservation lapses when the decision expires, and guard() turns
 * it into spend or gives it back.
 */
export async function decide(
  authority: Authority,
  request: AuthorizationRequest,
  opts: DecideOptions = {},
): Promise<AuthorizationResult> {
  const now = (opts.now ?? (() => new Date()))();
  const evaluatedAt = now.toISOString();
  const engagementId = opts.engagementId;

  let decision: Decision;
  let reasons: VerificationError[];
  const denials: VerificationError[] = [];
  const escalations: VerificationError[] = [];

  if (authority.refusal) {
    decision = "deny";
    reasons = [authority.refusal];
  } else {
    checkScope(authority, request, denials);
    checkCounterparty(authority, request, denials);
    checkCompliance(authority, request, denials);
    await checkAmount(authority, request, denials, escalations, opts);
    decision = denials.length ? "deny" : escalations.length ? "escalate" : "allow";
    reasons =
      decision === "allow"
        ? [
            {
              code: "authority.within-envelope",
              message: `${request.scope} is within ${describeOrigin(authority)}.`,
            },
          ]
        : [...denials, ...escalations];
  }

  const ttl = opts.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  const lifetime =
    decision === "escalate" && authority.humanInLoop
      ? Math.max(ttl, authority.humanInLoop.slaHours * 3600)
      : ttl;
  const binding: DecisionBinding = {
    digest: await requestDigest(authority.subject, authority.origin, request),
    nonce: crypto.randomUUID(),
    issuedAt: evaluatedAt,
    expiresAt: new Date(now.getTime() + lifetime * 1000).toISOString(),
  };

  let charge: DecisionCharge | undefined;
  if (request.amount) {
    charge = {
      amount: request.amount.amount,
      currency: request.amount.currency.toUpperCase(),
      ceilings: authority.ceilings,
      engagementId,
      reserved: false,
    };
    // Hold the money only for a decision that could execute right now. An
    // escalation may sit for hours, so it reserves when the person confirms.
    if (decision === "allow" && opts.ledger) {
      const held = await opts.ledger.reserve({
        subject: authority.subject.agentId,
        amount: charge.amount,
        currency: charge.currency,
        ceilings: charge.ceilings,
        nonce: binding.nonce,
        expiresAt: binding.expiresAt,
        engagementId,
        at: now,
      });
      if (held.ok) charge.reserved = true;
      else {
        decision = "deny";
        reasons = [ceilingError(held.ceiling, held.wouldBe, held.prior)];
      }
    }
  }

  return {
    decision,
    allow: decision === "allow",
    reasons,
    escalation:
      decision === "allow" || !authority.humanInLoop
        ? undefined
        : { to: authority.humanInLoop.escalation, slaHours: authority.humanInLoop.slaHours },
    subject: authority.subject,
    origin: authority.origin,
    agentId: authority.refusal ? undefined : authority.subject.agentId,
    issuerDomain: authority.subject.issuerDomain,
    keyId: authority.subject.keyId,
    evaluatedAt,
    binding,
    charge,
  };
}

/**
 * Decide one request against a counterparty's passport. A verification that
 * failed denies everything, and its contents are not read: an unverified
 * passport could name any agent and any escalation contact.
 */
export async function authorize(
  verification: VerifyResult,
  request: AuthorizationRequest,
  opts: AuthorizeOptions = {},
): Promise<AuthorizationResult> {
  return decide(passportAuthority(verification), request, opts);
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
      message: `A person must confirm first${decision.escalation ? ` (${decision.escalation.to})` : ""}.`,
    });
  }
  if (Date.parse(decision.binding.expiresAt) <= now) {
    errors.push({
      code: "execution.expired",
      message: `The decision expired at ${decision.binding.expiresAt}. Authorize the final request again.`,
    });
  }
  const subject = decision.subject ?? {
    agentId: decision.agentId ?? "unknown",
    issuerDomain: decision.issuerDomain,
    keyId: decision.keyId,
  };
  // agentId, issuerDomain and keyId repeat what subject already says, for
  // callers that read them directly. Only subject is covered by the digest,
  // so a copy that disagrees with it means the decision was edited.
  const altered = (["agentId", "issuerDomain", "keyId"] as const).filter(
    (field) => decision[field] !== undefined && decision[field] !== subject[field],
  );
  if (altered.length) {
    errors.push({
      code: "execution.decision-altered",
      message: `The decision was changed after it was issued: ${altered.join(", ")} no longer matches the subject it was issued for.`,
    });
  }
  if ((await requestDigest(subject, decision.origin ?? [], request)) !== decision.binding.digest) {
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
 *
 * Expired entries are dropped using this store's own clock. Pass the same
 * `now` you pass to `checkExecution()` when you inject one, or entries from
 * an injected clock look expired and stop blocking reuse.
 */
export function memoryNonceStore(opts: { now?: () => Date } = {}): NonceStore {
  const claimed = new Map<string, number>();
  const clock = opts.now ?? (() => new Date());
  return {
    claim(nonce, expiresAt) {
      const now = clock().getTime();
      for (const [n, expiry] of claimed) if (expiry <= now) claimed.delete(n);
      if (claimed.has(nonce)) return false;
      claimed.set(nonce, Date.parse(expiresAt));
      return true;
    },
  };
}

function describeOrigin(authority: Authority): string {
  const labels = authority.origin.map((o) => o.label);
  if (!labels.length) return "the authority in force";
  if (labels.length === 1) return labels[0]!;
  return `${labels.join(" and ")}, both of which apply`;
}

export function ceilingError(
  ceiling: AuthorityCeiling,
  wouldBe: number,
  prior: number,
): VerificationError {
  const fmt = (n: number) => `${n.toLocaleString("en-US")} ${ceiling.currency}`;
  const period =
    ceiling.window === "engagement"
      ? "this engagement"
      : ceiling.window === "total"
        ? "in total"
        : `this ${ceiling.window}`;
  return {
    code: "amount.above-ceiling",
    message: `${fmt(wouldBe)} for ${period} exceeds ${fmt(ceiling.amount)} under ${ceiling.label}.`,
    hint: prior > 0 ? `${fmt(prior)} is already committed or held.` : undefined,
  };
}

async function requestDigest(
  subject: AuthoritySubject,
  origin: AuthorityOrigin[],
  request: AuthorizationRequest,
): Promise<string> {
  const material = canonicalJson({
    context: DIGEST_CONTEXT,
    subject: {
      agentId: subject.agentId,
      issuerDomain: subject.issuerDomain,
      keyId: subject.keyId,
    },
    origin: origin.map((o) => `${o.kind}:${o.id}`).sort(),
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
  authority: Authority,
  request: AuthorizationRequest,
  denials: VerificationError[],
): void {
  if (!authority.scope.includes(request.scope)) {
    denials.push({
      code: "scope.not-granted",
      message: `${describeOrigin(authority)} does not grant ${request.scope}. Granted: ${
        authority.scope.length ? authority.scope.join(", ") : "nothing"
      }.`,
    });
  }
}

function checkCounterparty(
  authority: Authority,
  request: AuthorizationRequest,
  denials: VerificationError[],
): void {
  const rules = authority.counterparties ?? {};
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
  authority: Authority,
  request: AuthorizationRequest,
  denials: VerificationError[],
): void {
  const compliance = authority.compliance ?? {};
  if (request.region && compliance.regions) {
    const region = request.region.toUpperCase();
    if (!compliance.regions.some((r) => r.toUpperCase() === region)) {
      denials.push({
        code: "region.not-cleared",
        message: `The agent is not cleared to operate in ${region}. Cleared: ${
          compliance.regions.length ? compliance.regions.join(", ") : "nowhere"
        }.`,
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

async function checkAmount(
  authority: Authority,
  request: AuthorizationRequest,
  denials: VerificationError[],
  escalations: VerificationError[],
  opts: DecideOptions,
): Promise<void> {
  if (!request.amount) return;
  const { currency } = request.amount;
  const amount = request.amount.amount;
  const upper = currency.toUpperCase();
  const now = (opts.now ?? (() => new Date()))();
  let mismatched = false;
  let overCeiling = false;

  for (const ceiling of authority.ceilings) {
    if (ceiling.currency.toUpperCase() !== upper) {
      if (!mismatched) {
        mismatched = true;
        escalations.push({
          code: "amount.currency-unsupported",
          message: `${ceiling.label} is in ${ceiling.currency}, not ${currency}; a person must confirm the conversion.`,
        });
      }
      continue;
    }
    // A ledger knows the real prior total. Without one, the caller's
    // priorSpend is all there is, and for a window wider than a single
    // engagement, not supplying it means nobody has counted.
    let prior: number;
    if (opts.ledger && (ceiling.window !== "engagement" || opts.engagementId)) {
      prior = await opts.ledger.outstanding({
        subject: authority.subject.agentId,
        currency: upper,
        window: ceiling.window,
        engagementId: opts.engagementId,
        at: now,
      });
    } else if (request.priorSpend !== undefined) {
      prior = request.priorSpend;
    } else if (ceiling.window === "engagement") {
      prior = 0;
    } else {
      escalations.push({
        code: "amount.cumulative-unknown",
        message: `${ceiling.label} covers ${ceiling.window === "total" ? "everything committed so far" : `a whole ${ceiling.window}`}; pass a ledger or priorSpend so it can be checked.`,
      });
      continue;
    }
    if (prior + amount > ceiling.amount) {
      denials.push(ceilingError(ceiling, prior + amount, prior));
      overCeiling = true;
    }
  }

  // An amount that is refused outright does not also need "and a person
  // would have had to confirm it": it is not happening either way.
  const gate = authority.humanInLoop;
  if (!gate || overCeiling) return;
  if (gate.above.currency.toUpperCase() !== upper) {
    if (!mismatched) {
      escalations.push({
        code: "amount.currency-unsupported",
        message: `The human-in-the-loop threshold is in ${gate.above.currency}, not ${currency}.`,
      });
    }
  } else if (amount > gate.above.amount) {
    escalations.push({
      code: "amount.above-human-threshold",
      message: `${amount.toLocaleString("en-US")} ${currency} is above the ${gate.above.amount.toLocaleString("en-US")} ${currency} threshold, so a person must confirm before commitment.`,
    });
  }
}
