/**
 * Authority: what something is allowed to do, separated from where that
 * permission came from.
 *
 * A passport is one source of authority. A policy file on the machine the
 * agent runs on is another. They answer the same questions (which scopes,
 * how much, when does a person decide, who may be dealt with), so the
 * decision engine should not care which one it is holding.
 *
 * Two sources can also be combined. `intersect()` returns an authority that
 * grants only what both grant, which is how a receiver runs its own local
 * limits over whatever a counterparty published: the issuer's envelope is a
 * maximum, never a licence to exceed the receiver's own rules.
 */

import type {
  AgentPassport,
  PassportCompliance,
  VerificationError,
  VerifyResult,
} from "./types.js";
import type { ToolRule, UnmatchedPolicy } from "./tool-policy.js";
import { runawayRegex } from "./tool-policy.js";
import type { ApproverKey } from "./approval.js";

export type DataClassification = NonNullable<PassportCompliance["dataClassification"]>;

/**
 * The period a ceiling applies over.
 *
 *  - "engagement": this one piece of work, identified by engagementId.
 *  - "day", "month": the UTC calendar day or month the action falls in.
 *  - "total": everything this subject has ever committed.
 */
export type SpendWindow = "engagement" | "day" | "month" | "total";

/** Every window a ceiling may use. A typo here would silently widen a cap. */
export const SPEND_WINDOWS: readonly SpendWindow[] = ["engagement", "day", "month", "total"];

export interface AuthorityCeiling {
  amount: number;
  currency: string;
  window: SpendWindow;
  /** Shown in refusals, e.g. "the passport's ceiling" or "your daily cap". */
  label: string;
}

export interface AuthorityHumanGate {
  above: { amount: number; currency: string };
  /** Who decides. An email, a URL, or a channel name for a local policy. */
  escalation: string;
  slaHours: number;
}

export interface AuthorityCounterparties {
  allowlist?: string[];
  blocklist?: string[];
  openTo?: "any" | "verified-passports" | "allowlist-only";
}

export interface AuthorityCompliance {
  dataClassification?: DataClassification;
  regions?: string[];
}

/** Who is acting. Bound into every decision digest. */
export interface AuthoritySubject {
  agentId: string;
  /** The domain that published this authority, when one did. */
  issuerDomain?: string;
  /** The key that signed it, when it was signed. */
  keyId?: string;
}

/** How an authority was established. Carried through to receipts. */
export interface AuthorityOrigin {
  kind: "passport" | "policy";
  /** Stable identifier: a domain for a passport, a policy id for a policy. */
  id: string;
  label: string;
}

export interface Authority {
  subject: AuthoritySubject;
  origin: AuthorityOrigin[];
  scope: string[];
  ceilings: AuthorityCeiling[];
  humanInLoop?: AuthorityHumanGate;
  counterparties?: AuthorityCounterparties;
  compliance?: AuthorityCompliance;
  /**
   * Set when this authority grants nothing at all, for example because the
   * passport it came from did not verify. Every request against it is denied
   * with this reason, without consulting anything else.
   */
  refusal?: VerificationError;
}

/** A local policy: the same envelope, written by the operator rather than published. */
export interface LocalPolicy {
  /** Stable id for this policy, e.g. "treasury-local". */
  id: string;
  /** What the policy governs, e.g. "claude-code" or an agent id. */
  agentId?: string;
  label?: string;
  scope: string[];
  /** Caps. A bare `{ amount, currency }` is read as a total cap. */
  limits?: Array<{ amount: number; currency: string; window?: SpendWindow; label?: string }>;
  humanInLoop?: { above: { amount: number; currency: string }; escalation: string; slaHours?: number };
  counterparties?: AuthorityCounterparties;
  compliance?: AuthorityCompliance;
  /**
   * How tool calls map onto the scopes above. Only a guard that sees real tool
   * calls uses these; decide() never reads them.
   */
  tools?: ToolRule[];
  /** What happens to a tool no rule matches. Default "escalate". */
  unmatched?: UnmatchedPolicy;
  /**
   * Whose answer counts when a call is escalated. Name keys here and an
   * unsigned approval is refused, which is what stops an agent that can run a
   * shell from approving its own escalations. Leave it out only where the
   * agent cannot write the approvals file.
   */
  approvers?: ApproverKey[];
}

/**
 * Read a verified passport as an authority. A verification that failed
 * produces an authority that refuses everything, so an unverified passport
 * is never a partial grant, and its contents are not read at all.
 */
export function passportAuthority(verification: VerifyResult): Authority {
  if (!verification.ok) {
    return {
      subject: { agentId: "unknown" },
      origin: [{ kind: "passport", id: "unverified", label: "an unverified passport" }],
      scope: [],
      ceilings: [],
      refusal: {
        code: "passport.unverified",
        message: "The passport did not verify, so it grants no authority.",
        hint: verification.errors.map((e) => e.code).join(", "),
      },
    };
  }
  return fromPassport(verification.passport);
}

/** The authority a passport describes, for a passport already known to be valid. */
export function fromPassport(passport: AgentPassport): Authority {
  const { authority, issuer, agent } = passport;
  return {
    subject: {
      agentId: agent.id,
      issuerDomain: issuer.domain,
      keyId: passport.signature.keyId,
    },
    origin: [
      {
        kind: "passport",
        id: issuer.domain,
        label: `the passport ${issuer.displayName} publishes at ${issuer.domain}`,
      },
    ],
    scope: [...authority.scope],
    ceilings: [
      {
        amount: authority.spendCeiling.amount,
        currency: authority.spendCeiling.currency,
        window: authority.spendCeiling.perEngagement ? "engagement" : "total",
        label: `the ceiling ${issuer.displayName} published`,
      },
    ],
    humanInLoop: {
      above: { ...authority.humanInLoop.above },
      escalation: authority.humanInLoop.escalation,
      slaHours: authority.humanInLoop.slaHours,
    },
    counterparties: passport.counterparties ? { ...passport.counterparties } : undefined,
    compliance: passport.compliance
      ? {
          dataClassification: passport.compliance.dataClassification,
          regions: passport.compliance.regions ? [...passport.compliance.regions] : undefined,
        }
      : undefined,
  };
}

/**
 * Read a local policy as an authority. Nothing is fetched and nothing is
 * signed: this is the operator's own rule set, for an agent running on their
 * own machine or inside their own service.
 */
export function localPolicy(policy: LocalPolicy): Authority {
  if (!policy.id || typeof policy.id !== "string") {
    throw new TypeError("a local policy needs a stable id");
  }
  if (!Array.isArray(policy.scope)) {
    throw new TypeError("a local policy needs a scope list, even an empty one");
  }
  const label = policy.label ?? `the local policy ${policy.id}`;
  // Validate the tool rules here, at load, so a policy that cannot enforce
  // what it claims fails before it has waved anything through.
  for (const rule of policy.tools ?? []) {
    if (!rule || typeof rule.match !== "string" || !rule.match) {
      throw new TypeError(`every tool rule in policy ${policy.id} needs a match pattern`);
    }
    if (rule.effect !== undefined && rule.effect !== "deny" && rule.effect !== "ask") {
      throw new TypeError(`effect on "${rule.match}" in policy ${policy.id} must be deny or ask`);
    }
    // A rule that says outright what to do needs no scope. Any other rule
    // does, and it has to be one the policy actually grants: a scope that is
    // merely absent denies by accident, which reads the same as a typo.
    if (!rule.effect) {
      if (typeof rule.scope !== "string" || !rule.scope) {
        throw new TypeError(`the tool rule "${rule.match}" in policy ${policy.id} needs a scope, or an effect`);
      }
      if (!policy.scope.includes(rule.scope)) {
        throw new TypeError(
          `the tool rule "${rule.match}" in policy ${policy.id} uses scope "${rule.scope}", which the policy does not grant`,
        );
      }
    }
    if (rule.amountUnit !== undefined && rule.amountUnit !== "major" && rule.amountUnit !== "minor") {
      throw new TypeError(`amountUnit on "${rule.match}" in policy ${policy.id} must be major or minor`);
    }
    if (rule.when !== undefined) {
      if (typeof rule.when.path !== "string" || typeof rule.when.matches !== "string") {
        throw new TypeError(`when on "${rule.match}" in policy ${policy.id} needs a path and a matches pattern`);
      }
      try {
        new RegExp(rule.when.matches);
      } catch (err) {
        throw new TypeError(
          `when.matches on "${rule.match}" in policy ${policy.id} is not a valid regular expression: ${(err as Error).message}`,
        );
      }
      if (runawayRegex(rule.when.matches)) {
        throw new TypeError(
          `when.matches on "${rule.match}" in policy ${policy.id} can take exponential time: a quantifier applied to a group that already contains one, such as (a+)+. ` +
            `The text it runs against is a tool argument, so a long one would hang the guard. Rewrite it without the nested quantifier.`,
        );
      }
    }
  }
  if (policy.unmatched !== undefined && !["allow", "escalate", "deny"].includes(policy.unmatched)) {
    throw new TypeError(`unmatched in policy ${policy.id} must be allow, escalate or deny`);
  }
  for (const key of policy.approvers ?? []) {
    if (!key?.keyId || typeof key.keyId !== "string") {
      throw new TypeError(`every approver in policy ${policy.id} needs a keyId`);
    }
    if (key.alg !== "ed25519") {
      throw new TypeError(`approver "${key.keyId}" in policy ${policy.id} must use alg ed25519`);
    }
    if (typeof key.publicKey !== "string" || !key.publicKey) {
      throw new TypeError(`approver "${key.keyId}" in policy ${policy.id} needs a publicKey`);
    }
  }
  return {
    subject: { agentId: policy.agentId ?? policy.id },
    origin: [{ kind: "policy", id: policy.id, label }],
    scope: [...policy.scope],
    ceilings: (policy.limits ?? []).map((l) => {
      if (!(typeof l.amount === "number") || !Number.isFinite(l.amount) || l.amount < 0) {
        throw new TypeError(`limit in policy ${policy.id} needs a non-negative amount`);
      }
      if (!l.currency) throw new TypeError(`limit in policy ${policy.id} needs a currency`);
      if (l.window !== undefined && !SPEND_WINDOWS.includes(l.window)) {
        throw new TypeError(
          `limit in policy ${policy.id} has window "${String(l.window)}"; use one of ${SPEND_WINDOWS.join(", ")}`,
        );
      }
      return {
        amount: l.amount,
        currency: l.currency.toUpperCase(),
        window: l.window ?? "total",
        label: l.label ?? `${label}'s ${l.window ?? "total"} cap`,
      };
    }),
    humanInLoop: policy.humanInLoop
      ? {
          above: {
            amount: policy.humanInLoop.above.amount,
            currency: policy.humanInLoop.above.currency.toUpperCase(),
          },
          escalation: policy.humanInLoop.escalation,
          slaHours: policy.humanInLoop.slaHours ?? 24,
        }
      : undefined,
    counterparties: policy.counterparties ? { ...policy.counterparties } : undefined,
    compliance: policy.compliance ? { ...policy.compliance } : undefined,
  };
}

const CLASSIFICATION_RANK: Record<DataClassification, number> = {
  public: 0,
  internal: 1,
  "confidential-business": 2,
  "regulated-pii": 3,
};

/**
 * The authority both sources grant, and nothing more.
 *
 * Scopes intersect. Every ceiling from both sides is kept and each is
 * enforced, so the tighter one always binds. The lower human threshold wins.
 * Blocklists merge, allowlists intersect, and the stricter openTo rule and
 * data classification apply. A refusal on either side refuses everything.
 */
export function intersect(a: Authority, b: Authority): Authority {
  const subject = a.subject.issuerDomain ? a.subject : b.subject.issuerDomain ? b.subject : a.subject;
  const openToRank = { any: 0, "verified-passports": 1, "allowlist-only": 2 } as const;
  const cpA = a.counterparties ?? {};
  const cpB = b.counterparties ?? {};
  const lower = (x?: AuthorityHumanGate, y?: AuthorityHumanGate): AuthorityHumanGate | undefined => {
    if (!x) return y;
    if (!y) return x;
    // Thresholds in different currencies are not comparable, so keep the
    // first and let the amount check escalate on the currency mismatch.
    if (x.above.currency !== y.above.currency) return x;
    const gate = y.above.amount < x.above.amount ? y : x;
    return { ...gate, slaHours: Math.min(x.slaHours, y.slaHours) };
  };
  const classification = (): DataClassification | undefined => {
    const x = a.compliance?.dataClassification;
    const y = b.compliance?.dataClassification;
    if (!x) return y;
    if (!y) return x;
    return CLASSIFICATION_RANK[x] <= CLASSIFICATION_RANK[y] ? x : y;
  };
  const regions = (): string[] | undefined => {
    const x = a.compliance?.regions;
    const y = b.compliance?.regions;
    if (!x) return y ? [...y] : undefined;
    if (!y) return [...x];
    const set = new Set(y.map((r) => r.toUpperCase()));
    return x.map((r) => r.toUpperCase()).filter((r) => set.has(r));
  };
  const allowlist = (): string[] | undefined => {
    if (!cpA.allowlist) return cpB.allowlist ? [...cpB.allowlist] : undefined;
    if (!cpB.allowlist) return [...cpA.allowlist];
    const set = new Set(cpB.allowlist.map((d) => d.toLowerCase()));
    return cpA.allowlist.filter((d) => set.has(d.toLowerCase()));
  };
  const blocklist = [...(cpA.blocklist ?? []), ...(cpB.blocklist ?? [])];
  const openTo =
    cpA.openTo || cpB.openTo
      ? openToRank[cpA.openTo ?? "any"] >= openToRank[cpB.openTo ?? "any"]
        ? cpA.openTo ?? "any"
        : cpB.openTo ?? "any"
      : undefined;
  const compliance = { dataClassification: classification(), regions: regions() };

  return {
    subject,
    origin: [...a.origin, ...b.origin],
    scope: a.scope.filter((s) => b.scope.includes(s)),
    ceilings: [...a.ceilings, ...b.ceilings],
    humanInLoop: lower(a.humanInLoop, b.humanInLoop),
    counterparties:
      allowlist() || blocklist.length || openTo
        ? { allowlist: allowlist(), blocklist: blocklist.length ? blocklist : undefined, openTo }
        : undefined,
    compliance:
      compliance.dataClassification || compliance.regions ? compliance : undefined,
    refusal: a.refusal ?? b.refusal,
  };
}
