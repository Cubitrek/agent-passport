/**
 * Turn a verified passport into a decision about one inbound request:
 * allow, escalate to a human, or deny. This is spec §7 step 10 as code, so
 * every receiver applies the authority envelope the same way.
 */

import type {
  AgentPassport,
  PassportCompliance,
  VerificationError,
  VerifyResult,
} from "./types.js";

export type DataClassification = NonNullable<PassportCompliance["dataClassification"]>;

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
}

export type Decision = "allow" | "escalate" | "deny";

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
}

const CLASSIFICATION_RANK: Record<DataClassification, number> = {
  public: 0,
  internal: 1,
  "confidential-business": 2,
  "regulated-pii": 3,
};

export function authorize(
  verification: VerifyResult,
  request: AuthorizationRequest,
  opts: { now?: () => Date } = {},
): AuthorizationResult {
  const evaluatedAt = (opts.now ?? (() => new Date()))().toISOString();

  if (!verification.ok) {
    return {
      decision: "deny",
      allow: false,
      reasons: [
        {
          code: "passport.unverified",
          message: "The passport did not verify, so it grants no authority.",
          hint: verification.errors.map((e) => e.code).join(", "),
        },
      ],
      evaluatedAt,
    };
  }

  const passport = verification.passport;
  const denials: VerificationError[] = [];
  const escalations: VerificationError[] = [];

  checkScope(passport, request, denials);
  checkCounterparty(passport, request, denials);
  checkCompliance(passport, request, denials);
  checkAmount(passport, request, denials, escalations);

  const decision: Decision = denials.length ? "deny" : escalations.length ? "escalate" : "allow";
  const reasons =
    decision === "allow"
      ? [
          {
            code: "authority.within-envelope",
            message: `${request.scope} is within the authority ${passport.issuer.displayName} published for this agent.`,
          },
        ]
      : [...denials, ...escalations];

  return {
    decision,
    allow: decision === "allow",
    reasons,
    escalation:
      decision === "allow"
        ? undefined
        : {
            to: passport.authority.humanInLoop.escalation,
            slaHours: passport.authority.humanInLoop.slaHours,
          },
    agentId: passport.agent.id,
    issuerDomain: passport.issuer.domain,
    keyId: passport.signature.keyId,
    evaluatedAt,
  };
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
