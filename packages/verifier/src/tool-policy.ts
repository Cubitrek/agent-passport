/**
 * Turning a tool call into a question the decision engine can answer.
 *
 * A policy talks about scopes and money: "payments.charge, up to 5,000 USD a
 * day". A tool call is `stripe.create_charge({ amount: 800000 })`. Something
 * has to bridge the two, and it has to be written down rather than guessed,
 * because a guess that reads the wrong field silently stops enforcing the cap.
 *
 * So the operator writes the rules in the policy. Each rule says which tools
 * it matches, which scope they exercise, and where in the arguments the value
 * lives. A tool no rule matches is handled by `unmatched`, which defaults to
 * asking a person rather than waving it through.
 */

import type { AuthorizationRequest, AuthorizedAction } from "./authorize.js";
import type { VerificationError } from "./types.js";

/** An extra condition on a rule, so one tool can be governed several ways. */
export interface ToolCondition {
  /** Where to look, as a dotted path from the call, e.g. "args.command". */
  path: string;
  /** A regular expression the value has to match, as a string. */
  matches: string;
}

export interface ToolRule {
  /** Tool name, or a pattern where `*` stands for any run of characters. */
  match: string;
  /**
   * Short-circuit this rule to an outcome without consulting the authority.
   * For shapes that are simply not on, such as `rm -rf` or a piped installer,
   * where saying so outright is clearer than routing it through a scope the
   * policy happens not to grant.
   */
  effect?: "deny" | "ask";
  /**
   * Only apply this rule when the call also looks like this. Lets one tool be
   * governed several ways: `rm -rf` under a scope you do not grant, and
   * everything else under one you do. A rule whose condition does not hold is
   * skipped, and the next rule gets its turn.
   */
  when?: ToolCondition;
  /** The scope this tool exercises, checked against the policy's scope list. */
  scope?: string;
  /** Where the value lives, as a dotted path from the call, e.g. "args.amount". */
  amountFrom?: string;
  /** "major" (5000 means 5,000 USD) or "minor" (500000 means 5,000 USD). Default major. */
  amountUnit?: "major" | "minor";
  /** Fixed currency for this tool. Default USD, or whatever `currencyFrom` reads. */
  currency?: string;
  /** Where the currency lives, if the tool carries one. */
  currencyFrom?: string;
  /** Where the thing being acted on lives, e.g. "args.customer". */
  targetFrom?: string;
  /** Shown to the model on tools/list, so it knows the tool is governed. */
  note?: string;
}

/** What to do with a tool no rule matches. */
export type UnmatchedPolicy = "allow" | "escalate" | "deny";

export interface ToolCall {
  name: string;
  args?: unknown;
}

export type ToolMapping =
  | { ok: true; request: AuthorizationRequest; rule: ToolRule }
  | {
      ok: false;
      errors: VerificationError[];
      rule?: ToolRule;
      /** Set when a rule said so outright, rather than a mapping problem. */
      effect?: "deny" | "ask";
    };

/**
 * The shapes that make a regular expression take exponential time: a group
 * that already contains a quantifier, with another quantifier applied to the
 * whole group. `(a+)+` against forty characters takes the better part of a
 * minute, and the text being matched is a tool argument, which is exactly
 * what an injected instruction gets to choose.
 *
 * This is a heuristic and catches the common accidental forms rather than
 * every possible one. A pattern in a policy is operator-supplied code; keep
 * it simple.
 */
export function runawayRegex(pattern: string): boolean {
  return /\([^()]*[+*}][^()]*\)\s*(?:[+*]|\{\d+,\s*\})/.test(pattern);
}

/** A `*` pattern, anchored, with everything else taken literally. */
function matches(pattern: string, name: string): boolean {
  if (pattern === name) return true;
  if (!pattern.includes("*")) return false;
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(name);
}

/**
 * First matching rule wins, so order in the policy is the operator's priority.
 * Put the narrow rules above the broad ones.
 */
export function ruleFor(
  rules: ToolRule[] | undefined,
  name: string,
  call?: ToolCall,
): ToolRule | undefined {
  return (rules ?? []).find((rule) => {
    if (!matches(rule.match, name)) return false;
    if (!rule.when) return true;
    // Without the call in hand a conditional rule cannot be judged, so it is
    // reported as matching: the describe path wants to mention it, and the
    // decide path always passes the call.
    if (!call) return true;
    const value = readPath(call, rule.when.path);
    if (value === undefined || value === null) return false;
    return new RegExp(rule.when.matches).test(String(value));
  });
}

function readPath(call: ToolCall, path: string): unknown {
  const root: Record<string, unknown> = { args: call.args, name: call.name };
  let value: unknown = root;
  for (const key of path.split(".")) {
    if (value === null || typeof value !== "object") return undefined;
    value = (value as Record<string, unknown>)[key];
  }
  return value;
}

/**
 * Build the authorization request for one tool call.
 *
 * A rule that names `amountFrom` and cannot read a number there is refused,
 * not passed through without an amount. The alternative is worse: the call
 * would sail past every spend ceiling because nothing knew what it was worth.
 */
export function toolRequest(
  call: ToolCall,
  rules: ToolRule[] | undefined,
  extra: Partial<AuthorizationRequest> = {},
): ToolMapping {
  const rule = ruleFor(rules, call.name, call);
  if (!rule) {
    return {
      ok: false,
      errors: [
        {
          code: "tool.unmatched",
          message: `No rule in this policy covers the tool "${call.name}".`,
          hint: "Add it to the policy's tools list, or set unmatched to say what should happen.",
        },
      ],
    };
  }

  if (rule.effect) {
    return {
      ok: false,
      rule,
      effect: rule.effect,
      errors: [
        {
          code: rule.effect === "deny" ? "tool.refused-by-rule" : "tool.needs-a-person",
          message:
            rule.note ??
            (rule.effect === "deny"
              ? `The policy refuses "${call.name}" calls that look like this.`
              : `The policy wants a person to look at "${call.name}" calls that look like this.`),
          hint: rule.when ? `The rule matched ${rule.when.path} against /${rule.when.matches}/.` : undefined,
        },
      ],
    };
  }

  const action: AuthorizedAction = { tool: call.name, args: call.args };
  if (rule.targetFrom) {
    const target = readPath(call, rule.targetFrom);
    if (typeof target === "string" || typeof target === "number") action.target = String(target);
  }

  const request: AuthorizationRequest = { scope: rule.scope!, action, ...extra };

  if (rule.amountFrom) {
    const raw = readPath(call, rule.amountFrom);
    const value = typeof raw === "string" && raw.trim() !== "" ? Number(raw) : raw;
    if (typeof value !== "number" || !Number.isFinite(value)) {
      return {
        ok: false,
        rule,
        errors: [
          {
            code: "tool.amount-unreadable",
            message: `The rule for "${call.name}" reads its value from ${rule.amountFrom}, and there is no number there.`,
            hint: "A call whose value cannot be read cannot be held to a spending limit, so it is not allowed through.",
          },
        ],
      };
    }
    const amount = rule.amountUnit === "minor" ? value / 100 : value;
    const currency =
      (rule.currencyFrom ? String(readPath(call, rule.currencyFrom) ?? "") : "") ||
      rule.currency ||
      "USD";
    request.amount = { amount, currency: currency.toUpperCase() };
  }

  return { ok: true, request, rule };
}

/** The note a guarded tool carries on tools/list, so the model knows the rules. */
export function describeRule(rule: ToolRule, limits: string | undefined): string {
  if (rule.effect) {
    const what = rule.effect === "deny" ? "Refused by local policy" : "Sent to a person by local policy";
    return [
      `${what}${rule.when ? ` when ${rule.when.path} matches /${rule.when.matches}/` : ""}.`,
      rule.note,
    ]
      .filter(Boolean)
      .join(" ");
  }
  const parts = [`Governed by local policy as "${rule.scope}".`];
  if (rule.when) parts.push(`That applies when ${rule.when.path} matches /${rule.when.matches}/.`);
  // Only a tool that carries a value can be held to a spending limit, so only
  // those are told about one. Naming a cap on a read-only tool reads as though
  // the cap applies, and it does not.
  if (rule.amountFrom) {
    parts.push(`Its value is read from ${rule.amountFrom}.`);
    if (limits) parts.push(limits);
  }
  if (rule.note) parts.push(rule.note);
  return parts.join(" ");
}
