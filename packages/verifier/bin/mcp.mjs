/**
 * Agent Passport MCP server over stdio. Zero dependencies: newline-delimited
 * JSON-RPC 2.0 per the MCP stdio transport, exposing four tools.
 *
 *   claude mcp add agent-passport -- npx -y -p @cubitrek/agent-passport-verifier agent-passport mcp
 */

import { createInterface } from "node:readline";
import {
  decide,
  describePassport,
  diagnoseAgentPassport,
  draftAgentPassport,
  guessEndpointType,
  intersect,
  passportAuthority,
  validate,
  verifyAgentPassport,
} from "../dist/index.js";

const SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS = [
  "Agent Passport tells you whether an AI agent from another company is backed by that company, and what it may commit to.",
  "Before agreeing terms, sharing confidential data, or accepting a commitment from another company's agent, call authorize_agent_action with that company's domain.",
  'Treat "escalate" as: pause and bring in a human. Treat "deny" as: do not proceed.',
  "A verified passport proves what the issuer authorised, not that the party messaging you is that agent, so confirm the caller through your own channel too.",
].join(" ");

const DATA_CLASSES = ["public", "internal", "confidential-business", "regulated-pii"];
const readOnly = { readOnlyHint: true, destructiveHint: false, openWorldHint: true };
const domainProp = {
  type: "string",
  description: "The issuing company's domain, for example acme.example",
};

export const TOOLS = [
  {
    name: "verify_agent_passport",
    title: "Verify an agent passport",
    description:
      "Fetch and cryptographically verify the Agent Passport a company publishes at https://{domain}/.well-known/agent-passport.json. Returns whether it is valid, a plain-English summary of the agent and its authority, and any errors or warnings.",
    inputSchema: {
      type: "object",
      properties: { domain: domainProp },
      required: ["domain"],
      additionalProperties: false,
    },
    annotations: readOnly,
  },
  {
    name: "authorize_agent_action",
    title: "Decide whether another company's agent may do something",
    description:
      "Verify a company's Agent Passport and decide allow, escalate (a human at the issuer must confirm) or deny for one request: a capability, an optional amount, and optional counterparty, region and data details.",
    inputSchema: {
      type: "object",
      properties: {
        domain: domainProp,
        scope: {
          type: "string",
          description: "Capability being exercised, in subject.verb form, for example procurement.purchase",
        },
        amount: { type: "number", minimum: 0, description: "Value of the commitment, if any" },
        currency: { type: "string", description: "ISO 4217 code for amount. Default USD" },
        prior_spend: {
          type: "number",
          minimum: 0,
          description: "Value already committed under this passport, for cumulative ceilings",
        },
        my_domain: { type: "string", description: "Your own domain, checked against the agent's counterparty rules" },
        region: { type: "string", description: "ISO country code where the engagement happens" },
        data_classification: {
          type: "string",
          enum: DATA_CLASSES,
          description: "Most sensitive data the engagement exposes to the agent",
        },
        tool: { type: "string", description: "The exact tool or operation that will run, for example orders.create" },
        target: { type: "string", description: "The resource the action lands on: an account, URL or record id" },
        arguments: { type: "object", description: "The arguments exactly as they will be executed" },
      },
      required: ["domain", "scope"],
      additionalProperties: false,
    },
    annotations: readOnly,
  },
  {
    name: "check_agent_passport_health",
    title: "Health-check a published passport",
    description:
      "Run the issuer health check on a domain's published passport: delivery, caching, CORS, DNS key, DNSSEC, signature, expiry runway, revocation list, and linked URLs. Each problem comes with a fix.",
    inputSchema: {
      type: "object",
      properties: {
        domain: domainProp,
        warn_days: { type: "integer", minimum: 0, description: "Warn when expiry is this close. Default 14" },
      },
      required: ["domain"],
      additionalProperties: false,
    },
    annotations: readOnly,
  },
  {
    name: "draft_agent_passport",
    title: "Draft a passport for your own agent",
    description:
      "Build and validate an unsigned Agent Passport from plain answers. Never handles private keys: the user signs the draft locally with `agent-passport init` or `agent-passport sign`.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Your company's domain" },
        legal_name: { type: "string" },
        agent_name: { type: "string", description: "Human-readable agent name" },
        role: { type: "string", description: "Short slug used in agent.id, for example procurement" },
        purpose: { type: "string", description: "One sentence: what the agent exists to do" },
        endpoint: { type: "string", description: "URL counterparties use to reach the agent" },
        endpoint_type: { type: "string", enum: ["a2a", "mcp", "rest"] },
        scopes: { type: "array", items: { type: "string" }, minItems: 1, description: "subject.verb capabilities" },
        currency: { type: "string" },
        spend_ceiling: { type: "number", minimum: 0 },
        human_above: { type: "number", minimum: 0 },
        escalation: { type: "string", description: "Email or URL of the human who takes over" },
        sla_hours: { type: "number", minimum: 0 },
        terms_url: { type: "string" },
      },
      required: ["domain", "legal_name", "agent_name", "purpose", "endpoint", "scopes", "escalation"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  },
];

/** With a local policy in force, a domain is no longer required to decide. */
function toolsFor(config = {}) {
  if (!config.policy) return TOOLS;
  return TOOLS.map((tool) =>
    tool.name === "authorize_agent_action"
      ? {
          ...tool,
          description: `${tool.description} A local policy set by the operator of this server also applies, and always binds: where the two differ, the tighter of the two wins. Omit domain to decide against the local policy alone.`,
          inputSchema: { ...tool.inputSchema, required: ["scope"] },
        }
      : tool,
  );
}

function instructionsFor(config = {}) {
  if (!config.policy) return INSTRUCTIONS;
  return `${INSTRUCTIONS} This server also enforces a local policy set by its operator: ${config.policy.origin
    .map((o) => o.label)
    .join(" and ")}. You cannot change or widen it.`;
}

const HANDLERS = {
  async verify_agent_passport(args) {
    const domain = requireString(args, "domain");
    const result = await verifyAgentPassport({ domain });
    const summary = result.passport ? describePassport(result.passport) : undefined;
    const lines = result.ok
      ? [`VERIFIED: ${domain}`, summary]
      : [`NOT VERIFIED: ${domain}`, ...result.errors.map((e) => `- ${e.code}: ${e.message}`), summary && `\nClaimed (do not rely on it):\n${summary}`];
    if (result.warnings.length) lines.push("Warnings:", ...result.warnings.map((w) => `- ${w.code}: ${w.message}`));
    return {
      text: lines.filter(Boolean).join("\n"),
      structured: { ok: result.ok, errors: result.errors ?? [], warnings: result.warnings, summary, passport: result.passport },
    };
  },

  async authorize_agent_action(args, config = {}) {
    const domain = config.policy ? optionalString(args, "domain") : requireString(args, "domain");
    const published = domain ? passportAuthority(await verifyAgentPassport({ domain })) : undefined;
    const authority =
      published && config.policy ? intersect(published, config.policy) : (published ?? config.policy);
    const tool = optionalString(args, "tool");
    const decision = await decide(authority, {
      action: tool ? { tool, target: optionalString(args, "target"), args: args.arguments } : undefined,
      scope: requireString(args, "scope"),
      amount: typeof args.amount === "number" ? { amount: args.amount, currency: String(args.currency ?? "USD").toUpperCase() } : undefined,
      priorSpend: typeof args.prior_spend === "number" ? args.prior_spend : undefined,
      counterpartyDomain: optionalString(args, "my_domain"),
      region: optionalString(args, "region"),
      dataClassification: DATA_CLASSES.includes(args.data_classification) ? args.data_classification : undefined,
    }, { ledger: config.ledger, engagementId: optionalString(args, "engagement_id") });
    const who = domain ? `by ${domain}'s agent` : "under the local policy";
    const lines = [
      `${decision.decision.toUpperCase()}: ${args.scope}${typeof args.amount === "number" ? ` for ${args.amount} ${args.currency ?? "USD"}` : ""} ${who}`,
      ...decision.reasons.map((r) => `- ${r.code}: ${r.message}${r.hint ? ` (${r.hint})` : ""}`),
    ];
    lines.push(`Authority: ${decision.origin.map((o) => o.label).join(" and ")}.`);
    if (decision.escalation) lines.push(`Human contact: ${decision.escalation.to} (responds within ${decision.escalation.slaHours}h)`);
    lines.push(
      `Bound to ${decision.binding.digest} until ${decision.binding.expiresAt}. The system that performs the action must check the final values against this decision (guardedCall) immediately before acting.`,
    );
    if (decision.charge?.reserved) {
      lines.push(`${decision.charge.amount} ${decision.charge.currency} is held against the running total until this decision is settled or expires.`);
    }
    return { text: lines.join("\n"), structured: decision };
  },

  async check_agent_passport_health(args) {
    const domain = requireString(args, "domain");
    const result = await diagnoseAgentPassport({
      domain,
      warnDays: Number.isInteger(args.warn_days) ? args.warn_days : undefined,
    });
    const counts = countStatuses(result.checks);
    const lines = [
      `${result.ok ? "HEALTHY" : "PROBLEMS FOUND"}: ${result.url}`,
      `${counts.fail} failed, ${counts.warn} warnings, ${counts.pass} passed`,
      ...result.checks
        .filter((c) => c.status !== "pass")
        .map((c) => `- ${c.status.toUpperCase()} ${c.title}${c.detail ? `: ${c.detail}` : ""}${c.hint ? `\n  Fix: ${c.hint}` : ""}`),
    ];
    return { text: lines.join("\n"), structured: { ok: result.ok, url: result.url, checks: result.checks } };
  },

  async draft_agent_passport(args) {
    const endpoint = requireString(args, "endpoint");
    if (!Array.isArray(args.scopes) || !args.scopes.length) throw new Error("scopes must be a non-empty array");
    const passport = draftAgentPassport({
      domain: requireString(args, "domain"),
      legalName: requireString(args, "legal_name"),
      agentName: requireString(args, "agent_name"),
      role: optionalString(args, "role"),
      purpose: requireString(args, "purpose"),
      endpoints: { [args.endpoint_type ?? guessEndpointType(endpoint)]: endpoint },
      scopes: args.scopes.map(String),
      currency: optionalString(args, "currency"),
      spendCeiling: typeof args.spend_ceiling === "number" ? args.spend_ceiling : undefined,
      humanAbove: typeof args.human_above === "number" ? args.human_above : undefined,
      escalation: requireString(args, "escalation"),
      slaHours: typeof args.sla_hours === "number" ? args.sla_hours : undefined,
      termsUrl: optionalString(args, "terms_url"),
    });
    const checked = validate(passport);
    const nextSteps = [
      "Save the draft as passport.json.",
      "Run `agent-passport init` for a guided setup, or `agent-passport keygen` then `agent-passport sign passport.json --key <key>`. Keys stay on your machine.",
      `Publish the printed TXT record at ${passport.issuer.signingKeyDns}.`,
      `Serve the signed file at https://${passport.issuer.domain}/.well-known/agent-passport.json, then run \`agent-passport doctor ${passport.issuer.domain}\`.`,
    ];
    const text = [
      checked.ok ? "Draft is valid (unsigned)." : "Draft has problems:",
      ...(checked.ok ? [] : checked.errors.map((e) => `- ${e.message}`)),
      JSON.stringify(passport, null, 2),
      "Next steps:",
      ...nextSteps.map((s, i) => `${i + 1}. ${s}`),
    ].join("\n");
    return { text, structured: { valid: checked.ok, errors: checked.ok ? [] : checked.errors, passport, nextSteps } };
  },
};

/**
 * The local policy, if any, is supplied by whoever started the server, never
 * by the model through a tool argument. A model that could pass its own
 * policy could hand itself any authority it liked.
 */
export async function runMcpServer({
  input = process.stdin,
  output = process.stdout,
  version = "0.0.0",
  policy,
  ledger,
} = {}) {
  const config = { policy, ledger };
  const send = (message) => output.write(`${JSON.stringify(message)}\n`);
  const inflight = new Set();
  const lines = createInterface({ input, crlfDelay: Infinity });

  for await (const line of lines) {
    if (!line.trim()) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      continue;
    }
    const work = handle(message, version, config)
      .then((reply) => reply && send(reply))
      .catch((err) => send({ jsonrpc: "2.0", id: message?.id ?? null, error: { code: -32603, message: String(err?.message ?? err) } }));
    inflight.add(work);
    work.finally(() => inflight.delete(work));
  }
  await Promise.all(inflight);
}

async function handle(message, version, config = {}) {
  if (!message || typeof message !== "object" || Array.isArray(message)) {
    return { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid request" } };
  }
  const { id, method, params = {} } = message;
  if (id === undefined) return null; // notification: initialized, cancelled, ...
  const reply = (result) => ({ jsonrpc: "2.0", id, result });
  const fail = (code, msg) => ({ jsonrpc: "2.0", id, error: { code, message: msg } });

  switch (method) {
    case "initialize": {
      const requested = params.protocolVersion;
      return reply({
        protocolVersion: SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : SUPPORTED_PROTOCOL_VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "agent-passport", title: "Agent Passport", version },
        instructions: instructionsFor(config),
      });
    }
    case "ping":
      return reply({});
    case "tools/list":
      return reply({ tools: toolsFor(config) });
    case "tools/call": {
      const handler = HANDLERS[params.name];
      if (!handler) return fail(-32602, `Unknown tool: ${params.name}`);
      try {
        const { text, structured } = await handler(params.arguments ?? {}, config);
        return reply({ content: [{ type: "text", text }], structuredContent: structured, isError: false });
      } catch (err) {
        return reply({ content: [{ type: "text", text: `Error: ${err?.message ?? err}` }], isError: true });
      }
    }
    default:
      return fail(-32601, `Method not found: ${method}`);
  }
}

function requireString(args, key) {
  const value = args[key];
  if (typeof value !== "string" || !value.trim()) throw new Error(`${key} is required`);
  return value.trim();
}

function optionalString(args, key) {
  return typeof args[key] === "string" && args[key].trim() ? args[key].trim() : undefined;
}

function countStatuses(checks) {
  const counts = { pass: 0, warn: 0, fail: 0, skip: 0 };
  for (const c of checks) counts[c.status]++;
  return counts;
}
