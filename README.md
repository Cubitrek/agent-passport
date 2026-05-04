# Agent Passport

> A standard for verifiable, business-issued identity and authority for AI agents that talk to other AI agents across organisational boundaries.

Agent Passport is a JSON document a business publishes at `/.well-known/agent-passport.json` that tells another business's agent **who** is contacting it, **what that agent is authorised to do**, **how much it can spend**, **when a human takes over**, and **how the conversation is audited**. It is the trust and authority layer that sits on top of MCP and Google's A2A.

- **Canonical spec:** [`spec/agent-passport-v0.1.md`](./spec/agent-passport-v0.1.md)
- **Authored by:** [Cubitrek](https://cubitrek.com)
- **Status:** Draft v0.1 (2026-04-28)
- **Licence:** MIT

## Why this exists

MCP standardised agent-to-tool calls inside one organisation. Google's A2A standardised agent-to-agent transport across organisations. Neither covers the commercial layer that B2B counterparties actually need before they trust an inbound agent message:

| Layer | Spec |
| --- | --- |
| Agent-to-tool, same org | Model Context Protocol (MCP) |
| Agent-to-agent transport | Agent2Agent (A2A) Agent Card |
| Capability manifest | `agents.json` (Wildcard), A2A skills |
| **Identity, authority, audit, escalation** | **Agent Passport (this spec)** |

Without an Agent Passport, an inbound agent message is anonymous, unbounded, and unauditable. With one, the receiving agent (or its operator) can verify the issuer, check the spending ceiling, route to a human at the right threshold, and log a signed conversation that survives a court order.

## What's in the box

```
agent-passport/
  spec/
    agent-passport-v0.1.md      # Canonical spec text
    threat-model.md              # Failure modes the spec addresses
  schemas/
    agent-passport.schema.json   # JSON Schema (draft 2020-12)
  examples/
    acme.agent-passport.json     # Procurement agent for a fictional buyer
    globex.agent-passport.json   # Sales agent for a fictional seller
    cubitrek.agent-passport.json # Cubitrek's own live passport
  packages/
    verifier/                    # @cubitrek/agent-passport-verifier (npm)
```

## Quick start

### 1. Issue a passport

Drop a JSON file at `https://yourdomain.example/.well-known/agent-passport.json`. Start from one of the [examples](./examples/) and edit the fields. The spec walks through every field; the [JSON Schema](./schemas/agent-passport.schema.json) catches typos.

Sign the canonical JSON with an Ed25519 key, publish the public key as a DNS TXT record at `_agent-passport.yourdomain.example`, and paste the signature into the `signature` block.

### 2. Verify a passport you received

```bash
npm install @cubitrek/agent-passport-verifier
```

```typescript
import { verifyAgentPassport } from "@cubitrek/agent-passport-verifier";

const result = await verifyAgentPassport({
  domain: "acme.example",            // we fetch /.well-known/agent-passport.json
  resolveSignerPublicKey: "dns",     // looks up the DNS TXT record
});

if (!result.ok) {
  console.error("Reject the inbound agent:", result.errors);
} else {
  const { passport } = result;
  if (engagementValueUSD > passport.authority.spendCeiling.amount) {
    // route to human escalation
  }
}
```

### 3. Validate without verifying signatures

For local linting, use the schema directly:

```bash
npx ajv validate \
  -s schemas/agent-passport.schema.json \
  -d examples/acme.agent-passport.json
```

## Adopters

Add yourself by sending a PR to [`adopters.md`](./adopters.md). Once your passport validates, your domain shows up in [the Cubitrek registry](https://cubitrek.com/agent-passport/adopters) with a verification badge.

## Relationship to other specs

Agent Passport is **additive**. It does not replace anything.

- **A2A `/.well-known/agent.json`** answers "what can this agent do." Agent Passport answers "what is this agent authorised to commit to on behalf of which business."
- **MCP** is about a single agent-tool boundary. Agent Passport is about cross-organisational trust.
- **OpenAPI** describes HTTP surface. Agent Passport describes commercial surface.
- **W3C Verifiable Credentials** are a primitive Agent Passport can lean on for stronger identity proofs in v0.2.

## Versioning

Spec versions follow semver-ish: `MAJOR.MINOR`. Breaking changes bump `MAJOR` and ship under a new path (`/spec/agent-passport-v1.0.md`). Additive changes bump `MINOR`. Field deprecations keep one major-version of backward compatibility.

The `version` field on every passport is required and reads as `0.1.0`.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). The short version: file an issue first if you want to change the schema; trivial doc fixes go straight to PR.

## Authors

Authored at [Cubitrek](https://cubitrek.com) by Faizan Ali Khan, April 2026. Maintained as a public good for the agentic economy.

If your business would like guidance on rolling out Agent Passport, the Cubitrek AEO/GEO team handles the issuing key setup, DNS records, and the workflow integration. See [cubitrek.com/services/aeo-geo](https://cubitrek.com/services/aeo-geo).

## Licence

MIT. See [LICENSE](./LICENSE).
