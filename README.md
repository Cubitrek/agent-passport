# Agent Passport

> A standard for verifiable, business-issued identity and authority for AI agents that talk to other AI agents across organisational boundaries.

A business publishes one signed JSON file at `/.well-known/agent-passport.json`. It tells another business's agent **who** the agent acts for, **what it may do**, **how much it can commit**, **when a human takes over**, and **where the audit trail lives**. The signing key sits in the business's own DNS, so anyone can check a passport without asking Cubitrek or any other third party. It is the trust and authority layer that sits on top of MCP and A2A.

- **Canonical spec:** [`spec/agent-passport-v0.1.md`](./spec/agent-passport-v0.1.md) (draft v0.1, 2026-04-28), with a [threat model](./spec/threat-model.md)
- **Authored by:** [Cubitrek](https://cubitrek.com)
- **Licence:** MIT

## Pick your path

| You are | Start here |
| --- | --- |
| Running an agent that deals with other companies | [Issue a passport](#issue-a-passport-for-your-agent) |
| Receiving agent traffic: an API, an MCP server, a sales or procurement flow | [Decide what an inbound agent may do](#decide-what-an-inbound-agent-may-do) |
| Using Claude, Cursor or another MCP client | [Give your AI assistant the tools](#give-your-ai-assistant-the-tools) |
| Responsible for a published passport | [Keep it healthy](#keep-it-healthy) |

The commands below use `npx`. After `npm install -g @cubitrek/agent-passport-verifier` you can type `agent-passport` directly.

## Issue a passport for your agent

```bash
npx -p @cubitrek/agent-passport-verifier agent-passport init
```

`init` asks about your company and your agent: domain, legal name, what the agent does, where counterparties reach it, what it may do, how much it may commit, and who takes over. It then writes:

- `.well-known/agent-passport.json`, signed and valid for 90 days
- `.well-known/revoked-passports.json`, an empty revocation list
- a private key under `~/.agent-passport/keys/`, never inside the public folder

It finishes by printing the one DNS TXT record to add. Upload the two files so they are served from your domain's `/.well-known/`, add the record, then check the result the way a counterparty will:

```bash
npx -p @cubitrek/agent-passport-verifier agent-passport doctor yourdomain.example
```

Every question has a flag, so `init` also runs unattended in scripts and CI (`agent-passport help init`). Before the passport expires, re-issue it:

```bash
npx -p @cubitrek/agent-passport-verifier agent-passport renew .well-known/agent-passport.json --key ~/.agent-passport/keys/yourdomain-2026-q3.pem
```

`renew` also confirms your DNS record still carries the key.

## Decide what an inbound agent may do

```bash
npm install @cubitrek/agent-passport-verifier
```

```typescript
import { authorize, checkExecution, verifyAgentPassport } from "@cubitrek/agent-passport-verifier";

const verification = await verifyAgentPassport({ domain: "acme.example" });
const decision = await authorize(verification, {
  scope: "procurement.purchase",
  amount: { amount: 42_000, currency: "USD" },
  counterpartyDomain: "yourcompany.example",
  action: { tool: "orders.create", target: "sku-123", args: { quantity: 20 } },
});

switch (decision.decision) {
  case "allow":
    // Proceed.
    break;
  case "escalate":
    // Pause. decision.escalation.to must confirm, within decision.escalation.slaHours.
    break;
  case "deny":
    // Refuse. decision.reasons explains why.
    break;
}
```

`authorize` applies the whole authority envelope: scope, spend ceiling, the human-in-the-loop threshold, cumulative ceilings, counterparty rules, regions and data classification. An unverified passport is always a deny. Every result carries reason codes, so it doubles as an audit record.

Each decision is also bound to the exact request, including the concrete tool, target and arguments, and expires after 60 seconds (or the issuer's response window for an escalation). Whatever performs the side effect checks the final values immediately before acting:

```typescript
const check = await checkExecution(decision, finalRequest, { nonceStore });
if (!check.ok) throw new Error(check.errors.map((e) => e.code).join(", "));
```

It refuses if the target or arguments changed, the decision expired, it was a deny, an escalation has no person's confirmation, or it was already used.

From a shell or a script:

```bash
npx -p @cubitrek/agent-passport-verifier agent-passport authorize acme.example --scope procurement.purchase --amount 42000
```

It exits 0 for allow, 2 for escalate and 1 for deny. Add `--json` for the full decision.

A valid passport proves what the issuer authorised, not who is calling you. Authenticate the caller as the issuer's agent through your transport before acting on it; see spec §7, "What verification proves".

## Give your AI assistant the tools

Claude Code:

```bash
claude mcp add agent-passport -- npx -y -p @cubitrek/agent-passport-verifier agent-passport mcp
```

Claude Desktop, Cursor and other MCP clients:

```json
{
  "mcpServers": {
    "agent-passport": {
      "command": "npx",
      "args": ["-y", "-p", "@cubitrek/agent-passport-verifier", "agent-passport", "mcp"]
    }
  }
}
```

| Tool | What it does |
| --- | --- |
| `verify_agent_passport` | Verifies a company's passport and explains it in plain English |
| `authorize_agent_action` | Allow, escalate or deny one request from that company's agent |
| `check_agent_passport_health` | Runs the health check, with a fix for each problem |
| `draft_agent_passport` | Drafts a passport for your own agent; signing stays on your machine |

Four tools on purpose: few enough for a model to choose correctly, and no private key ever passes through the model. The server has no dependencies beyond the verifier.

## Keep it healthy

`agent-passport doctor` checks what counterparties will run into: delivery without redirects, content type, CORS, cache lifetimes that could keep a revoked passport alive, the DNS key, DNSSEC, the signature, expiry runway, lifetime, spending thresholds, the revocation list, and whether the logo, terms, contact and endpoint URLs respond. Each problem comes with a fix, and the command exits 1 when anything fails.

Run it on a schedule with the GitHub Action in this repository:

```yaml
name: Agent Passport monitor
on:
  schedule:
    - cron: "0 6 * * *"
  workflow_dispatch:
jobs:
  passport:
    runs-on: ubuntu-latest
    steps:
      - uses: Cubitrek/agent-passport@v0
        with:
          domain: yourdomain.example
          warn-days: "14"
```

The job fails on any failed check, annotates warnings, and writes the full checklist to the job summary. Set `fail-on-warn: "true"` to fail on warnings too, for example two weeks before expiry.

## What's in the box

```
agent-passport/
  spec/
    agent-passport-v0.1.md       # Canonical spec text
    threat-model.md              # Failure modes the spec addresses
    proposals/attestations.md    # Proposal: third-party test results, signed by the tester
  schemas/
    agent-passport.schema.json   # JSON Schema (draft 2020-12)
  examples/
    acme.agent-passport.json     # Procurement agent for a fictional buyer
    globex.agent-passport.json   # Sales agent for a fictional seller
    cubitrek.agent-passport.json # Cubitrek's own published passport
  packages/
    verifier/                    # @cubitrek/agent-passport-verifier: library, CLI, MCP server
  action.yml                     # GitHub Action: scheduled health check
```

To lint a file against the schema without the CLI:

```bash
npx ajv validate -s schemas/agent-passport.schema.json -d examples/acme.agent-passport.json
```

## Adopters

Add yourself by sending a PR to [`adopters.md`](./adopters.md). Once your passport validates, your domain is listed in [the Cubitrek registry](https://cubitrek.com/agent-passport/adopters).

## Relationship to other specs

Agent Passport is **additive**. It does not replace anything.

| Layer | Spec |
| --- | --- |
| Agent-to-tool, same org | Model Context Protocol (MCP) |
| Agent-to-agent transport | Agent2Agent (A2A) Agent Card |
| Capability manifest | `agents.json` (Wildcard), A2A skills |
| **Identity, authority, audit, escalation** | **Agent Passport (this spec)** |

- **A2A `/.well-known/agent-card.json`** answers "what can this agent do." Agent Passport answers "what is this agent authorised to commit to on behalf of which business."
- **MCP** is about a single agent-tool boundary. Agent Passport is about cross-organisational trust.
- **OpenAPI** describes HTTP surface. Agent Passport describes commercial surface.
- **Hosted agent registries and runtime guardrails** decide inside one platform. A published passport works across companies with no shared platform, and those products can read it as an input.
- **W3C Verifiable Credentials** are a primitive Agent Passport can lean on for stronger identity proofs in v0.2.

## Versioning

Spec versions follow semver-ish: `MAJOR.MINOR`. Breaking changes bump `MAJOR` and ship under a new path (`/spec/agent-passport-v1.0.md`). Additive changes bump `MINOR`. Field deprecations keep one major-version of backward compatibility.

The `version` field on every passport is required and reads as `0.1.0`. Changes to the spec and the tooling are recorded in [CHANGELOG.md](./CHANGELOG.md).

## Security

Please report vulnerabilities privately. See [SECURITY.md](./SECURITY.md).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). The short version: file an issue first if you want to change the schema; trivial doc fixes go straight to PR.

## Authors

Authored at [Cubitrek](https://cubitrek.com) by Faizan Ali Khan, April 2026. Maintained as a public good for the agentic economy.

If your business would like guidance on rolling out Agent Passport, the Cubitrek AEO/GEO team handles the issuing key setup, DNS records, and the workflow integration. See [cubitrek.com/services/aeo-geo](https://cubitrek.com/services/aeo-geo).

## Licence

MIT. See [LICENSE](./LICENSE).
