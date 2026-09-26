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
| Running your own agent and wanting limits on it | [Set limits on your own agent](#set-limits-on-your-own-agent) |
| Using Claude, Cursor or another MCP client | [Give your AI assistant the tools](#give-your-ai-assistant-the-tools) |
| Responsible for a published passport | [Keep it healthy](#keep-it-healthy) |

The commands below use `npx`. After `npm install -g @cubitrek/agent-passport-verifier` you can type `agent-passport` directly.

> **Not on npm yet.** 0.1.2 publishes when the release workflow runs. Until then, clone this repository and run `npm install && npm run build` in `packages/verifier`, and call the CLI as `node packages/verifier/bin/agent-passport.mjs`.

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

Each decision is also bound to the exact request, including the concrete tool, target and arguments, and expires after 60 seconds (or the issuer's response window for an escalation). Whatever performs the side effect goes through the guard, with the final values:

```typescript
import { guardedCall } from "@cubitrek/agent-passport-verifier";

const result = await guardedCall(decision, finalRequest, () => provider.transfer(finalRequest), {
  ledger,
  nonceStore,
  receipts,
});
if (result.outcome !== "executed") console.warn(result.receipt);
```

It refuses if the target or arguments changed, the decision expired, it was a deny, an escalation has no person's confirmation, or it was already used. Whichever way it goes, it settles the amount against the ledger and writes a receipt.

### Prove who is calling

A passport is public, so verifying one proves what the issuer authorised, not who is contacting you. When the issuer publishes request-signing keys in its passport, check the signature on the request itself:

```typescript
import { verifyAgentCaller } from "@cubitrek/agent-passport-verifier";

const caller = await verifyAgentCaller(request, verification.passport, { nonceStore });
if (!caller.ok) return reject(caller.errors);
```

That verifies a standard HTTP Message Signature (RFC 9421) over the method, host, path, query and body against the keys the passport publishes, and refuses one that is stale, replayed, made with an unpublished key, or that leaves part of the request uncovered. On the agent side, one call signs the request:

```typescript
import { signAgentRequest } from "@cubitrek/agent-passport-verifier";

const headers = await signAgentRequest({ method: "POST", url, body }, { keyId, privateKey });
```

Issuers create the key with `agent-passport init --request-key`, or add one to an existing passport with `agent-passport request-key`. Mutual TLS or an OAuth client registered to the issuer bind a caller just as well; the point is to bind it before acting on the passport's authority.

From a shell or a script:

```bash
npx -p @cubitrek/agent-passport-verifier agent-passport authorize acme.example --scope procurement.purchase --amount 42000
```

It exits 0 for allow, 2 for escalate and 1 for deny. Add `--json` for the full decision.

Without one of those bindings, a valid passport still only proves what the issuer authorised, not who is calling; see spec §7, "What verification proves".

## Set limits on your own agent

The same envelope works with no counterparty in sight. Write the rules down and the decision engine applies them exactly as it applies a passport's:

```json
{
  "id": "treasury-local",
  "agentId": "ops-bot",
  "scope": ["payments.transfer"],
  "limits": [{ "amount": 5000, "currency": "USD", "window": "day" }],
  "humanInLoop": { "above": { "amount": 500, "currency": "USD" },
                   "escalation": "finance@yourcompany.example" }
}
```

```bash
npx -p @cubitrek/agent-passport-verifier agent-passport authorize \
  --policy treasury.json --ledger spend.jsonl \
  --scope payments.transfer --amount 400 --tool payments.create_transfer
```

`--ledger` keeps the running total, so a cap over a day, a month or a whole engagement is counted rather than merely published. An allow holds its amount until you close it out:

```bash
npx -p @cubitrek/agent-passport-verifier agent-passport settle <nonce> --ledger spend.jsonl --commit
```

A hold that is never settled lapses when the decision expires, so a crashed run frees its own headroom. Without a ledger, a cap wider than a single engagement escalates instead of passing unchecked: nothing is counting it, so it is a question for a person rather than a quiet yes.

Pass a domain **and** a policy to run both at once. Scopes intersect, every ceiling is enforced, and the lower human threshold wins, so what a counterparty published is a maximum it will be held to, never permission to exceed your own rules:

```bash
npx -p @cubitrek/agent-passport-verifier agent-passport authorize acme.example \
  --policy treasury.json --scope payments.transfer --amount 5000
```

In code that is `localPolicy()`, `passportAuthority()` and `intersect()`, all feeding the same `decide()`. See [`spec/proposals/local-policy.md`](./spec/proposals/local-policy.md).

### Receipts

Every decision that reaches the guard leaves a record: who acted, under which authority, what was decided and why, the binding digest, and what became of it. Receipts can be signed with Ed25519 and checked by anyone holding the public key.

A receipt carries no payload. The tool name, the scope and the amount are in it; the target and the arguments are not. The binding digest already covers those, so anyone holding the original request can prove it is the one the receipt refers to, while the receipt on its own discloses nothing. That makes it safe to hand to an auditor or a counterparty.

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
    proposals/local-policy.md    # Proposal: local policy, counted ceilings, receipts
  schemas/
    agent-passport.schema.json   # JSON Schema (draft 2020-12)
  examples/
    acme.agent-passport.json     # Procurement agent for a fictional buyer
    globex.agent-passport.json   # Sales agent for a fictional seller
    cubitrek.agent-passport.json # Cubitrek's own published passport
    execution-boundary/          # Harness: one action, many executions, three authorities
    end-to-end/                  # Two companies, one purchase, the whole chain in one run
  packages/
    verifier/                    # @cubitrek/agent-passport-verifier: library, CLI, MCP server
  action.yml                     # GitHub Action: scheduled health check
```

To lint a file against the schema without the CLI:

```bash
npx ajv validate -s schemas/agent-passport.schema.json -d examples/acme.agent-passport.json
```

## Questions people ask

### What is an Agent Passport?

A signed JSON file a business publishes at `/.well-known/agent-passport.json` that says who an AI agent acts for, what it may do, how much it may commit, when a human takes over, and where the audit trail lives. The signing key is published in the business's own DNS, so anyone can verify it without a central registry.

### How is this different from OAuth?

OAuth authenticates a caller against one provider that issued the token. A passport is published by the business that owns the agent and read by anyone, with no prior relationship and nobody to register with. The two compose: authenticate the caller however you already do, then read the passport for what that caller's employer has publicly committed to.

### How is this different from an A2A Agent Card?

An Agent Card answers "what can this agent do". A passport answers "what is this agent authorised to commit to on behalf of which business, and who takes over when it should not decide alone". Agent Passport is additive to A2A and MCP, not a replacement for either.

### What stops someone forging a passport?

The signing key has to live inside the issuer's own DNS zone. A passport that names `acme.example` as issuer but points at a key in a zone the forger controls is refused before that zone is ever queried. Controlling the domain is the root of trust, which is the same thing a TLS certificate proves.

### Does a verified passport prove who is calling me?

No, and the spec says so plainly. A passport is a public file, so anyone can quote one. It proves what the issuer authorised, not who is on the other end. Bind the caller separately: mutual TLS, an OAuth client registered to the issuer, or the request-signing keys the issuer can publish inside the passport itself.

### Do I need Cubitrek to verify a passport?

No. Verification is a DNS lookup and an Ed25519 signature check. There is no registry, no API key and no service to call. The reference verifier is MIT licensed and the spec is complete enough to reimplement.

### What happens when an agent asks for more than it is allowed?

The decision is allow, escalate or deny, and every answer carries a reason code. Above the issuer's human-in-the-loop threshold it escalates to the named person with a published response window. Above the ceiling it is denied outright, because no autonomous commitment at that size was ever authorised.

### Can it stop an agent quietly exceeding a spend cap?

Yes, when you give it a ledger. A published ceiling that nobody counts is a statement of intent: forty commitments of 2,000 each pass every individual check against a 50,000 ceiling. The ledger reserves the amount when the decision is made and commits it once the effect has happened, so two decisions taken before either executes cannot both spend the same headroom.

### Is it ready to use?

The spec is draft v0.1 and the version field reads `0.1.0`. Cubitrek publishes a passport in production at [cubitrek.com/.well-known/agent-passport.json](https://cubitrek.com/.well-known/agent-passport.json). The reference implementation is covered by the test suite in this repository, an execution-boundary harness and an end-to-end scenario, all of which run in CI. Breaking changes will bump the major version and ship under a new spec path.

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
