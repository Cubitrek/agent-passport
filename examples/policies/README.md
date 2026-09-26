# Policy examples

A policy is the same envelope a passport publishes, written by you instead. It
says what your own agent may do, how much it may commit, and when a person
decides. `agent-passport guard` reads one and enforces it.

## treasury.json

A payments example, and the shape most policies take.

```bash
agent-passport guard \
  --policy examples/policies/treasury.json \
  --ledger ~/.agent-passport/spend.jsonl \
  --receipts ~/.agent-passport/receipts.jsonl \
  -- npx -y @stripe/mcp
```

Reading it top to bottom:

**`scope`** is what this agent may do at all, in `subject.verb` form. Anything
not listed is refused no matter what else the policy says.

**`limits`** are the money. Each one is enforced separately, so the tightest
always binds. A window of `day` or `month` is the UTC calendar day or month;
`total` is everything ever; `engagement` is one piece of work you name with
`--engagement`.

A limit is only real if something counts against it, so `guard` refuses to
start without `--ledger` when a policy sets one. That file is the running
total, and it survives restarts.

**`humanInLoop`** is the threshold above which the agent stops and a person
decides. Below it the agent proceeds alone. Above the ceiling nothing proceeds
at all, because no autonomous commitment that size was ever authorised.

**`tools`** is the bridge between what the policy talks about and what actually
gets called. A policy says `payments.charge, up to 5,000 USD`; the agent calls
`stripe.create_charge({ amount: 800000 })`. Only you know that 800000 means
8,000 USD, so you write it down:

| Field | What it does |
| --- | --- |
| `match` | The tool name, or a pattern where `*` stands for any run of characters |
| `scope` | Which of your scopes this tool exercises |
| `amountFrom` | Where the value lives, as a path from the call, e.g. `args.amount` |
| `amountUnit` | `minor` for cents, `major` for whole units. Default `major` |
| `targetFrom` | Where the thing being acted on lives, e.g. `args.customer` |
| `note` | Extra text shown to the model on the tool |

The first matching rule wins, so order is your priority. Put specific rules
above wildcards.

A rule that names `amountFrom` and finds no number there is refused rather than
let through unpriced. A call whose value cannot be read cannot be held to a
limit, and letting it pass would quietly defeat the cap.

**`unmatched`** decides what happens to a tool no rule covers: `escalate` (the
default, a person decides), `deny`, or `allow`. `allow` means the tool is not
governed and leaves no receipt, which is worth knowing before you choose it.

## claude-code.json

Limits on the assistant running on your own machine, applied through a Claude
Code hook rather than a proxy. This one sees the built-in tools too, so it can
speak about `Bash`, `Write` and `Edit`, not only MCP tools.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [{
          "type": "command",
          "command": "agent-passport",
          "args": ["hook", "--policy", "/abs/path/claude-code.json",
                   "--ledger", "/abs/path/spend.jsonl",
                   "--receipts", "/abs/path/receipts.jsonl"]
        }]
      }
    ]
  }
}
```

Two things it does differently from the proxy.

**An escalation becomes a prompt.** Claude Code can put the question to the
person at the keyboard, so `ask` is a real answer here rather than a refusal
with a phone number in it.

**An allowed call is answered with nothing at all.** Saying `allow` would
bypass Claude Code's own permission prompts, so a policy that said yes would
quietly approve things you would otherwise have been asked about. The guard
narrows what may happen and never widens it. Pass `--skip-prompt-on-allow` if
you want the policy to be the last word.

### Check the hook is actually running

A hook whose command cannot be found exits non-zero, and Claude Code treats
that as "carry on". So a typo in the path means no guard at all, quietly. That
part is outside what this tool can defend against, so confirm it once by hand:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}' \
  | agent-passport hook --policy /abs/path/claude-code.json
```

You should get a `deny` back. If you get nothing, or an error, the hook is not
wired up and Claude Code is running unguarded.

Until the package is on npm, `command` has to point at the checkout:

```json
"command": "node",
"args": ["/abs/path/agent-passport/packages/verifier/bin/agent-passport.mjs",
         "hook", "--policy", "/abs/path/claude-code.json",
         "--ledger", "/abs/path/spend.jsonl"]
```

### Rules that say so outright

Some shapes are not a question of scope or budget, they are simply not on. A
rule can say that directly with `effect`, and skip the authority entirely:

```json
{
  "match": "Bash",
  "when": { "path": "args.command",
            "matches": "(^|[;&|]\\s*)(sudo\\b|rm\\s+-[a-zA-Z]*[rf]|shutdown\\b|mkfs\\b)" },
  "effect": "deny",
  "note": "Destructive shell commands are not granted, so they are refused."
}
```

`effect` is `deny` or `ask`. Because the first matching rule wins, put these
above the general rule for the same tool: `rm -rf` is refused, and every other
`Bash` call falls through to `shell.run`.

### What command matching can and cannot do

Matching a shell command with a regular expression catches mistakes and the
obvious cases. It is not a boundary against someone trying to get past it. An
agent that wanted to could write `r""m -rf`, build the command from variables,
or base64 it, and no pattern of this kind would see it coming.

Treat these rules as a seatbelt rather than a lock. The real control is the
scope list: an agent that is never granted `shell.run` cannot run a shell at
all, however the command is spelled.

### What it counts

A call is counted when it is allowed, before it runs, because nothing tells the
hook afterwards whether it did. That over-counts a tool that fails, and a
prompt you decline. It is the safe direction, and for priced tools the proxy is
the better surface because it settles against what actually happened.

## When a call needs a person

An escalation used to be a dead end: the guard refused it and named somebody to
ask, and nothing more could happen. With `--approvals` it becomes a question
that can actually be answered.

```bash
agent-passport guard \
  --policy treasury.json \
  --ledger ~/.agent-passport/spend.jsonl \
  --approvals ~/.agent-passport/approvals.jsonl \
  -- npx -y @stripe/mcp
```

The agent gets a refusal with a reference:

```
Waiting for a person: stripe.create_charge
2,500 USD is above the 1,000 USD threshold, so a person must confirm before commitment.
Request 4ad06d81 is recorded. Someone can answer it with:
  agent-passport approve 4ad06d81 --approvals ~/.agent-passport/approvals.jsonl
This call was not sent to the server.
```

You look at what is waiting, and answer it:

```bash
agent-passport approvals --approvals ~/.agent-passport/approvals.jsonl
```

```
4ad06d81  WAITING
  stripe.create_charge  2,500 USD
  on cus_7
  amount.above-human-threshold
  asked 2026-09-26 18:35:31, window closes 2026-09-27 02:35:31
  {"amount":250000,"customer":"cus_7"}
```

```bash
agent-passport approve 4ad06d81 --approvals ~/.agent-passport/approvals.jsonl --by faizan
```

Next time the agent makes that call, it goes through.

### What an approval is worth

**One exact call.** What ties an approval to a call is the digest of the call
itself, taken over the subject, the authority and the request. Change the
amount by a penny, the customer, or any argument, and the approval no longer
matches. It cannot be spent on something else.

**Once.** It is marked used when the call actually runs, so a retry needs
asking again.

**Until the window closes.** The window is the policy's `slaHours`. After that
the call has to be decided afresh.

Unlike a receipt, a waiting request shows the arguments in full. Nobody can
approve what they cannot see, and this file is yours rather than something
handed to a counterparty.

### Who may answer

Here is the part worth being blunt about. An agent that can run a shell can
also run `agent-passport approve`. On anything unattended, the answer has to be
something the agent does not hold, so name the keys that may answer:

```json
"approvers": [
  { "keyId": "approver-2026", "alg": "ed25519",
    "publicKey": "2ib2Yj3Xd1dzjWXBiz_Hu98_DAsLYEabhoSYgObSDgs" }
]
```

```bash
agent-passport keygen --kid approver-2026 --out ~/.agent-passport/keys/approver.pem
agent-passport approve 4ad06d81 --approvals ~/.agent-passport/approvals.jsonl \
  --key ~/.agent-passport/keys/approver.pem --kid approver-2026 --by faizan
```

With `approvers` set, an unsigned answer is refused, an answer signed by a key
the policy does not name is refused, and an answer edited after signing is
refused. Without it, anything in the file counts, which is only safe where the
agent cannot write to that file.

## What the agent sees

The guard annotates the tool list, so the model knows the rules before it tries:

```
stripe.create_charge   Charge a customer. Governed by local policy as
                       "payments.charge". Its value is read from args.amount.
                       Limits: 5,000 USD per day, 40,000 USD per month.
stripe.refund          Refund a charge. Not covered by the local policy, so
                       calling it will be refused (unmatched: escalate).
```

And a refusal explains itself, so the agent can adapt rather than retry:

```
Refused by the local policy: stripe.create_charge
amount.above-ceiling: 9,000 USD for this day exceeds 5,000 USD under your daily cap.
This call was not sent to the server.
```
