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
