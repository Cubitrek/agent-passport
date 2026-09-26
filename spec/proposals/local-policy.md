# Proposal: local policy, counted ceilings, and receipts

Status: implemented in `@cubitrek/agent-passport-verifier` 0.1.2. Not part of
the v0.1 passport format. Nothing here changes what a passport says or how it
is verified.

## The problem

Agent Passport answers a question between companies: this agent belongs to
that business, and here is what it may commit to. The answer arrives as a
signed document published by someone else.

That leaves two things out.

The first is the other direction. A business running its own agent needs the
same envelope for itself, on its own machine, with no counterparty involved:
this assistant may call these tools, up to this much a day, and above that a
person decides. There is no passport to fetch, because there is no second
company. The rules are identical; only the source differs.

The second is arithmetic. A published ceiling is a number in a document. The
0.1.1 verifier took `priorSpend` from the caller and trusted it. Nobody was
counting, so two requests evaluated in the same second both saw the old total
and both passed, and every individual check said yes while the ceiling was
exceeded. A ceiling nothing counts is a statement of intent.

## What changed

**Authority is separated from its source.** An `Authority` is the envelope:
scopes, ceilings, the human threshold, counterparty rules, compliance, and the
subject it applies to. `passportAuthority()` reads one out of a verified
passport. `localPolicy()` builds one from a policy the operator wrote.
`decide()` takes an `Authority` and knows nothing about where it came from, so
the same rules, reason codes, digests and expiries apply either way.
`authorize()` is now a thin wrapper: verify a passport, read its authority,
decide.

**Two authorities can be combined.** `intersect(a, b)` grants only what both
grant: scopes intersect, every ceiling from both sides is kept and each is
enforced, the lower human threshold wins, blocklists merge, allowlists
intersect, and the stricter openness rule and data classification apply. A
refusal on either side refuses everything. This is how a receiver runs its own
limits over whatever a counterparty published. What an issuer publishes is a
maximum it is willing to be held to, never permission to exceed the receiver's
own rules.

**Ceilings are counted.** A `SpendLedger` records what a subject has committed
and over which period: one engagement, a UTC day, a UTC month, or all time. A
decision that could execute now *reserves* its amount, so a second decision
taken before the first executes sees the money as already spoken for. The
guard turns the reservation into spend once the effect has happened, or gives
it back when it has not. A reservation lapses with the decision that holds it,
so a crashed run frees its own headroom.

A cap over a period wider than a single engagement, with no ledger and no
`priorSpend`, now escalates (`amount.cumulative-unknown`) rather than passing.
That is the point: an uncounted cap is an open question, not a yes.

**There is one place a side effect may happen.** `guardedCall()` checks the
decision against the values about to be executed, settles the money, and
writes a receipt, whichever way it goes. `checkAndHold()` is the same gate in
two steps for effects that are not one function call.

**Receipts.** Every decision that reaches the guard leaves a record: who acted,
under which authority, what was decided and why, the binding digest, and what
became of it. Receipts can be signed with Ed25519 and verified by anyone
holding the public key.

## What a receipt deliberately does not carry

No arguments and no target. The tool name, the scope and the amount are in it;
the account that was paid and the contents of the call are not.

The binding digest already covers all of them, so anyone holding the original
request can prove it is the one the receipt refers to, while the receipt on its
own discloses nothing. That makes a receipt safe to hand to an auditor, a
counterparty or a customer, and it means the guard can run somewhere the
payload is never persisted.

The test suite asserts this directly, with a known account number planted in
the request and checked for in the serialised receipt.

## The unknown outcome

When the effect throws, the result is genuinely unknown: the provider may have
acted before the connection died. Treating that as "did not happen" and
releasing the hold would let a retry spend the same headroom twice. The default
is therefore to commit it and record the outcome as `unknown`. Over-counting
only makes the next decision more cautious; under-counting silently raises the
ceiling. `onUnknown: "release"` is available where the provider is known to be
transactional.

## What this does not do

Nothing here intercepts arbitrary code. A component that skips the guard and
calls the provider directly is outside what this layer can see. What the
library can do, and does, is refuse to hand out reusable, unbound approvals in
the first place: every decision is bound to one exact request, expires in
seconds, and can be made single-use.

The in-process ledger and nonce store are for one process. A fleet needs a
shared store whose reserve step is a single atomic operation, such as a Redis
transaction or a database row lock. The interfaces are small on purpose.

The on-disk ledger lives behind the `@cubitrek/agent-passport-verifier/node`
subpath rather than the main entry, because it needs `node:fs` and the rest of
the package deliberately runs unchanged in Workers and browsers.

## Worked through

`examples/execution-boundary/harness.mjs` runs the same cases against all
three sources of authority, including two that only a running total can catch:
a run of individually-legal actions that exceeds a cap, and two decisions taken
while there is room for only one. Each case passes only when a stub provider
recorded no side effect.
