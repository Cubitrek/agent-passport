# Execution-boundary harness

One synthetic action, authorized once, then executed several ways. It answers
a single question: when the action that reaches the provider is not the action
that was authorized, does anything actually happen?

The harness is deliberately small and framework-neutral. It uses a stub
provider that records every side effect it performs, so a case passes only
when the provider observed nothing, not merely when a library returned an
error.

The same cases run against three sources of authority, which is the other
point of the file. The rules are one engine, and where the permission came
from does not change what reaches the provider.

| Mode | Where the authority comes from |
| --- | --- |
| `passport` | A counterparty's published passport, fetched and verified |
| `policy` | A policy file on this machine. No counterparty, no passport |
| `combined` | Both at once, where the tighter of the two binds |

## Run it

```bash
cd packages/verifier && npm install && npm run build && cd ../..
node examples/execution-boundary/harness.mjs
node examples/execution-boundary/harness.mjs --authority policy
node examples/execution-boundary/harness.mjs --json
```

Exit code 0 means every case matched its expectation under every authority,
and no receipt carried the payload.

## The cases

| Case | What happens | Expected |
| --- | --- | --- |
| `control` | The exact action that was authorized is executed | executes |
| `mutate-target` | The target changes after authorization | blocked |
| `mutate-arguments` | An argument (the destination account) changes | blocked |
| `mutate-amount` | The value changes | blocked |
| `replay` | The same approved decision is used twice | blocked on the second use |
| `expired` | The decision is used after its window | blocked |
| `reauthorize-B` | B is authorized fresh, on its own merits | blocked, because B needs a person or exceeds a cap |
| `over-budget` | Individually legal actions, run until the cap is gone | blocked once the total no longer fits |
| `concurrent` | Two decisions taken while there is room for one | blocked on the second |
| `in-transit-body` | The request body changes between signing and receipt | blocked |

Cases 1 to 9 sit at the authorization boundary. Case 10 sits at the transport
boundary, where the caller's signature is checked, and needs a request key the
issuer published, so it is skipped where there is no passport.

## Result for Agent Passport 0.1.2

```
authority: passport (the passport Acme Corporation publishes at acme.example)
case              expected  executed  effects  blocked because
--------------------------------------------------------------------------------------------
control           executes  true      1
mutate-target     blocked   false     0        execution.request-changed
mutate-arguments  blocked   false     0        execution.request-changed
mutate-amount     blocked   false     0        execution.request-changed
replay            blocked   false     1        execution.replayed
expired           blocked   false     0        execution.expired
reauthorize-B     blocked   false     0        execution.needs-human
over-budget       blocked   false     6        execution.denied
concurrent        blocked   false     2        execution.denied
in-transit-body   blocked   false     0        httpsig.digest-mismatch
receipts: 2 written (executed, blocked), target in receipt: false, arguments in receipt: false
```

`policy` and `combined` produce the same verdicts, with `combined` refusing
`reauthorize-B` outright rather than sending it to a person, because the local
cap is below the amount. The `replay` row shows one effect because its first,
legitimate execution went through; the second attempt with the same decision
did not.

## How it works, and what it assumes

`decide()` returns a decision bound to the exact request: a digest over the
subject, the authority behind it, the scope, amount, counterparty and the
concrete tool, target and arguments, plus a nonce and a short expiry.
`guardedCall()` recomputes that digest from the values about to be executed and
refuses on any difference, after the window, on reuse, and for a decision that
was a deny or an unconfirmed escalation.

The assumption this rests on is explicit: the component that performs the side
effect goes through the guard. The harness does exactly that, using the
library's own `guardedCall()` rather than a helper written for the test.
Nothing here intercepts arbitrary code: a caller that skips the guard and calls
the provider directly is outside what this layer can see, which is why the
library also refuses to hand out reusable, unbound approvals in the first
place.

Cases 8 and 9 need a running total, which is what the ledger is. Both are set
inside one engagement, because a ceiling a passport publishes per engagement
only binds when the receiver says which engagement this is. A local cap over a
day or a month does not need that.

## Reusing it against another system

Swap the stub provider and the `guardedExecute()` wrapper for the equivalent
call in the system under test, keep the same cases and the same pass criterion
(the provider observed no effect), and compare the `--json` output. The pass
criterion is deliberately about observed effects rather than returned errors,
so the comparison stays fair across designs.

## Proving the harness can fail

A test that cannot go red proves nothing, so each of these was run against the
harness to confirm it does:

| Break | Result |
| --- | --- |
| The integrator skips the guard and calls the provider directly | 8 cases red in every mode |
| `checkExecution()` stops comparing the request digest | 3 cases red in every mode |
| Receipts start carrying the arguments | the payload check fails |
| Both ceiling checks disabled at once | 2 cases red in every mode |

The ceiling is enforced twice: when the decision is made, so the refusal can
say why, and inside the ledger's reservation, which is the atomic one. Either
alone still blocks the harness, so the unit tests isolate each one separately.
