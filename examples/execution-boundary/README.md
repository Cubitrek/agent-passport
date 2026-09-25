# Execution-boundary harness

One synthetic action, authorized once, then executed eight ways. It answers a
single question: when the action that reaches the provider is not the action
that was authorized, does anything actually happen?

The harness is deliberately small and framework-neutral. It uses a stub
provider that records every side effect it performs, so a case passes only
when the provider observed nothing, not merely when a library returned an
error.

## Run it

```bash
cd packages/verifier && npm install && npm run build && cd ../..
node examples/execution-boundary/harness.mjs
node examples/execution-boundary/harness.mjs --json
```

Exit code 0 means every case matched its expectation.

## The cases

| Case | What happens | Expected |
| --- | --- | --- |
| `control` | The exact action that was authorized is executed | executes |
| `mutate-target` | The target changes after authorization | blocked |
| `mutate-arguments` | An argument (the destination account) changes | blocked |
| `mutate-amount` | The value changes | blocked |
| `replay` | The same approved decision is used twice | blocked on the second use |
| `expired` | The decision is used after its window | blocked |
| `reauthorize-B` | B is authorized fresh, on its own merits | blocked, because B needs a person |
| `in-transit-body` | The request body changes between signing and receipt | blocked |

## Result for Agent Passport 0.1.2

```
case              expected  executed  effects  blocked because
--------------------------------------------------------------------------------------
control           executes  true      1
mutate-target     blocked   false     0        execution.request-changed
mutate-arguments  blocked   false     0        execution.request-changed
mutate-amount     blocked   false     0        execution.request-changed
replay            blocked   false     1        execution.replayed
expired           blocked   false     0        execution.expired
reauthorize-B     blocked   false     0        execution.needs-human
in-transit-body   blocked   false     0        httpsig.digest-mismatch
```

The `replay` row shows one effect because its first, legitimate execution went
through; the second attempt with the same decision did not.

## How it works, and what it assumes

`authorize()` returns a decision bound to the exact request: a digest over the
scope, amount, counterparty and the concrete tool, target and arguments, plus
a nonce and a short expiry. `checkExecution()` recomputes that digest from the
values about to be executed and refuses on any difference, after the window,
on reuse, and for a decision that was a deny or an unconfirmed escalation.

The assumption this rests on is explicit: the component that performs the side
effect calls `checkExecution()` with the final values. The harness models that
with a `guardedExecute()` helper, which is the integration contract. Nothing
here intercepts arbitrary code: a caller that skips the check and calls the
provider directly is outside what this layer can see, which is why the library
also refuses to hand out reusable, unbound approvals in the first place.

Case 8 sits one layer lower. The request itself is signed (RFC 9421) with a
key the issuer publishes inside its passport, so a body altered in transit
fails before authorization is even considered.

## Reusing it against another system

Swap `guardedExecute()` and the stub provider for the equivalent call in the
system under test, keep the same cases and the same pass criterion (the
provider observed no effect), and compare the `--json` output. The pass
criterion is deliberately about observed effects rather than returned errors,
so the comparison stays fair across designs.
