# End-to-end scenario

Two companies, one purchase, the whole chain in one run.

Acme runs a procurement agent and publishes a passport. Globex sells, and
receives a signed call from that agent. Nothing is stubbed except the network:
real Ed25519 keys, real signatures, real DNS records, the real library.

```bash
cd packages/verifier && npm install && npm run build && cd ../..
node examples/end-to-end/scenario.mjs
```

Exit code 0 means every link held and every break was caught.

## Why this exists

The unit suite tests each layer, and the execution-boundary harness tests the
guard. Neither tests the joins, and that is where the interesting failures
live: a passport that verifies but whose authority is read wrongly, a caller
bound to the wrong passport, a receipt nobody but its author can check, a
ledger that agrees with itself and not with the decision. Those only appear
when the whole thing runs in one go.

## What it walks through

1. Acme issues a passport, signs it, and publishes the key as a DNS TXT record
2. Globex verifies it the way any counterparty would: fetch, DNS key by key id, signature, expiry, revocation
3. Globex ties the live caller to that passport with an RFC 9421 signature over the request
4. Globex intersects Acme's published envelope with its own inbound policy, so the tighter of the two binds
5. Globex decides, and the amount is reserved against a running total
6. Globex performs the side effect once, through the guard, and settles the reservation
7. An auditor holding only the public key verifies the receipt

## Then it breaks every link

| Break | Expected |
| --- | --- |
| A passport edited after signing | fails verification |
| A DNS key that is not the signer | fails verification |
| A signing key published outside the issuer's zone | fails verification |
| A caller using a key the passport does not publish | refused |
| The same signed call replayed | refused |
| An action swapped between approval and execution | never reaches the provider |
| The same decision used twice | refused on the second use |
| An order past the receiver's own daily cap | denied |
| A receipt edited after signing | fails verification |

The last check reads the ledger and confirms exactly one commitment across the
whole run, so a refusal that happened to leave spend behind would show up.

## What a receipt does and does not carry

The receipt names the agent, both sources of authority, the tool, the scope,
the amount and the outcome. It does not carry the target or the arguments. The
scenario asserts that directly, because the whole point of handing a receipt to
a third party is that it can be read without disclosing the call.
