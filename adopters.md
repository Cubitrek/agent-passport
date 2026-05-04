# Adopters

Businesses that publish a valid Agent Passport at `/.well-known/agent-passport.json`.

To add yourself, send a PR appending one row to the table below. Once the maintainers fetch your passport and it validates against the [reference verifier](./packages/verifier), the row goes live and a verification badge appears at [cubitrek.com/agent-passport/adopters](https://cubitrek.com/agent-passport/adopters).

| Domain | Agent | Issued | Status |
| --- | --- | --- | --- |
| cubitrek.com | Cubitrek Humans-for-Agents Router | 2026-04-28 | Live |

## Verification badge

Adopters can embed the badge on their site:

```html
<a href="https://cubitrek.com/agent-passport/adopters">
  <img src="https://cubitrek.com/agent-passport/badge?domain=acme.example"
       alt="Verified Agent Passport adopter" />
</a>
```

The badge endpoint re-verifies on each render and returns red if the passport drops out of conformance.
