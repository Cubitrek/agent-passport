# Security policy

Agent Passport is a trust specification. A flaw in the spec or in the reference verifier can let one business pass as another, so please report it privately.

## Reporting a vulnerability

- Preferred: GitHub private vulnerability reporting, from this repository's **Security** tab, **Report a vulnerability**.
- Or email hello@cubitrek.com with "agent-passport security" in the subject.

Please do not open a public issue or pull request for a vulnerability. Include the spec section or verifier version, a minimal passport or script that reproduces the problem, and the impact you see.

We acknowledge reports within 5 business days, agree a disclosure date with you, and credit you in the changelog unless you prefer otherwise.

## Scope

- The spec text in `spec/`, including places where the spec claims a protection it does not deliver.
- The JSON Schema in `schemas/`.
- `@cubitrek/agent-passport-verifier` and its `agent-passport` CLI.

A specific company's deployment (its passport, DNS records or keys) is out of scope here. Report those to the issuer through `issuer.contact` in their passport.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.2 and later | Yes |
| 0.1.1 and earlier | No. These accept passports whose signing key is published outside `issuer.domain`. See [CHANGELOG.md](./CHANGELOG.md). |
