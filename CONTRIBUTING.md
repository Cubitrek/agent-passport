# Contributing to Agent Passport

Thanks for your interest. Agent Passport is a public-good spec maintained by [Cubitrek](https://cubitrek.com); contributions are welcome from anyone running, building, or critiquing agent infrastructure.

**Security issues:** please do not open a public issue. Report them privately as described in [SECURITY.md](./SECURITY.md).

## What we want

- Real-world adoption notes (file an issue under "adopters")
- Threat-model gaps the spec misses
- Library implementations in other languages (Python, Go, Rust)
- Tooling: schema validators, IDE plugins, issuer integrations (the reference CLI lives in `packages/verifier/bin`)
- Editorial improvements to the spec text and examples

## What to discuss before opening a PR

- **Schema changes.** Open an issue first. Schema changes propagate across every implementation, so we want a thread on the trade-offs before code lands.
- **New required fields.** Same as above. Required fields raise the issuer-side burden; we add them only when a concrete attack or use case forces it.
- **Renames.** If a current field is misnamed, we will introduce the new name as an alias for one minor version before the rename lands.

## What can go straight to PR

- Typos and clarifications in `spec/*.md`
- New example passports in `examples/`
- Tests in `packages/verifier/test/`
- Bug fixes in the verifier package

Add a line to [CHANGELOG.md](./CHANGELOG.md) under the unreleased version for any change a spec reader or verifier user would notice.

## Versioning rules

- `MAJOR.MINOR` for the spec. Breaking changes bump MAJOR and ship under a new path (`spec/agent-passport-v1.0.md`).
- The verifier package follows semver tied to the spec it targets.
- The JSON Schema's `$id` carries the spec version: `https://cubitrek.com/spec/agent-passport/v0.1/schema.json`.

## Running the verifier locally

```bash
cd packages/verifier
npm ci
npm run build
npm test
```

The tests run offline: network calls are stubbed, and signing uses freshly generated keys.

If you change `schemas/agent-passport.schema.json`, also run:

```bash
node scripts/sync-schema.mjs
```

so the verifier's inlined copy stays in sync.

## Releasing the verifier

Bump `version` in `packages/verifier/package.json`, move the changelog entry out of "unreleased", merge, then push a tag named `verifier-v<version>`. The Release workflow builds, tests, checks the tag against the package version, and publishes to npm with provenance.

The GitHub Action (`action.yml`) is referenced as `Cubitrek/agent-passport@v0`. After a release, move the `v0` tag to the release commit so monitors pick up the new checks.

## Code of conduct

Be excellent to each other. No CoC document yet; the project is small enough that the maintainers respond directly. If something is going wrong, email hello@cubitrek.com.

## Maintainer

[Cubitrek](https://cubitrek.com), authored by Faizan Ali Khan, April 2026.
