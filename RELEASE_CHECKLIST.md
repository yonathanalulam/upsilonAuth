# Release checklist

This file records the local public-beta candidate checks completed on 2026-09-14. Remote CI must repeat the automated gates for the exact commit before a beta tag is published.

## Completed beta checks

- [x] `gofmt -l cmd internal sdk examples` prints nothing.
- [x] unit, property, integration, concurrency, malformed-input, and race tests pass against a clean PostgreSQL database.
- [x] `go vet` passes and pinned `golangci-lint` reports zero issues.
- [x] pinned `govulncheck` reports no reachable vulnerabilities.
- [x] authority, audience, substitution, parser, replay, revocation, rotation, disabled-workload, and double-spend regressions pass.
- [x] migration checksums verify and a fresh migration chain succeeds.
- [x] Gitleaks full-history and commit-eligible working-tree scans found no real secrets.
- [x] README, documentation, and website claims were checked against the router, SDK, migrations, and tests.
- [x] limitations, beta maturity, disclosure instructions, and key-compromise guidance are explicit.
- [x] API and SDK examples compile, and the documented Compose flow passes enrollment through revocation.
- [x] website lint, production build, and 14 desktop/mobile Playwright tests pass.
- [x] the interactive example supports keyboard and pointer input and is labeled as frontend-only.
- [x] the container builds as `nonroot:nonroot`, exposes only port 8080, and passes the configured security checks.
- [x] the pinned Trivy scan reports no unaccepted HIGH/CRITICAL finding.
- [x] a pinned Syft build generated a valid CycloneDX SBOM.
- [x] signing, admin, consumption, and database secrets are absent from committed history and final image layers.

## Publication steps

- [ ] Remote GitHub Actions passes for the exact release commit.
- [ ] The CI-generated SBOM is attached to the beta release.
- [ ] Release tag, image tag, source revision, and changelog version agree.
- [ ] Target-environment signing-key rotation, backup, rollback, and restore procedures are reviewed.

## Future production considerations

These are not blockers for a developer-evaluation beta:

- independent security assessment and penetration testing;
- distributed PoP replay protection and distributed rate limiting;
- independently signed revocation distribution;
- automated KMS/HSM-backed signing-key lifecycle management;
- large-scale, multi-instance load, failover, and stale-cache validation; and
- production support, SLOs, and an enterprise SLA.

Passing this checklist supports a public beta decision. It does not establish that a new security product is battle-tested or production-ready.
