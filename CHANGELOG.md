# Changelog

All notable changes will be documented here. UpsilonAuth follows semantic versioning after `v1.0.0`; pre-1.0 releases may contain explicit breaking changes.

## Unreleased — beta hardening

### Added

- Frontend-only delegated-authority example with explainable allow/deny decisions and a matching Gin middleware snippet.
- Versioned workload authority grants and transactional root ceilings.
- Explicit delegation recipients and subject/parent/root lineage.
- Strict versioned `upsilon-lease+jwt` token profile.
- Optional Ed25519 JWK-thumbprint proof-of-possession with DPoP-style proofs.
- Typed stateless constraints and atomically consumed `max_uses` capabilities.
- Workload key rotation/overlap, disable, trace, inspection, audit, readiness, metrics, and three revocation modes.
- Typed Go client, dynamic Gin resources, structured errors, operator inspect/trace CLI, integration/property/concurrency tests, CI, SBOM, and container scanning.

### Security

- Fixed unrestricted root authority, anonymous delegation, nonce replay lifetime, ambiguous resource parsing, token/parent substitution gaps, capability-exhaustion abuse, key-rotation transaction races, panic-path credential logging, and unsafe production defaults.
- Upgraded dependencies and added `govulncheck`, lint, race, migration, frontend, quickstart, and image gates.

### Changed

- Go module path is now `github.com/yonathanalulam/upsilonAuth`.
- Production defaults to migration verification instead of automatic application.
- Limited-use consumption requires a distinct `CONSUMPTION_TOKEN` verifier credential.
