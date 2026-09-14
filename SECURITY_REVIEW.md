# UpsilonAuth post-remediation security review

Date: 2026-09-14

This review covers the effective working tree after the P0–P4 remediation. It does not replace an independent security assessment, penetration test, or production operating evidence.

## Decision

Maturity: **beta**.

The original critical root-authority escalation is closed, authorization lineage is explicit, delegation is monotonically attenuating, and the implementation has meaningful unit/property/fuzz/database/concurrency coverage. The project is credible for developer evaluation and constrained beta deployments. It is not production-ready because independent assessment, production history, multi-instance PoP replay coordination, independently signed revocation snapshots, and automated signing-key lifecycle are still absent.

## Fixed security findings

### Critical / high

- Enrolled workloads now have mandatory, versioned authority grants. Root issuance transactionally rechecks active status, exact authenticating key, grant version, audience, action/resource set, TTL, depth, delegation permission, PoP requirement, uses, and constraints.
- Delegation requires a bearer parent token, a new signed request from the parent lease's current subject, and an explicit active recipient. Subject, delegator, parent, root lease, and root workload remain distinct.
- Child authority cannot add actions, broaden resources/audience, extend expiration, increase depth, restore delegation, weaken constraints, or amplify finite-use semantics. Randomized delegation trees test this invariant.
- JWT parsing is EdDSA-only with a three-field JOSE header, explicit `typ`, schema version, one audience, required registered/capability claims, duplicate/unknown top-level claim rejection, strict base64 decoding, and a 16 KiB limit.
- Token hashes and meaningful path/token/lease/parent/subject identifiers are cross-checked to prevent substitution.
- Resource values use one case-sensitive NFC grammar: exact or a final bounded `/*` wildcard. Traversal, percent encodings, separators, empty segments, non-NFC Unicode, arbitrary globbing, and malformed values fail closed.
- Signed workload requests bind method, escaped path, timestamp, nonce, and SHA-256 body digest. Nonce consumption is atomic and its lifetime covers the accepted timestamp window.
- Optional Ed25519 key-thumbprint binding and DPoP-style request proof protect PoP leases from token-only theft.
- Finite-use leases use authenticated, atomic PostgreSQL consumption with row locking and idempotency. The protected service consumes before handler execution; failures are not refunded.
- Lease revocation covers descendants. Workload disable and emergency rotation serialize with issuance/delegation so invalidated authority cannot cross the transaction boundary.
- Panic recovery uses a header-free structured log path. It does not dump capability, PoP, workload-signature, authorization, or consumption headers even when Gin debug mode is active.

### Medium / operational

- Revocation behavior is explicit: `STRICT`, `BOUNDED_STALE`, or `EXPIRY_ONLY`, with ETag-aware caching and last-known-good bounds.
- Production configuration rejects missing/weak credentials, insecure issuer/database/TLS choices, unsafe migration behavior, and invalid time/depth/rate settings.
- Admin and consumption credentials are distinct, high entropy, header-only, and constant-time compared. Secret-file inputs support mounted secret-manager values.
- Request/body/header/token/list/depth limits, in-memory rate limits, trusted-proxy allowlisting, no-redirect metadata fetching, request IDs, structured logs, readiness, and low-cardinality metrics are present.
- Audit events are append-only at the database layer and lineage can be inspected through HTTP or the `upsilon` CLI. JWTs, private keys, authorization headers, workload signatures, and admin credentials are not intentionally logged.
- Migrations have version/checksum tracking and support separate apply/verify commands. Production defaults to verification rather than application startup mutation.
- The distroless container runs as `nonroot:nonroot`; the supplied Compose runtime is read-only, drops all Linux capabilities, and enables no-new-privileges.

## Red-team regression matrix

| Attack attempted | Enforced boundary / evidence | Result |
| --- | --- | --- |
| Root action/resource/audience/TTL/depth escalation | grant validation plus transactional grant/key/version recheck | Rejected |
| Child privilege amplification and restored constraints | deterministic attenuation plus 1,000 randomized trees and 1,000 randomized escalations | Rejected |
| Traversal, encoded traversal, wildcard and Unicode ambiguity | centralized resource grammar, table tests, fuzzing | Rejected |
| `alg`/`typ`/version confusion, missing/duplicate/unknown claims, malformed or oversized JWT | strict token profile and malformed-token matrix | Rejected |
| Wrong service audience | mandatory verifier audience | Rejected |
| Parent/path/token/subject substitution | token hash and identifier/subject checks | Rejected |
| Signed-request replay and nonce race | atomic nonce insert/expiry and concurrency tests | Rejected |
| PoP token without the bound private key or replayed proof | thumbprint/`ath`/method/URL/time/JTI checks | Rejected per verifier instance |
| Parent revocation racing child creation | root-lineage transaction lock | No active child survives |
| Workload disable/key retirement racing issuance | workload row/key recheck in transaction | No active invalid lease survives |
| Final-use double spend and duplicate retry | lease row lock plus unique idempotency record | Exactly one spend; retry is stable |
| Metadata redirect/oversize/duplicate JSON | redirect disabled, origin checked, bounded strict JSON | Rejected |

## Verification evidence

- `go test ./cmd/... ./internal/... ./sdk/... ./examples/...`: pass.
- `go test -race ./cmd/... ./internal/... ./sdk/... ./examples/...` in Linux/CGO: pass.
- `go vet` across commands, internals, SDK, and examples: pass.
- `golangci-lint v2.12.2`: zero issues.
- `govulncheck v1.8.0`: no reachable vulnerabilities; three advisories exist only in required module code paths the project does not call.
- Resource fuzz target: 7,918,359 executions over 20 seconds, pass.
- Fresh PostgreSQL migration chain and repository concurrency suite: pass.
- Fresh Compose image/startup/readiness and executable smoke flow: pass (`smoke ok`).
- Effective API container: non-root, read-only root filesystem, all capabilities dropped, no-new-privileges, healthy.
- Website locked install, ESLint, and Node 24 optimized build: pass; `/`, `/docs`, and `/security` return HTTP 200.
- Playwright: 14 tests pass across desktop and 390-pixel mobile projects, including keyboard/pointer demo behavior, branding, documentation content, and horizontal-overflow checks on every public route. A separate 320-pixel capture was inspected.
- npm production and full dependency audits: zero reported vulnerabilities.
- Pinned Trivy `0.74.0` image scan: zero HIGH/CRITICAL findings in Debian and all three Go binaries; the image secret scan reported no findings.
- Pinned Syft `1.51.1` generated a valid CycloneDX 1.7 SBOM for the inspected image.
- Pinned Gitleaks `8.30.0` scanned all Git history and found no leaks. Commit-eligible working-tree files were also scanned; the only alerts were reviewed synthetic test credentials/UUIDs and non-secret API documentation prose.
- Container configuration and layer history: `nonroot:nonroot`, only port 8080 exposed, expected entrypoint, and no embedded credential values.

## Remaining risks and intentionally deferred work

- Rate limiting and PoP replay caches are process-local. Multi-instance deployments need edge limits and a shared proof-replay design for the threat model that requires global single-use proofs.
- Revocation snapshots depend on HTTPS/origin trust and are not independently signed. The server feed is a bounded flat list; very large revocation populations need another transport.
- Verifier refreshes are mutex-coalesced and ETag-aware but do not yet add exponential backoff/jitter or a streaming/incremental feed.
- Signing-key rotation is an operator deployment procedure, not an online KMS/HSM-backed rotation API. Image base references are version tags rather than repository-pinned digests.
- V1 human/admin access is a static bearer token. A multi-user dashboard would still need OIDC/SSO, RBAC, CSRF-safe sessions, and secure cookie handling.
- Audit success events are append-only. Denials are represented in structured request logs/metrics rather than persisted as a complete append-only denial ledger.
- Cumulative monetary budgets, quotas, and rates are not implemented. They must not be inferred from stateless constraints.
- Expired nonce cleanup is an operator maintenance task.
- No independent security review, penetration test, chaos/failover exercise, benchmark/SLO evidence, or substantial production history exists.
- The public beta has no enterprise support SLA.
- Remote CI and release-artifact generation must still pass for the exact final commit and immutable release tag; local results do not substitute for that final provenance check.

## Release recommendation

Publish only as a beta/developer preview after the remote CI run—including Playwright, Trivy, SBOM generation, clean PostgreSQL integration tests, and quickstart—passes for the exact commit. Use constrained deployments, short leases, service-specific audiences, least-privilege grants, TLS, PostgreSQL TLS/backups, PoP for theft-sensitive flows, and a documented revocation mode. Do not market this revision as production-ready, enterprise-ready, or battle-tested.
