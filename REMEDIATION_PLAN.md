# UpsilonAuth prioritized remediation plan

> Implementation status: P0 through P4 were implemented and re-reviewed on 2026-09-14. Items deliberately deferred or only partially implemented are listed in `SECURITY_REVIEW.md`; this file remains the prioritized plan and invariant record.

This plan follows the 2026-09-13 audit. Required security work is separated from optional product expansion.

## P0 — privilege escalation and known vulnerabilities (implemented)

1. Added a versioned workload authority grant: allowed audiences/actions/resources, maximum TTL, maximum delegation depth, delegation permission, PoP requirement, and typed constraints.
2. Enforced the root request as a subset of the grant and rechecked the active workload plus grant version inside the lease-insert transaction.
3. Fixed nonce expiry to the signed timestamp's final acceptable instant and replaced global hot-path cleanup with atomic conflict handling.
4. Centralized strict resource parsing/canonicalization and rejected ambiguous encodings/traversal/separators/Unicode forms.
5. Upgraded vulnerable Go dependencies and made `govulncheck` a release gate.

Invariant: no authenticated workload can receive authority outside its administrator-configured ceiling, and replay/canonicalization cannot bypass that ceiling.

## P1 — authorization integrity (implemented)

1. Required an active `delegate_to` workload and modeled current subject, delegator, parent, and root explicitly in storage and tokens.
2. Defined a versioned `upsilon-lease+jwt` profile with strict header/claim parsing, a distinct JTI and lease ID, root ID, parent ID, audience, subject, authority, and optional `cnf.jkt`.
3. Added optional Ed25519 proof-of-possession using standard JWK thumbprints and DPoP-style request proofs; bearer and PoP modes remain explicit.
4. Added typed stateless constraints with formal attenuation; mutable usage state remains outside local-only checks.
5. Added atomic `max_uses` consumption with idempotency keys. Consumption occurs before handler execution, is not refunded on handler failure, and same-key retries return the original result.
6. Added property/fuzz tests proving no generated delegation sequence increases authority, plus substitution/audience/token/resource regression matrices.
7. Added workload key rotation with explicit overlap, disable semantics, descendant revocation, and audit preservation.

Invariant: every accepted token has one unambiguous identity, lineage, schema, audience, authority set, and stateful-consumption decision.

## P2 — reliability and operational safety (implemented)

1. Implemented `STRICT`, `BOUNDED_STALE`, and `EXPIRY_ONLY` revocation modes with last-known-good caching, ETag, and bounded freshness.
2. Added request IDs, structured logs, stable error envelopes/codes, readiness, and low-cardinality metrics.
3. Separated schema migration from application startup and added migration checksum/version checks with documented recovery behavior.
4. Added bounded, process-local request-source rate limiting and documented the need for upstream controls in distributed deployments.
5. Added secret-file inputs for signing/admin credentials and documented secret-manager injection.

## P3 — developer experience (implemented)

1. Expanded the Go client to enroll/request/delegate/revoke/consume/inspect with typed requests, responses, and errors.
2. Added dynamic Gin resource derivation and constraint context.
3. Added workload/lease read routes, trace, audit inspection, and `upsilon inspect`/`upsilon trace` commands.
4. Added a reproducible database-backed example and smoke script.

## P4 — website and documentation (implemented)

1. Replaced unsupported claims with the implemented grant/recipient/revocation/PoP semantics and disclosed maturity.
2. Added home, why, how-it-works, security, quickstart, API, SDK, deployment, and limitations content.
3. Made documented quickstart commands copy-paste complete and added them to CI.
4. Added `SECURITY.md`, `THREAT_MODEL.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, the release checklist, examples, and operator docs.

## P5 — explicitly deferred unless evidence demands them

- Human management dashboard and OIDC/SSO.
- Multi-tenant policy administration.
- Redis-backed distributed rate/replay state.
- Endpoint-specific or distributed abuse controls if deployment evidence shows the process-local limiter is insufficient.
- Exponential backoff/jitter, independently signed snapshots, pagination/incremental feeds, or streaming for deployments that outgrow the current request-driven flat revocation feed.
- Kubernetes manifests, Kafka, policy languages, and AI-based authorization decisions.

These are not required for the focused machine-authorization control plane and must not be marketed as present.
