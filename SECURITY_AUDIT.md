# UpsilonAuth security and release audit

> Historical baseline: this document records the pre-remediation state found on 2026-09-13. The findings drove the implementation in `REMEDIATION_PLAN.md`; resolved status and residual risks are recorded in `SECURITY_REVIEW.md`.

Date: 2026-09-13

Scope: the effective working tree, including uncommitted backend hardening and the untracked `website/` application. This document describes observed behavior, not intended behavior.

## Executive assessment

UpsilonAuth has a coherent small Go control plane, sound Ed25519 primitives, useful parent-to-child attenuation checks, replay nonces, transactional lineage revocation, TLS/configuration guardrails, and a local Gin verifier. It is not ready for a developer release or production deployment.

The release blocker is architectural: a workload record contains identity material but no authority grant. A successfully enrolled workload can request any audience, action, resource, TTL up to the global maximum, and delegation depth. Therefore the intended invariant cannot be established at the root:

```
Authority(child)
  subset-of Authority(parent)
  subset-of Authority(root lease)
  subset-of Authority(workload grant)
```

The current code enforces only the first relationship.

Current maturity: **experimental**.

## A. Current architecture

- `cmd/upsilonauth` loads environment configuration, opens PostgreSQL, automatically applies migrations, composes the repository/use-case/HTTP layers, and serves on port 8080.
- `internal/domain` defines workloads, leases, audit events, and repository/use-case interfaces.
- `internal/attenuation` validates action/resource/expiry/depth narrowing between a parent and child.
- `internal/crypto` parses Ed25519 keys, signs EdDSA JWTs, verifies lease JWTs, derives key IDs, and publishes JWKS.
- `internal/repository` stores workloads, leases, nonces, revocations, and audit events in PostgreSQL. It uses transactions and a root-lineage advisory lock for delegation/revocation races.
- `internal/usecase` authenticates workload signatures and issues, delegates, and revokes leases.
- `internal/delivery` exposes Gin routes, TLS enforcement, admin bearer authentication, body/header limits, an in-memory IP limiter, JWKS, and a revocation list.
- `sdk/go/client` creates signed root-lease HTTP requests.
- `sdk/go/middleware` fetches JWKS/revocations and enforces EdDSA, registered claims, action/resource scope, and revocation in Gin.
- `website/` is a Next.js marketing/docs application with a small Playwright suite.

## B. Implemented features verified in code

- Ed25519 workload and control-plane signing keys.
- Signed root requests covering method, escaped path, timestamp, nonce, and raw-body SHA-256.
- Atomic nonce uniqueness per workload via a PostgreSQL primary key.
- EdDSA-only JWT verification with issuer, audience, expiry, issued-at, not-before, subject, and JWT ID checks.
- Parent token hash binding during delegation.
- Strict parent-to-child action, resource-prefix, expiry, depth, and maximum-depth attenuation.
- Recursive descendant revocation, serialized against delegation by a root-lineage advisory lock.
- Workload disable plus revocation of leases currently owned by that workload.
- Active/previous control-plane verification keys in JWKS.
- TLS-required-by-default API configuration and database-TLS validation.
- 64 KiB request bodies, 16 KiB server headers, 16 KiB verifier token limit, list/value/depth limits.
- Constant-time admin token digest comparison.
- Non-root distroless container, read-only Compose filesystem, dropped Linux capabilities, and loopback-only host binding.
- Unit tests for selected token attacks, attenuation cases, replay reuse, body limits, proxy trust, and metadata redirects.

## C. README claims that are true

- UpsilonAuth is machine-oriented and not a human identity provider.
- Workloads prove possession of enrolled Ed25519 keys for root issuance.
- Existing child leases cannot add actions, broaden the currently supported resource-prefix model, extend expiry, or increase maximum depth.
- The parent JWT is signature/claim checked and compared to the persisted token hash before delegation.
- Revoking a lease recursively revokes current descendants.
- The verifier requires a configured audience and EdDSA.
- The container runs as non-root and the local Compose API binds to loopback.

## D. README claims that are inaccurate or incomplete

- “Bounded” root authority is not implemented; there is no workload grant or authority ceiling.
- “Child task” delegation is not implemented as an identity transition. Child leases retain the parent workload as subject and no recipient is required.
- Resource matching is described as safe but does not canonicalize traversal, percent encoding, Unicode, slash, or case ambiguity.
- “Local verification” still has a hard central dependency whenever the two-second revocation cache expires; no bounded-stale or expiry-only mode exists.
- The quickstart is not copy-paste complete: `.env` values used by Compose are not exported into the shell for later `$ADMIN_TOKEN`/`$WORKLOAD_PUBLIC_KEY` commands.
- Key rotation covers control-plane verification overlap only; workload key rotation and compromise procedures are absent.
- API documentation omits request/response schemas, error codes, readiness, inspection, tracing, consumption, and operational semantics.

## E. Website claims that are accurate

- The product uses Ed25519, JWT/JWKS, short expirations, signed root requests, and a Gin verifier.
- Existing parent-to-child action/resource/expiry/depth checks are monotonic for accepted resource strings.
- Metadata redirects are not followed and strict revocation failures fail closed.
- The listed current HTTP routes match the current router.

## F. Website claims that are inaccurate or incomplete

- “A root workload starts with a bounded lease” and “issue bounded authority” are false without workload grants.
- The depicted child-task identity handoff is false; current delegation is bearer-only and keeps the same subject.
- “Verification should remain local and stateless” conflicts with mandatory live revocation refreshes.
- The quickstart is fragments, not an executable workflow; variables/imports/error checks are missing.
- The website README says port 3000 while Playwright is configured for 3100.
- There is no security page, complete API/SDK/deployment documentation, maturity disclosure, limitations section, or threat-model link.

## G. Security vulnerabilities

### CRITICAL

1. **No root authority ceiling.** Any enrolled workload can mint arbitrary authority within global limits. This is direct privilege escalation relative to the product model.

### HIGH

2. **Replay lifetime is wrong for future timestamps.** Nonces expire at server-now plus the request window. A request dated at the positive edge of the window can be replayed after that nonce expires while the timestamp remains acceptable. Expiry must be based on the signed timestamp's latest valid instant.
3. **No explicit delegation recipient.** A bearer parent token delegates anonymously and children retain the parent's subject. Stolen tokens can mint further bearer capabilities, and lineage does not identify the receiving workload.
4. **Resource canonicalization is insufficient.** Values such as traversal segments, percent-encoded equivalents, backslashes, non-normalized Unicode, and slash variants are not rejected/canonicalized consistently. A protected service that normalizes differently can authorize outside the intended scope.
5. **Token profile is incomplete.** Header type is generic `JWT`; there is no schema version, distinct token ID and lease ID, root lease ID, explicit current/root workload identity, or confirmation claim. Duplicate JSON claims are not rejected.
6. **Reachable vulnerable dependencies.** `govulncheck` reports GO-2026-5970 (`x/text`), GO-2026-5676 and GO-2025-4233 (`quic-go`), and GO-2026-5004 (`pgx/v5`). The fixed minimums reported by the scanner are `x/text` 0.39.0, `quic-go` 0.59.1, and `pgx/v5` 5.9.2. Some traces may be conservative, but release artifacts must not ship with known reachable findings.
7. **No limited-use atomicity.** `max_uses`, idempotent consumption, and double-spend protection do not exist.

### MEDIUM

8. **Duplicate JSON keys are accepted.** Go's JSON decoder accepts repeated known fields with last-value semantics for API bodies and JWT claims.
9. **Only strict revocation mode exists.** Every verifier instance can poll every two seconds; there is no bounded-stale last-known-good mode, expiry-only mode, ETag, backoff, or jitter.
10. **Revocation snapshots are unsigned and unbounded.** The endpoint materializes every unexpired revoked ID and provides no conditional response or maximum count/size contract.
11. **No optional proof of possession.** Lease theft is bearer-token compromise with no supported key binding.
12. **Startup always runs migrations.** Production application instances mutate schema automatically; migrations have names but no checksums or rollback/recovery contract.
13. **Workload key rotation is absent.** There is no overlap model, rotation endpoint, audit event, or old-key validity policy.
14. **Admin-token validation checks length, not decoded entropy/format.** Low-entropy 32-character values are accepted.
15. **No request correlation IDs or structured error codes.** This impairs incident response and SDK-safe error handling.
16. **Audit records are incomplete.** Denials, request IDs, source metadata, requested/granted authority, root/parent relationships, and reason codes are not recorded. No inspection/trace API exists.
17. **Readiness and metrics are absent.** `/healthz` is process-only; DB/schema readiness and security metrics are unavailable.
18. **Rate limiting is instance-local and uniform.** Limits reset on restart, do not coordinate across replicas, and treat health/JWKS/admin/issuance alike.
19. **JWK `kid` is not recomputed from the supplied key.** A JWKS can assign arbitrary IDs to keys; TLS/configuration still protects the source, but strict key identity should reject mismatch.
20. **Signed-route canonical behavior is not explicitly locked.** Gin redirect/fixed-path behavior and exact route binding are not configured as a security contract.

### LOW

21. Invalid UUID-like path IDs can become database errors rather than stable client errors.
22. API content type is not required to be JSON.
23. HSTS has no `includeSubDomains`; this may be intentional but is undocumented.
24. The full repository Go pattern traverses an accidental Go package inside `website/node_modules`, making release checks noisy and environment-dependent.
25. An audit-generated HTML response artifact is currently untracked at repository root and must be removed before release.

## H. Missing production features

- Workload authority grants and grant versioning.
- Explicit recipient delegation and recipient-active checks.
- Optional RFC-style key confirmation/proof of possession.
- Typed stateless constraints and a separate stateful-use path.
- Atomic limited-use consumption with retry/idempotency semantics.
- Workload public-key rotation and overlap.
- Configurable strict, bounded-stale, and expiry-only revocation.
- Workload/lease read APIs, trace, audit inspection, and a CLI.
- Request IDs, structured logs/errors, readiness, and metrics.
- Explicit development/production mode and a separate migration command.

## I. Missing tests

- PostgreSQL repository and migration integration tests.
- Root-ceiling privilege-escalation tests.
- Property/fuzz tests for arbitrary delegation trees.
- Resource canonicalization bypass/fuzz tests.
- Explicit-recipient, disabled-recipient, and workload-rotation tests.
- Duplicate/malformed/oversized/wrong-type/wrong-version token tests.
- Audience-confusion and token-substitution matrix tests.
- Concurrent nonce, revoke-vs-delegate, disable-vs-issue, and max-use double-spend tests.
- Revocation-mode, stale-cache, ETag, backoff, and key-rotation tests.
- Full API contract tests and a database-backed end-to-end quickstart.
- Container health/security checks and CI release gates.

## J. Architecture risks

- Resource validation is duplicated in attenuation, signing verification, and SDK verification, making semantic drift likely.
- Authorization decisions are split across unlocked reads and transactional writes; future grant/key mutation would introduce TOCTOU without grant/key versions and row locks.
- A flat full revocation list scales with all active revocations and creates synchronized polling pressure across services.
- The public SDK exposes only a request signer and static-resource middleware, leaving callers to rebuild API/error/retry behavior.
- Audit data cannot currently reconstruct delegation actors/recipients or explain denials.
- Environment-only signing secrets are deployable but lack file/secret-provider ergonomics and documented compromise containment.

## Existing quality-gate results

- `go test ./...`: pass, but accidentally includes a package below `website/node_modules`.
- `go vet ./...`: pass.
- `gofmt -d`: clean.
- Website ESLint: pass.
- Website TypeScript: pass.
- `npm audit --omit=dev --audit-level=moderate`: zero reported production vulnerabilities.
- Next production build: previously passes with process-spawn permission; sandboxed build fails at worker spawn (`EPERM`), an environment limitation that CI must avoid.
- Docker engine and database integration: not available in the current host session, so container/database behavior is not yet validated.
