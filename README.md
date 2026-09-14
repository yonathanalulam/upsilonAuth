# UpsilonAuth

Temporary, delegated authority for machine workloads.

UpsilonAuth is an authorization service for machine workloads. It issues temporary capability leases to services, workers, CI/CD jobs, pipelines, serverless functions, agents, MCP servers, and internal automation. Workloads authenticate with Ed25519 signatures, root leases stay within explicit administrator grants, and delegated authority can shrink but cannot expand.

> **Maturity: beta.** The security model is implemented and covered by unit, property, integration, concurrency, malformed-input, and end-to-end tests. It has not yet received an independent security assessment or substantial production operating history. Do not describe this release as battle-tested or production-ready.

UpsilonAuth is not a human identity provider, Auth0/Keycloak replacement, secrets manager, cloud IAM, API gateway, general policy engine, or replacement for OAuth/OIDC, SPIFFE, OPA, or OpenFGA. It sits between workload identity and protected services to issue and verify task-level machine authority.

## Why UpsilonAuth exists

Machine workloads often share credentials that are broader and longer-lived than the task requires. UpsilonAuth lets an administrator set the maximum authority for each workload, then lets that workload request a short lease and delegate a smaller lease to another workload. The resulting token can be checked inside the protected service, while parent, root, and recipient IDs keep the decision traceable.

## Interactive example

The project website includes a frontend-only example of an orchestrator delegating smaller leases to a research agent and browser worker. You can try an allowed request and a denied request, inspect the reason, and see the matching Gin middleware call. The example is illustrative; it does not claim to contact a live authorization server.

```sh
cd website
npm install
npm run dev
```

Open `http://localhost:3000/#demo`. Use Node.js 20.9 or newer.

## Authority invariant

```text
Authority(child)
  subset-of Authority(parent)
  subset-of Authority(root lease)
  subset-of Authority(workload grant)
```

Authority includes one audience, actions, canonical resources, expiration, delegation depth, typed constraints, and optional use limits. A delegated lease names its recipient and preserves root/parent/delegator lineage.

## Implemented security properties

- Ed25519 workload identities, signed requests, Ed25519 lease tokens, key IDs, and JWKS verification overlap.
- Explicit versioned workload grants bound audiences/actions/resources/TTL/depth/delegation/PoP/use/constraints.
- Strict `typ=upsilon-lease+jwt` schema version 1 with required issuer, audience, subject, expiry, issued-at, not-before, JTI, lease/root/parent/workload lineage, and authority claims.
- Exact resources and final-segment bounded prefix wildcards only; ambiguous traversal, encoding, separator, Unicode, and glob forms fail closed.
- Explicit active delegation recipient and signed delegation by the current parent subject.
- Optional Ed25519 key-thumbprint PoP with DPoP-style method/URI/token binding and replay checks.
- Recursive transactional revocation, workload disable, workload key rotation/overlap, and authenticated-key transaction binding.
- `STRICT`, `BOUNDED_STALE`, and `EXPIRY_ONLY` local-verifier revocation modes with ETag/last-known-good caching.
- Atomic finite-use consumption with verifier authentication and idempotency; no claim that mutable counts are stateless.
- Request/body/header/token/list/depth bounds, explicit trusted proxies, production TLS/config validation, structured errors/logs, request IDs, readiness, metrics, append-only application audit events, inspection, and lineage tracing.

Read the precise model and residual risks in [THREAT_MODEL.md](THREAT_MODEL.md) and [docs/security-model.md](docs/security-model.md).

## Quickstart

Prerequisites: Go 1.26+, Docker, and Docker Compose v2.

```sh
git clone https://github.com/yonathanalulam/upsilonAuth.git
cd upsilonAuth
go run ./cmd/keygen > .env
docker compose up --build -d
curl --fail http://127.0.0.1:8080/readyz
```

Run the complete enrollment → root issuance → explicit delegation → Gin verification → lineage revocation test:

```sh
set -a
. ./.env
set +a
go run ./cmd/smoke -base http://127.0.0.1:8080 -admin "$ADMIN_TOKEN"
```

Success prints `smoke ok`. PowerShell commands and manual integration guidance are in [docs/quickstart.md](docs/quickstart.md).

## Go integration

```go
control, err := client.NewControlPlane("https://auth.internal", nil, false)
signer, err := client.NewSigner(workloadID, workloadPrivateKey)

lease, err := control.RequestLease(ctx, signer, client.LeaseRequest{
    Audience: "service:payments",
    Actions: []string{"payments:refund"},
    Resources: []string{"customer/*"},
    TTL: "60s",
    MaxDepth: 2,
    Constraints: map[string]string{},
})
```

Protect a dynamic Gin resource:

```go
verifier, err := middleware.New(middleware.Config{
    JWKSURL: "https://auth.internal/.well-known/jwks.json",
    Issuer: "https://auth.internal",
    Audience: "service:payments",
    RevocationMode: middleware.RevocationStrict,
})

router.POST("/customers/:customerID/refunds",
    verifier.Require("payments:refund", func(c *gin.Context) string {
        return "customer/" + c.Param("customerID")
    }),
    refundHandler,
)
```

See [docs/sdk.md](docs/sdk.md) for imports, typed enrollment/delegation/revocation, PoP, constraints, limited-use consumers, structured errors, and revocation modes.

## Architecture overview

```text
Admin grant → Root lease → Delegated lease → Protected service
                    │              │
                    └──── PostgreSQL lineage and revocation state
```

The Go control plane authenticates signed workload requests, checks grant and delegation rules, stores lease lineage in PostgreSQL, and signs leases with Ed25519. Protected services use the Go middleware to verify token claims locally and consult revocation or finite-use state only when their configured mode requires it. See [docs/architecture.md](docs/architecture.md) for component and transaction boundaries.

### Repository map

- `cmd/upsilonauth`: production server and fail-fast configuration.
- `cmd/migrate`: explicit migration apply/verify command.
- `cmd/upsilon`: safe lease inspect/trace operator CLI.
- `cmd/keygen`, `cmd/smoke`: development credentials and tested local flow.
- `internal/attenuation`, `constraints`, `resource`, `crypto`: authorization invariants and token profile.
- `internal/usecase`, `repository`, `delivery`: orchestration, PostgreSQL transactions, and Gin API.
- `sdk/go/client`, `middleware`, `pop`, `autherrors`: developer integration surface.
- `migrations`: ordered checksum-tracked PostgreSQL migrations.
- `website`: Next.js product and documentation site.

## Documentation

- [Local quickstart](docs/quickstart.md)
- [Architecture](docs/architecture.md)
- [Security model and limits](docs/security-model.md)
- [HTTP API reference](docs/api.md)
- [Go SDK](docs/sdk.md)
- [Deployment](docs/deployment.md)
- [Migrations and recovery](docs/migrations.md)
- [Security reporting](SECURITY.md)
- [Threat model](THREAT_MODEL.md)
- [Release checklist](RELEASE_CHECKLIST.md)

## Verification

```sh
make test
make vet
make vuln
make lint
```

`make release-check` additionally runs race tests, website lint/build/e2e, and a container build. CI also runs a clean PostgreSQL migration/concurrency suite, the end-to-end Compose quickstart, a HIGH/CRITICAL image scan, and CycloneDX SBOM generation.

## Current limitations

UpsilonAuth has not had an independent security audit or substantial production use. Rate limits and PoP replay caches are process-local, revocation snapshots are not independently signed, signing-key rotation is operator-managed, and V1 administration uses a static high-entropy bearer credential. The beta has no enterprise support SLA. Production deployments should evaluate operational requirements around key management, revocation distribution, and workload scale. Review [docs/security-model.md](docs/security-model.md) and [THREAT_MODEL.md](THREAT_MODEL.md) before a controlled deployment.

## License

[MIT](LICENSE)
