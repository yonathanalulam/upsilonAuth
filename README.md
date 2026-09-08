# upsilonAuth

upsilonAuth is an open-source authorization control plane for machine-to-machine workloads. It issues short-lived Ed25519-signed capability leases and permits workloads to delegate narrower leases without allowing descendants to recover privileges removed by an ancestor.

The system is designed for task graphs, automation workers, build agents, data pipelines, and service-to-service calls where long-lived bearer credentials create unnecessary exposure.

## Security Model

A lease carries an action set, a resource set, an expiration, and a delegation depth. A delegated lease is accepted only when:

- Every child action exists in the parent action set.
- Every child resource exists in the parent resource set.
- The child expiration is no later than the parent expiration.
- The child depth is exactly the parent depth plus one.
- At least one authority dimension is strictly reduced.
- The parent is active and unexpired when delegation occurs.

Capability tokens are compact JWTs signed with EdDSA. Target APIs verify them locally from the published JWKS, so request authorization does not require a synchronous control-plane lookup.

Root lease issuance is a privileged control-plane operation. The current HTTP surface must be deployed behind workload authentication such as an mTLS gateway, a private service mesh, or an authenticated internal API proxy. Network exposure alone is not an authorization boundary.

## Architecture

The codebase follows Clean Architecture:

- cmd/upsilonauth wires configuration, PostgreSQL, cryptography, HTTP delivery, and graceful shutdown.
- internal/domain defines core lease data and dependency contracts.
- internal/attenuation contains pure monotonic attenuation rules.
- internal/crypto owns Ed25519 key generation, JWT signing, and JWKS serialization.
- internal/usecase coordinates minting, delegation, signing, hashing, and persistence.
- internal/repository implements lease persistence with pgx.
- internal/delivery exposes the Gin HTTP API.
- sdk/go/middleware provides local capability verification for Gin services.

Dependencies point inward through small interfaces. Delivery does not depend on pgx, and repository code does not own authorization policy.

## Token Claims

JWT registered claims identify the lease and target audience. The subject is included when a workload identity is supplied:

```json
{
  "sub": "workload-id",
  "jti": "lease-id",
  "iat": 1788861600,
  "exp": 1788865200,
  "ups": {
    "actions": ["read"],
    "resources": ["orders"],
    "depth": 1,
    "parent": "parent-lease-id"
  }
}
```

The parent field is omitted for root leases.

## HTTP API

### POST /v1/leases

Mints a root lease for a target service. TTL values use Go duration syntax.

```json
{
  "audience": "service:payments",
  "actions": ["read", "write"],
  "resources": ["payments/*"],
  "ttl": "5m",
  "max_depth": 3
}
```

### POST /v1/leases/:id/delegate

Mints a strictly attenuated child lease.

```json
{
  "actions": ["read"],
  "resources": ["payments/*"],
  "ttl": "2m"
}
```

### GET /.well-known/jwks.json

Publishes the active Ed25519 verification key as an OKP JWK.

## Verification SDK

```go
package main

import (
    "log"

    "github.com/gin-gonic/gin"

    upsmiddleware "upsilonAuth/sdk/go/middleware"
)

func main() {
    verifier, err := upsmiddleware.New(upsmiddleware.Config{
        JWKSURL: "http://upsilonauth:8080/.well-known/jwks.json",
    })
    if err != nil {
        log.Fatal(err)
    }

    router := gin.New()
    router.GET("/orders", verifier.Require("read", "orders"), func(c *gin.Context) {
        claims, _ := upsmiddleware.ClaimsFromContext(c)
        c.JSON(200, gin.H{"workload_id": claims.Subject})
    })
    log.Fatal(router.Run(":8090"))
}
```

The verifier caches JWKS keys, refreshes on expiry or an unknown key ID, accepts only EdDSA, requires token expiration, validates issued-at time, and checks exact action and resource membership.

## Local Development

Requirements:

- Go 1.23 or newer
- PostgreSQL 16
- Docker with Compose for containerized development

```sh
make test
make build
DATABASE_URL='postgres://upsilonauth:upsilonauth@localhost:5432/upsilonauth?sslmode=disable' make run
```

Start the complete local stack:

```sh
make up
```

The Compose stack applies the initial migration when the PostgreSQL data volume is first created and exposes the API on port 8080.

Stop the stack:

```sh
make down
```

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| DATABASE_URL | Yes | PostgreSQL connection URL |
| GIN_MODE | No | Gin runtime mode; use release outside development |

## Key Lifecycle

The current process generates an Ed25519 signing key at startup. Restarting the control plane rotates the key immediately, which invalidates outstanding leases. This behavior suits fully ephemeral deployments. Deployments requiring restart continuity should add an external key-management adapter before production use.

## Operational Guidance

- Terminate TLS at a trusted ingress or service mesh.
- Restrict root minting and delegation endpoints to authenticated workloads.
- Use short expirations aligned with task duration.
- Keep PostgreSQL private and enable TLS outside local Compose.
- Export audit events to durable monitoring and incident-response systems.
- Treat token logs and database token hashes as sensitive security data.

## License

upsilonAuth is available under the MIT License.
