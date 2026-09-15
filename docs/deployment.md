# Deployment guide

UpsilonAuth is beta software. Deploy it first in a constrained environment, keep leases short, and monitor both correctness and revocation behavior. It has not received an independent security assessment.

## Required configuration

| Variable | Default | Rules |
| --- | --- | --- |
| `UPSILON_ENV` | none | Required: `development` or `production` |
| `UPSILON_PORT` | `8080` | Compose-only loopback host port; does not change the container listener |
| `DATABASE_URL` | none | Required PostgreSQL URL; production requires `sslmode=require`, `verify-ca`, or `verify-full` |
| `ADMIN_TOKEN` | none | Required base64url value decoding to at least 24 random bytes |
| `CONSUMPTION_TOKEN` | none | Required distinct high-entropy verifier credential |
| `SIGNING_PRIVATE_KEY` | none | Required base64/base64url Ed25519 32-byte seed or valid 64-byte private key |
| `TOKEN_ISSUER` | none | Absolute URL; production requires HTTPS, no credentials/query/fragment |
| `PREVIOUS_PUBLIC_KEYS` | empty | Comma-separated Ed25519 public keys retained only for verification overlap |
| `MAX_LEASE_TTL` | `5m` | Positive, at most 24 hours |
| `TOKEN_CLOCK_SKEW` | `5s` | Zero through one minute |
| `SIGNED_REQUEST_WINDOW` | `30s` | Positive, at most five minutes |
| `REQUIRE_TLS` | `true` | Cannot be false in production |
| `TRUST_FORWARDED_PROTO` | `false` | Requires explicit trusted proxy CIDRs |
| `TRUSTED_PROXY_CIDRS` | empty | Comma-separated IP/CIDR allowlist used by Gin/proto trust |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | empty | Must be set together for application TLS |
| `ALLOW_INSECURE_DATABASE` | `false` | Forbidden in production |
| `MIGRATIONS_DIR` | `migrations` | Ordered migration directory |
| `MIGRATION_MODE` | apply in development, verify in production | `apply` or `verify` |
| `RATE_LIMIT_PER_MINUTE` | `120` | Positive, at most 10,000 per instance/source IP |
| `RATE_LIMIT_BURST` | `30` | 1–1,000 |

`DATABASE_URL_FILE`, `ADMIN_TOKEN_FILE`, `CONSUMPTION_TOKEN_FILE`, `SIGNING_PRIVATE_KEY_FILE`, and `PREVIOUS_PUBLIC_KEYS_FILE` are supported. The direct value and matching `_FILE` are mutually exclusive. Use mounted secret files or your platform's secret-injection mechanism; do not bake values into images.

## TLS and reverse proxies

Prefer end-to-end TLS. If a trusted reverse proxy terminates TLS, set `REQUIRE_TLS=true`, `TRUST_FORWARDED_PROTO=true`, and restrict `TRUSTED_PROXY_CIDRS` to the proxy network. UpsilonAuth ignores forwarded HTTPS claims from any other source. Configure the proxy to replace, not append/forward, client-controlled scheme headers.

Expose administrative/consumption routes only to required networks. JWKS, revocation, health, and readiness are public API routes but still need abuse controls at the edge for internet-facing deployments. The built-in limiter is in-memory per process.

## PostgreSQL and migrations

Use a dedicated role/database, TLS with certificate verification where available, encrypted backups, restricted network access, and tested restore procedures. Run migration jobs separately and application replicas in `MIGRATION_MODE=verify`; see [migrations.md](migrations.md).

Expired nonce cleanup can be scheduled with a conservative query such as:

```sql
DELETE FROM workload_nonces WHERE expires_at < NOW() - INTERVAL '1 hour';
```

Run it in small batches for high-volume systems. Do not delete audit records; export them to durable security storage according to retention policy.

## Container

The shipped multi-stage image supports `linux/amd64` and `linux/arm64`. Release tags are published as a multi-platform image index, so Docker selects the matching image for the deployment host. The image uses a distroless runtime, runs as `nonroot:nonroot`, contains only the server/migration/health binaries and migrations, and has no shell. Compose drops all Linux capabilities, enables `no-new-privileges`, uses a read-only filesystem plus a small `noexec` tmpfs, publishes only port 8080 on loopback, and keeps PostgreSQL private.

Build an image for the current platform locally:

```sh
make container
```

Validate both supported platforms into a local OCI archive, or publish a release image to a registry:

```sh
# One-time setup when the current builder does not support multi-platform output.
docker buildx create --name upsilonauth-builder --driver docker-container --use --bootstrap

make container-multiarch
make container-push RELEASE_IMAGE=ghcr.io/your-org/upsilonauth:v0.1.0
```

Publishing is what creates the registry manifest that lets deployment platforms pull the correct architecture automatically. The tag-based GitHub release workflow uses the same `linux/amd64,linux/arm64` build.

Equivalent production runtime controls should include:

- read-only root filesystem;
- all capabilities dropped;
- no privilege escalation;
- explicit CPU/memory/process limits;
- only port 8080 exposed to intended networks;
- `/readyz` readiness and `/healthz` liveness checks;
- immutable version/image digest and generated SBOM;
- secrets mounted separately from the image.

The base images are version-tagged but not digest-pinned in this beta repository. Production release automation should record and approve resolved image digests.

## Signing-key rotation

Normal rotation:

1. Generate a new Ed25519 seed in the secret manager.
2. Add the old public key to `PREVIOUS_PUBLIC_KEYS` and deploy the new private key atomically.
3. Keep the old verification key for at least the longest outstanding token lifetime plus clock skew and deployment/cache propagation.
4. Remove it only after all tokens it signed are invalid.

Emergency rotation removes the compromised public key immediately, deploys a new signing key, revokes affected lineages, and accepts that cached verifiers may require refresh/restart or cache expiry. See [SECURITY.md](../SECURITY.md).

## Workload-key rotation

Use `POST /v1/workloads/:id/rotate-key`. Normal rotation may specify an overlap up to 24 hours. Emergency rotation uses zero overlap and normally `revoke_outstanding: true`. The exact authenticating key is rechecked in lease-creation transactions, so a retired key cannot cross the rotation boundary.

## Production checklist

- Set `UPSILON_ENV=production`, `REQUIRE_TLS=true`, HTTPS issuer, TLS PostgreSQL, and `MIGRATION_MODE=verify`.
- Use distinct randomly generated admin and consumption credentials.
- Keep server/workload private keys in secret managers with least-privilege access.
- Choose and document verifier revocation mode/staleness.
- Use service-specific audiences, narrow grants, short TTLs, and PoP for theft-sensitive flows.
- Configure trusted proxies and edge rate limits explicitly.
- Alert on readiness failures, denial/replay spikes, rotations, disables, revocations, and audit export failures.
- Exercise key compromise, database restore, and revocation outage procedures.
- Pass [RELEASE_CHECKLIST.md](../RELEASE_CHECKLIST.md) for the exact source/image revision.
