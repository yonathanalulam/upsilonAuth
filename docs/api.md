# HTTP API reference

The API is JSON over HTTP. Production mode requires TLS. Request bodies are limited to 64 KiB, server headers to 16 KiB, lease tokens to 16 KiB, action/resource arrays to 64 entries, and delegation depth to 16.

Successful mutating responses include `X-Request-ID`; callers may send a 16–64 character alphanumeric/`-`/`_` request ID. Errors use:

```json
{
  "error": {"code": "AUTHORITY_ESCALATION", "message": "request violates authorization policy"},
  "request_id": "V1StGXR8_Z5jdHi6B-myT"
}
```

Common errors are `400 INVALID_REQUEST`, `401 AUTHENTICATION_FAILED`, `404 RESOURCE_NOT_FOUND`, `409 RESOURCE_CONFLICT`, `422 AUTHORITY_ESCALATION`, `429 RATE_LIMITED`, and `500 INTERNAL_ERROR`. Authentication failures intentionally avoid sensitive detail.

## Authentication schemes

### Administrator

`Authorization: Bearer $ADMIN_TOKEN`. Query-string credentials are unsupported. Used by workload management, inspection, audit, metrics, and revocation.

### Signed workload request

Root issuance and delegation require:

```text
X-Upsilon-Workload-ID: workload UUID
X-Upsilon-Timestamp: Unix seconds
X-Upsilon-Nonce: 32–128 URL-safe characters
X-Upsilon-Signature: base64url Ed25519 signature
```

The exact signed bytes are:

```text
METHOD\nESCAPED_PATH\nUNIX_TIMESTAMP\nNONCE\nLOWERCASE_HEX_SHA256_RAW_BODY
```

Queries are rejected on signed routes. The timestamp must be within `SIGNED_REQUEST_WINDOW`; the nonce is atomically single-use per workload.

### Verifier consumption

Limited-use consumption requires both:

```text
Authorization: Bearer $CONSUMPTION_TOKEN
Upsilon-Capability: complete lease JWT
Idempotency-Key: 16–128 printable ASCII characters
```

The consumption credential is distinct from the admin credential and should only be available to protected-service verifier infrastructure.

## Workloads

### `POST /v1/workloads`

Admin authentication. Enrolls an Ed25519 public key and required authority grant.

```json
{
  "name": "payments-worker",
  "public_key": "base64url-32-byte-ed25519-public-key",
  "grant": {
    "audiences": ["service:payments"],
    "actions": ["payments:read", "payments:refund"],
    "resources": ["customer/*"],
    "max_ttl": "5m",
    "max_delegation_depth": 2,
    "can_delegate": true,
    "require_proof_of_possession": true,
    "max_uses": 0,
    "constraints": {"environment": "prod"}
  }
}
```

Returns `201` with workload ID, name, timestamps, public-key thumbprint, normalized grant, and grant version. It never returns a private key. Duplicate names/keys return `409`; invalid keys/grants return `400`/`422`.

### `GET /v1/workloads/:id`

Admin authentication; no body. Returns `200` with the public workload metadata/grant and optional `disabled_at`. Returns `404` when absent.

### `POST /v1/workloads/:id/disable`

Admin authentication; no body. Atomically disables the workload and revokes leases currently held by it plus their descendants. Returns:

```json
{"revoked": 4}
```

Repeated disable is safe; a missing workload returns `404`.

### `POST /v1/workloads/:id/rotate-key`

Admin authentication.

```json
{
  "public_key": "base64url-new-ed25519-public-key",
  "overlap": "10m",
  "revoke_outstanding": false
}
```

`overlap` may be empty/zero through 24 hours. During overlap, the previous key remains valid for signed requests. Zero overlap is required for emergency retirement. `revoke_outstanding` recursively revokes leases currently held by this workload. Returns `200` with ID, update time, previous-key expiry, and revoked count. Key conflicts return `409`.

## Leases

### `POST /v1/leases`

Signed workload authentication. The requested authority must fit the current workload grant.

```json
{
  "audience": "service:payments",
  "actions": ["payments:refund"],
  "resources": ["customer/*"],
  "ttl": "60s",
  "max_depth": 2,
  "proof_of_possession": true,
  "max_uses": 0,
  "constraints": {"environment": "prod", "http_method": "POST"}
}
```

Use exactly one of `ttl` or RFC 3339 `expiration`. Returns `201` with ID, token, subject workload, audience, expiration, depth/max depth, PoP flag, max uses, and constraints. Grant/audience/scope/depth/TTL escalation returns `422 AUTHORITY_ESCALATION`; replay/signature/disabled-workload failures return `401`.

### `POST /v1/leases/:id/delegate`

Requires `Authorization: Bearer $PARENT_TOKEN` plus a signed workload request by the parent lease's current subject.

```json
{
  "delegate_to": "recipient-workload-uuid",
  "actions": ["payments:refund"],
  "resources": ["customer/cus_123"],
  "ttl": "30s",
  "proof_of_possession": true,
  "max_uses": 0,
  "constraints": {"environment": "prod", "http_method": "POST"}
}
```

The recipient must exist and be active. Audience remains the parent's. Expiry, actions, resources, depth, maximum depth, constraints, and use semantics must strictly attenuate. A PoP parent cannot be delegated with a different authenticating key. Returns the same `201` shape as root issuance, including `parent_lease_id`.

### `GET /v1/leases/:id`

Admin authentication; no body. Returns `200` inspection metadata including the JTI, lease and lineage identifiers, audience, actions/resources, times, revocation state, depth, use counters, PoP flag, and constraints. The JWT and token hash are never returned.

### `GET /v1/leases/:id/trace`

Admin authentication; no body. Returns ordered root-to-target lineage:

```json
{"lineage": [{"id": "root-uuid", "depth": 0}, {"id": "child-uuid", "depth": 1}]}
```

Each element has the full safe inspection shape described above. Returns `404` when the target does not exist.

### `POST /v1/leases/:id/revoke`

Admin authentication; no body. Atomically revokes the lease and all current descendants, serialized against delegation. Returns `200` with `{"revoked": N}`. Repeating a revocation returns zero; an unknown ID returns `404`.

### `POST /v1/leases/:id/consume`

Verifier-consumption authentication; no body. The path ID, capability token, persisted token hash/claims, subject status, revocation, expiry, and finite use count must agree. Returns:

```json
{
  "lease_id": "lease-uuid",
  "idempotency_key": "request-unique-operation-id",
  "use_number": 1,
  "max_uses": 1,
  "replayed": false
}
```

Same-key retries return `replayed: true`. Exhaustion returns `403 MAX_USES_EXCEEDED`. Unlimited leases cannot be consumed through this endpoint.

## Audit and operational endpoints

### `GET /v1/audit-events`

Admin authentication. Optional query parameters: `workload_id`, `lease_id`, and `limit` (1–200, default 100). Returns newest-first append-only application audit events. No request body.

### `GET /.well-known/jwks.json`

Public; no body. Returns active and configured previous Ed25519 verification keys with `kid`, `use=sig`, and `alg=EdDSA`. Cache policy is public with 60-second revalidation guidance.

### `GET /.well-known/revocations.json`

Public; no body. Returns sorted unexpired revoked lease IDs plus `generated_at`. Supports `If-None-Match` and `304`; callers should use the SDK cache/modes rather than poll per request.

### `GET /healthz`

Public; no body. Returns `204` when the process/router is alive. It does not check PostgreSQL.

### `GET /readyz`

Public; no body. Pings PostgreSQL with a two-second bound and returns `204` or `503 NOT_READY`.

### `GET /metrics`

Admin authentication; no body. Returns Prometheus text counters for requests, authorization denials, issuance, delegation, revocation operations, and cumulative HTTP latency. Labels are intentionally avoided to prevent sensitive/high-cardinality data.
