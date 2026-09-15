# Architecture

```text
Administrator policy
        |
        v
Versioned workload grant
        |
        | signed Ed25519 request
        v
Root capability lease
        |
        | signed request by current subject + parent token
        v
Delegated lease for explicit recipient
        |
        | EdDSA/JWKS verification + audience/action/resource checks
        v
Protected service
```

The Go server is split into domain contracts, pure attenuation/resource/constraint checks, cryptographic token handling, use cases, transactional PostgreSQL persistence, and Gin delivery. The verifier fetches signing keys and, depending on mode, revocation state; normal authorization decisions are performed in-process. `max_uses` is deliberately stateful and calls the control plane for atomic consumption.

## Authority model

The workload grant is the root ceiling. It defines audiences, actions, resources, maximum TTL, maximum delegation depth, whether delegation is permitted, whether root leases require PoP, an optional finite use ceiling, and stateless constraints.

A child retains the parent's single audience and must have exactly `parent.depth + 1`. It cannot add actions, broaden resource patterns, extend expiry, increase maximum depth, remove/weaken constraints, or restore a removed authority dimension. At least one dimension must normally narrow. The child subject is `delegate_to`; its parent, root lease, root workload, and delegating workload remain explicit.

Finite-use roots cannot delegate. An unlimited parent may create a finite-use terminal child. This avoids duplicating a mutable budget across sibling capabilities.

## Persistence and concurrency

Root issuance locks the workload and rechecks active status, grant version, and the exact key that authenticated the request. Delegation locks the recipient, delegator, and root lineage. Revocation and delegation share a root-scoped PostgreSQL advisory lock. Limited-use consumption locks the lease row and uses unique `(lease, idempotency key)` and `(lease, use number)` constraints.

Audit events are inserted in the same transaction as security mutations. A database trigger rejects audit updates and deletes. This is append-only at the application database level, not tamper-proof against a database superuser.

## Verification model

Lease tokens are Ed25519 JWS compact tokens with `typ=upsilon-lease+jwt`, one exact audience, schema version 1, registered time/identity claims, unique JTI, and an `ups` capability claim. The parser rejects unexpected algorithms, headers, claims, duplicate JSON names, unknown versions, malformed resources/constraints, and tokens larger than 16 KiB.

PoP-bound tokens include `cnf.jkt`, the RFC 7638-style JWK thumbprint of the subject workload's Ed25519 public key. The caller sends a DPoP-style EdDSA proof bound to method, canonical URI (without query), access-token hash, issue time, and proof ID. Replay storage is local to each verifier process.

See [security-model.md](security-model.md), [THREAT_MODEL.md](../THREAT_MODEL.md), and [deployment.md](deployment.md).
