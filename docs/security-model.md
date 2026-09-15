# Security model and limits

## Resource scopes

Resources are case-sensitive NFC strings. Supported forms are exact values (`customer/cus_123`) and a final complete prefix-wildcard segment (`customer/*`). Arbitrary globbing and regular expressions are unsupported.

The parser rejects leading/trailing or duplicate separators, empty/`.`/`..` segments, backslashes, percent encoding, URL query/fragment markers, control/space characters, non-NFC Unicode, and wildcards outside the final segment. Protected services must derive and act on the same canonical identifier; do not authorize a logical ID and later interpret it as an independently decoded path.

## Stateless constraints

Schema version 1 supports:

| Constraint | Rule |
| --- | --- |
| `environment` | Exact string; child must preserve it |
| `repository` | Exact string; child must preserve it |
| `branch` | Exact string; child must preserve it |
| `http_method` | Exact uppercase method; automatically derived by middleware |
| `max_transaction_minor_units` | Positive canonical integer ceiling; child may lower it |

Children may add constraints. Unknown keys fail closed. Application-derived values are provided through `middleware.Config.ConstraintValues`; they must come from trusted state, not unvalidated client headers.

## Stateful constraints

`max_uses` cannot be securely checked from a stateless JWT. A protected service configures an SDK `client.Consumer` with the distinct `CONSUMPTION_TOKEN`, then assigns `consumer.Consume` to `middleware.Config.ConsumeLease`. The verifier atomically consumes before invoking the handler.

- Same lease and same idempotency key: returns the original use and does not spend again.
- Same lease and a new idempotency key: spends a new use if available.
- Concurrent final-use requests: exactly one succeeds.
- Handler/network failure after successful consumption: no refund.
- Control-plane unavailability: fail closed with `AUTHORIZATION_UNAVAILABLE`.

Cumulative monetary budgets, rates, and cross-lease quotas are not implemented.

## Revocation modes

| Mode | Unavailable revocation source | Intended use |
| --- | --- | --- |
| `STRICT` | Deny after the current cache expires | High assurance; default |
| `BOUNDED_STALE` | Use last-known-good data up to `MaxRevocationStaleness`, then deny | Availability with a stated exposure bound |
| `EXPIRY_ONLY` | No revocation request | Very short TTLs and disconnected operation |

The default revocation cache interval is 30 seconds. ETag conditional requests avoid retransferring unchanged snapshots. There is no claim of instantaneous global revocation. The current feed is a bounded HTTP response on each verifier but remains a flat list at the server; deployments with very large active revocation sets must monitor and evolve this transport.

## Bearer versus PoP

Bearer mode accepts possession of the signed token. Use TLS and short TTLs.

PoP mode requires the token plus the private key corresponding to `cnf.jkt`. Set `proof_of_possession: true` on issuance/delegation or require it in the workload grant. The SDK signs DPoP-style proofs and the middleware rejects missing, mismatched, stale, or replayed proofs. In a multi-instance protected service, proof replay caches are per instance; an external shared replay store is not currently implemented.

## Known limits

- V1 admin and verifier-consumption authentication use separate static high-entropy bearer credentials. OIDC/mTLS integration for human administration is not included.
- Rate limiting and PoP replay state are instance-local.
- Revocation snapshots are not separately signed; their authenticity depends on configured HTTPS and origin trust.
- Signing-key rotation is operator-driven through secrets/JWKS overlap, not an online key-management API.
- Nonce rows are retained; routine database maintenance should remove rows whose `expires_at` is safely in the past.
- There has been no independent external security assessment or production operating history.
- The beta does not include an enterprise support SLA.
