# UpsilonAuth threat model

## Scope and security objective

UpsilonAuth is an authorization control plane for machine workloads. An administrator enrolls a workload public key and a versioned authority grant. A signed workload request may receive a root capability lease only within that grant. A current lease subject may delegate a strictly narrower lease to an explicit active recipient.

The primary invariant is:

```text
Authority(child)
  subset-of Authority(parent)
  subset-of Authority(root lease)
  subset-of Authority(workload grant)
```

Authority includes audience, actions, resources, expiry, delegation depth, use limits, and typed constraints. Delegation may remove authority; it cannot restore or broaden it.

## Trust boundaries and assumptions

- PostgreSQL, the control-plane process, configured signing key source, and administrative credential source are trusted components.
- TLS or an equivalently protected internal transport is required between workloads, protected services, metadata consumers, PostgreSQL, and the control plane.
- Protected services derive dynamic resources and constraint values from trusted, canonical application state. UpsilonAuth cannot correct a service that authorizes one resource string and later acts on another.
- The host clock is synchronized within the configured skew/window.
- Local verification is only as fresh as its JWKS and revocation mode permit.
- The built-in rate limiter is instance-local and is not a substitute for edge/network denial-of-service controls.
- UpsilonAuth does not establish the runtime identity or integrity of a machine beyond possession of its enrolled private key.

## Threat analysis

| Threat | Attack and impact | Implemented mitigation | Residual risk |
| --- | --- | --- | --- |
| Stolen workload private key | An attacker signs root requests or delegation requests as the workload. | Explicit grant ceiling, short TTLs, nonce replay protection, rotation with zero-overlap containment, disable plus recursive revocation, audit lineage. | Until detected/rotated, the attacker can exercise the workload's configured grant. A broad grant remains broad. |
| Stolen bearer lease | An attacker presents the token to its audience. | Short expiry, exact audience, narrow scopes, revocation, optional `cnf.jkt` PoP binding. | Bearer mode intentionally treats possession as authority. Revocation can be stale under non-STRICT modes. |
| Compromised child workload | A child uses all delegated authority or attempts to delegate further. | Child authority is strictly attenuated, subject-bound, depth-limited, and cannot exceed parent expiry. PoP can bind use to the child key. | All authority intentionally granted to that child is exposed until expiry/revocation. |
| Compromised parent workload | A parent delegates many narrow children or uses its own lease. | Signed delegation by current subject, grant/root ceilings, lineage, audit, depth limits, disable/revocation. | An unlimited parent may create multiple children within its authority. This is intentional and must be constrained by grants/TTL. |
| Compromised signing key | Forged leases pass cryptographic verification. | Secret-file/secret-manager deployment, Ed25519, `kid`, JWKS overlap, strict algorithm/type checks, emergency rotation procedure. | This is a control-plane root-of-trust compromise. Cached old JWKS and already forged tokens remain dangerous until cache/expiry/revocation containment. |
| Database compromise | An attacker reads lineage/token hashes or mutates grants/revocations. | No private keys or full tokens are stored; token hashes are persisted; constraints and foreign keys enforce structural integrity; audit table rejects update/delete. | A write-capable DB attacker can alter authority records or suppress future availability. Database controls cannot defend against a fully privileged DB administrator. |
| Replay attacks | A signed issuance/delegation request is resent. | Method/path/timestamp/nonce/body digest signature; bounded timestamp window; atomic `(workload, nonce hash)` insertion; expiry based on signed timestamp. | A valid request can be delayed within the window once. Nonce rows require operational cleanup as they age. |
| Privilege escalation / authority amplification | Root requests exceed policy, or children add actions/resources/time/depth/constraints. | Transactionally checked workload/grant version, formal attenuation, bounded wildcard model, property tests over delegation trees. | Application bugs outside the checked authority dimensions remain possible; independent review is still warranted. |
| Delegation loops | Workloads delegate back to prior workloads to reset authority. | Depth always increments, root/parent IDs remain fixed, expiry cannot increase, and authority cannot expand. | Identity can repeat in a lineage, but it cannot reset depth or authority. Cycles in the lease parent graph are prevented by immutable creation and parent-before-child references. |
| Stale revocation cache | A revoked token is accepted locally. | `STRICT`, `BOUNDED_STALE`, and `EXPIRY_ONLY` modes; explicit maximum staleness; ETag and last-known-good cache; short TTL guidance. | No local verifier can provide instantaneous revocation without a live dependency. Operators choose this tradeoff. |
| JWKS poisoning | A metadata source returns attacker keys or redirects to another host. | HTTPS by default, exact configured URL, no cross-origin redirects, strict JWK fields/algorithm/curve, `kid` derived from key, size and duplicate-key limits. | Compromise of the configured origin, DNS/TLS trust, or its private key can poison metadata until cache refresh/repair. |
| SSRF through metadata URLs | Configuration or redirects target internal services. | Absolute HTTP(S) URL validation, HTTPS by default, response bounds, redirects disabled/same-origin only. | The operator can deliberately configure an internal URL; configuration is trusted. Network egress controls remain recommended. |
| Redirect attacks | Metadata or SDK calls redirect credentials/tokens. | SDK and verifier clients override redirect handling and do not follow API metadata/control-plane redirects. | A custom transport/proxy can still alter traffic if TLS trust is compromised. |
| Algorithm confusion | A token changes `alg`, omits `typ`, or abuses key types. | Only EdDSA accepted; exact `typ=upsilon-lease+jwt`; strict three-field JOSE header; Ed25519-only JWKS. | None known beyond cryptographic/library flaws. |
| Token substitution | Parent/path/token IDs or database rows are swapped. | Persisted SHA-256 token hash; constant-time hash compare; exact JTI, lease, subject, root, parent, audience, authority, expiry, depth, and confirmation comparisons. | A signing-key or DB compromise defeats this boundary. |
| Audience confusion / confused deputy | A service accepts a token intended for another service. | Verifier requires one exact configured audience and tokens contain exactly one audience. | Overly broad audience naming chosen by operators can recreate the problem. Use service-specific audiences. |
| Resource canonicalization bypass | Encoded traversal, duplicate separators, Unicode variants, or wildcard ambiguity broaden scope. | NFC-only, case-sensitive parser; rejects percent encoding, traversal segments, slash variants, controls/spaces, arbitrary glob/regex; only a final complete `*` segment is accepted. | The protected service must use the exact same canonical resource identity and avoid later URL/filesystem decoding. |
| Malformed JSON/token | Duplicate fields, unknown claims, oversized payloads, or malformed NumericDates trigger parser differentials. | Duplicate-key rejection, unknown-field rejection, token/request/metadata size limits, required claims and schema version. | Parser/library vulnerabilities remain a supply-chain risk covered by scanning and updates. |
| Oversized requests | Large bodies, headers, tokens, lists, or metadata exhaust memory/CPU. | 64 KiB body, 16 KiB server headers/token, 1 MiB metadata, action/resource/depth/value limits, server timeouts and rate limiting. | Distributed volumetric attacks require upstream controls. Revocation-list growth still requires capacity monitoring. |
| Race conditions | Revoke races delegation, disable races issuance, or key rotation crosses authentication. | Row/advisory locks and transactions; exact authenticated key thumbprint rechecked in the issuance transaction; concurrency regression tests. | New mutation paths must use the same locking protocol. |
| Nonce collision/reuse | Repeated or collided nonces bypass replay controls. | SDK generates 192-bit random nonces; server validates format; per-workload hash uniqueness is atomic. | Broken workload randomness can cause denial of service, but cannot make the same nonce valid twice concurrently. |
| One-time token double spend | Concurrent requests consume the final use more than once. | Lease row `FOR UPDATE`, unique idempotency/use constraints, consume-before-handler semantics, dedicated verifier credential. | A handler failure after consumption does not refund. This favors no double-spend over automatic retry transparency. |
| Limited-use exhaustion DoS | A stolen lease is submitted directly to the consumption endpoint. | Consumption requires a distinct high-entropy verifier credential plus the capability token and idempotency key. | A stolen verifier credential plus token can still spend uses. Scope the credential to protected-service infrastructure and rotate it separately. |
| Admin credential theft | Attacker enrolls/disables/rotates/inspects/revokes. | High-entropy validation, constant-time comparison, TLS requirement, no query-string auth, secret-file support, rate limiting, audit/request IDs. | V1 admin auth is a powerful shared secret. Network restriction and future human OIDC/mTLS integration are recommended. |
| Internal network compromise | Attacker observes or modifies plaintext internal traffic. | Production mode refuses plaintext API and insecure PostgreSQL configuration; metadata clients default to HTTPS. | Development Compose intentionally uses plaintext on an isolated local network. TLS termination and trust configuration remain operator duties. |

## Stateful versus stateless enforcement

Actions, resources, audience, environment, repository, branch, HTTP method, transaction ceiling, expiry, and depth can be checked from signed claims plus trusted request context. `max_uses` is mutable shared state and is never claimed as stateless. It requires an authenticated call to PostgreSQL-backed atomic consumption.

Consumption happens before the protected handler. A handler failure does not refund a use. Retrying with the same idempotency key returns the original use number and does not spend again. Retrying with a different key spends another use if available. This makes failure semantics explicit and prevents concurrent double-spend.

## Out of scope

Human login, workforce SSO, secrets storage, cloud IAM, network admission, general policy languages, rate-budget accounting, cumulative monetary budgets, and runtime malware detection are outside this release.
