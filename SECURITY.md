# Security policy

## Supported versions

UpsilonAuth is currently beta software. Until the first stable release, security fixes are applied to the latest commit on `main`. When beta releases are tagged, the supported tag will be listed here. Pin evaluations and controlled deployments to an immutable commit or supported release tag, and review the changelog before upgrading.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Please use GitHub Private Vulnerability Reporting if it is enabled for this repository. If that option is unavailable, email the maintainer at [yonathanalulam@gmail.com](mailto:yonathanalulam@gmail.com) with `UpsilonAuth security report` in the subject. This address is already published in the repository license; it is not an encrypted reporting channel, so ask to arrange a safer transfer method before sending sensitive evidence.

Include the affected revision, deployment assumptions, reproduction steps, impact, and any suggested mitigation. Do not include real credentials, private keys, capability tokens, production data, or secrets from a live deployment.

The maintainers aim to acknowledge a report within three business days and provide an initial severity assessment within seven business days. These are targets, not a service-level agreement. Coordinated disclosure timing will depend on impact and fix availability.

## Security boundaries

UpsilonAuth authorizes non-human workloads. It is not a human identity provider, secrets manager, API gateway, network security boundary, or replacement for TLS. Operators remain responsible for protecting PostgreSQL, signing keys, workload private keys, admin credentials, verifier consumption credentials, and metadata transport.

See [THREAT_MODEL.md](THREAT_MODEL.md) for assumptions, mitigations, and residual risks.

## Credential or key compromise

### Workload private key

1. Rotate the workload key with zero overlap.
2. Set `revoke_outstanding: true`, or disable the workload if its integrity is uncertain.
3. Inspect `/v1/audit-events` and trace suspicious leases.
4. Re-enroll or re-enable only after the workload environment is remediated.

An overlap window deliberately keeps the previous key valid. Do not use overlap during emergency containment.

### Control-plane signing key

1. Stop issuance if the attacker may still possess the key.
2. Generate a new Ed25519 seed in the deployment secret manager.
3. Remove the compromised public key from `PREVIOUS_PUBLIC_KEYS`; do not provide a normal overlap.
4. Deploy the new key and publish its JWKS entry atomically.
5. Revoke affected leases. If complete identification is impossible, treat every unexpired token signed by the compromised key as suspect and wait at least `MAX_LEASE_TTL + TOKEN_CLOCK_SKEW` before declaring containment.
6. Review audit and infrastructure logs without copying full JWTs into incident records.

Local verification cannot distinguish a forged token signed by a compromised trusted signing key until that key is removed from JWKS/cache or the token is revoked.

### Admin or consumption credential

Rotate the credential in the secret manager and all consumers, restrict the control-plane network while rotating, and inspect audit/request logs. The consumption credential can spend limited-use leases but cannot create grants or revoke leases. The admin credential can perform all administrative API operations.

## Operational reporting

Security-relevant logs must never include `Authorization`, `DPoP`, `Upsilon-Capability`, workload signature headers, admin/consumption credentials, JWTs, or private key material. UpsilonAuth's built-in request logger records method, route template, status, latency, and request ID only.
