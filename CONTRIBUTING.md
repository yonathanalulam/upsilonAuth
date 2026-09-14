# Contributing

UpsilonAuth accepts focused changes that preserve a small, reviewable machine-authorization model.

1. Open an issue or discussion before broad protocol/schema changes.
2. Never include real credentials, private keys, JWTs, authorization headers, or production data in code, tests, logs, or issues.
3. Add a regression test for every authorization/security fix.
4. Keep authority monotonic: no child may broaden any parent dimension.
5. Run `make release-check` where supported, or the equivalent commands in [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
6. Update API/SDK/deployment documentation when behavior changes.

Security reports follow [SECURITY.md](SECURITY.md), not the public issue tracker.

Pull requests should be small enough to review, explain the affected invariant, include migration/recovery notes when schema changes, and avoid unrelated formatting. New dependencies require a maintenance and security justification.
