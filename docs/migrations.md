# Database migrations

Migrations are ordered `migrations/*.up.sql` files recorded with SHA-256 checksums in `schema_migrations`. Modified applied migrations fail verification.

## Development

`UPSILON_ENV=development` defaults to `MIGRATION_MODE=apply`. Compose sets this explicitly.

## Production

Run migrations as a separate deployment job, then start every application replica with `MIGRATION_MODE=verify`:

```sh
docker run --rm \
  --entrypoint /usr/local/bin/migrate \
  --env-file /secure/path/upsilon.env \
  upsilonauth:VERSION -mode apply -directory /migrations
```

Verify without mutation:

```sh
docker run --rm \
  --entrypoint /usr/local/bin/migrate \
  --env-file /secure/path/upsilon.env \
  upsilonauth:VERSION -mode verify -directory /migrations
```

The production server defaults to verification and refuses to start if files/checksums/database state disagree.

## Recovery and rollback

There are intentionally no automatic down migrations. Before applying a release, take and test a PostgreSQL backup/snapshot, review every new migration, and stage it against a production-like copy. If application rollout fails after a compatible additive migration, roll back the application image and keep the schema. For an incompatible/failed migration, stop writers and restore the tested backup or apply a reviewed forward-fix migration.

Migration `000005_authority_model` refuses to infer grants for pre-existing workloads. Export required identities, re-enroll them with explicit grants, and test the transition before applying it to legacy data.
