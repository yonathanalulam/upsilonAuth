# Local quickstart

This workflow starts PostgreSQL and UpsilonAuth, enrolls a workload, issues and delegates a lease, verifies the child in Gin, revokes the root, and confirms the child is denied.

## Prerequisites

- Git
- Go 1.26 or newer
- Docker with Compose v2
- `make` for the short commands; direct equivalents are shown where useful

## 1. Clone and generate development credentials

```sh
git clone https://github.com/yonathanalulam/upsilonAuth.git
cd upsilonAuth
go run ./cmd/keygen > .env
```

The generated file contains random PostgreSQL, admin, verifier-consumption, server-signing, and example workload values. `.env` is ignored by Git. Never use these development values in another environment.

## 2. Start PostgreSQL and UpsilonAuth

```sh
docker compose up --build -d
docker compose ps
curl --fail http://127.0.0.1:8080/readyz
```

Compose applies migrations because it explicitly sets `UPSILON_ENV=development` and `MIGRATION_MODE=apply`. PostgreSQL is not published to the host; the API is bound to `127.0.0.1:8080`.

If port 8080 is already in use, set `UPSILON_PORT=18080` in `.env` and use `http://127.0.0.1:18080` in the commands below.

## 3. Run the tested end-to-end flow

POSIX shell:

```sh
set -a
. ./.env
set +a
go run ./cmd/smoke -base http://127.0.0.1:8080 -admin "$ADMIN_TOKEN"
```

PowerShell:

```powershell
Get-Content .env | ForEach-Object {
  if ($_ -match '^([^=]+)=(.*)$') {
    Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2]
  }
}
go run ./cmd/smoke -base http://127.0.0.1:8080 -admin $env:ADMIN_TOKEN
```

Success prints `smoke ok`. The smoke program uses the Go SDK to sign requests and the Gin middleware to enforce the child lease. Its source is [cmd/smoke/main.go](../cmd/smoke/main.go).

## 4. Inspect a lease or lineage

Build the operator CLI:

```sh
go build -o ./bin/upsilon ./cmd/upsilon
export UPSILON_BASE_URL=http://127.0.0.1:8080
export UPSILON_ADMIN_TOKEN="$ADMIN_TOKEN"
./bin/upsilon -allow-insecure-http inspect lease_uuid
./bin/upsilon -allow-insecure-http trace lease_uuid
```

Use an ID returned by your own SDK/API flow. Admin secrets may also be supplied with `UPSILON_ADMIN_TOKEN_FILE`; command-line secret flags are intentionally not supported.

## 5. Stop the stack

```sh
docker compose down
```

Add `--volumes` only when you intentionally want to delete the local PostgreSQL data volume.

## Manual API integration

The smoke command is the canonical executable example. For typed client calls, dynamic Gin resources, PoP, revocation modes, and limited-use setup, continue with [sdk.md](sdk.md). The complete HTTP contract is in [api.md](api.md).
