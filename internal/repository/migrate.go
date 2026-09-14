package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool, directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".up.sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return errorsNoMigrations()
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(782347923487)`); err != nil {
			return fmt.Errorf("lock migrations: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`CREATE TABLE IF NOT EXISTS schema_migrations (
				name TEXT PRIMARY KEY,
				applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				checksum BYTEA
			)`,
		); err != nil {
			return fmt.Errorf("create migration table: %w", err)
		}
		if _, err := tx.Exec(ctx, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum BYTEA`); err != nil {
			return fmt.Errorf("upgrade migration table: %w", err)
		}
		if err := baselineExistingSchema(ctx, tx, names); err != nil {
			return err
		}
		for _, name := range names {
			// #nosec G304 -- name comes from ReadDir and never includes a path separator.
			data, err := os.ReadFile(filepath.Join(directory, name))
			if err != nil {
				return fmt.Errorf("read migration %s: %w", name, err)
			}
			digest := sha256.Sum256(data)
			var storedChecksum []byte
			err = tx.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE name = $1`, name).Scan(&storedChecksum)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("check migration %s: %w", name, err)
			}
			if err == nil {
				if len(storedChecksum) == 0 {
					if _, err := tx.Exec(ctx, `UPDATE schema_migrations SET checksum = $2 WHERE name = $1`, name, digest[:]); err != nil {
						return fmt.Errorf("record migration checksum %s: %w", name, err)
					}
				} else if !bytes.Equal(storedChecksum, digest[:]) {
					return fmt.Errorf("migration %s checksum mismatch", name)
				}
				continue
			}
			if _, err := tx.Exec(ctx, string(data)); err != nil {
				return fmt.Errorf("apply migration %s: %w", name, err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)`, name, digest[:]); err != nil {
				return fmt.Errorf("record migration %s: %w", name, err)
			}
		}
		return nil
	})
}

func VerifyMigrations(ctx context.Context, pool *pgxpool.Pool, directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	files := make(map[string][sha256.Size]byte)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		// #nosec G304 -- entry.Name comes from ReadDir for this operator-configured directory.
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		files[entry.Name()] = sha256.Sum256(data)
	}
	if len(files) == 0 {
		return errorsNoMigrations()
	}
	rows, err := pool.Query(ctx, `SELECT name, checksum FROM schema_migrations ORDER BY name`)
	if err != nil {
		return fmt.Errorf("query migration state: %w", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(files))
	for rows.Next() {
		var name string
		var checksum []byte
		if err := rows.Scan(&name, &checksum); err != nil {
			return fmt.Errorf("scan migration state: %w", err)
		}
		expected, exists := files[name]
		if !exists || len(checksum) != sha256.Size || !bytes.Equal(checksum, expected[:]) {
			return fmt.Errorf("migration %s is missing or has a checksum mismatch", name)
		}
		seen[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate migration state: %w", err)
	}
	if len(seen) != len(files) {
		return fmt.Errorf("database has unapplied migrations")
	}
	return nil
}

func baselineExistingSchema(ctx context.Context, tx pgx.Tx, migrations []string) error {
	var applied int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&applied); err != nil {
		return fmt.Errorf("count migrations: %w", err)
	}
	if applied != 0 {
		return nil
	}
	var workloads, leases, auditEvents bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('workloads') IS NOT NULL, to_regclass('leases') IS NOT NULL, to_regclass('audit_events') IS NOT NULL`).Scan(&workloads, &leases, &auditEvents); err != nil {
		return fmt.Errorf("inspect existing schema: %w", err)
	}
	if !workloads && !leases && !auditEvents {
		return nil
	}
	if !workloads || !leases || !auditEvents {
		return fmt.Errorf("existing schema is incomplete")
	}
	initialColumns := map[string][]string{
		"workloads":    {"id", "name", "public_key", "created_at", "updated_at"},
		"leases":       {"id", "workload_id", "parent_lease_id", "actions", "resources", "expires_at", "depth", "token_hash", "issued_at", "revoked_at"},
		"audit_events": {"id", "workload_id", "lease_id", "event_type", "actor", "details", "occurred_at"},
	}
	for table, columns := range initialColumns {
		complete, err := hasColumns(ctx, tx, table, columns)
		if err != nil {
			return err
		}
		if !complete {
			return fmt.Errorf("existing schema does not match the initial UpsilonAuth schema")
		}
	}
	audienceStageColumns, err := countColumns(ctx, tx, "leases", []string{"audience", "max_depth"})
	if err != nil {
		return err
	}
	if audienceStageColumns == 1 {
		return fmt.Errorf("existing lease schema is partially migrated")
	}
	disabledStageColumns, err := countColumns(ctx, tx, "workloads", []string{"disabled_at"})
	if err != nil {
		return err
	}
	var nonceTable bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('workload_nonces') IS NOT NULL`).Scan(&nonceTable); err != nil {
		return fmt.Errorf("inspect existing schema: %w", err)
	}
	if disabledStageColumns == 1 != nonceTable {
		return fmt.Errorf("existing security schema is partially migrated")
	}
	stages := []struct {
		name    string
		active  bool
		columns map[string][]string
		tables  []string
	}{
		{name: "000001_initial.up.sql", active: true},
		{name: "000002_lease_audience.up.sql", columns: map[string][]string{"leases": {"audience", "max_depth"}}},
		{name: "000003_security_hardening.up.sql", columns: map[string][]string{"workloads": {"disabled_at"}}, tables: []string{"workload_nonces"}},
	}
	previousComplete := true
	for index := range stages {
		stage := &stages[index]
		if !stage.active {
			stage.active = previousComplete
			for table, columns := range stage.columns {
				complete, err := hasColumns(ctx, tx, table, columns)
				if err != nil {
					return err
				}
				stage.active = stage.active && complete
			}
			for _, table := range stage.tables {
				var exists bool
				if err := tx.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
					return fmt.Errorf("inspect existing schema: %w", err)
				}
				stage.active = stage.active && exists
			}
		}
		previousComplete = stage.active
		if !stage.active {
			continue
		}
		if !containsMigration(migrations, stage.name) {
			return fmt.Errorf("existing schema requires missing migration %s", stage.name)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, stage.name); err != nil {
			return fmt.Errorf("baseline migration %s: %w", stage.name, err)
		}
	}
	return nil
}

func hasColumns(ctx context.Context, tx pgx.Tx, table string, columns []string) (bool, error) {
	count, err := countColumns(ctx, tx, table, columns)
	if err != nil {
		return false, err
	}
	return count == len(columns), nil
}

func countColumns(ctx context.Context, tx pgx.Tx, table string, columns []string) (int, error) {
	var count int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = ANY($2)`,
		table, columns,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("inspect %s columns: %w", table, err)
	}
	return count, nil
}

func containsMigration(migrations []string, name string) bool {
	for _, migration := range migrations {
		if migration == name {
			return true
		}
	}
	return false
}

func errorsNoMigrations() error {
	return fmt.Errorf("no up migrations found")
}
