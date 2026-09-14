package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatal(err)
	}

	required := []string{"workloads", "leases", "audit_events", "workload_nonces", "schema_migrations"}
	for _, table := range required {
		var exists bool
		err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables
			WHERE table_schema = current_schema() AND table_name = $1
		)`, table).Scan(&exists)
		if err != nil {
			log.Fatal(err)
		}
		if !exists {
			log.Fatal(errors.New("required table is missing: " + table))
		}
		fmt.Println(table)
	}

	for _, column := range []string{"audience", "max_depth"} {
		var exists bool
		err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1
			FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = 'leases' AND column_name = $1
		)`, column).Scan(&exists)
		if err != nil {
			log.Fatal(err)
		}
		if !exists {
			log.Fatal(errors.New("required lease column is missing: " + column))
		}
		fmt.Println("leases." + column)
	}

	var disabledAtExists bool
	err = pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1
		FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'workloads' AND column_name = 'disabled_at'
	)`).Scan(&disabledAtExists)
	if err != nil {
		log.Fatal(err)
	}
	if !disabledAtExists {
		log.Fatal(errors.New("required workload column is missing: disabled_at"))
	}
	fmt.Println("workloads.disabled_at")
}
