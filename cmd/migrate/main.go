package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yonathanalulam/upsilonAuth/internal/repository"
)

func main() {
	mode := flag.String("mode", "apply", "migration mode: apply or verify")
	directory := flag.String("directory", envDefault("MIGRATIONS_DIR", "migrations"), "migration directory")
	flag.Parse()
	if *mode != "apply" && *mode != "verify" {
		log.Fatal(errors.New("mode must be apply or verify"))
	}
	databaseURL, err := envOrFile("DATABASE_URL")
	if err != nil || strings.TrimSpace(databaseURL) == "" {
		log.Fatal(errors.New("DATABASE_URL or DATABASE_URL_FILE is required"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, strings.TrimSpace(databaseURL))
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatal(err)
	}
	if *mode == "apply" {
		err = repository.ApplyMigrations(ctx, pool, *directory)
	} else {
		err = repository.VerifyMigrations(ctx, pool, *directory)
	}
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("migration %s completed", *mode)
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envOrFile(name string) (string, error) {
	value, valueSet := os.LookupEnv(name)
	fileName := strings.TrimSpace(os.Getenv(name + "_FILE"))
	if valueSet && value != "" && fileName != "" {
		return "", fmt.Errorf("%s and %s_FILE are mutually exclusive", name, name)
	}
	if fileName == "" {
		return value, nil
	}
	// #nosec G304,G703 -- the operator explicitly supplies this migration secret-file path.
	data, err := os.ReadFile(fileName)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", name, err)
	}
	if len(data) == 0 || len(data) > 64<<10 {
		return "", fmt.Errorf("%s_FILE has an invalid size", name)
	}
	return strings.TrimSpace(string(data)), nil
}
