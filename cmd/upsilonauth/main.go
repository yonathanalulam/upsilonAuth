package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	authcrypto "github.com/yonathanalulam/upsilonAuth/internal/crypto"
	"github.com/yonathanalulam/upsilonAuth/internal/delivery"
	"github.com/yonathanalulam/upsilonAuth/internal/repository"
	"github.com/yonathanalulam/upsilonAuth/internal/usecase"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	config, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	poolConfig, err := pgxpool.ParseConfig(config.databaseURL)
	if err != nil {
		log.Fatal("invalid DATABASE_URL")
	}
	poolConfig.MaxConns = 20
	poolConfig.MinConns = 2
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatal(err)
	}
	if config.migrationMode == "apply" {
		if err := repository.ApplyMigrations(ctx, pool, config.migrationsDirectory); err != nil {
			log.Fatal(err)
		}
	} else if err := repository.VerifyMigrations(ctx, pool, config.migrationsDirectory); err != nil {
		log.Fatal(err)
	}

	publicKey := config.privateKey.Public().(ed25519.PublicKey)
	publicKeys := append([]ed25519.PublicKey{publicKey}, config.previousPublicKeys...)
	verificationKeys := authcrypto.VerificationKeys(publicKeys)
	leaseRepository := repository.NewLeaseRepository(pool)
	leaseUsecase, err := usecase.NewLeaseUsecase(usecase.Config{
		Repository: leaseRepository, PrivateKey: config.privateKey, VerificationKeys: verificationKeys,
		Issuer: config.issuer, MaxTTL: config.maxTTL, ClockSkew: config.clockSkew, RequestWindow: config.requestWindow,
	})
	if err != nil {
		log.Fatal(err)
	}
	handler, err := delivery.NewHandler(delivery.Config{
		Usecase: leaseUsecase, PublicKeys: publicKeys, AdminToken: config.adminToken, ConsumptionToken: config.consumptionToken,
		RequireTLS: config.requireTLS, TrustForwardedProto: config.trustForwardedProto,
		TrustedProxies:     config.trustedProxies,
		RateLimitPerMinute: config.rateLimitPerMinute, RateLimitBurst: config.rateLimitBurst,
		Readiness: pool.Ping,
	})
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr: ":8080", Handler: handler.Router(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10,
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
	}

	var tasks sync.WaitGroup
	serverErrors := make(chan error, 1)
	tasks.Add(1)
	go func() {
		defer tasks.Done()
		if config.tlsCertFile != "" {
			serverErrors <- server.ListenAndServeTLS(config.tlsCertFile, config.tlsKeyFile)
			return
		}
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			log.Printf("server shutdown: %v", err)
		}
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server: %v", err)
		}
	}
	tasks.Wait()
}

type applicationConfig struct {
	databaseURL         string
	adminToken          string
	consumptionToken    string
	issuer              string
	privateKey          ed25519.PrivateKey
	previousPublicKeys  []ed25519.PublicKey
	maxTTL              time.Duration
	clockSkew           time.Duration
	requestWindow       time.Duration
	requireTLS          bool
	trustForwardedProto bool
	trustedProxies      []string
	tlsCertFile         string
	tlsKeyFile          string
	migrationsDirectory string
	rateLimitPerMinute  float64
	rateLimitBurst      int
	environment         string
	migrationMode       string
}

func loadConfig() (applicationConfig, error) {
	environment := strings.ToLower(strings.TrimSpace(os.Getenv("UPSILON_ENV")))
	if environment != "development" && environment != "production" {
		return applicationConfig{}, errors.New("UPSILON_ENV must be explicitly set to development or production")
	}
	databaseURLValue, err := envOrFile("DATABASE_URL")
	if err != nil {
		return applicationConfig{}, err
	}
	databaseURL := strings.TrimSpace(databaseURLValue)
	adminToken, err := envOrFile("ADMIN_TOKEN")
	if err != nil {
		return applicationConfig{}, err
	}
	consumptionToken, err := envOrFile("CONSUMPTION_TOKEN")
	if err != nil {
		return applicationConfig{}, err
	}
	issuer := strings.TrimSpace(os.Getenv("TOKEN_ISSUER"))
	if databaseURL == "" || !validConfiguredSecret(adminToken) || !validConfiguredSecret(consumptionToken) || adminToken == consumptionToken || issuer == "" {
		return applicationConfig{}, errors.New("DATABASE_URL, TOKEN_ISSUER, and distinct high-entropy ADMIN_TOKEN and CONSUMPTION_TOKEN values are required")
	}
	allowInsecureDatabase, err := envBool("ALLOW_INSECURE_DATABASE", false)
	if err != nil {
		return applicationConfig{}, err
	}
	if err := validateDatabaseTLS(databaseURL, allowInsecureDatabase); err != nil {
		return applicationConfig{}, err
	}
	if environment == "production" && allowInsecureDatabase {
		return applicationConfig{}, errors.New("ALLOW_INSECURE_DATABASE is forbidden in production")
	}
	privateKeyValue, err := envOrFile("SIGNING_PRIVATE_KEY")
	if err != nil {
		return applicationConfig{}, err
	}
	privateKey, err := authcrypto.ParsePrivateKey(privateKeyValue)
	if err != nil {
		return applicationConfig{}, errors.New("SIGNING_PRIVATE_KEY must contain a base64-encoded Ed25519 seed or private key")
	}
	previousKeysValue, err := envOrFile("PREVIOUS_PUBLIC_KEYS")
	if err != nil {
		return applicationConfig{}, err
	}
	previousKeys, err := authcrypto.ParsePublicKeys(previousKeysValue)
	if err != nil {
		return applicationConfig{}, errors.New("PREVIOUS_PUBLIC_KEYS contains an invalid Ed25519 public key")
	}
	maxTTL, err := envDuration("MAX_LEASE_TTL", 5*time.Minute)
	if err != nil {
		return applicationConfig{}, err
	}
	clockSkew, err := envDuration("TOKEN_CLOCK_SKEW", 5*time.Second)
	if err != nil {
		return applicationConfig{}, err
	}
	requestWindow, err := envDuration("SIGNED_REQUEST_WINDOW", 30*time.Second)
	if err != nil {
		return applicationConfig{}, err
	}
	if maxTTL <= 0 || maxTTL > 24*time.Hour || clockSkew < 0 || clockSkew > time.Minute || requestWindow <= 0 || requestWindow > 5*time.Minute {
		return applicationConfig{}, errors.New("lease timing configuration is outside safe bounds")
	}
	tlsCertFile := strings.TrimSpace(os.Getenv("TLS_CERT_FILE"))
	tlsKeyFile := strings.TrimSpace(os.Getenv("TLS_KEY_FILE"))
	if (tlsCertFile == "") != (tlsKeyFile == "") {
		return applicationConfig{}, errors.New("TLS_CERT_FILE and TLS_KEY_FILE must be configured together")
	}
	requireTLS, err := envBool("REQUIRE_TLS", true)
	if err != nil {
		return applicationConfig{}, err
	}
	trustForwardedProto, err := envBool("TRUST_FORWARDED_PROTO", false)
	if err != nil {
		return applicationConfig{}, err
	}
	if requireTLS && tlsCertFile == "" && !trustForwardedProto {
		return applicationConfig{}, errors.New("TLS enforcement requires certificate files or TRUST_FORWARDED_PROTO=true")
	}
	if environment == "production" && !requireTLS {
		return applicationConfig{}, errors.New("REQUIRE_TLS cannot be disabled in production")
	}
	issuerURL, err := url.Parse(issuer)
	if err != nil || issuerURL.Scheme != "http" && issuerURL.Scheme != "https" || issuerURL.Host == "" || issuerURL.User != nil || issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
		return applicationConfig{}, errors.New("TOKEN_ISSUER must be an absolute URL without credentials, query, or fragment")
	}
	if environment == "production" && issuerURL.Scheme != "https" {
		return applicationConfig{}, errors.New("TOKEN_ISSUER must use https in production")
	}
	trustedProxies := splitCSV(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if trustForwardedProto && len(trustedProxies) == 0 {
		return applicationConfig{}, errors.New("TRUSTED_PROXY_CIDRS is required when TRUST_FORWARDED_PROTO=true")
	}
	migrationsDirectory := strings.TrimSpace(os.Getenv("MIGRATIONS_DIR"))
	if migrationsDirectory == "" {
		migrationsDirectory = "migrations"
	}
	migrationMode := strings.ToLower(strings.TrimSpace(os.Getenv("MIGRATION_MODE")))
	if migrationMode == "" {
		if environment == "development" {
			migrationMode = "apply"
		} else {
			migrationMode = "verify"
		}
	}
	if migrationMode != "apply" && migrationMode != "verify" {
		return applicationConfig{}, errors.New("MIGRATION_MODE must be apply or verify")
	}
	rateLimit, err := envFloat("RATE_LIMIT_PER_MINUTE", 120)
	if err != nil || rateLimit <= 0 || rateLimit > 10000 {
		return applicationConfig{}, errors.New("RATE_LIMIT_PER_MINUTE must be between 0 and 10000")
	}
	rateBurst, err := envInt("RATE_LIMIT_BURST", 30)
	if err != nil || rateBurst <= 0 || rateBurst > 1000 {
		return applicationConfig{}, errors.New("RATE_LIMIT_BURST must be between 1 and 1000")
	}
	return applicationConfig{
		databaseURL: databaseURL, adminToken: adminToken, consumptionToken: consumptionToken, issuer: issuer, privateKey: privateKey,
		previousPublicKeys: previousKeys, maxTTL: maxTTL, clockSkew: clockSkew, requestWindow: requestWindow,
		requireTLS: requireTLS, trustForwardedProto: trustForwardedProto,
		trustedProxies: trustedProxies,
		tlsCertFile:    tlsCertFile, tlsKeyFile: tlsKeyFile, migrationsDirectory: migrationsDirectory,
		rateLimitPerMinute: rateLimit, rateLimitBurst: rateBurst,
		environment: environment, migrationMode: migrationMode,
	}, nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func validateDatabaseTLS(databaseURL string, allowInsecure bool) error {
	parsed, err := url.Parse(databaseURL)
	if err != nil || parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" || parsed.Host == "" {
		return errors.New("DATABASE_URL must be a valid PostgreSQL URL")
	}
	if !allowInsecure {
		mode := strings.ToLower(parsed.Query().Get("sslmode"))
		if mode != "require" && mode != "verify-ca" && mode != "verify-full" {
			return errors.New("DATABASE_URL must explicitly require TLS")
		}
	}
	return nil
}

func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s is invalid", name)
	}
	return parsed, nil
}

func envBool(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return parsed, nil
}

func envFloat(name string, fallback float64) (float64, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return 0, fmt.Errorf("%s must be a finite number", name)
	}
	return parsed, nil
}

func envInt(name string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	return strconv.Atoi(value)
}

func validConfiguredSecret(value string) bool {
	if len(value) < 32 || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) < 24 {
		return false
	}
	counts := make(map[rune]int)
	maximum := 0
	for _, character := range value {
		counts[character]++
		if counts[character] > maximum {
			maximum = counts[character]
		}
	}
	return len(counts) >= 8 && maximum*2 <= len(value)
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
	// #nosec G304,G703 -- the operator explicitly supplies this Docker-secret-compatible path.
	data, err := os.ReadFile(fileName)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", name, err)
	}
	if len(data) == 0 || len(data) > 64<<10 {
		return "", fmt.Errorf("%s_FILE has an invalid size", name)
	}
	return strings.TrimSpace(string(data)), nil
}
