package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	authcrypto "upsilonAuth/internal/crypto"
	"upsilonAuth/internal/delivery"
	"upsilonAuth/internal/repository"
	"upsilonAuth/internal/usecase"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

	publicKey, privateKey, err := authcrypto.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	leaseRepository := repository.NewLeaseRepository(pool)
	leaseUsecase, err := usecase.NewLeaseUsecase(leaseRepository, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	handler := delivery.NewHandler(leaseUsecase, publicKey)
	server := &http.Server{
		Addr:              ":8080",
		Handler:           handler.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	var tasks sync.WaitGroup
	serverErrors := make(chan error, 1)
	tasks.Add(1)
	go func() {
		defer tasks.Done()
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
