package main

import (
	"context"
	"net/http"
	"os"
	"time"
)

func main() {
	const target = "http://127.0.0.1:8080/readyz"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		os.Exit(1)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		os.Exit(1)
	}
	if err := response.Body.Close(); err != nil {
		os.Exit(1)
	}
	if response.StatusCode != http.StatusNoContent {
		os.Exit(1)
	}
}
