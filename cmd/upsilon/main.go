package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yonathanalulam/upsilonAuth/sdk/go/client"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "upsilon:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("upsilon", flag.ContinueOnError)
	baseURL := flags.String("base-url", envDefault("UPSILON_BASE_URL", "https://127.0.0.1:8080"), "UpsilonAuth control-plane URL")
	allowInsecure := flags.Bool("allow-insecure-http", false, "allow plaintext HTTP for local development only")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	remaining := flags.Args()
	if len(remaining) != 2 || remaining[0] != "inspect" && remaining[0] != "trace" {
		return errors.New("usage: upsilon [flags] inspect|trace LEASE_ID")
	}
	adminToken, err := secretFromEnvironment("UPSILON_ADMIN_TOKEN")
	if err != nil {
		return err
	}
	control, err := client.NewControlPlane(*baseURL, nil, *allowInsecure)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var output any
	if remaining[0] == "inspect" {
		output, err = control.GetLease(ctx, adminToken, remaining[1])
	} else {
		output, err = control.TraceLease(ctx, adminToken, remaining[1])
	}
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func secretFromEnvironment(name string) (string, error) {
	value, valueSet := os.LookupEnv(name)
	fileName := strings.TrimSpace(os.Getenv(name + "_FILE"))
	if valueSet && value != "" && fileName != "" {
		return "", fmt.Errorf("%s and %s_FILE are mutually exclusive", name, name)
	}
	if fileName != "" {
		// #nosec G304,G703 -- the local operator explicitly supplies this secret-file path.
		data, err := os.ReadFile(fileName)
		if err != nil {
			return "", fmt.Errorf("read %s_FILE: %w", name, err)
		}
		if len(data) == 0 || len(data) > 4096 {
			return "", fmt.Errorf("%s_FILE has invalid size", name)
		}
		value = string(data)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s or %s_FILE is required", name, name)
	}
	return value, nil
}
