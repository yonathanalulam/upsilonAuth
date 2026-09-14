package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
)

func main() {
	admin := randomBytes(32)
	consumption := randomBytes(32)
	database := randomBytes(24)
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	workloadPublic, workloadPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	encoding := base64.RawURLEncoding
	fmt.Printf("POSTGRES_PASSWORD=%s\n", encoding.EncodeToString(database))
	fmt.Printf("ADMIN_TOKEN=%s\n", encoding.EncodeToString(admin))
	fmt.Printf("CONSUMPTION_TOKEN=%s\n", encoding.EncodeToString(consumption))
	fmt.Printf("SIGNING_PRIVATE_KEY=%s\n", encoding.EncodeToString(serverPrivate.Seed()))
	fmt.Printf("SIGNING_PUBLIC_KEY=%s\n", encoding.EncodeToString(serverPublic))
	fmt.Printf("WORKLOAD_PRIVATE_KEY=%s\n", encoding.EncodeToString(workloadPrivate.Seed()))
	fmt.Printf("WORKLOAD_PUBLIC_KEY=%s\n", encoding.EncodeToString(workloadPublic))
}

func randomBytes(size int) []byte {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		log.Fatal(err)
	}
	return value
}
