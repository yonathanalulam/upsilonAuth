APP=upsilonauth
BIN=bin/$(APP)

.PHONY: build test run up down

build:
	mkdir -p bin
	go build -o $(BIN) ./cmd/upsilonauth

test:
	go test ./...

run:
	go run ./cmd/upsilonauth

up:
	docker compose up --build -d

down:
	docker compose down
