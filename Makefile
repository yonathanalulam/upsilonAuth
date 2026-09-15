APP=upsilonauth
BIN=bin/$(APP)
GO_PACKAGES=./cmd/... ./internal/... ./sdk/... ./examples/...
IMAGE?=upsilonauth:local
PLATFORMS?=linux/amd64,linux/arm64
MULTIARCH_OUTPUT?=artifacts/upsilonauth-multiarch.oci.tar
RELEASE_IMAGE?=

.PHONY: build fmt fmt-check test test-race vet vuln lint run secrets up down website-check container container-multiarch container-push release-check

build:
	mkdir -p bin
	go build -trimpath -o $(BIN) ./cmd/upsilonauth
	go build -trimpath -o bin/upsilon ./cmd/upsilon

fmt:
	gofmt -w cmd internal sdk examples

fmt-check:
	test -z "$$(gofmt -l cmd internal sdk examples)"

test:
	go test $(GO_PACKAGES)

test-race:
	go test -race $(GO_PACKAGES)

vet:
	go vet $(GO_PACKAGES)

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 $(GO_PACKAGES)

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run $(GO_PACKAGES)

run:
	go run ./cmd/upsilonauth

secrets:
	go run ./cmd/keygen

up:
	docker compose up --build -d

down:
	docker compose down

website-check:
	cd website && npm ci && npm run lint && npm run build && npm run test:e2e

container:
	docker buildx build --pull --load -t $(IMAGE) .

container-multiarch:
	mkdir -p artifacts
	docker buildx build --pull --platform $(PLATFORMS) --output type=oci,dest=$(MULTIARCH_OUTPUT) .

container-push:
	test -n "$(RELEASE_IMAGE)" || (echo "RELEASE_IMAGE is required" && exit 1)
	docker buildx build --pull --platform $(PLATFORMS) --tag $(RELEASE_IMAGE) --push .

release-check: fmt-check test-race vet vuln lint website-check container
