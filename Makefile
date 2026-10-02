# Makefile for SentinelFlow

BINARY_NAME=sentinelflow
DOCKER_IMAGE=sentinelflow/sentinelflow:local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: all build test test-scripts bench clean docker-build run demo

all: test test-scripts build

build:
	@echo "Building SentinelFlow..."
	go build -ldflags "-X main.version=$(VERSION:v%=%) -X main.commit=$(COMMIT) -X main.date=$(DATE)" -o $(BINARY_NAME) ./cmd/sentinelflow

test:
	@echo "Running unit tests..."
	go test -v ./...

test-scripts:
	@echo "Running shell helper tests..."
	@chmod +x ./scripts/install_checksum_test.sh ./scripts/count-findings.sh
	./scripts/install_checksum_test.sh
	@tmp=$$(mktemp); echo '{}' > "$$tmp"; test "$$(./scripts/count-findings.sh json "$$tmp")" = "0"; rm -f "$$tmp"

integration:
	@echo "Running integration tests..."
	go test -tags=integration -v ./test/...

bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem -v ./internal/scanner/... ./internal/reporter/...

docker-build:
	@echo "Building Docker image..."
	docker build --build-arg VERSION=$(VERSION:v%=%) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t $(DOCKER_IMAGE) .

clean:
	@echo "Cleaning up..."
	@if [ -f $(BINARY_NAME) ]; then rm $(BINARY_NAME); fi
	@if [ -f sentinelflow.exe ]; then rm sentinelflow.exe; fi
	@go clean

run: build
	./$(BINARY_NAME) --help

demo: build
	@chmod +x ./scripts/demo.sh
	./scripts/demo.sh

scan-self: build
	./$(BINARY_NAME) scan --all .
	./$(BINARY_NAME) scan-artifact ./$(BINARY_NAME) --fail-on critical

lint:
	@echo "Running lint (requires golangci-lint)..."
	golangci-lint run
