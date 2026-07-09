VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
DATABASE_URL ?= postgres://keysmith:keysmith@localhost:5433/keysmith?sslmode=disable
GOOSE := go run github.com/pressly/goose/v3/cmd/goose@latest

.PHONY: all fmt lint test build run dev wire tidy db-up db-down migrate-up migrate-down

all: fmt lint test build

fmt:
	gofmt -s -w .

lint:
	@if ! command -v golangci-lint > /dev/null 2>&1; then \
		echo "golangci-lint not found. Install with: brew install golangci-lint"; \
		exit 1; \
	fi
	golangci-lint run ./...
	cd pkg/authkit && golangci-lint run ./...

# go.work does not span ./... across modules, so run each module explicitly.
test:
	go test -race -coverprofile=coverage.out ./...
	cd pkg/authkit && go test -race ./...

build:
	CGO_ENABLED=0 go build -trimpath \
		-ldflags '-s -w -X github.com/sriganeshlokesh/keysmith/config.Version=$(VERSION)' \
		-o bin/keysmith ./cmd

run:
	@if [ -f .env ]; then set -a; . ./.env; set +a; fi; go run ./cmd

db-up:
	docker compose up -d --wait postgres mailpit

db-down:
	docker compose down

dev: db-up
	ENV=local DATABASE_URL="$(DATABASE_URL)" go run ./cmd

wire:
	go tool wire ./adapter/dependency/

tidy:
	go mod tidy
	cd pkg/authkit && go mod tidy

migrate-up:
	$(GOOSE) -dir migrations postgres "$(DATABASE_URL)" up

migrate-down:
	$(GOOSE) -dir migrations postgres "$(DATABASE_URL)" down
