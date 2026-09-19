.DEFAULT_GOAL := help

VERSION  ?= $(shell scripts/version.sh)
CONFIG   ?= config.dev.yaml
LISTEN   ?= 127.0.0.1:3128
FUZZTIME ?= 60s

LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: help build run test fuzz vulncheck fmt check release image clean

help: ## Show the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-10s %s\n", $$1, $$2}'
	@echo "Variables: VERSION=$(VERSION) CONFIG=$(CONFIG) LISTEN=$(LISTEN) FUZZTIME=$(FUZZTIME)"

build: ## Build bin/proxy-acl
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/proxy-acl ./cmd/proxy-acl

run: ## Run locally with the race detector, console logs and CONFIG (reloads on edit)
	go run -race -ldflags "-X main.version=$(VERSION)" ./cmd/proxy-acl \
		-config $(CONFIG) -listen $(LISTEN) -log-format console

test: ## Run the tests with the race detector
	go test -race -count=1 ./...

fuzz: ## Fuzz the ACL for FUZZTIME
	go test ./internal/acl -run '^$$' -fuzz '^FuzzCheck$$' -fuzztime $(FUZZTIME)

vulncheck: ## Check dependencies for known vulnerabilities
	go tool govulncheck ./...

fmt: ## Format the code
	gofmt -w .

check: ## Everything CI checks: formatting, vet, vulncheck, tests
	@test -z "$$(gofmt -l .)" || { echo "Not formatted (run make fmt):"; gofmt -l .; exit 1; }
	go vet ./...
	$(MAKE) --no-print-directory vulncheck test

release: ## Build the release binaries and archives into dist/, as CI does
	scripts/build-release.sh "$(VERSION)"

image: ## Build the Docker image proxy-acl:dev
	docker build -t proxy-acl:dev --build-arg VERSION=$(VERSION) .

update:
	go get -u ./...

clean: ## Remove build output
	rm -rf bin dist
