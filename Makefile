.PHONY: all build test lint lint-fix fmt vet tidy check ci web-lint clean setup-hooks

GO                := go
GOLANGCI_LINT     := golangci-lint
GOLANGCI_VERSION  := v2.1.6

all: check

## build: lint then compile — a successful build requires clean lints
build: lint vet
	$(GO) build ./...

## test: run all Go tests with race detector
test:
	$(GO) test -race -count=1 ./...

## vet: run go vet
vet:
	$(GO) vet ./...

## fmt: format all Go sources with gofumpt + goimports
fmt:
	gofumpt -w .
	goimports -w -local github.com/unlikeotherai/silkie .

## tidy: tidy go.mod and verify module graph
tidy:
	$(GO) mod tidy
	$(GO) mod verify

## lint: run golangci-lint (installs it if missing)
lint:
	@if ! command -v $(GOLANGCI_LINT) >/dev/null 2>&1; then \
		echo "golangci-lint not found, installing $(GOLANGCI_VERSION)..."; \
		GOFLAGS= $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION); \
	fi
	$(GOLANGCI_LINT) run ./...

## lint-fix: run golangci-lint with --fix
lint-fix:
	$(GOLANGCI_LINT) run --fix ./...

## web-lint: lint the static web assets (HTML)
web-lint:
	@if ! command -v npx >/dev/null 2>&1; then \
		echo "npx not found; skipping web lint"; \
		exit 0; \
	fi
	npx --yes htmlhint@1.1.4 "web/**/*.html"
	npx --yes prettier@3.3.3 --check "web/**/*.{html,css,js}"

## check: the full strict pipeline — lint + vet + build + test + web
check: lint vet
	$(GO) build ./...
	$(GO) test -race -count=1 ./...
	@$(MAKE) web-lint

## ci: the canonical CI entrypoint
ci: tidy check

## setup-hooks: install git pre-commit hook that enforces lint
setup-hooks:
	@mkdir -p .git/hooks
	@printf '#!/bin/sh\nset -e\nmake lint vet\ngo build ./...\n' > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "pre-commit hook installed"

## clean: remove build artifacts
clean:
	$(GO) clean ./...
	rm -rf bin dist
