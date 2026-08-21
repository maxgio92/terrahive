# TinyGo release pinned for the bumble flavor. Keep in sync with
# tinygo.Version in internal/hive/tinygo/embed_bumble.go.
TINYGO_VERSION ?= 0.38.0
TINYGO_ARCH ?= amd64
TINYGO_URL = https://github.com/tinygo-org/tinygo/releases/download/v$(TINYGO_VERSION)/tinygo$(TINYGO_VERSION).linux-$(TINYGO_ARCH).tar.gz
TOOLCHAIN_DIR = internal/hive/tinygo/toolchain

.PHONY: build build-bumble fetch-tinygo test testacc cover fuzz validate-examples e2e lint docs

# FUZZTIME bounds each target in the fuzz aggregate below.
FUZZTIME ?= 15s

build:
	go build ./...

# The bumble binary embeds the toolchain fetched by fetch-tinygo.
build-bumble: fetch-tinygo
	go build -tags bumble -o terraform-provider-terrahive-bumble .

# Downloads the pinned TinyGo release into the go:embed tree
# ($(TOOLCHAIN_DIR)/_tinygo, git-ignored). The dir is underscore-prefixed
# so `go build`/`go test ./...` skip TinyGo's own source tree; go:embed
# all: still bundles it. goreleaser runs this as a pre-hook of the
# bumble build.
fetch-tinygo:
	@if ! $(TOOLCHAIN_DIR)/_tinygo/bin/tinygo version 2>/dev/null | grep -q "version $(TINYGO_VERSION) linux/$(TINYGO_ARCH)"; then \
		rm -rf $(TOOLCHAIN_DIR)/_tinygo; \
		mkdir -p $(TOOLCHAIN_DIR)/_tinygo; \
		curl -fsSL $(TINYGO_URL) | tar -xz --strip-components=1 -C $(TOOLCHAIN_DIR)/_tinygo; \
	fi

test:
	go test ./...
	go test -tags bumble ./...

testacc:
	TF_ACC=1 go test ./... -v -timeout 20m

# Runs the unit tests under the race detector and writes a coverage
# profile. The fetched TinyGo tree is underscore-prefixed, so ./... never
# reaches it.
cover:
	go test -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

# Runs each fuzz target briefly to catch parser panics on untrusted input
# (ELF objects, stapsdt notes, map-entry IDs). Bump FUZZTIME for longer
# runs.
fuzz:
	go test ./internal/hive -run=^$$ -fuzz=^FuzzLoadELF$$ -fuzztime=$(FUZZTIME)
	go test ./internal/hive -run=^$$ -fuzz=^FuzzScanStapsdtNotes$$ -fuzztime=$(FUZZTIME)
	go test ./internal/provider -run=^$$ -fuzz=^FuzzMapEntryID$$ -fuzztime=$(FUZZTIME)

# Validates every example root module offline against a locally built
# provider using Terraform dev_overrides. See scripts/validate-examples.sh.
validate-examples:
	./scripts/validate-examples.sh

# True end-to-end apply/destroy of the built provider through the
# Terraform CLI. Needs root and bpffs; skips with a message otherwise.
# See scripts/e2e.sh.
e2e:
	./scripts/e2e.sh

lint:
	golangci-lint run
	golangci-lint run --build-tags bumble

# Generates docs/ from templates/ and examples/ with tfplugindocs. The
# templates carry the curated prose and inject the schema and examples, so
# generation keeps the prose instead of dumping bare schema. The resource
# prefix (ebpf_) differs from the provider name (terrahive), so generation
# runs with --provider-name ebpf for schema lookup (see tools/tools.go) and
# the templates drop the prefix; the rename restores ebpf_ on the pages.
docs:
	go generate ./tools
	@for f in docs/resources/*.md; do \
		base=$$(basename $$f); \
		case $$base in \
		ebpf_*) ;; \
		*) mv "$$f" "docs/resources/ebpf_$$base" ;; \
		esac; \
	done
