# TinyGo release pinned for the bumble flavor. Keep in sync with
# tinygo.Version in internal/hive/tinygo/embed_bumble.go.
TINYGO_VERSION ?= 0.38.0
TINYGO_ARCH ?= amd64
TINYGO_URL = https://github.com/tinygo-org/tinygo/releases/download/v$(TINYGO_VERSION)/tinygo$(TINYGO_VERSION).linux-$(TINYGO_ARCH).tar.gz
TOOLCHAIN_DIR = internal/hive/tinygo/toolchain

.PHONY: build build-bumble fetch-tinygo test testacc lint docs

build:
	go build ./...

# The bumble binary embeds the toolchain fetched by fetch-tinygo.
build-bumble: fetch-tinygo
	go build -tags bumble -o terraform-provider-terrahive-bumble .

# Downloads the pinned TinyGo release into the go:embed tree
# ($(TOOLCHAIN_DIR)/tinygo, git-ignored). goreleaser runs this as a
# pre-hook of the bumble build.
fetch-tinygo:
	@if ! $(TOOLCHAIN_DIR)/tinygo/bin/tinygo version 2>/dev/null | grep -q "version $(TINYGO_VERSION) linux/$(TINYGO_ARCH)"; then \
		rm -rf $(TOOLCHAIN_DIR)/tinygo; \
		curl -fsSL $(TINYGO_URL) | tar -xz -C $(TOOLCHAIN_DIR); \
	fi

test:
	go test ./...
	go test -tags bumble ./...

testacc:
	TF_ACC=1 go test ./... -v -timeout 20m

lint:
	golangci-lint run
	golangci-lint run --build-tags bumble

# The docs/resources/*.md pages are hand-maintained. The resource prefix
# (ebpf_) differs from the provider name (terrahive), and the pages carry
# curated prose and examples, so tfplugindocs generation is not wired up:
# it would overwrite the curated content with bare schema dumps.
