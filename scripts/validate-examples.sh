#!/usr/bin/env bash
# Validate every example root module against a locally built provider.
#
# It builds the provider, points a Terraform CLI dev_overrides config at
# the binary, then runs `terraform init -backend=false` and `terraform
# validate` in each root module. dev_overrides makes both work offline:
# Terraform uses the local binary and never contacts the registry.
#
# A root module is a dir directly under examples/ whose config declares
# the provider with source "maxgio92/terrahive". Modules that use
# go_source need the bumble flavor (it embeds TinyGo); the lean binary
# rejects go_source at validate time. Such modules are validated against
# a bumble binary, built on demand.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TERRAFORM="${TERRAFORM:-terraform}"
PROVIDER_SOURCE="maxgio92/terrahive"
BINARY="terraform-provider-terrahive"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

LEAN_DIR="$WORK/lean"
mkdir -p "$LEAN_DIR"
echo "building lean provider"
go build -o "$LEAN_DIR/$BINARY" .

BUMBLE_DIR=""
build_bumble() {
	if [ -n "$BUMBLE_DIR" ]; then
		return
	fi
	echo "building bumble provider (embeds TinyGo; fetches the toolchain if missing)"
	make fetch-tinygo
	BUMBLE_DIR="$WORK/bumble"
	mkdir -p "$BUMBLE_DIR"
	go build -tags bumble -o "$BUMBLE_DIR/$BINARY" .
}

tfrc_for() {
	local dir="$1"
	local rc="$WORK/dev.tfrc"
	cat >"$rc" <<EOF
provider_installation {
  dev_overrides {
    "$PROVIDER_SOURCE" = "$dir"
  }
  direct {}
}
EOF
	echo "$rc"
}

status=0
for module in examples/*/; do
	module="${module%/}"
	# Only root modules that bind the provider to our source address.
	if ! grep -qsF "$PROVIDER_SOURCE" "$module"/*.tf; then
		continue
	fi

	override_dir="$LEAN_DIR"
	# Match a go_source attribute assignment, not the word in a comment.
	if grep -Eqs '^[[:space:]]*go_source[[:space:]]*=' "$module"/*.tf; then
		build_bumble
		override_dir="$BUMBLE_DIR"
	fi
	rc="$(tfrc_for "$override_dir")"

	echo "==> validating $module"
	rm -rf "$module/.terraform" "$module/.terraform.lock.hcl"
	if TF_CLI_CONFIG_FILE="$rc" "$TERRAFORM" -chdir="$module" init -backend=false >/dev/null &&
		TF_CLI_CONFIG_FILE="$rc" "$TERRAFORM" -chdir="$module" validate; then
		echo "    ok"
	else
		echo "    FAILED"
		status=1
	fi
	rm -rf "$module/.terraform" "$module/.terraform.lock.hcl"
done

exit "$status"
