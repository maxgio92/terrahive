#!/usr/bin/env bash
# End-to-end test of the built provider through the Terraform CLI.
#
# It builds the lean provider, points a dev_overrides config at it, then
# runs a real `terraform apply` and `terraform destroy` on a generated
# config: load a precompiled object_file program and attach an
# ebpf_kprobe. It asserts the kprobe link pin appears after apply and is
# gone after destroy. This exercises the whole path (CLI, provider
# binary, kernel BPF), unlike the in-process acceptance tests.
#
# Managing kernel BPF objects needs root and a bpffs mount, so the test
# skips (exit 0) with a clear message when either is missing.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TERRAFORM="${TERRAFORM:-terraform}"
PROVIDER_SOURCE="maxgio92/terrahive"
BINARY="terraform-provider-terrahive"
BPFFS="${BPFFS:-/sys/fs/bpf}"
BPFFS_MAGIC="cafe4a11"

if [ "$(id -u)" -ne 0 ]; then
	echo "SKIP: e2e manages kernel BPF objects and needs root (run: sudo -E make e2e)"
	exit 0
fi
if [ "$(stat -f -c '%t' "$BPFFS" 2>/dev/null)" != "$BPFFS_MAGIC" ]; then
	echo "SKIP: $BPFFS is not a bpffs mount (mount -t bpf bpf $BPFFS)"
	exit 0
fi
if ! command -v clang >/dev/null 2>&1; then
	echo "SKIP: e2e compiles a BPF object and needs clang on PATH"
	exit 0
fi

WORK="$(mktemp -d)"
PIN_DIR="$BPFFS/terrahive-e2e"
cleanup() {
	if [ -f "$WORK/main.tf" ]; then
		TF_CLI_CONFIG_FILE="$WORK/dev.tfrc" "$TERRAFORM" -chdir="$WORK" destroy -auto-approve >/dev/null 2>&1 || true
	fi
	rm -rf "$WORK" "$PIN_DIR"
}
trap cleanup EXIT

echo "building lean provider"
go build -o "$WORK/$BINARY" .

cat >"$WORK/dev.tfrc" <<EOF
provider_installation {
  dev_overrides {
    "$PROVIDER_SOURCE" = "$WORK"
  }
  direct {}
}
EOF

cat >"$WORK/prog.bpf.c" <<'EOF'
__attribute__((section("kprobe/vfs_read"), used))
int hive_probe(void *ctx) { return 0; }
char __license[] __attribute__((section("license"), used)) = "GPL";
EOF
clang -O2 -g -target bpf -c "$WORK/prog.bpf.c" -o "$WORK/prog.bpf.o"

cat >"$WORK/main.tf" <<EOF
terraform {
  required_providers {
    ebpf = {
      source = "$PROVIDER_SOURCE"
    }
  }
}

provider "ebpf" {
  pin_dir = "$PIN_DIR"
}

resource "ebpf_program" "e2e" {
  name        = "e2e"
  object_file = "$WORK/prog.bpf.o"
}

resource "ebpf_kprobe" "e2e" {
  name    = "e2e"
  program = ebpf_program.e2e.id
  symbol  = "vfs_read"
}
EOF

export TF_CLI_CONFIG_FILE="$WORK/dev.tfrc"
LINK_PIN="$PIN_DIR/kprobe/e2e"
PROG_PIN="$PIN_DIR/program/e2e"

echo "==> terraform apply"
"$TERRAFORM" -chdir="$WORK" init -backend=false >/dev/null
"$TERRAFORM" -chdir="$WORK" apply -auto-approve

if [ ! -e "$LINK_PIN" ]; then
	echo "FAIL: kprobe link pin $LINK_PIN missing after apply"
	exit 1
fi
if [ ! -e "$PROG_PIN" ]; then
	echo "FAIL: program pin $PROG_PIN missing after apply"
	exit 1
fi
echo "    pins present: $LINK_PIN, $PROG_PIN"

echo "==> terraform destroy"
"$TERRAFORM" -chdir="$WORK" destroy -auto-approve

if [ -e "$LINK_PIN" ]; then
	echo "FAIL: kprobe link pin $LINK_PIN still present after destroy"
	exit 1
fi
if [ -e "$PROG_PIN" ]; then
	echo "FAIL: program pin $PROG_PIN still present after destroy"
	exit 1
fi
echo "    pins gone after destroy"
echo "PASS: e2e apply/destroy cycle"
