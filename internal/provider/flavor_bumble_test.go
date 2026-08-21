//go:build bumble

package provider

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeTinygo emulates the `tinygo build -o <out> -target=bpf <src>`
// interface, writing a fixed marker instead of BPF bytecode.
const fakeTinygo = `#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf 'fake-bpf-object' > "$out"
`

func TestBumbleFlavorSelected(t *testing.T) {
	if flavorName != "bumble" {
		t.Fatalf("flavorName = %q, want bumble", flavorName)
	}
	if err := checkGoSourceSupported(); err != nil {
		t.Fatalf("bumble flavor must accept go_source: %v", err)
	}
}

func TestProgramResourceValidateConfigAcceptsGoSource(t *testing.T) {
	resp := validateGoSourceConfig(t)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
}

func TestBumbleCompileGoSourceWithToolchainOverride(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "tinygo")
	if err := os.WriteFile(bin, []byte(fakeTinygo), 0o755); err != nil {
		t.Fatalf("writing fake tinygo: %v", err)
	}
	t.Setenv("TERRAHIVE_TINYGO", bin)

	obj, err := compileGoSource("package main")
	if err != nil {
		t.Fatalf("compileGoSource: %v", err)
	}
	if string(obj) != "fake-bpf-object" {
		t.Fatalf("obj = %q, want fake-bpf-object", obj)
	}
}

func TestBumbleCompileGoSourceWithoutToolchainErrors(t *testing.T) {
	// Dev builds embed no release: the compile must explain how to get
	// a toolchain instead of failing obscurely.
	t.Setenv("TERRAHIVE_TINYGO", "")
	if _, err := compileGoSource("package main"); err == nil {
		t.Fatal("expected an error from a dev build without an embedded toolchain")
	}
}
