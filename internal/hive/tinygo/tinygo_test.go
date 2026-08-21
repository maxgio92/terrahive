package tinygo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// fakeToolchainFS builds a release-shaped tree whose bin/tinygo is a
// shell script emulating `tinygo build -o <out> -target=bpf <src>` by
// writing the given payload plus $TINYGOROOT to the output file.
func fakeToolchainFS(payload string) fstest.MapFS {
	script := `#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '` + payload + ` root=%s' "$TINYGOROOT" > "$out"
`
	return fstest.MapFS{
		"bin/tinygo": &fstest.MapFile{Data: []byte(script)},
		"VERSION":    &fstest.MapFile{Data: []byte("fake")},
	}
}

func TestExtractIsIdempotent(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "cache")
	tc := New(fakeToolchainFS("v1"), cache)

	bin, err := tc.Extract()
	if err != nil {
		t.Fatalf("first Extract: %v", err)
	}
	info, err := os.Stat(bin)
	if err != nil {
		t.Fatalf("stat extracted binary: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("extracted binary is not executable: %v", info.Mode())
	}

	// Mutate the extracted binary: a second Extract must reuse the
	// cache, not overwrite it from the embedded tree.
	if err := os.WriteFile(bin, []byte("sentinel"), 0o755); err != nil {
		t.Fatalf("mutating extracted binary: %v", err)
	}
	again, err := tc.Extract()
	if err != nil {
		t.Fatalf("second Extract: %v", err)
	}
	if again != bin {
		t.Fatalf("second Extract returned %q, want %q", again, bin)
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("reading binary after second Extract: %v", err)
	}
	if string(data) != "sentinel" {
		t.Fatal("second Extract re-extracted over a complete cache")
	}
}

func TestExtractReplacesIncompleteCache(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "cache")
	// A cache directory without the completion marker is a crashed
	// extraction and must be replaced.
	if err := os.MkdirAll(filepath.Join(cache, "bin"), 0o755); err != nil {
		t.Fatalf("seeding stale cache: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cache, "bin", "tinygo"), []byte("stale"), 0o755); err != nil {
		t.Fatalf("seeding stale binary: %v", err)
	}

	bin, err := New(fakeToolchainFS("v1"), cache).Extract()
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("reading binary: %v", err)
	}
	if string(data) == "stale" {
		t.Fatal("Extract kept an incomplete cache")
	}
}

func TestCompileUsesExtractedToolchain(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "cache")
	tc := New(fakeToolchainFS("v1"), cache)

	obj, err := tc.Compile("package main")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if want := "v1 root=" + cache; string(obj) != want {
		t.Fatalf("obj = %q, want %q", obj, want)
	}

	// Swap the cached binary for a variant: a second Compile must run
	// the cached one, proving extraction happened once.
	variant := fakeToolchainFS("v2")["bin/tinygo"].Data
	if err := os.WriteFile(filepath.Join(cache, "bin", "tinygo"), variant, 0o755); err != nil {
		t.Fatalf("swapping cached binary: %v", err)
	}
	obj, err = tc.Compile("package main")
	if err != nil {
		t.Fatalf("second Compile: %v", err)
	}
	if !strings.HasPrefix(string(obj), "v2 ") {
		t.Fatalf("second Compile did not reuse the cache: %q", obj)
	}
}

func TestCompileWithMissingBinary(t *testing.T) {
	if _, err := CompileWith(filepath.Join(t.TempDir(), "tinygo"), "package main"); err == nil {
		t.Fatal("expected an error for a missing tinygo binary")
	}
}

func TestCompileWithFailingToolchain(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "tinygo")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho boom >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("writing failing tinygo: %v", err)
	}
	_, err := CompileWith(bin, "package main")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error does not carry compiler output: %v", err)
	}
}
