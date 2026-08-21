// Package tinygo extracts a bundled TinyGo toolchain to a local cache
// directory and compiles BPF Go source with it. The bumble flavor feeds
// it the embedded release tree (see embed_bumble.go); tests feed it any
// fs.FS carrying a bin/tinygo entry.
package tinygo

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
)

// binaryRelPath is where the tinygo binary lives inside a release tree.
const binaryRelPath = "bin/tinygo"

// extractedMarker is written last during extraction, so its presence
// means the cache holds a complete toolchain.
const extractedMarker = ".extracted"

// Toolchain is a TinyGo release tree plus the cache directory it is
// extracted to on first use.
type Toolchain struct {
	fsys     fs.FS
	cacheDir string
}

// New returns a Toolchain rooted at fsys (the directory containing
// bin/tinygo) that extracts into cacheDir.
func New(fsys fs.FS, cacheDir string) *Toolchain {
	return &Toolchain{fsys: fsys, cacheDir: cacheDir}
}

// Extract unpacks the toolchain into the cache directory unless a
// previous run already did, and returns the tinygo binary path.
// Extraction goes through a temp directory renamed into place, so a
// crashed run never leaves a half-populated cache behind.
func (t *Toolchain) Extract() (string, error) {
	bin := filepath.Join(t.cacheDir, filepath.FromSlash(binaryRelPath))
	if _, err := os.Stat(filepath.Join(t.cacheDir, extractedMarker)); err == nil {
		return bin, nil
	}

	parent := filepath.Dir(t.cacheDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", fmt.Errorf("creating toolchain cache parent: %w", err)
	}
	tmp, err := os.MkdirTemp(parent, ".extract-*")
	if err != nil {
		return "", fmt.Errorf("creating extraction directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	if err := copyTree(t.fsys, tmp); err != nil {
		return "", fmt.Errorf("extracting toolchain: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, extractedMarker), nil, 0o644); err != nil {
		return "", fmt.Errorf("marking extraction complete: %w", err)
	}
	// A leftover incomplete cache (no marker) is stale: replace it.
	if err := os.RemoveAll(t.cacheDir); err != nil {
		return "", fmt.Errorf("clearing stale toolchain cache: %w", err)
	}
	if err := os.Rename(tmp, t.cacheDir); err != nil {
		return "", fmt.Errorf("moving toolchain into cache: %w", err)
	}
	return bin, nil
}

// Compile extracts the toolchain if needed and compiles BPF Go source
// with it. TINYGOROOT points at the extracted tree so the relocated
// binary finds its runtime.
func (t *Toolchain) Compile(source string) ([]byte, error) {
	bin, err := t.Extract()
	if err != nil {
		return nil, err
	}
	return CompileWith(bin, source, "TINYGOROOT="+t.cacheDir)
}

// CompileWith compiles BPF Go source with the given tinygo binary,
// mirroring hive.CompileC for C source.
func CompileWith(bin, source string, extraEnv ...string) ([]byte, error) {
	if _, err := os.Stat(bin); err != nil {
		return nil, fmt.Errorf("tinygo binary %s: %w", bin, err)
	}
	dir, err := os.MkdirTemp("", "terrahive-tinygo-*")
	if err != nil {
		return nil, fmt.Errorf("creating build directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	srcPath := filepath.Join(dir, "program.go")
	objPath := filepath.Join(dir, "program.o")
	if err := os.WriteFile(srcPath, []byte(source), 0o644); err != nil {
		return nil, fmt.Errorf("writing source: %w", err)
	}
	cmd := exec.Command(bin, "build", "-o", objPath, "-target=bpf", srcPath)
	cmd.Env = append(os.Environ(), extraEnv...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("tinygo failed: %w\n%s", err, out)
	}
	obj, err := os.ReadFile(objPath)
	if err != nil {
		return nil, errors.New("tinygo reported success but produced no object file")
	}
	return obj, nil
}

// copyTree materializes fsys under dst. embed.FS carries no permission
// bits, so directories get 0755, files under bin/ 0755, the rest 0644.
func copyTree(fsys fs.FS, dst string) error {
	return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dst, filepath.FromSlash(path))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		mode := fs.FileMode(0o644)
		if filepath.Dir(path) == "bin" {
			mode = 0o755
		}
		return os.WriteFile(target, data, mode)
	})
}
