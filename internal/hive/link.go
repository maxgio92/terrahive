package hive

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf/link"
)

// PinLink pins l at pinPath, creating parent directories on bpffs so
// resources can pin under per-kind subdirectories.
func (h *Hive) PinLink(l link.Link, pinPath string) error {
	if err := os.MkdirAll(filepath.Dir(pinPath), 0o755); err != nil {
		return fmt.Errorf("creating pin directory for %s: %w", pinPath, err)
	}
	if err := l.Pin(pinPath); err != nil {
		return fmt.Errorf("pinning link at %s: %w", pinPath, err)
	}
	return nil
}

// LoadPinnedLink resolves a pinned link for Read and import.
func (h *Hive) LoadPinnedLink(pinPath string) (link.Link, error) {
	return link.LoadPinnedLink(pinPath, nil)
}
