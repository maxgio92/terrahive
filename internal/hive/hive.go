// Package hive wraps the kernel BPF object lifecycle shared by all
// terrahive resources: pinning, loading, reading back, and unpinning.
package hive

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// bpffsMagic is the superblock magic of bpffs (linux/magic.h BPF_FS_MAGIC).
const bpffsMagic = 0xcafe4a11

// DefaultPinDir is used when the provider block sets no pin_dir.
const DefaultPinDir = "/sys/fs/bpf/terrahive"

// Hive is the handle every resource uses to talk to the kernel.
type Hive struct {
	pinDir string
}

// New validates the environment and returns a Hive rooted at pinDir.
// It fails if pinDir is not on bpffs or the process lacks BPF privileges,
// so misconfiguration surfaces at provider configure time, not mid-apply.
func New(pinDir string) (*Hive, error) {
	if pinDir == "" {
		pinDir = DefaultPinDir
	}
	if err := checkPrivileges(); err != nil {
		return nil, err
	}
	if err := checkBpffs(pinDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating pin directory %s: %w", pinDir, err)
	}
	return &Hive{pinDir: pinDir}, nil
}

// PinDir returns the root pin directory.
func (h *Hive) PinDir() string {
	return h.pinDir
}

// PinPath derives the bpffs pin path that doubles as the Terraform
// resource ID. Parts typically encode kind and resource name.
func (h *Hive) PinPath(parts ...string) string {
	return filepath.Join(append([]string{h.pinDir}, parts...)...)
}

// LoadPinnedProgram resolves a pinned program for Read and import.
func (h *Hive) LoadPinnedProgram(pinPath string) (*ebpf.Program, error) {
	return ebpf.LoadPinnedProgram(pinPath, nil)
}

// LoadPinnedMap resolves a pinned map for Read and import.
func (h *Hive) LoadPinnedMap(pinPath string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(pinPath, nil)
}

// Unpin removes a pin, dropping the last user-visible reference.
// A missing pin is not an error: destroy must be idempotent.
func (h *Hive) Unpin(pinPath string) error {
	err := os.Remove(pinPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unpinning %s: %w", pinPath, err)
	}
	return nil
}

// PinExists reports whether a pin path resolves, without opening it.
func (h *Hive) PinExists(pinPath string) (bool, error) {
	_, err := os.Stat(pinPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func checkBpffs(pinDir string) error {
	// pinDir itself may not exist yet; check the closest existing ancestor.
	probe := pinDir
	for {
		var st unix.Statfs_t
		err := unix.Statfs(probe, &st)
		if err == nil {
			if uint64(st.Type) != bpffsMagic {
				return fmt.Errorf("pin_dir %s is not on a bpffs mount (mount -t bpf bpf /sys/fs/bpf)", pinDir)
			}
			return nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("checking filesystem of %s: %w", probe, err)
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return fmt.Errorf("pin_dir %s: no existing ancestor found", pinDir)
		}
		probe = parent
	}
}

func checkPrivileges() error {
	if os.Geteuid() == 0 {
		return nil
	}
	ok, err := hasCapability()
	if err != nil {
		return fmt.Errorf("checking BPF privileges: %w", err)
	}
	if !ok {
		return errors.New("terrahive needs root or CAP_BPF to manage kernel BPF objects")
	}
	return nil
}

// hasCapability checks CapEff in /proc/self/status for CAP_BPF (39)
// or CAP_SYS_ADMIN (21), which implies it on pre-5.8 kernels.
func hasCapability() (bool, error) {
	const (
		capSysAdmin = 21
		capBPF      = 39
	)
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		val, found := strings.CutPrefix(line, "CapEff:")
		if !found {
			continue
		}
		var eff uint64
		if _, err := fmt.Sscanf(strings.TrimSpace(val), "%x", &eff); err != nil {
			return false, err
		}
		return eff&(1<<capBPF) != 0 || eff&(1<<capSysAdmin) != 0, nil
	}
	return false, errors.New("CapEff not found in /proc/self/status")
}
