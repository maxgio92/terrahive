package hive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

// SourceHash fingerprints program source bytes so plans can force
// replacement when content changes behind a stable path.
func SourceHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ProgramTypeString renders a program type in the lowercase form used
// by the ebpf_program `type` attribute.
func ProgramTypeString(t ebpf.ProgramType) string {
	return strings.ToLower(t.String())
}

// CompileC compiles BPF C source with the system clang.
func CompileC(source string) ([]byte, error) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		return nil, errors.New("compiling c_source requires clang on PATH, but clang was not found")
	}
	dir, err := os.MkdirTemp("", "terrahive-clang-*")
	if err != nil {
		return nil, fmt.Errorf("creating build directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	srcPath := filepath.Join(dir, "program.c")
	objPath := filepath.Join(dir, "program.o")
	if err := os.WriteFile(srcPath, []byte(source), 0o644); err != nil {
		return nil, fmt.Errorf("writing source: %w", err)
	}
	cmd := exec.Command(clang, "-O2", "-g", "-target", "bpf", "-c", srcPath, "-o", objPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("clang failed: %w\n%s", err, out)
	}
	return os.ReadFile(objPath)
}

// LoadELF parses a BPF object file and returns its single program spec,
// with the program type already inferred from the ELF section name.
func LoadELF(obj []byte) (*ebpf.ProgramSpec, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return nil, fmt.Errorf("parsing BPF object: %w", err)
	}
	if len(spec.Programs) == 0 {
		return nil, errors.New("BPF object contains no programs")
	}
	if len(spec.Programs) > 1 {
		names := make([]string, 0, len(spec.Programs))
		for name := range spec.Programs {
			names = append(names, name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("BPF object contains %d programs (%s); ebpf_program manages exactly one", len(names), strings.Join(names, ", "))
	}
	for _, prog := range spec.Programs {
		return prog, nil
	}
	panic("unreachable")
}

// LoadAndPinProgram loads the object's single program together with the
// maps it references and pins the program, returning the kernel-computed
// tag. Referenced maps are pinned by name under the hive map directory,
// so several programs (and an ebpf_map of the same name) share one kernel
// map through a stable bpffs pin. The object must hold exactly one
// program; callers gate that with LoadELF.
func (h *Hive) LoadAndPinProgram(obj []byte, pinPath string) (string, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return "", fmt.Errorf("parsing BPF object: %w", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinByName
	}

	mapDir := h.PinPath("map")
	if err := os.MkdirAll(mapDir, 0o755); err != nil {
		return "", fmt.Errorf("creating map pin directory: %w", err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: mapDir},
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			return "", fmt.Errorf("kernel rejected program: %+v", verr)
		}
		return "", fmt.Errorf("loading BPF collection: %w", err)
	}
	defer coll.Close()

	var prog *ebpf.Program
	for _, p := range coll.Programs {
		prog = p
	}
	if prog == nil {
		return "", errors.New("BPF object contains no programs")
	}

	if err := os.MkdirAll(filepath.Dir(pinPath), 0o755); err != nil {
		return "", fmt.Errorf("creating pin directory: %w", err)
	}
	if err := prog.Pin(pinPath); err != nil {
		return "", fmt.Errorf("pinning program at %s: %w", pinPath, err)
	}
	info, err := prog.Info()
	if err != nil {
		return "", fmt.Errorf("reading program info: %w", err)
	}
	return info.Tag, nil
}

// PinnedProgramInfo returns the type and tag of a pinned program.
func (h *Hive) PinnedProgramInfo(pinPath string) (typ, tag string, err error) {
	prog, err := ebpf.LoadPinnedProgram(pinPath, nil)
	if err != nil {
		return "", "", fmt.Errorf("opening pinned program %s: %w", pinPath, err)
	}
	defer func() { _ = prog.Close() }()
	info, err := prog.Info()
	if err != nil {
		return "", "", fmt.Errorf("reading program info: %w", err)
	}
	return ProgramTypeString(info.Type), info.Tag, nil
}
