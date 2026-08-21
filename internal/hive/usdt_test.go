package hive

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// usdtFixture is what sys/sdt.h expands to: a stapsdt ELF note pointing
// at a nop inside traced(), plus the .stapsdt.base anchor section. The
// second probe declares a semaphore in .probes.
const usdtFixture = `
__extension__ unsigned short terrahive_gauged_semaphore
    __attribute__((unused)) __attribute__((section(".probes")))
    __attribute__((visibility("hidden"))) = 0;

#define STAPSDT_NOTE(provider, name, semaphore)                        \
	__asm__ __volatile__(                                          \
	    "990: nop\n"                                               \
	    ".pushsection .note.stapsdt,\"?\",\"note\"\n"              \
	    ".balign 4\n"                                              \
	    ".4byte 992f-991f, 994f-993f, 3\n"                         \
	    "991: .asciz \"stapsdt\"\n"                                \
	    "992: .balign 4\n"                                         \
	    "993: .8byte 990b\n"                                       \
	    ".8byte _.stapsdt.base\n"                                  \
	    ".8byte " semaphore "\n"                                   \
	    ".asciz \"" provider "\"\n"                                \
	    ".asciz \"" name "\"\n"                                    \
	    ".asciz \"\"\n"                                            \
	    "994: .balign 4\n"                                         \
	    ".popsection\n")

__asm__(
    ".pushsection .stapsdt.base,\"aG\",\"progbits\",.stapsdt.base,comdat\n"
    ".weak _.stapsdt.base\n"
    ".hidden _.stapsdt.base\n"
    "_.stapsdt.base: .space 1\n"
    ".size _.stapsdt.base, 1\n"
    ".popsection\n");

__attribute__((noinline)) int traced(void) {
	STAPSDT_NOTE("terrahive", "buzzed", "0");
	STAPSDT_NOTE("terrahive", "gauged", "terrahive_gauged_semaphore");
	return 0;
}

int main(void) { return traced(); }
`

func buildUSDTFixture(t *testing.T) string {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang not available to build the usdt fixture")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "usdt.c")
	bin := filepath.Join(dir, "usdt")
	if err := os.WriteFile(src, []byte(usdtFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(clang, "-O0", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Fatalf("compiling usdt fixture: %v\n%s", err, out)
	}
	return bin
}

// symbolFileRange returns the file-offset range of a function symbol.
func symbolFileRange(t *testing.T, path, name string) (uint64, uint64) {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	syms, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	for _, sym := range syms {
		if sym.Name != name {
			continue
		}
		off, err := fileOffset(f, sym.Value)
		if err != nil {
			t.Fatal(err)
		}
		return off, off + sym.Size
	}
	t.Fatalf("symbol %s not found in %s", name, path)
	return 0, 0
}

func TestResolveUSDT(t *testing.T) {
	bin := buildUSDTFixture(t)
	lo, hi := symbolFileRange(t, bin, "traced")

	probe, err := ResolveUSDT(bin, "terrahive", "buzzed")
	if err != nil {
		t.Fatalf("ResolveUSDT: %v", err)
	}
	if probe.Address < lo || probe.Address >= hi {
		t.Errorf("probe address %#x outside traced() file range [%#x, %#x)", probe.Address, lo, hi)
	}
	if probe.SemaphoreOffset != 0 {
		t.Errorf("unexpected semaphore offset %#x for a probe without semaphore", probe.SemaphoreOffset)
	}
}

func TestResolveUSDTSemaphore(t *testing.T) {
	bin := buildUSDTFixture(t)

	probe, err := ResolveUSDT(bin, "terrahive", "gauged")
	if err != nil {
		t.Fatalf("ResolveUSDT: %v", err)
	}
	if probe.SemaphoreOffset == 0 {
		t.Fatal("semaphore offset is zero for a probe with a semaphore")
	}
}

func TestResolveUSDTNotFound(t *testing.T) {
	bin := buildUSDTFixture(t)
	if _, err := ResolveUSDT(bin, "terrahive", "missing"); err == nil {
		t.Fatal("expected an error for a missing probe")
	}
}

func TestResolveUSDTNoNotes(t *testing.T) {
	if _, err := ResolveUSDT("/proc/self/exe", "terrahive", "buzzed"); err == nil {
		t.Fatal("expected an error for a binary without stapsdt notes")
	}
}
