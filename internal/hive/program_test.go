package hive

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

const kprobeSource = `
__attribute__((section("kprobe/do_sys_openat2"), used))
int hive_probe(void *ctx) { return 0; }
char __license[] __attribute__((section("license"), used)) = "GPL";
`

const twoProgramsSource = `
__attribute__((section("kprobe/do_sys_openat2"), used))
int probe_a(void *ctx) { return 0; }
__attribute__((section("xdp"), used))
int probe_b(void *ctx) { return 2; }
char __license[] __attribute__((section("license"), used)) = "GPL";
`

func TestCompileCAndLoadELFInfersType(t *testing.T) {
	obj, err := CompileC(kprobeSource)
	if err != nil {
		t.Fatalf("CompileC: %v", err)
	}
	spec, err := LoadELF(obj)
	if err != nil {
		t.Fatalf("LoadELF: %v", err)
	}
	if spec.Type != ebpf.Kprobe {
		t.Fatalf("inferred type = %v, want Kprobe", spec.Type)
	}
	if got := ProgramTypeString(spec.Type); got != "kprobe" {
		t.Fatalf("ProgramTypeString = %q, want kprobe", got)
	}
}

func TestCompileCInvalidSource(t *testing.T) {
	_, err := CompileC("this is not C")
	if err == nil {
		t.Fatal("expected compile error")
	}
	if !strings.Contains(err.Error(), "clang failed") {
		t.Fatalf("error %q does not name clang", err)
	}
}

func TestLoadELFRejectsGarbage(t *testing.T) {
	if _, err := LoadELF([]byte("not an ELF")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadELFRejectsMultiplePrograms(t *testing.T) {
	obj, err := CompileC(twoProgramsSource)
	if err != nil {
		t.Fatalf("CompileC: %v", err)
	}
	_, err = LoadELF(obj)
	if err == nil {
		t.Fatal("expected error for multi-program object")
	}
	if !strings.Contains(err.Error(), "probe_a") || !strings.Contains(err.Error(), "probe_b") {
		t.Fatalf("error %q does not list program names", err)
	}
}

func TestSourceHashIsStable(t *testing.T) {
	a := SourceHash([]byte("bees"))
	b := SourceHash([]byte("bees"))
	if a != b {
		t.Fatalf("hash not deterministic: %s vs %s", a, b)
	}
	if a == SourceHash([]byte("wasps")) {
		t.Fatal("distinct inputs hashed equal")
	}
}
