package provider

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/cilium/ebpf/link"
)

func testAccPreCheck(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("acceptance tests manage kernel BPF objects and must run as root (sudo -E)")
	}
}

// accPinDir gives every test an isolated hive under bpffs and cleans it
// up. It applies the same TF_ACC gate as resource.Test because it runs
// kernel-touching setup before the framework gets a chance to skip.
func accNamedPinDir(t *testing.T, name string) string {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run acceptance tests")
	}
	testAccPreCheck(t)
	dir := "/sys/fs/bpf/terrahive-acc-" + name
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// returnProgSpec assembles the smallest loadable program: return a constant.
// The ebpf_program resource does not exist yet, so tests load and pin the
// program under test directly with cilium/ebpf.
func returnProgSpec(typ ebpf.ProgramType, attach ebpf.AttachType, ret int32) *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Type:       typ,
		AttachType: attach,
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, ret),
			asm.Return(),
		},
	}
}

func pinTestProgram(t *testing.T, pinDir string, spec *ebpf.ProgramSpec) string {
	t.Helper()
	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		t.Fatalf("loading test program: %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	if err := os.MkdirAll(filepath.Join(pinDir, "progs"), 0o755); err != nil {
		t.Fatalf("creating program pin directory: %v", err)
	}
	pin := filepath.Join(pinDir, "progs", "prog")
	if err := prog.Pin(pin); err != nil {
		t.Fatalf("pinning test program: %v", err)
	}
	return pin
}

func checkLinkPinned(pinPath string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		l, err := link.LoadPinnedLink(pinPath, nil)
		if err != nil {
			return fmt.Errorf("pinned link %s: %w", pinPath, err)
		}
		return l.Close()
	}
}

// checkDestroyed verifies the spec's "destroy attachment only" scenario:
// the link pin is gone while the program stays loaded and pinned.
func checkDestroyed(linkPin, progPin string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if _, err := os.Stat(linkPin); err == nil {
			return fmt.Errorf("link pin %s still exists after destroy", linkPin)
		}
		prog, err := ebpf.LoadPinnedProgram(progPin, nil)
		if err != nil {
			return fmt.Errorf("program pin %s must survive attachment destroy: %w", progPin, err)
		}
		return prog.Close()
	}
}

// attachmentSteps returns the shared create-then-drift test steps: apply,
// verify the pin, delete the pin out of band, and verify a fresh apply
// recreates it (refresh must mark the resource for recreation).
func attachmentSteps(config, linkPin, resourceAddr string) []resource.TestStep {
	checks := resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr(resourceAddr, "id", linkPin),
		resource.TestCheckResourceAttrSet(resourceAddr, "link_id"),
		resource.TestCheckResourceAttrSet(resourceAddr, "program_id"),
		checkLinkPinned(linkPin),
	)
	return []resource.TestStep{
		{Config: config, Check: checks},
		{
			PreConfig: func() { _ = os.Remove(linkPin) },
			Config:    config,
			Check:     checks,
		},
	}
}

func TestAccKprobe(t *testing.T) {
	pinDir := accNamedPinDir(t, "kprobe")
	progPin := pinTestProgram(t, pinDir, returnProgSpec(ebpf.Kprobe, ebpf.AttachNone, 0))
	linkPin := filepath.Join(pinDir, "kprobe", "test")

	config := fmt.Sprintf(`
provider "ebpf" { pin_dir = %q }

resource "ebpf_kprobe" "test" {
  name    = "test"
  program = %q
  symbol  = "vfs_read"
}
`, pinDir, progPin)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    attachmentSteps(config, linkPin, "ebpf_kprobe.test"),
		CheckDestroy:             checkDestroyed(linkPin, progPin),
	})
}

func TestAccKretprobe(t *testing.T) {
	pinDir := accNamedPinDir(t, "kretprobe")
	progPin := pinTestProgram(t, pinDir, returnProgSpec(ebpf.Kprobe, ebpf.AttachNone, 0))
	linkPin := filepath.Join(pinDir, "kprobe", "test")

	config := fmt.Sprintf(`
provider "ebpf" { pin_dir = %q }

resource "ebpf_kprobe" "test" {
  name    = "test"
  kind    = "kretprobe"
  program = %q
  symbol  = "vfs_read"
}
`, pinDir, progPin)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    attachmentSteps(config, linkPin, "ebpf_kprobe.test"),
		CheckDestroy:             checkDestroyed(linkPin, progPin),
	})
}

func TestAccTracepoint(t *testing.T) {
	pinDir := accNamedPinDir(t, "tracepoint")
	progPin := pinTestProgram(t, pinDir, returnProgSpec(ebpf.TracePoint, ebpf.AttachNone, 0))
	linkPin := filepath.Join(pinDir, "tracepoint", "test")

	config := fmt.Sprintf(`
provider "ebpf" { pin_dir = %q }

resource "ebpf_tracepoint" "test" {
  name    = "test"
  program = %q
  group   = "sched"
  event   = "sched_switch"
}
`, pinDir, progPin)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    attachmentSteps(config, linkPin, "ebpf_tracepoint.test"),
		CheckDestroy:             checkDestroyed(linkPin, progPin),
	})
}

func TestAccRawTracepoint(t *testing.T) {
	pinDir := accNamedPinDir(t, "rawtp")
	progPin := pinTestProgram(t, pinDir, returnProgSpec(ebpf.RawTracepoint, ebpf.AttachNone, 0))
	linkPin := filepath.Join(pinDir, "tracepoint", "test")

	config := fmt.Sprintf(`
provider "ebpf" { pin_dir = %q }

resource "ebpf_tracepoint" "test" {
  name    = "test"
  kind    = "raw_tracepoint"
  program = %q
  event   = "sched_switch"
}
`, pinDir, progPin)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    attachmentSteps(config, linkPin, "ebpf_tracepoint.test"),
		CheckDestroy:             checkDestroyed(linkPin, progPin),
	})
}

func TestAccPerfEvent(t *testing.T) {
	pinDir := accNamedPinDir(t, "perfevent")
	progPin := pinTestProgram(t, pinDir, returnProgSpec(ebpf.PerfEvent, ebpf.AttachPerfEvent, 0))
	linkPin := filepath.Join(pinDir, "tracepoint", "test")

	config := fmt.Sprintf(`
provider "ebpf" { pin_dir = %q }

resource "ebpf_tracepoint" "test" {
  name        = "test"
  kind        = "perf_event"
  program     = %q
  sample_freq = 1
}
`, pinDir, progPin)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    attachmentSteps(config, linkPin, "ebpf_tracepoint.test"),
		CheckDestroy:             checkDestroyed(linkPin, progPin),
	})
}

func TestAccXDP(t *testing.T) {
	pinDir := accNamedPinDir(t, "xdp")
	// XDP_PASS keeps loopback traffic flowing.
	progPin := pinTestProgram(t, pinDir, returnProgSpec(ebpf.XDP, ebpf.AttachNone, 2))
	linkPin := filepath.Join(pinDir, "xdp", "test")

	config := fmt.Sprintf(`
provider "ebpf" { pin_dir = %q }

resource "ebpf_xdp" "test" {
  name      = "test"
  program   = %q
  interface = "lo"
  mode      = "generic"
}
`, pinDir, progPin)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    attachmentSteps(config, linkPin, "ebpf_xdp.test"),
		CheckDestroy:             checkDestroyed(linkPin, progPin),
	})
}

func TestAccTCX(t *testing.T) {
	pinDir := accNamedPinDir(t, "tcx")
	// TC_ACT_OK keeps loopback traffic flowing.
	progPin := pinTestProgram(t, pinDir, returnProgSpec(ebpf.SchedCLS, ebpf.AttachNone, 0))
	linkPin := filepath.Join(pinDir, "tcx", "test")

	config := fmt.Sprintf(`
provider "ebpf" { pin_dir = %q }

resource "ebpf_tcx" "test" {
  name      = "test"
  program   = %q
  interface = "lo"
  direction = "ingress"
}
`, pinDir, progPin)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    attachmentSteps(config, linkPin, "ebpf_tcx.test"),
		CheckDestroy:             checkDestroyed(linkPin, progPin),
	})
}

func TestAccCgroup(t *testing.T) {
	pinDir := accNamedPinDir(t, "cgroup")
	// Returning 1 from a cgroup skb program allows the packet.
	progPin := pinTestProgram(t, pinDir, returnProgSpec(ebpf.CGroupSKB, ebpf.AttachCGroupInetIngress, 1))
	linkPin := filepath.Join(pinDir, "cgroup", "test")

	cgroupPath := "/sys/fs/cgroup/terrahive-acc"
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("creating test cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cgroupPath) })

	config := fmt.Sprintf(`
provider "ebpf" { pin_dir = %q }

resource "ebpf_cgroup" "test" {
  name        = "test"
  program     = %q
  cgroup      = %q
  attach_type = "cgroup_inet_ingress"
}
`, pinDir, progPin, cgroupPath)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    attachmentSteps(config, linkPin, "ebpf_cgroup.test"),
		CheckDestroy:             checkDestroyed(linkPin, progPin),
	})
}

func TestAccNetfilter(t *testing.T) {
	pinDir := accNamedPinDir(t, "netfilter")
	// NF_ACCEPT keeps packets flowing.
	progPin := pinTestProgram(t, pinDir, returnProgSpec(ebpf.Netfilter, ebpf.AttachNetfilter, 1))
	linkPin := filepath.Join(pinDir, "netfilter", "test")

	config := fmt.Sprintf(`
provider "ebpf" { pin_dir = %q }

resource "ebpf_netfilter" "test" {
  name     = "test"
  program  = %q
  family   = "ipv4"
  hook     = "input"
  priority = -128
}
`, pinDir, progPin)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    attachmentSteps(config, linkPin, "ebpf_netfilter.test"),
		CheckDestroy:             checkDestroyed(linkPin, progPin),
	})
}

// accUSDTFixture is what sys/sdt.h expands to: a stapsdt ELF note whose
// "gauged" probe declares a semaphore, exercising the Address and
// RefCtrOffset wiring in attachKprobe.
const accUSDTFixture = `
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
	if err := os.WriteFile(src, []byte(accUSDTFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(clang, "-O0", "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("compiling usdt fixture: %v\n%s", err, out)
	}
	return bin
}

func TestAccUSDT(t *testing.T) {
	pinDir := accNamedPinDir(t, "usdt")
	progPin := pinTestProgram(t, pinDir, returnProgSpec(ebpf.Kprobe, ebpf.AttachNone, 0))
	linkPin := filepath.Join(pinDir, "kprobe", "test")
	bin := buildUSDTFixture(t)

	config := fmt.Sprintf(`
provider "ebpf" { pin_dir = %q }

resource "ebpf_kprobe" "test" {
  name          = "test"
  kind          = "usdt"
  program       = %q
  path          = %q
  usdt_provider = "terrahive"
  symbol        = "gauged"
}
`, pinDir, progPin, bin)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    attachmentSteps(config, linkPin, "ebpf_kprobe.test"),
		CheckDestroy:             checkDestroyed(linkPin, progPin),
	})
}

func TestAccUprobe(t *testing.T) {
	pinDir := accNamedPinDir(t, "uprobe")
	progPin := pinTestProgram(t, pinDir, returnProgSpec(ebpf.Kprobe, ebpf.AttachNone, 0))
	linkPin := filepath.Join(pinDir, "kprobe", "test")
	bin := buildUSDTFixture(t)

	config := fmt.Sprintf(`
provider "ebpf" { pin_dir = %q }

resource "ebpf_kprobe" "test" {
  name    = "test"
  kind    = "uprobe"
  program = %q
  path    = %q
  symbol  = "traced"
}
`, pinDir, progPin, bin)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    attachmentSteps(config, linkPin, "ebpf_kprobe.test"),
		CheckDestroy:             checkDestroyed(linkPin, progPin),
	})
}

func TestAccStructOps(t *testing.T) {
	t.Skip("struct_ops needs a BTF-defined struct_ops map (e.g. a BPF TCP congestion control) compiled from a full object file; no safe target can be assembled with the asm package")
}
