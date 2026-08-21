package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/maxgio92/terrahive/internal/hive"
)

const accKprobeSource = `
__attribute__((section("kprobe/do_sys_openat2"), used))
int hive_probe(void *ctx) { return 0; }
char __license[] __attribute__((section("license"), used)) = "GPL";
`

// Same section, different body: compiles to a different program tag.
const accKprobeSourceV2 = `
__attribute__((section("kprobe/do_sys_openat2"), used))
int hive_probe(void *ctx) { return 1; }
char __license[] __attribute__((section("license"), used)) = "GPL";
`

var accProtoV6Factories = map[string]func() (tfprotov6.ProviderServer, error){
	"terrahive": providerserver.NewProtocol6WithError(New("test")()),
}

func accPreCheck(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("acceptance tests need root; run with sudo -E TF_ACC=1")
	}
}

// accPinDir returns a per-test bpffs pin directory, removed on cleanup.
func accPinDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("/sys/fs/bpf", "terrahive-acc-"+t.Name())
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func accCompile(t *testing.T, source string) string {
	t.Helper()
	obj, err := hive.CompileC(source)
	if err != nil {
		t.Fatalf("compiling fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "prog.o")
	if err := os.WriteFile(path, obj, 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

func accProviderBlock(pinDir string) string {
	return fmt.Sprintf("provider \"terrahive\" {\n  pin_dir = %q\n}\n", pinDir)
}

func TestAccProgramObjectFile(t *testing.T) {
	pinDir := accPinDir(t)
	objPath := accCompile(t, accKprobeSource)

	config := accProviderBlock(pinDir) + fmt.Sprintf(`
resource "terrahive_ebpf_program" "probe" {
  name        = "openat"
  object_file = %q
}
`, objPath)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
		ProtoV6ProviderFactories: accProtoV6Factories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("terrahive_ebpf_program.probe", "id", filepath.Join(pinDir, "program", "openat")),
					resource.TestCheckResourceAttr("terrahive_ebpf_program.probe", "type", "kprobe"),
					resource.TestMatchResourceAttr("terrahive_ebpf_program.probe", "tag", regexp.MustCompile(`^[0-9a-f]{16}$`)),
					resource.TestMatchResourceAttr("terrahive_ebpf_program.probe", "source_hash", regexp.MustCompile(`^[0-9a-f]{64}$`)),
					func(*terraform.State) error {
						_, err := os.Stat(filepath.Join(pinDir, "program", "openat"))
						return err
					},
				),
			},
			{
				ResourceName:            "terrahive_ebpf_program.probe",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"object_file", "source_hash"},
			},
			{
				// Rewriting the object at the same path changes the
				// content hash: the plan must replace the program.
				PreConfig: func() {
					obj, err := hive.CompileC(accKprobeSourceV2)
					if err != nil {
						t.Fatalf("compiling v2 fixture: %v", err)
					}
					if err := os.WriteFile(objPath, obj, 0o644); err != nil {
						t.Fatalf("rewriting fixture: %v", err)
					}
				},
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("terrahive_ebpf_program.probe", plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
			},
		},
	})
}

func TestAccProgramCSource(t *testing.T) {
	pinDir := accPinDir(t)

	config := accProviderBlock(pinDir) + fmt.Sprintf(`
resource "terrahive_ebpf_program" "probe" {
  name     = "csource"
  type     = "kprobe"
  c_source = %q
}
`, accKprobeSource)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
		ProtoV6ProviderFactories: accProtoV6Factories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("terrahive_ebpf_program.probe", "type", "kprobe"),
					resource.TestMatchResourceAttr("terrahive_ebpf_program.probe", "tag", regexp.MustCompile(`^[0-9a-f]{16}$`)),
				),
			},
		},
	})
}

func TestAccProgramTypeAssertionMismatch(t *testing.T) {
	pinDir := accPinDir(t)
	objPath := accCompile(t, accKprobeSource)

	config := accProviderBlock(pinDir) + fmt.Sprintf(`
resource "terrahive_ebpf_program" "probe" {
  name        = "mismatch"
  type        = "xdp"
  object_file = %q
}
`, objPath)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
		ProtoV6ProviderFactories: accProtoV6Factories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`ELF section implies`),
			},
		},
	})
}

func TestAccProgramExactlyOneSource(t *testing.T) {
	pinDir := accPinDir(t)
	objPath := accCompile(t, accKprobeSource)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
		ProtoV6ProviderFactories: accProtoV6Factories,
		Steps: []resource.TestStep{
			{
				Config: accProviderBlock(pinDir) + `
resource "terrahive_ebpf_program" "probe" {
  name = "nosource"
}
`,
				ExpectError: regexp.MustCompile(`Invalid Attribute Combination|Missing Attribute Configuration`),
			},
			{
				Config: accProviderBlock(pinDir) + fmt.Sprintf(`
resource "terrahive_ebpf_program" "probe" {
  name        = "twosources"
  object_file = %q
  c_source    = "int x;"
}
`, objPath),
				ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
			},
		},
	})
}

func TestAccProgramGoSourceRejected(t *testing.T) {
	pinDir := accPinDir(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
		ProtoV6ProviderFactories: accProtoV6Factories,
		Steps: []resource.TestStep{
			{
				Config: accProviderBlock(pinDir) + `
resource "terrahive_ebpf_program" "probe" {
  name      = "gopher"
  go_source = "package main"
}
`,
				ExpectError: regexp.MustCompile(`terrahive-bumble`),
			},
		},
	})
}

func TestAccProgramDriftOnPinSwap(t *testing.T) {
	pinDir := accPinDir(t)
	objPath := accCompile(t, accKprobeSource)
	pinPath := filepath.Join(pinDir, "program", "swapped")

	config := accProviderBlock(pinDir) + fmt.Sprintf(`
resource "terrahive_ebpf_program" "probe" {
  name        = "swapped"
  object_file = %q
}
`, objPath)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
		ProtoV6ProviderFactories: accProtoV6Factories,
		Steps: []resource.TestStep{
			{
				Config: config,
			},
			{
				// Swap the pin out-of-band: refresh must report drift
				// and the plan must recreate the program.
				PreConfig: func() {
					if err := os.Remove(pinPath); err != nil {
						t.Fatalf("removing pin: %v", err)
					}
					obj, err := hive.CompileC(accKprobeSourceV2)
					if err != nil {
						t.Fatalf("compiling swap fixture: %v", err)
					}
					spec, err := hive.LoadELF(obj)
					if err != nil {
						t.Fatalf("parsing swap fixture: %v", err)
					}
					prog, err := ebpf.NewProgram(spec)
					if err != nil {
						t.Fatalf("loading swap program: %v", err)
					}
					defer func() { _ = prog.Close() }()
					if err := prog.Pin(pinPath); err != nil {
						t.Fatalf("pinning swap program: %v", err)
					}
				},
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
