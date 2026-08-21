//go:build bumble

package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// accGoKprobeSource must compile to a single-program BPF object with
// the TinyGo toolchain TERRAHIVE_TINYGO points at.
const accGoKprobeSource = `package main

//go:section kprobe/do_sys_openat2
func probe(ctx uintptr) int32 { return 0 }

func main() {}
`

// TestAccProgramGoSource is the end-to-end bumble path: TinyGo
// compiles go_source and the kernel loads the result. It needs a real
// toolchain, which this repo does not vendor, so it runs only when
// TERRAHIVE_TINYGO points at one (CI fetches the pinned release).
func TestAccProgramGoSource(t *testing.T) {
	if os.Getenv("TERRAHIVE_TINYGO") == "" {
		t.Skip("set TERRAHIVE_TINYGO to a TinyGo binary with BPF target support to run the go_source acceptance test")
	}
	pinDir := accPinDir(t)

	config := accProviderBlock(pinDir) + fmt.Sprintf(`
resource "ebpf_program" "probe" {
  name      = "gopher"
  go_source = %q
}
`, accGoKprobeSource)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
		ProtoV6ProviderFactories: accProtoV6Factories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestMatchResourceAttr("ebpf_program.probe", "tag", regexp.MustCompile(`^[0-9a-f]{16}$`)),
					resource.TestMatchResourceAttr("ebpf_program.probe", "source_hash", regexp.MustCompile(`^[0-9a-f]{64}$`)),
				),
			},
		},
	})
}
