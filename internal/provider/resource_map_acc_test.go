package provider

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Resources carry the ebpf_ prefix, so the provider's local name in
// configuration is "ebpf".
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"ebpf": providerserver.NewProtocol6WithError(New("test")()),
}

// testAccPinDir returns a per-test pin directory on bpffs and removes it
// when the test ends. Acceptance tests run as root.
func testAccPinDir(t *testing.T) string {
	t.Helper()
	dir := fmt.Sprintf("/sys/fs/bpf/terrahive-test-%s-%d", t.Name(), os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func testAccMapConfig(pinDir string, maxEntries int) string {
	return fmt.Sprintf(`
provider "ebpf" {
  pin_dir = %q
}

resource "ebpf_map" "test" {
  name        = "counters"
  type        = "hash"
  key_size    = 4
  value_size  = 8
  max_entries = %d
}
`, pinDir, maxEntries)
}

func TestAccMap_basic(t *testing.T) {
	pinDir := testAccPinDir(t)
	pinPath := pinDir + "/map/counters"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccMapConfig(pinDir, 16),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ebpf_map.test", "id", pinPath),
					resource.TestCheckResourceAttr("ebpf_map.test", "type", "hash"),
					resource.TestCheckResourceAttr("ebpf_map.test", "key_size", "4"),
					resource.TestCheckResourceAttr("ebpf_map.test", "value_size", "8"),
					resource.TestCheckResourceAttr("ebpf_map.test", "max_entries", "16"),
					testAccCheckPinnedMap(pinPath, ebpf.Hash, 4, 8, 16),
				),
			},
			{
				ResourceName:      "ebpf_map.test",
				ImportState:       true,
				ImportStateId:     pinPath,
				ImportStateVerify: true,
			},
			{
				// Shape change forces replacement.
				Config: testAccMapConfig(pinDir, 32),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("ebpf_map.test", plancheck.ResourceActionReplace),
					},
				},
				Check: testAccCheckPinnedMap(pinPath, ebpf.Hash, 4, 8, 32),
			},
		},
		CheckDestroy: testAccCheckNoPin(pinPath),
	})
}

func TestAccMap_disappears(t *testing.T) {
	pinDir := testAccPinDir(t)
	pinPath := pinDir + "/map/counters"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccMapConfig(pinDir, 16),
				Check: func(_ *terraform.State) error {
					return os.Remove(pinPath)
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccCheckPinnedMap(pinPath string, mt ebpf.MapType, keySize, valueSize, maxEntries uint32) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		m, err := ebpf.LoadPinnedMap(pinPath, nil)
		if err != nil {
			return fmt.Errorf("loading pinned map %s: %w", pinPath, err)
		}
		defer func() { _ = m.Close() }()
		if m.Type() != mt || m.KeySize() != keySize || m.ValueSize() != valueSize || m.MaxEntries() != maxEntries {
			return fmt.Errorf("pinned map %s is %v/%d/%d/%d, want %v/%d/%d/%d",
				pinPath, m.Type(), m.KeySize(), m.ValueSize(), m.MaxEntries(), mt, keySize, valueSize, maxEntries)
		}
		return nil
	}
}

func testAccCheckNoPin(pinPath string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		if _, err := os.Stat(pinPath); !os.IsNotExist(err) {
			return fmt.Errorf("pin %s still exists (stat err: %v)", pinPath, err)
		}
		return nil
	}
}

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
