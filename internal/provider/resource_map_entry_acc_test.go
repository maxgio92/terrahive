package provider

import (
	"bytes"
	"fmt"
	"regexp"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

var (
	testAccEntryKey      = []byte{1, 0, 0, 0}
	testAccEntryValue    = []byte{42, 0, 0, 0, 0, 0, 0, 0}
	testAccEntryNewValue = []byte{43, 0, 0, 0, 0, 0, 0, 0}
	testAccDriftedValue  = []byte{99, 0, 0, 0, 0, 0, 0, 0}
)

func testAccMapEntryConfig(pinDir string, value []byte) string {
	return testAccMapConfig(pinDir, 16) + fmt.Sprintf(`
resource "ebpf_map_entry" "test" {
  map   = ebpf_map.test.id
  key   = %q
  value = %q
}
`, b64(testAccEntryKey), b64(value))
}

func TestAccMapEntry_basic(t *testing.T) {
	pinDir := testAccPinDir(t)
	pinPath := pinDir + "/map/counters"
	entryID := pinPath + ":" + b64(testAccEntryKey)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccMapEntryConfig(pinDir, testAccEntryValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ebpf_map_entry.test", "id", entryID),
					testAccCheckEntryValue(pinPath, testAccEntryKey, testAccEntryValue),
				),
			},
			{
				ResourceName:      "ebpf_map_entry.test",
				ImportState:       true,
				ImportStateId:     entryID,
				ImportStateVerify: true,
			},
			{
				// Value change updates in place.
				Config: testAccMapEntryConfig(pinDir, testAccEntryNewValue),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("ebpf_map_entry.test", plancheck.ResourceActionUpdate),
					},
				},
				Check: testAccCheckEntryValue(pinPath, testAccEntryKey, testAccEntryNewValue),
			},
			{
				// Out-of-band kernel write drifts; plan restores the value.
				PreConfig: func() {
					if err := testAccPutEntry(pinPath, testAccEntryKey, testAccDriftedValue); err != nil {
						t.Fatalf("injecting drift: %v", err)
					}
				},
				Config: testAccMapEntryConfig(pinDir, testAccEntryNewValue),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("ebpf_map_entry.test", plancheck.ResourceActionUpdate),
					},
				},
				Check: testAccCheckEntryValue(pinPath, testAccEntryKey, testAccEntryNewValue),
			},
			{
				// Destroying the entry deletes the key but keeps the map.
				Config: testAccMapConfig(pinDir, 16),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckPinnedMap(pinPath, ebpf.Hash, 4, 8, 16),
					testAccCheckEntryAbsent(pinPath, testAccEntryKey),
				),
			},
		},
	})
}

func TestAccMapEntry_disappears(t *testing.T) {
	pinDir := testAccPinDir(t)
	pinPath := pinDir + "/map/counters"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccMapEntryConfig(pinDir, testAccEntryValue),
				Check: func(_ *terraform.State) error {
					m, err := ebpf.LoadPinnedMap(pinPath, nil)
					if err != nil {
						return err
					}
					defer func() { _ = m.Close() }()
					return m.Delete(testAccEntryKey)
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccMapEntry_arrayDestroy proves destroy tolerates the EINVAL that
// array-family maps return from delete: an entry on an array map applies
// and the framework's teardown succeeds instead of wedging.
func TestAccMapEntry_arrayDestroy(t *testing.T) {
	pinDir := testAccPinDir(t)
	pinPath := pinDir + "/map/arr"
	key := []byte{0, 0, 0, 0}
	value := []byte{7, 0, 0, 0, 0, 0, 0, 0}

	config := fmt.Sprintf(`
provider "ebpf" {
  pin_dir = %q
}

resource "ebpf_map" "arr" {
  name        = "arr"
  type        = "array"
  key_size    = 4
  value_size  = 8
  max_entries = 4
}

resource "ebpf_map_entry" "test" {
  map   = ebpf_map.arr.id
  key   = %q
  value = %q
}
`, pinDir, b64(key), b64(value))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  testAccCheckEntryValue(pinPath, key, value),
			},
		},
	})
}

// TestAccMapEntry_perCPURejected proves ebpf_map_entry refuses per-CPU
// maps at create instead of silently mishandling per-CPU values.
func TestAccMapEntry_perCPURejected(t *testing.T) {
	pinDir := testAccPinDir(t)

	config := fmt.Sprintf(`
provider "ebpf" {
  pin_dir = %q
}

resource "ebpf_map" "pc" {
  name        = "pc"
  type        = "percpu_hash"
  key_size    = 4
  value_size  = 8
  max_entries = 4
}

resource "ebpf_map_entry" "test" {
  map   = ebpf_map.pc.id
  key   = %q
  value = %q
}
`, pinDir, b64([]byte{1, 0, 0, 0}), b64([]byte{2, 0, 0, 0, 0, 0, 0, 0}))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`per-CPU map not supported`),
			},
		},
	})
}

func testAccPutEntry(pinPath string, key, value []byte) error {
	m, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()
	return m.Put(key, value)
}

func testAccCheckEntryValue(pinPath string, key, want []byte) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		m, err := ebpf.LoadPinnedMap(pinPath, nil)
		if err != nil {
			return fmt.Errorf("loading pinned map %s: %w", pinPath, err)
		}
		defer func() { _ = m.Close() }()
		got, err := m.LookupBytes(key)
		if err != nil {
			return fmt.Errorf("lookup in %s: %w", pinPath, err)
		}
		if got == nil {
			return fmt.Errorf("key %v not found in %s", key, pinPath)
		}
		if !bytes.Equal(got[:len(want)], want) {
			return fmt.Errorf("value in %s is %v, want %v", pinPath, got, want)
		}
		return nil
	}
}

func testAccCheckEntryAbsent(pinPath string, key []byte) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		m, err := ebpf.LoadPinnedMap(pinPath, nil)
		if err != nil {
			return fmt.Errorf("loading pinned map %s: %w", pinPath, err)
		}
		defer func() { _ = m.Close() }()
		got, err := m.LookupBytes(key)
		if err != nil {
			return fmt.Errorf("lookup in %s: %w", pinPath, err)
		}
		if got != nil {
			return fmt.Errorf("key %v still present in %s with value %v", key, pinPath, got)
		}
		return nil
	}
}
