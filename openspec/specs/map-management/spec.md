# Map Management

## Requirements

### Requirement: Map lifecycle

The `ebpf_map` resource SHALL create a BPF map with the given `type`, `key_size`, `value_size`, and `max_entries`, pin it, and delete it by unpinning.

#### Scenario: Create and pin

- WHEN apply creates an `ebpf_map`
- THEN the map appears in `bpftool map list` and its pin exists

#### Scenario: Shape change forces replacement

- WHEN `key_size` or `max_entries` changes
- THEN plan shows the map as requiring replacement

### Requirement: Map sharing

Programs SHALL be able to reference a pinned `ebpf_map` so that multiple programs share one map.

#### Scenario: Two programs, one map

- WHEN two `ebpf_program` resources reference the same `ebpf_map`
- THEN both loaded programs operate on the same kernel map

### Requirement: Managed map entries

The `ebpf_map_entry` resource SHALL manage a single key/value pair, encoded as base64, in a referenced map.

#### Scenario: Entry create and read

- WHEN apply creates an `ebpf_map_entry`
- THEN a map lookup for the key returns the configured value

#### Scenario: Entry drift

- WHEN the value is changed in the kernel outside Terraform (for example by a BPF program)
- THEN refresh reports drift and plan proposes restoring the configured value

#### Scenario: Entry delete

- WHEN the resource is destroyed
- THEN the key is deleted from the map
