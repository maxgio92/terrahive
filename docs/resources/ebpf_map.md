---
page_title: "ebpf_map Resource - terrahive"
description: |-
  Creates a BPF map in the kernel and pins it under the provider pin directory.
---

# ebpf_map (Resource)

Creates a BPF map in the kernel and pins it under the provider `pin_dir`. The
pin path is the resource ID. Map dimensions are immutable in the kernel, so any
shape change forces replacement. Reference the pinned map from programs or from
`ebpf_map_entry` so several programs share one map.

## Example Usage

```terraform
resource "ebpf_map" "flags" {
  name        = "flags"
  type        = "hash"
  key_size    = 4
  value_size  = 8
  max_entries = 1024
}
```

## Schema

### Required

- `name` (String) Name of the map; the last element of the pin path. Forces replacement.
- `type` (String) Map type, for example hash, array, lru_hash, ringbuf. Forces replacement.
- `key_size` (Number) Key size in bytes. Forces replacement.
- `value_size` (Number) Value size in bytes. Forces replacement.
- `max_entries` (Number) Maximum number of entries. Forces replacement.

### Read-Only

- `id` (String) bpffs pin path of the map.

## Import

```shell
terraform import ebpf_map.flags /sys/fs/bpf/terrahive/map/flags
```
