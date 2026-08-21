---
page_title: "ebpf_netfilter Resource - terrahive"
description: |-
  Attaches a netfilter program to a hook through a pinned bpf_link.
---

# ebpf_netfilter (Resource)

Attaches a netfilter program to a hook through a pinned `bpf_link`. Requires
kernel 6.4. Any attribute change forces replacement.

## Example Usage

```terraform
resource "ebpf_netfilter" "input" {
  name     = "nf-input"
  program  = ebpf_program.filter.id
  family   = "ipv4"
  hook     = "input"
  priority = 0
}
```

## Schema

### Required

- `name` (String) Pin name of the link under the pin directory. Forces replacement.
- `program` (String) bpffs pin path of the program to attach. Forces replacement.
- `family` (String) Protocol family: ipv4 or ipv6. Forces replacement.
- `hook` (String) Netfilter hook: prerouting, input, forward, output, or postrouting. Forces replacement.

### Optional

- `priority` (Number) Priority within the hook. Defaults to 0. Forces replacement.

### Read-Only

- `id` (String) bpffs pin path of the link.
- `link_id` (Number) Kernel ID of the bpf_link.
- `program_id` (Number) Kernel ID of the attached program.
