---
page_title: "ebpf_tcx Resource - terrahive"
description: |-
  Attaches a tc program to a network interface via tcx through a pinned bpf_link.
---

# ebpf_tcx (Resource)

Attaches a tc program to a network interface via tcx through a pinned
`bpf_link`. Requires kernel 6.6. Any attribute change forces replacement.

## Example Usage

```terraform
resource "ebpf_tcx" "eth0_ingress" {
  name      = "tcx-eth0-ingress"
  program   = ebpf_program.classifier.id
  interface = "eth0"
  direction = "ingress"
}
```

## Schema

### Required

- `name` (String) Pin name of the link under the pin directory. Forces replacement.
- `program` (String) bpffs pin path of the program to attach. Forces replacement.
- `interface` (String) Network interface name to attach to. Forces replacement.
- `direction` (String) Traffic direction: ingress or egress. Forces replacement.

### Read-Only

- `id` (String) bpffs pin path of the link.
- `link_id` (Number) Kernel ID of the bpf_link.
- `program_id` (Number) Kernel ID of the attached program.
