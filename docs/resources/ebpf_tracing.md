---
page_title: "ebpf_tracing Resource - terrahive"
description: |-
  Attaches a BTF-powered tracing program through a pinned bpf_link.
---

# ebpf_tracing (Resource)

Attaches a BTF-powered tracing program (fentry, fexit, fmod_ret, lsm, iter)
through a pinned `bpf_link`. The attach target is fixed at program load time, so
the program itself names the function it hooks. Any attribute change forces
replacement.

## Example Usage

```terraform
resource "ebpf_tracing" "openat_entry" {
  name    = "openat-fentry"
  program = ebpf_program.fentry.id
  kind    = "fentry"
}
```

## Schema

### Required

- `name` (String) Pin name of the link under the pin directory. Forces replacement.
- `program` (String) bpffs pin path of the program to attach. Forces replacement.
- `kind` (String) Tracing flavor: fentry, fexit, fmod_ret, lsm, or iter. Forces replacement.

### Read-Only

- `id` (String) bpffs pin path of the link.
- `link_id` (Number) Kernel ID of the bpf_link.
- `program_id` (Number) Kernel ID of the attached program.
