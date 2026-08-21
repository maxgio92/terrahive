---
page_title: "ebpf_kprobe Resource - terrahive"
description: |-
  Attaches a program to a kernel or user probe through a pinned bpf_link.
---

# ebpf_kprobe (Resource)

Attaches a program to a kernel or user probe through a pinned `bpf_link`. The
link survives Terraform exiting because it is pinned. Destroy the resource to
detach without unloading the program. Any attribute change forces replacement.

## Example Usage

```terraform
resource "ebpf_kprobe" "openat" {
  name    = "hello-openat"
  program = ebpf_program.hello.id
  symbol  = "do_sys_openat2"
}

resource "ebpf_kprobe" "malloc" {
  name    = "malloc-probe"
  program = ebpf_program.trace.id
  kind    = "uprobe"
  path    = "/lib/x86_64-linux-gnu/libc.so.6"
  symbol  = "malloc"
}
```

## Schema

### Required

- `name` (String) Pin name of the link under the pin directory. Forces replacement.
- `program` (String) bpffs pin path of the program to attach. Forces replacement.
- `symbol` (String) Traced symbol; the probe name for usdt. Forces replacement.

### Optional

- `kind` (String) Probe flavor: kprobe, kretprobe, uprobe, uretprobe, or usdt. Defaults to kprobe. Forces replacement.
- `path` (String) Executable path, required for uprobe, uretprobe, and usdt. Forces replacement.
- `usdt_provider` (String) USDT provider name, required for usdt. Forces replacement.
- `offset` (Number) Offset relative to the symbol. Forces replacement.

### Read-Only

- `id` (String) bpffs pin path of the link.
- `link_id` (Number) Kernel ID of the bpf_link.
- `program_id` (Number) Kernel ID of the attached program.
