---
page_title: "ebpf_program Resource - terrahive"
description: |-
  Loads a BPF program into the kernel and pins it under the provider pin directory.
---

# ebpf_program (Resource)

Loads a BPF program into the kernel and pins it under the provider pin
directory. Give exactly one source: `object_file`, `c_source`, or `go_source`.
The program type is inferred from the ELF section name. `type` acts as an
assertion against the inferred type.

A loaded program is immutable in the kernel, so any change to a source or the
type forces replacement. Attachments reference programs by pin path, so a
replacement cascades to dependent attachments.

## Example Usage

```terraform
resource "ebpf_program" "hello" {
  name        = "hello"
  object_file = "${path.module}/hello.bpf.o"
}

resource "ebpf_program" "drop" {
  name     = "xdp_drop"
  c_source = file("${path.module}/xdp_drop.c")
}
```

## Schema

### Required

- `name` (String) Program name, used as the last pin path element. Forces replacement.

### Optional

- `object_file` (String) Path to a compiled BPF ELF object containing exactly one program. Exactly one of `object_file`, `c_source`, `go_source`. Forces replacement.
- `c_source` (String) BPF C source, compiled with the system clang at apply time. Forces replacement.
- `go_source` (String) BPF Go source, compiled with the embedded TinyGo toolchain (terrahive-bumble flavor only). Forces replacement.
- `type` (String) Program type in lowercase (for example kprobe, xdp). Inferred from the ELF section; when set, acts as an assertion against the inferred type. Forces replacement.

### Read-Only

- `id` (String) bpffs pin path of the program.
- `tag` (String) Kernel-computed program tag, used for drift detection.
- `source_hash` (String) SHA-256 of the program source; a change forces replacement.

## Import

Import a program by its pin path:

```shell
terraform import ebpf_program.hello /sys/fs/bpf/terrahive/program/hello
```
