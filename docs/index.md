---
page_title: "terrahive Provider"
description: |-
  Manage eBPF programs, maps, and attachments on the local Linux kernel.
---

# terrahive Provider

Terrahive manages eBPF objects on the Linux kernel it runs on. It loads BPF
programs, creates maps, writes map entries, and attaches programs to kernel
hooks, all through `terraform apply`. Every object is pinned to bpffs, and the
pin path is the resource ID, so objects outlive the Terraform process.

Read [ANTIPATTERNS.md](https://github.com/maxgio92/terrahive/blob/main/docs/ANTIPATTERNS.md)
before you rely on this. It lists every Terraform and eBPF practice the
provider breaks and why.

## Caveats

- The provider manages the local machine only. State and kernel share fate.
- It needs root or CAP_BPF to call the `bpf()` syscall.
- Kernel 5.15 or newer covers most attach types. tcx needs 6.6, netfilter needs 6.4.
- `c_source` needs the system clang on PATH. `go_source` needs the bumble flavor.

## The resource name prefix

Resources use the `ebpf_` prefix, not `terrahive_`. Terraform convention wants
the provider name as the prefix, so every configuration sets a local name:

```terraform
terraform {
  required_providers {
    ebpf = {
      source = "maxgio92/terrahive"
    }
  }
}
```

## Example Usage

```terraform
provider "ebpf" {
  pin_dir = "/sys/fs/bpf/terrahive"
}

resource "ebpf_program" "hello" {
  name        = "hello"
  object_file = "${path.module}/hello.bpf.o"
}

resource "ebpf_kprobe" "openat" {
  name    = "hello-openat"
  program = ebpf_program.hello.id
  symbol  = "do_sys_openat2"
}
```

## Schema

### Optional

- `pin_dir` (String) bpffs directory where managed objects are pinned. Defaults to `/sys/fs/bpf/terrahive`.
