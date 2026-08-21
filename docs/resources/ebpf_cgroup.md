---
page_title: "ebpf_cgroup Resource - terrahive"
description: |-
  Attaches a program to a cgroup through a pinned bpf_link.
---

# ebpf_cgroup (Resource)

Attaches a program to a cgroup through a pinned `bpf_link`. Any attribute change
forces replacement.

## Example Usage

```terraform
resource "ebpf_cgroup" "ingress" {
  name        = "cgroup-ingress"
  program     = ebpf_program.skb.id
  cgroup      = "/sys/fs/cgroup/my-service"
  attach_type = "cgroup_inet_ingress"
}
```

## Schema

### Required

- `name` (String) Pin name of the link under the pin directory. Forces replacement.
- `program` (String) bpffs pin path of the program to attach. Forces replacement.
- `cgroup` (String) Filesystem path of the cgroup to attach to. Forces replacement.
- `attach_type` (String) Cgroup attach type, for example cgroup_inet_ingress. Forces replacement.

### Read-Only

- `id` (String) bpffs pin path of the link.
- `link_id` (Number) Kernel ID of the bpf_link.
- `program_id` (Number) Kernel ID of the attached program.
