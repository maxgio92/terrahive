# terrahive

Terrahive is a Terraform provider that keeps eBPF objects. It loads BPF
programs, creates maps, writes map entries, and attaches programs to kernel
hooks, all through `terraform apply`. It is a meme project built to be
technically sound.

The name is the frame. A hive holds bees, and eBPF is the swarm: many small
programs living in one kernel, each doing one job. Terrahive is the beekeeper.
It puts the bees in the hive, tells them where to work, and pulls them out when
you are done. bpffs is the honeycomb: every program, map, and link is pinned to
a cell so it stays put after the keeper walks away.

## The premise

Terraform providers call remote APIs and manage infrastructure that lives
somewhere else. Terrahive calls the `bpf()` syscall on the kernel it runs
inside. There is no "somewhere else". The API endpoint is `/proc/self`, and the
blast radius is exactly one machine: the one you are standing on.

That is a bad idea, and it works anyway, because the kernel's BPF object model
genuinely maps to CRUD. Create loads and pins, Read resolves the pin and reads
real kernel state, Delete unpins and unloads. Read
[docs/ANTIPATTERNS.md](docs/ANTIPATTERNS.md) for every rule this breaks and why
we broke it.

## Flavors

Two binaries ship from one codebase:

- `terrahive` (lean): takes precompiled object files and `c_source`. No embedded
  compiler. This is the flavor you should use.
- `terrahive-bumble`: embeds a pinned TinyGo toolchain (which statically links
  LLVM), so it compiles `go_source` into BPF bytecode at apply time. The binary
  is roughly 150 MB.

According to all known laws of aviation, a bumblebee is too heavy and its wings
too small to fly. It flies anyway. `terrahive-bumble` is 150 MB of compiler that
has no business being inside a Terraform provider, and it flies anyway. That is
the whole joke, and the joke has to work.

## Install

Both flavors publish to the Terraform Registry under `maxgio92/terrahive`. The
resources use the `ebpf_` prefix, so set a local provider name:

```terraform
terraform {
  required_providers {
    ebpf = {
      source = "maxgio92/terrahive"
    }
  }
}
```

Pick the flavor by version constraint or by building from source:

```shell
# Lean flavor.
make build

# Bumble flavor. Fetches the pinned TinyGo release first (needs network).
make build-bumble
```

## Quickstart

You need root or CAP_BPF and a bpffs mount at `/sys/fs/bpf`:

```shell
sudo mount -t bpf bpf /sys/fs/bpf
```

Load a precompiled program and attach it to a kernel symbol:

```terraform
provider "ebpf" {}

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

```shell
sudo terraform apply
```

The probe keeps firing after Terraform exits, because the link is pinned.
`terraform destroy` unpins the link and unloads the program. See the
[examples](examples/) directory for hello-kprobe, xdp-drop, and go-probe.

## Resources

- `ebpf_program`: loads a BPF program from an object file, C source, or Go source.
- `ebpf_map`: creates and pins a BPF map.
- `ebpf_map_entry`: manages one key/value pair in a pinned map.
- `ebpf_kprobe`: attaches to kprobe, kretprobe, uprobe, uretprobe, or usdt.
- `ebpf_tracepoint`: attaches to a tracepoint, raw tracepoint, or perf event.
- `ebpf_tracing`: attaches a BTF tracing program (fentry, fexit, fmod_ret, lsm, iter).
- `ebpf_xdp`: attaches an XDP program to a network interface.
- `ebpf_tcx`: attaches a tc program via tcx (kernel 6.6).
- `ebpf_cgroup`: attaches a program to a cgroup.
- `ebpf_netfilter`: attaches a netfilter program to a hook (kernel 6.4).
- `ebpf_struct_ops`: registers a struct_ops map.

Per-resource reference lives under [docs/resources/](docs/resources/).

## Caveats

Read these before you rely on terrahive:

- Local machine only. The state file and the target kernel share fate. Reinstall
  the OS and your state describes a kernel that no longer exists. There is no
  remote state story that makes sense here.
- Root or CAP_BPF. Loading BPF programs needs it, so `terraform apply` runs with
  kernel-level privileges. Every eBPF tool makes the same demand.
- Kernel version matters. Broad `bpf_link` coverage needs 5.15 or newer. tcx
  needs 6.6, netfilter needs 6.4. Available program and attach types change with
  the kernel.
- Program updates replace, they do not mutate. A loaded program is immutable, so
  a change destroys and recreates. Between detach and reattach the probe is off,
  and events in that window are not observed.
- The verifier runs at apply, not plan. A plan can validate and apply can still
  fail with a verifier rejection. The full verifier log surfaces in the apply
  error.
- `c_source` needs the system clang on PATH. `go_source` needs the bumble flavor,
  and TinyGo BPF output is experimental and often verifier-hostile.

If you want fleet-wide declarative BPF for real, use
[bpfman](https://bpfman.io). Terrahive is a well-built ship in a bottle: the
objection is not that it fails, but that it exists.
