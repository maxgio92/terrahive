# terrahive

Write eBPF probes as Terraform code. Run `terraform apply`. They load into the
running Linux kernel.

Terrahive is a Terraform provider that treats the kernel as infrastructure.
You declare a BPF program, a map, or a probe as an HCL resource. `apply` loads
and attaches it. `plan` reads the kernel back and shows real drift. `destroy`
unloads it. The workflow you already use for cloud servers.

```hcl
resource "ebpf_program" "trace_open" {
  object_file = "trace_open.bpf.o"
}

resource "ebpf_kprobe" "trace_open" {
  program = ebpf_program.trace_open.id
  symbol  = "do_sys_openat2"
}
```

That is it. `apply` loads the program, attaches the kprobe, and pins both so
they survive after Terraform exits. `destroy` detaches and unloads them. You can
declare the program from a precompiled object file (above), from inline C, or
from inline Go: see [Program sources](#program-sources).

It is a meme project, built to be technically sound. The name is the frame: a
hive holds bees, and eBPF is the swarm, many small programs living in one
kernel, each doing one job. Terrahive is the beekeeper. It puts the bees in the
hive, tells them where to work, and pulls them out when you are done. bpffs is
the honeycomb: every program, map, and link is pinned to a cell so it stays put
after the keeper walks away.

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

## Capabilities

Terrahive manages the full BPF object lifecycle through Terraform:

- Load and pin BPF programs. One `ebpf_program` resource loads a program from
  three input modes: a precompiled object file, inline C, or inline Go. See
  [Program sources](#program-sources) below.
- Create and pin BPF maps with `ebpf_map`, and manage individual entries with
  `ebpf_map_entry`.
- Attach programs to kernel hooks with eight attachment resources: `ebpf_kprobe`,
  `ebpf_tracepoint`, `ebpf_tracing`, `ebpf_xdp`, `ebpf_tcx`, `ebpf_cgroup`,
  `ebpf_netfilter`, and `ebpf_struct_ops`.
- Read real kernel state on refresh, so a plan reports actual drift.
- Pin every object to bpffs, so links keep firing after Terraform exits.

Every resource maps to CRUD on the `bpf()` syscall. Create loads and pins, Read
resolves the pin, Delete unpins and unloads. See
[docs/ANTIPATTERNS.md](docs/ANTIPATTERNS.md) for the rules this breaks and why.

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

The two flavors are separate build artifacts, not one release chosen by a
version constraint. Build the one you want from source:

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

## Program sources

The `ebpf_program` resource takes exactly one source. The three source
attributes are mutually exclusive: set one and only one. The program type comes
from the ELF section name, so you rarely need to set `type`.

### 1. object_file

Point at a precompiled CO-RE object. This is the recommended path. The lean
`terrahive` binary is enough. No
compiler runs at apply. Build the object yourself first:

```shell
clang -O2 -g -target bpf -c hello.bpf.c -o hello.bpf.o
```

The object must contain exactly one program. Then load and attach it:

```terraform
terraform {
  required_providers {
    ebpf = {
      source = "maxgio92/terrahive"
    }
  }
}

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

### 2. c_source

Pass BPF C inline. Terrahive compiles it with the system clang at apply time,
so clang must be on PATH. Both flavors support this mode. The `SEC()` name sets
the program type:

```terraform
terraform {
  required_providers {
    ebpf = {
      source = "maxgio92/terrahive"
    }
  }
}

provider "ebpf" {}

resource "ebpf_program" "openat" {
  name = "trace_openat"

  c_source = <<-EOT
    #include <linux/bpf.h>
    #include <bpf/bpf_helpers.h>

    SEC("kprobe/do_sys_openat2")
    int trace_openat(struct pt_regs *ctx) {
      return 0;
    }

    char _license[] SEC("license") = "GPL";
  EOT
}

resource "ebpf_kprobe" "openat" {
  name    = "c-openat"
  program = ebpf_program.openat.id
  symbol  = "do_sys_openat2"
}
```

### 3. go_source

Pass BPF Go inline. This mode needs the bumble flavor (`terrahive-bumble`),
which embeds the TinyGo toolchain and compiles Go into BPF bytecode at apply
time. The lean `terrahive` binary rejects `go_source` at plan time with a clear
error that points you to bumble. TinyGo BPF output is experimental and often
upsets the verifier, so treat this path as the showcase, not the safe default.

```terraform
terraform {
  required_providers {
    ebpf = {
      source = "maxgio92/terrahive"
    }
  }
}

provider "ebpf" {}

resource "ebpf_program" "counter" {
  name = "go_counter"

  # The body below is illustrative, not a working TinyGo BPF program.
  # A real probe declares its section and helpers the way TinyGo's BPF
  # target expects; the point here is the resource shape, not the source.
  go_source = <<-EOT
    package main

    func probe() int {
      return 0
    }

    func main() {}
  EOT
}

resource "ebpf_kprobe" "counter" {
  name    = "go-counter-openat"
  program = ebpf_program.counter.id
  symbol  = "do_sys_openat2"
}
```

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
