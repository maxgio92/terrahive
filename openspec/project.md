# Project Context

## Purpose

Terrahive is a Terraform provider that manages eBPF objects as infrastructure as code. It loads BPF programs into the Linux kernel, creates maps, and attaches programs to hooks, all through `terraform apply`. It is a meme project built to be technically sound.

## Tech Stack

- Go (latest stable)
- terraform-plugin-framework
- github.com/cilium/ebpf (pure Go, no CGo)
- bpffs pinning for object persistence
- TinyGo (embedded toolchain, `bumble` flavor only)

## Project Conventions

### Code Style

Standard Go style, `gofmt` and `golangci-lint` clean. Resource names use the `ebpf_` prefix. One package per capability under `internal/`.

### Architecture

The provider maps Terraform CRUD onto the four kernel BPF object kinds:

- Program: `ebpf_program` resource, one resource for all `BPF_PROG_TYPE_*` values.
- Map: `ebpf_map` and `ebpf_map_entry` resources.
- Link: one attachment resource per attach mechanism (kprobe, tracepoint, tracing, xdp, tcx, cgroup, netfilter, struct_ops).
- BTF: implicit, loaded with the program, never a standalone resource.

Every created object is pinned under a configurable bpffs directory. The pin path is the Terraform resource ID. Pinning is what lets objects outlive the Terraform process.

### Testing

Unit tests for schema and plan logic. Acceptance tests (`TF_ACC=1`) require root and a recent kernel; they run in a privileged CI job.

### Git Workflow

Conventional Commits. Main branch is `main`. PRs required.

## Domain Context

BPF programs die with the process that loaded them unless pinned to bpffs. Attachments are backed by kernel `bpf_link` objects, which are pinnable. Socket-fd attach types (`socket_filter`, `sk_msg`, `sk_skb`, `sk_reuseport`) bind to a live socket owned by a process, so Terraform can load and pin those programs but cannot own their attachment.

## Important Constraints

- The provider manages the local machine only. It needs root or CAP_BPF.
- Two release flavors: `terrahive` (lean, object files only) and `terrahive-bumble` (embeds the TinyGo/LLVM toolchain, compiles Go source at apply).
- Program updates are replace, not in-place mutate.

## External Dependencies

- Terraform Registry publication under `maxgio92/terrahive`.
- Kernel >= 5.15 for broad bpf_link coverage (tcx needs >= 6.6).
