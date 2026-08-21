# Add Terrahive Provider

## Why

No Terraform provider manages eBPF objects (verified against the Terraform Registry and GitHub, August 2026). The closest prior art is bpfman, which proves the declarative BPF lifecycle idea with Kubernetes CRDs. Terraform's CRUD model fits the kernel BPF object model: programs, maps, and links all have create, read, and delete syscall paths, and bpffs pinning gives them a stable identity that survives the Terraform process.

## What Changes

- New Terraform provider `terrahive` built on terraform-plugin-framework and cilium/ebpf.
- New resource `ebpf_program`: loads any BPF program type from an object file, C source, or Go source (mutually exclusive attributes), and pins it.
- New resources `ebpf_map` and `ebpf_map_entry`: create and pin maps, manage individual key/value pairs with drift detection.
- New attachment resources, one per link family: `ebpf_kprobe`, `ebpf_tracepoint`, `ebpf_tracing`, `ebpf_xdp`, `ebpf_tcx`, `ebpf_cgroup`, `ebpf_netfilter`, `ebpf_struct_ops`.
- Two release flavors: lean `terrahive` and `terrahive-bumble` with an embedded TinyGo/LLVM toolchain for compiling Go source at apply.

## Impact

- Affected specs: `provider-runtime`, `program-loading`, `map-management`, `program-attachment`, `toolchain-flavors` (all new).
- Affected code: entire repository (new project).
- Runtime requirements: Linux, root or CAP_BPF, mounted bpffs.
