# Design

## Context

The kernel exposes four first-class BPF object kinds: programs, maps, links, and BTF. Each has an fd, a global ID, and can be pinned to bpffs. Terraform providers implement CRUD against an API; here the API is the `bpf()` syscall via cilium/ebpf.

## Goals / Non-Goals

Goals:

- Manage programs, maps, and links declaratively with real drift detection.
- Support every loadable `BPF_PROG_TYPE_*` and every link-backed attach type.
- Keep the lean flavor free of compiler dependencies.

Non-Goals:

- Remote host management. The provider targets the machine Terraform runs on.
- Socket-fd attachments (`socket_filter`, `sk_msg`, `sk_skb`, `sk_reuseport`). No persistent kernel object exists for Terraform to own.
- A standalone BTF resource. BTF loads implicitly with the program.
- Production use.

## Decisions

### One program resource, three sources

`ebpf_program` accepts exactly one of `object_file`, `c_source`, `go_source`. Precedent: `aws_lambda_function` accepts local file, S3 object, or container image in one resource. `ExactlyOneOf` plan validators enforce exclusivity. All three converge on the same internal load-and-pin path.

### Pin path as resource ID

Every object is pinned under `<pin_dir>/<resource-address>`. Read resolves the pin, fetches the kernel object info, and diffs it against state. Delete unpins, which drops the last reference and unloads. Import takes a pin path.

### Attachment resources grouped by link family

Attach APIs differ per hook, but collapse into eight link families. Each family is one resource. All are `bpf_link` backed, so attachments survive Terraform exiting and are individually pinnable, readable, and deletable.

### Program updates are replace

A loaded program is immutable in the kernel. Any change to source or type forces replacement. Attachment resources reference programs by pin path, so replacement cascades correctly through plan.

### Embedded toolchain via embed.FS (bumble flavor only)

The bumble flavor embeds a pinned TinyGo release (which statically links LLVM), extracts it to a cache directory on first use, and compiles `go_source` at apply. This mirrors the BCC runtime-compilation approach. `c_source` shells out to system clang in both flavors. Build tags select the flavor; the lean binary returns a clear error if `go_source` is used.

## Risks / Trade-offs

- Verifier rejections surface at apply, not plan. Mitigation: clear diagnostics that include the verifier log.
- TinyGo eBPF output is experimental and often verifier-hostile. Mitigation: document it as the showcase path, not the recommended one.
- The bumble binary is roughly 150 MB. Accepted; it is the joke.
- Kernel version skew changes available program and attach types. Mitigation: probe feature availability at plan time and fail with actionable errors.

## Open Questions

- Should `ebpf_map_entry` support binary keys and values via base64, or structured encoding via BTF? Start with base64, revisit.
- Minimum supported kernel: 5.15 proposed; tcx requires 6.6.
