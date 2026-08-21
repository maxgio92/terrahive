# Program Attachment

## ADDED Requirements

### Requirement: Link-backed attachment resources

The provider SHALL expose one attachment resource per link family, each backed by a kernel `bpf_link` pinned to bpffs: `ebpf_kprobe`, `ebpf_tracepoint`, `ebpf_tracing`, `ebpf_xdp`, `ebpf_tcx`, `ebpf_cgroup`, `ebpf_netfilter`, `ebpf_struct_ops`.

#### Scenario: Kprobe attach

- WHEN apply creates an `ebpf_kprobe` with `symbol = "do_sys_openat2"` referencing a loaded program
- THEN a pinned kprobe link exists and the program fires on the symbol

#### Scenario: XDP attach

- WHEN apply creates an `ebpf_xdp` with an interface and mode
- THEN a pinned xdp link exists on that interface

#### Scenario: Attachment survives Terraform exit

- WHEN apply completes and Terraform exits
- THEN the link remains active because it is pinned

### Requirement: Detach on destroy

Destroying an attachment resource SHALL unpin and close its link, detaching the program without unloading it.

#### Scenario: Destroy attachment only

- WHEN an `ebpf_kprobe` is destroyed but its `ebpf_program` is not
- THEN the probe no longer fires and the program remains loaded and pinned

### Requirement: Attachment drift detection

Read SHALL resolve the pinned link and verify its target and attached program ID against state.

#### Scenario: Link removed out-of-band

- WHEN the pinned link is deleted outside Terraform
- THEN refresh marks the attachment for recreation

### Requirement: Program replacement cascades

Attachment resources SHALL reference programs by pin path so that program replacement forces attachment recreation.

#### Scenario: Program source changed

- WHEN an `ebpf_program` is replaced
- THEN plan shows dependent attachments as requiring replacement

### Requirement: Socket-fd attach types excluded

The provider SHALL NOT offer attachment resources for `socket_filter`, `sk_msg`, `sk_skb`, or `sk_reuseport`, because those attach to a live socket owned by a process. Loading and pinning such programs SHALL remain supported.

#### Scenario: Socket filter program

- WHEN an `ebpf_program` loads a `socket_filter` program
- THEN the load succeeds, the pin exists, and no terrahive attachment resource targets it
