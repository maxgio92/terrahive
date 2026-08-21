---
page_title: "ebpf_tracepoint Resource - terrahive"
description: |-
  Attaches a program to a tracepoint, raw tracepoint, or perf event.
---

# ebpf_tracepoint (Resource)

Attaches a program to a tracepoint, raw tracepoint, or perf event through a
pinned `bpf_link`. Any attribute change forces replacement.

## Example Usage

```terraform
resource "ebpf_tracepoint" "sched" {
  name    = "sched-switch"
  program = ebpf_program.trace.id
  kind    = "tracepoint"
  group   = "sched"
  event   = "sched_switch"
}
```

## Schema

### Required

- `name` (String) Pin name of the link under the pin directory. Forces replacement.
- `program` (String) bpffs pin path of the program to attach. Forces replacement.

### Optional

- `kind` (String) Hook flavor: tracepoint, raw_tracepoint, or perf_event. Defaults to tracepoint. Forces replacement.
- `group` (String) Tracepoint group (for example sched), required for tracepoint. Forces replacement.
- `event` (String) Tracepoint or raw tracepoint name, required for tracepoint and raw_tracepoint. Forces replacement.
- `sample_freq` (Number) CPU clock sampling frequency in Hz, required for perf_event. Forces replacement.
- `cpu` (Number) CPU to open the perf event on. Defaults to 0. Forces replacement.

### Read-Only

- `id` (String) bpffs pin path of the link.
- `link_id` (Number) Kernel ID of the bpf_link.
- `program_id` (Number) Kernel ID of the attached program.
