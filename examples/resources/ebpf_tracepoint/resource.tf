resource "ebpf_tracepoint" "sched" {
  name    = "sched-switch"
  program = ebpf_program.trace.id
  kind    = "tracepoint"
  group   = "sched"
  event   = "sched_switch"
}
