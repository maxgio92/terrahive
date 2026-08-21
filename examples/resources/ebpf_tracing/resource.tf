resource "ebpf_tracing" "openat_entry" {
  name    = "openat-fentry"
  program = ebpf_program.fentry.id
  kind    = "fentry"
}
