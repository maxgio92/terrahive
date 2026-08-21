resource "ebpf_netfilter" "input" {
  name     = "nf-input"
  program  = ebpf_program.filter.id
  family   = "ipv4"
  hook     = "input"
  priority = 0
}
