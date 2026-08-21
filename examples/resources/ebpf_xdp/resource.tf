resource "ebpf_xdp" "lo" {
  name      = "xdp-drop-lo"
  program   = ebpf_program.drop.id
  interface = "lo"
  mode      = "generic"
}
