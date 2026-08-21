resource "ebpf_tcx" "eth0_ingress" {
  name      = "tcx-eth0-ingress"
  program   = ebpf_program.classifier.id
  interface = "eth0"
  direction = "ingress"
}
