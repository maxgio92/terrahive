resource "ebpf_program" "hello" {
  name        = "hello"
  object_file = "${path.module}/hello.bpf.o"
}

resource "ebpf_program" "drop" {
  name     = "xdp_drop"
  c_source = file("${path.module}/xdp_drop.c")
}
