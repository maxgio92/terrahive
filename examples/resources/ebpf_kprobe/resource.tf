resource "ebpf_kprobe" "openat" {
  name    = "hello-openat"
  program = ebpf_program.hello.id
  symbol  = "do_sys_openat2"
}

resource "ebpf_kprobe" "malloc" {
  name    = "malloc-probe"
  program = ebpf_program.trace.id
  kind    = "uprobe"
  path    = "/lib/x86_64-linux-gnu/libc.so.6"
  symbol  = "malloc"
}
