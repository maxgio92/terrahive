terraform {
  required_providers {
    ebpf = {
      source = "maxgio92/terrahive"
    }
  }
}

# Works with either flavor. This example loads a precompiled object file,
# so the lean terrahive binary is enough.
provider "ebpf" {}

# Load a precompiled BPF object. Build it yourself first, for example:
#   clang -O2 -g -target bpf -c hello.bpf.c -o hello.bpf.o
# The object must contain exactly one program. The program type comes
# from the ELF section name (here a kprobe section).
resource "ebpf_program" "hello" {
  name        = "hello"
  object_file = "${path.module}/hello.bpf.o"
}

# Attach the loaded program to the do_sys_openat2 kernel symbol. The link
# is pinned, so the probe keeps firing after terraform exits. Destroy the
# kprobe to detach without unloading the program.
resource "ebpf_kprobe" "openat" {
  name    = "hello-openat"
  program = ebpf_program.hello.id
  symbol  = "do_sys_openat2"
}
