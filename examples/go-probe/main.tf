terraform {
  required_providers {
    ebpf = {
      source = "maxgio92/terrahive"
    }
  }
}

# go_source needs the bumble flavor (terrahive-bumble). Only bumble ships
# the embedded TinyGo toolchain that compiles Go into BPF bytecode at
# apply time. The lean terrahive binary rejects go_source with a clear
# error at plan time. TinyGo BPF output is experimental and often upsets
# the verifier, so treat this path as the showcase, not the safe default.
provider "ebpf" {}

# Compile a BPF program from Go with the embedded TinyGo toolchain.
resource "ebpf_program" "counter" {
  name = "go_counter"

  go_source = <<-EOT
    package main

    //go:generate echo build with the bumble flavor
    //export do_sys_openat2
    func probe() int {
      return 0
    }

    func main() {}
  EOT
}

# Attach the Go-built program to a kernel symbol.
resource "ebpf_kprobe" "counter" {
  name    = "go-counter-openat"
  program = ebpf_program.counter.id
  symbol  = "do_sys_openat2"
}
