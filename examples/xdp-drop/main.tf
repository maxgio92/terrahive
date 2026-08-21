terraform {
  required_providers {
    ebpf = {
      source = "maxgio92/terrahive"
    }
  }
}

# Both flavors compile c_source with the system clang at apply time.
# Make sure clang is on PATH before you apply.
provider "ebpf" {}

# Compile a small XDP program from C. The SEC("xdp") section name tells
# terrahive to load it as an XDP program.
resource "ebpf_program" "drop" {
  name = "xdp_drop"

  c_source = <<-EOT
    #include <linux/bpf.h>
    #include <bpf/bpf_helpers.h>

    SEC("xdp")
    int xdp_drop_all(struct xdp_md *ctx) {
      return XDP_DROP;
    }

    char _license[] SEC("license") = "GPL";
  EOT
}

# Attach the program to the loopback interface in generic mode. Generic
# mode runs in the network stack and works on any interface, including lo.
# It drops every packet on lo, so only run this where that is safe.
resource "ebpf_xdp" "lo" {
  name      = "xdp-drop-lo"
  program   = ebpf_program.drop.id
  interface = "lo"
  mode      = "generic"
}
