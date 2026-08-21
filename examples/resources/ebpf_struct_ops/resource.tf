resource "ebpf_struct_ops" "cc" {
  name = "my-congestion-control"
  map  = ebpf_map.cc_ops.id
}
