resource "ebpf_map" "flags" {
  name        = "flags"
  type        = "hash"
  key_size    = 4
  value_size  = 8
  max_entries = 1024
}
