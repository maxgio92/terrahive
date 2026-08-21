resource "ebpf_map_entry" "flag" {
  map = ebpf_map.flags.id

  # Key and value are base64 encoded, one entry per key.
  # key   decodes to the 4 bytes 01 00 00 00.
  # value decodes to the 8 bytes 01 00 00 00 00 00 00 00.
  key   = "AQAAAA=="
  value = "AQAAAAAAAAA="
}
