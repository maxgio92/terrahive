package provider

import (
	"encoding/base64"
	"testing"
)

// FuzzMapEntryID drives the ebpf_map_entry ID parse path: an imported ID
// is untrusted, split at the last colon, then base64-decoded as the map
// key. Read and ImportState feed arbitrary strings here, so a malformed
// ID must produce an error, never a panic.
func FuzzMapEntryID(f *testing.F) {
	f.Add("/sys/fs/bpf/terrahive/map/counters:AAAAAA==")
	f.Add("/sys/fs/bpf/odd:dir/m:AQ==")
	f.Add("no-colon")
	f.Add("")
	f.Add(":leading")
	f.Add("trailing:")

	f.Fuzz(func(t *testing.T, id string) {
		pinPath, keyB64, err := splitMapEntryID(id)
		if err != nil {
			return
		}
		if pinPath == "" {
			t.Fatalf("splitMapEntryID(%q) returned an empty pin path with no error", id)
		}
		if _, err := base64.StdEncoding.DecodeString(keyB64); err != nil {
			return
		}
	})
}

// FuzzMapEntryValueDecode covers the standard base64 decode applied to
// the key and value attributes before they reach the kernel map. The
// attribute values come from user config, so any input must decode or
// error without panicking.
func FuzzMapEntryValueDecode(f *testing.F) {
	f.Add("AAAAAA==")
	f.Add("AQ==")
	f.Add("not base64!!")
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = base64.StdEncoding.DecodeString(s)
	})
}
