package provider

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestParseMapType(t *testing.T) {
	tests := []struct {
		in   string
		want ebpf.MapType
	}{
		{"hash", ebpf.Hash},
		{"Hash", ebpf.Hash},
		{"array", ebpf.Array},
		{"lru_hash", ebpf.LRUHash},
		{"lruhash", ebpf.LRUHash},
		{"LRUHash", ebpf.LRUHash},
		{"ringbuf", ebpf.RingBuf},
		{"ring_buf", ebpf.RingBuf},
		{"percpu_hash", ebpf.PerCPUHash},
		{"lpm_trie", ebpf.LPMTrie},
	}
	for _, tt := range tests {
		got, err := parseMapType(tt.in)
		if err != nil {
			t.Errorf("parseMapType(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseMapType(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseMapTypeUnknown(t *testing.T) {
	for _, in := range []string{"", "nope", "unspecified_map"} {
		if _, err := parseMapType(in); err == nil {
			t.Errorf("parseMapType(%q): expected error", in)
		}
	}
}

func TestParseMapTypeRoundTrip(t *testing.T) {
	for mt := ebpf.Hash; mt <= ebpf.Arena; mt++ {
		got, err := parseMapType(mapTypeString(mt))
		if err != nil {
			t.Errorf("round trip %v: %v", mt, err)
			continue
		}
		// Compare rendered names: CGroupStorage and CgroupStorage are
		// distinct kernel types whose names collide case-insensitively.
		if mapTypeString(got) != mapTypeString(mt) {
			t.Errorf("round trip %v = %v", mt, got)
		}
	}
}

func TestKernelObjectName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"counters", "counters"},
		{"a-very-long-map-name", "averylongmapnam"},
		{"with-dash.and_underscore", "withdash.and_un"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := kernelObjectName(tt.in); got != tt.want {
			t.Errorf("kernelObjectName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMapEntryID(t *testing.T) {
	id := mapEntryID("/sys/fs/bpf/terrahive/map/counters", "AAAAAA==")
	pin, key, err := splitMapEntryID(id)
	if err != nil {
		t.Fatal(err)
	}
	if pin != "/sys/fs/bpf/terrahive/map/counters" || key != "AAAAAA==" {
		t.Fatalf("splitMapEntryID(%q) = %q, %q", id, pin, key)
	}
}

func TestSplitMapEntryIDColonInPath(t *testing.T) {
	pin, key, err := splitMapEntryID("/sys/fs/bpf/odd:dir/m:AQ==")
	if err != nil {
		t.Fatal(err)
	}
	if pin != "/sys/fs/bpf/odd:dir/m" || key != "AQ==" {
		t.Fatalf("got %q, %q", pin, key)
	}
}

func TestSplitMapEntryIDInvalid(t *testing.T) {
	for _, id := range []string{"", "no-colon", ":leading", "trailing:"} {
		if _, _, err := splitMapEntryID(id); err == nil {
			t.Errorf("splitMapEntryID(%q): expected error", id)
		}
	}
}
