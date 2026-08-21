package hive

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzLoadELF feeds arbitrary bytes to the BPF object loader. Untrusted
// object files reach this path, so a malformed ELF must return an error,
// never panic. The seed is a real single-program kprobe object.
func FuzzLoadELF(f *testing.F) {
	// Seed the malformed-input cases first, so LoadELF still gets fuzzed
	// on runners without clang (the compiled seed just adds one more case).
	f.Add([]byte("not an ELF"))
	f.Add([]byte{})
	if obj, err := CompileC(kprobeSource); err == nil {
		f.Add(obj)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		spec, err := LoadELF(data)
		if err != nil {
			return
		}
		if spec == nil {
			t.Fatal("LoadELF returned a nil spec with no error")
		}
	})
}

// FuzzScanStapsdtNotes exercises the .note.stapsdt record decoder with
// arbitrary section bytes. The parser reads size fields from the input,
// so it must reject malformed notes with an error and never slice out of
// range. The seed is a minimal well-formed note.
func FuzzScanStapsdtNotes(f *testing.F) {
	f.Add(validStapsdtNote())
	f.Add([]byte{})
	f.Add(make([]byte, 12))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Panic-only target: a malformed note must error, not crash.
		for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			_, _ = scanStapsdtNotes(data, bo)
		}
	})
}

// validStapsdtNote builds one well-formed stapsdt note record so the
// fuzzer starts from input that reaches the descriptor-parsing branch.
func validStapsdtNote() []byte {
	bo := binary.LittleEndian
	name := []byte("stapsdt\x00")
	desc := make([]byte, 0, 32)
	desc = bo.AppendUint64(desc, 0x1000) // location
	desc = bo.AppendUint64(desc, 0x2000) // base
	desc = bo.AppendUint64(desc, 0)      // semaphore
	desc = append(desc, "terrahive\x00"...)
	desc = append(desc, "buzzed\x00"...)
	for len(desc)%4 != 0 {
		desc = append(desc, 0)
	}

	var buf bytes.Buffer
	_ = binary.Write(&buf, bo, uint32(len(name)))
	_ = binary.Write(&buf, bo, uint32(len(desc)))
	_ = binary.Write(&buf, bo, uint32(stapsdtNoteType))
	buf.Write(name)
	buf.Write(desc)
	return buf.Bytes()
}
