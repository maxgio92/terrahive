package hive

import (
	"debug/elf"
	"fmt"
)

// stapsdtNoteType is the ELF note type of SystemTap SDT probe descriptors.
const stapsdtNoteType = 3

// USDT locates a statically defined tracepoint inside an executable.
type USDT struct {
	// Address is the probe location as an offset into the executable
	// file, ready for a uprobe attach.
	Address uint64
	// SemaphoreOffset is the file offset of the probe semaphore, zero
	// when the probe has none.
	SemaphoreOffset uint64
}

// ResolveUSDT parses the .note.stapsdt section of the executable at
// path and returns the location of the probe identified by provider
// and name. terrahive resolves the note itself and attaches a plain
// uprobe at the resulting offset.
func ResolveUSDT(path, provider, name string) (*USDT, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	sec := f.Section(".note.stapsdt")
	if sec == nil {
		return nil, fmt.Errorf("%s has no .note.stapsdt section", path)
	}
	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("reading .note.stapsdt of %s: %w", path, err)
	}

	// The recorded base lets us undo prelink-style relocation: the
	// runtime address of .stapsdt.base minus the recorded base is the
	// displacement to apply to every recorded address.
	var actualBase uint64
	if base := f.Section(".stapsdt.base"); base != nil {
		actualBase = base.Addr
	}

	bo := f.ByteOrder
	align4 := func(n uint32) uint32 { return (n + 3) &^ 3 }
	for len(data) >= 12 {
		namesz := bo.Uint32(data[0:4])
		descsz := bo.Uint32(data[4:8])
		typ := bo.Uint32(data[8:12])
		data = data[12:]
		if uint32(len(data)) < align4(namesz)+align4(descsz) {
			return nil, fmt.Errorf("%s: truncated note in .note.stapsdt", path)
		}
		noteName := string(data[:namesz])
		desc := data[align4(namesz) : align4(namesz)+descsz]
		data = data[align4(namesz)+align4(descsz):]

		if typ != stapsdtNoteType || noteName != "stapsdt\x00" || len(desc) < 24 {
			continue
		}
		location := bo.Uint64(desc[0:8])
		recordedBase := bo.Uint64(desc[8:16])
		semaphore := bo.Uint64(desc[16:24])
		noteProvider, rest, ok := cutNul(desc[24:])
		if !ok {
			continue
		}
		noteProbe, _, ok := cutNul(rest)
		if !ok || noteProvider != provider || noteProbe != name {
			continue
		}

		if actualBase != 0 && recordedBase != 0 {
			delta := actualBase - recordedBase
			location += delta
			if semaphore != 0 {
				semaphore += delta
			}
		}
		usdt := &USDT{}
		usdt.Address, err = fileOffset(f, location)
		if err != nil {
			return nil, fmt.Errorf("probe %s:%s in %s: %w", provider, name, path, err)
		}
		if semaphore != 0 {
			usdt.SemaphoreOffset, err = fileOffset(f, semaphore)
			if err != nil {
				return nil, fmt.Errorf("semaphore of %s:%s in %s: %w", provider, name, path, err)
			}
		}
		return usdt, nil
	}
	return nil, fmt.Errorf("usdt probe %s:%s not found in %s", provider, name, path)
}

// fileOffset translates a virtual address into an offset within the
// executable file, which is what the kernel uprobe API expects.
func fileOffset(f *elf.File, vaddr uint64) (uint64, error) {
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && vaddr >= p.Vaddr && vaddr < p.Vaddr+p.Filesz {
			return vaddr - p.Vaddr + p.Off, nil
		}
	}
	return 0, fmt.Errorf("address %#x is not in any PT_LOAD segment", vaddr)
}

func cutNul(b []byte) (string, []byte, bool) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return "", nil, false
}
