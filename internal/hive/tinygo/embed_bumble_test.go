//go:build bumble

package tinygo

import (
	"strings"
	"testing"
)

func TestEmbeddedWithoutFetchedRelease(t *testing.T) {
	// The committed tree holds only toolchain/README.md; a dev build
	// must fail with instructions, not a bare fs error.
	_, err := Embedded()
	if err == nil {
		t.Skip("a fetched TinyGo release is present under toolchain/tinygo")
	}
	if !strings.Contains(err.Error(), "make fetch-tinygo") ||
		!strings.Contains(err.Error(), "TERRAHIVE_TINYGO") {
		t.Fatalf("error lacks build instructions: %v", err)
	}
}
