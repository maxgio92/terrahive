//go:build bumble

package provider

import (
	"os"

	"github.com/maxgio92/terrahive/internal/hive/tinygo"
)

// flavorName identifies the build-tag-selected toolchain flavor.
const flavorName = "bumble"

// checkGoSourceSupported accepts go_source in the bumble flavor.
func checkGoSourceSupported() error {
	return nil
}

// compileGoSource compiles BPF Go source with TinyGo at apply time.
// TERRAHIVE_TINYGO overrides the embedded toolchain with a host
// binary, which is also how dev builds without a fetched release and
// the acceptance tests get a real compiler.
func compileGoSource(source string) ([]byte, error) {
	if bin := os.Getenv("TERRAHIVE_TINYGO"); bin != "" {
		return tinygo.CompileWith(bin, source)
	}
	tc, err := tinygo.Embedded()
	if err != nil {
		return nil, err
	}
	return tc.Compile(source)
}
