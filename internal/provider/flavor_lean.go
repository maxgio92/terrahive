//go:build !bumble

package provider

import "fmt"

// flavorName identifies the build-tag-selected toolchain flavor.
const flavorName = "lean"

// checkGoSourceSupported rejects go_source in the lean flavor at
// validate time, naming the running flavor and pointing at bumble.
func checkGoSourceSupported() error {
	return fmt.Errorf("go_source requires the terrahive-bumble flavor, which embeds the TinyGo toolchain; "+
		"this is the %s terrahive binary: use object_file or c_source, or switch to the bumble flavor", flavorName)
}

// compileGoSource is unreachable behind checkGoSourceSupported, but
// keeps Create flavor-agnostic.
func compileGoSource(string) ([]byte, error) {
	return nil, checkGoSourceSupported()
}
