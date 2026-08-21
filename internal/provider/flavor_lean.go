//go:build !bumble

package provider

import "errors"

// flavorName identifies the build-tag-selected toolchain flavor.
const flavorName = "lean"

const goSourceUnsupported = "go_source requires the terrahive-bumble flavor, which embeds the TinyGo toolchain. " +
	"This is the lean terrahive binary: use object_file or c_source, or switch to the bumble flavor"

// checkGoSourceSupported rejects go_source in the lean flavor at
// validate time, pointing at the bumble flavor.
func checkGoSourceSupported() error {
	return errors.New(goSourceUnsupported)
}

// compileGoSource is unreachable behind checkGoSourceSupported, but
// keeps Create flavor-agnostic.
func compileGoSource(string) ([]byte, error) {
	return nil, errors.New(goSourceUnsupported)
}
