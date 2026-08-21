//go:build bumble

package tinygo

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Version is the pinned TinyGo release the bumble flavor ships.
const Version = "0.38.0"

// The bumble flavor embeds a pinned TinyGo release here. Only
// toolchain/README.md is checked into git; a release build populates
// toolchain/tinygo/ first (`make fetch-tinygo`, wired as a goreleaser
// pre-hook), so the go:embed directive picks up the full 150MB tree
// while dev builds with -tags bumble still compile. go:embed ignores
// .gitignore, so the fetched tree is embedded without being committed.
//
//go:embed all:toolchain
var embedded embed.FS

// Embedded returns the toolchain shipped in this binary, caching the
// extraction under the user cache directory keyed by Version. It fails
// with build instructions when the binary was built without a fetched
// release (a dev build).
func Embedded() (*Toolchain, error) {
	sub, err := fs.Sub(embedded, "toolchain/tinygo")
	if err != nil {
		return nil, fmt.Errorf("resolving embedded toolchain: %w", err)
	}
	if _, err := fs.Stat(sub, binaryRelPath); err != nil {
		return nil, errors.New("this bumble binary was built without the TinyGo release embedded " +
			"(run `make fetch-tinygo` before `go build -tags bumble`), " +
			"or set TERRAHIVE_TINYGO to a tinygo binary on this host")
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("resolving cache directory: %w", err)
	}
	return New(sub, filepath.Join(cache, "terrahive", "tinygo", Version)), nil
}
