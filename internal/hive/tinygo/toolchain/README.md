# Embedded TinyGo toolchain

This directory is the go:embed root for the bumble flavor
(`embed_bumble.go`, build tag `bumble`).

Only this README is committed. A real bumble build first runs
`make fetch-tinygo`, which downloads the pinned TinyGo release and
extracts it to `toolchain/tinygo/` (git-ignored, roughly 150MB), so
`go build -tags bumble` embeds the full toolchain. Dev builds with the
bumble tag work without the fetch; the provider then reports how to get
a toolchain (fetch it, or set `TERRAHIVE_TINYGO`).
