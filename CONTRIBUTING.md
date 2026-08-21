# Contributing to Terrahive

Thanks for your interest. This guide covers how to build, test, and send
changes.

## Before you start

Terrahive loads real BPF programs into the running kernel. Acceptance tests
need root or `CAP_BPF` and a `bpffs` mount. Use a machine you can rebuild.
Read [SECURITY.md](SECURITY.md) for the risk model.

## Prerequisites

- Go (see the version in `go.mod`).
- `make`.
- `golangci-lint` for linting.
- Linux with a `bpffs` mount at `/sys/fs/bpf` for acceptance tests.
- `curl` for fetching the pinned TinyGo release (the bumble flavor).

## Flavors

Two binaries ship from one codebase:

- lean: the default build.
- bumble: built with `-tags bumble`. It embeds a pinned TinyGo toolchain that
  `make fetch-tinygo` downloads into a git-ignored `go:embed` tree.

## Build

```sh
make build          # lean build
make build-bumble   # bumble build (fetches TinyGo first)
```

## Test

```sh
make test           # unit tests, lean and bumble
make cover          # unit tests with race detector and coverage profile
make testacc        # acceptance tests (needs root or CAP_BPF and bpffs)
```

The acceptance tests set `TF_ACC=1` and load real BPF programs. Run them as
root or with the right capabilities:

```sh
sudo mount -t bpf bpf /sys/fs/bpf   # once, if not already mounted
make testacc
```

Other targets used in CI:

```sh
make validate-examples   # validate the Terraform examples
make e2e                 # end-to-end tests
make fuzz                # fuzz tests
```

## Lint

```sh
make lint           # golangci-lint, lean and bumble build tags
```

Run `gofmt -l .` and fix any listed files before you push.

## Docs

Resource docs are generated. Do not hand-edit files under `docs/`.

```sh
make docs
```

Edit the templates under `templates/` and the examples under `examples/`, then
regenerate.

## Pull requests

- Keep the change small and focused. One concern per PR.
- Use Conventional Commits for commit messages and the PR title, for example
  `feat: ...`, `fix: ...`, `chore(deps): ...`. The release changelog groups
  entries by these types.
- Add or update tests for behavior you change.
- Run `make lint`, `make test`, and (when your change touches BPF behavior)
  `make testacc` before you open the PR.
- CI runs fmt, vet, build, unit tests with coverage, example validation, the
  bumble build, lint, govulncheck, and CodeQL. Keep all checks green.
- Update docs when you change resource schemas or behavior.
