# Toolchain Flavors

## ADDED Requirements

### Requirement: Two release flavors

The project SHALL release two provider binaries from one codebase, selected by build tags: `terrahive` (lean) and `terrahive-bumble` (embedded TinyGo/LLVM toolchain).

#### Scenario: Lean flavor rejects Go source

- WHEN the lean binary plans an `ebpf_program` with `go_source`
- THEN plan fails with a diagnostic pointing to the bumble flavor

#### Scenario: Bumble flavor compiles Go source

- WHEN the bumble binary applies an `ebpf_program` with `go_source`
- THEN TinyGo compiles the source to BPF bytecode and the program loads

### Requirement: Embedded toolchain extraction

The bumble flavor SHALL embed a pinned TinyGo release via embed.FS and extract it to a local cache directory on first use.

#### Scenario: First compile

- WHEN `go_source` is compiled for the first time on a host
- THEN the toolchain is extracted to the cache and reused on later applies

#### Scenario: Deterministic toolchain

- WHEN the same provider version compiles the same source twice
- THEN the resulting program tag is identical

### Requirement: C source compilation

Both flavors SHALL compile `c_source` with the system clang at apply time.

#### Scenario: clang missing

- WHEN `c_source` is used and clang is not on PATH
- THEN apply fails with a diagnostic naming the missing dependency
