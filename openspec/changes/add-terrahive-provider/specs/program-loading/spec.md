# Program Loading

## ADDED Requirements

### Requirement: Universal program type support

The `ebpf_program` resource SHALL load any program type the running kernel accepts, inferring the type from the ELF section name, with an optional `type` attribute acting as an assertion.

#### Scenario: Type inferred from section

- WHEN an object file contains a program in section `kprobe/do_sys_openat2`
- THEN the program loads as `BPF_PROG_TYPE_KPROBE` without an explicit `type`

#### Scenario: Type assertion mismatch

- WHEN `type = "xdp"` is set but the section implies a kprobe program
- THEN plan fails with a diagnostic naming both types

#### Scenario: Unsupported type on running kernel

- WHEN the kernel rejects the program type
- THEN apply fails with a diagnostic that includes the kernel error

### Requirement: Exactly one program source

The `ebpf_program` resource SHALL accept exactly one of `object_file`, `c_source`, or `go_source`.

#### Scenario: No source given

- WHEN none of the three source attributes is set
- THEN plan fails with an `ExactlyOneOf` validation error

#### Scenario: Two sources given

- WHEN both `object_file` and `c_source` are set
- THEN plan fails with an `ExactlyOneOf` validation error

### Requirement: Load and pin

Creating an `ebpf_program` SHALL load the program via the bpf syscall and pin it under the provider pin directory.

#### Scenario: Successful load

- WHEN apply creates an `ebpf_program`
- THEN the program appears in `bpftool prog list` and its pin exists

#### Scenario: Verifier rejection

- WHEN the kernel verifier rejects the program
- THEN apply fails and the diagnostic includes the verifier log

### Requirement: Immutable programs replace

Any change to a program's source or type SHALL force resource replacement.

#### Scenario: Source change

- WHEN the object file content hash changes
- THEN plan shows the program as requiring replacement

### Requirement: Drift detection

Read SHALL compare the pinned program's tag and type against state.

#### Scenario: Program swapped out-of-band

- WHEN the pin is replaced with a different program outside Terraform
- THEN refresh reports drift
