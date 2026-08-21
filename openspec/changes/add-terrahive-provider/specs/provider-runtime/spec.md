# Provider Runtime

## ADDED Requirements

### Requirement: Provider configuration

The provider SHALL expose a `pin_dir` attribute, defaulting to `/sys/fs/bpf/terrahive`, under which all managed objects are pinned.

#### Scenario: Default pin directory

- WHEN the provider block sets no `pin_dir`
- THEN objects are pinned under `/sys/fs/bpf/terrahive`

#### Scenario: bpffs not mounted

- WHEN `pin_dir` does not reside on a bpffs mount
- THEN provider configuration fails with a diagnostic naming the expected filesystem

### Requirement: Privilege check

The provider SHALL verify at configure time that the process can perform BPF operations (root or CAP_BPF) and fail with an actionable diagnostic otherwise.

#### Scenario: Unprivileged run

- WHEN Terraform runs without root or CAP_BPF
- THEN configure fails and the diagnostic states the missing capability

### Requirement: Pin path as identity

Every managed object SHALL be pinned to a path derived from its resource address, and that path SHALL serve as the resource ID for read, import, and drift detection.

#### Scenario: Object survives Terraform exit

- WHEN an apply completes and the Terraform process exits
- THEN the pinned object remains loaded in the kernel

#### Scenario: Out-of-band removal

- WHEN a pinned object is removed outside Terraform
- THEN the next refresh marks the resource for recreation

#### Scenario: Import

- WHEN a user imports a resource with a pin path as the ID
- THEN state is populated from the kernel object info
