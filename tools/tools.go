//go:build tools

// Package tools pins developer tooling that is not part of the provider build.
// The default build tags exclude this file, so the provider binary is unaffected.
package tools

// The schema lookup keys resources by provider-name (ebpf), matching the ebpf_
// prefix. Rendered pages read terrahive. The Makefile docs target restores the
// ebpf_ prefix on the output filenames.
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name ebpf --rendered-provider-name terrahive

import (
	_ "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs"
)
