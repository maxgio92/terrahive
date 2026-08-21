//go:build tools

// Package tools pins the tfplugindocs generator so registry documentation
// can be regenerated from the provider schema. It is built only under the
// "tools" build tag and is excluded from the provider binary.
//
// Regenerate the docs/ tree with:
//
//	make docs
//
// which runs tfplugindocs against the schema. Generation needs network
// access to fetch the tool on first run.
package tools

import (
	_ "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs"
)

//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name terrahive
