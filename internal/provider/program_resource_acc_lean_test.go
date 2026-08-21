//go:build !bumble

package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccProgramGoSourceRejected(t *testing.T) {
	pinDir := accPinDir(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
		ProtoV6ProviderFactories: accProtoV6Factories,
		Steps: []resource.TestStep{
			{
				Config: accProviderBlock(pinDir) + `
resource "ebpf_program" "probe" {
  name      = "gopher"
  go_source = "package main"
}
`,
				ExpectError: regexp.MustCompile(`terrahive-bumble`),
			},
		},
	})
}
