package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/maxgio92/terrahive/internal/provider"
)

// version is set by goreleaser at build time.
var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run with debugger support")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/maxgio92/terrahive",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
