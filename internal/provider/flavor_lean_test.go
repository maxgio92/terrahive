//go:build !bumble

package provider

import (
	"strings"
	"testing"
)

func TestLeanFlavorSelected(t *testing.T) {
	if flavorName != "lean" {
		t.Fatalf("flavorName = %q, want lean", flavorName)
	}
	if err := checkGoSourceSupported(); err == nil {
		t.Fatal("lean flavor must reject go_source")
	}
}

func TestLeanCompileGoSourceFails(t *testing.T) {
	if _, err := compileGoSource("package main"); err == nil ||
		!strings.Contains(err.Error(), "terrahive-bumble") {
		t.Fatalf("error does not point to the bumble flavor: %v", err)
	}
}

func TestProgramResourceValidateConfigRejectsGoSource(t *testing.T) {
	resp := validateGoSourceConfig(t)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected go_source diagnostic")
	}
	found := false
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Detail(), "terrahive-bumble") {
			found = true
		}
	}
	if !found {
		t.Fatalf("diagnostic does not point to the bumble flavor: %v", resp.Diagnostics)
	}
}
