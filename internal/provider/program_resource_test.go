package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func programSchema(t *testing.T) schema.Schema {
	t.Helper()
	resp := &resource.SchemaResponse{}
	NewProgramResource().Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}
	return resp.Schema
}

func TestProgramResourceSchemaImplementation(t *testing.T) {
	s := programSchema(t)
	if diags := s.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatalf("schema implementation invalid: %v", diags)
	}
}

func TestProgramResourceSchemaSourceExclusivity(t *testing.T) {
	s := programSchema(t)
	obj, ok := s.Attributes["object_file"].(schema.StringAttribute)
	if !ok {
		t.Fatal("object_file is not a string attribute")
	}
	if len(obj.Validators) == 0 {
		t.Fatal("object_file has no ExactlyOneOf validator")
	}
}

func TestProgramResourceSchemaForcesReplacement(t *testing.T) {
	s := programSchema(t)
	for _, name := range []string{"name", "object_file", "c_source", "go_source", "type"} {
		attr, ok := s.Attributes[name].(schema.StringAttribute)
		if !ok {
			t.Fatalf("%s is not a string attribute", name)
		}
		if len(attr.PlanModifiers) == 0 {
			t.Fatalf("%s has no RequiresReplace plan modifier", name)
		}
	}
}

func programConfig(t *testing.T, values map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := programSchema(t)
	objType := s.Type().TerraformType(context.Background()).(tftypes.Object)
	full := map[string]tftypes.Value{}
	for name, attrType := range objType.AttributeTypes {
		if v, ok := values[name]; ok {
			full[name] = v
		} else {
			full[name] = tftypes.NewValue(attrType, nil)
		}
	}
	return tfsdk.Config{Raw: tftypes.NewValue(objType, full), Schema: s}
}

// validateGoSourceConfig runs ValidateConfig on a go_source-only
// config; the flavor test files assert the flavor-specific outcome.
func validateGoSourceConfig(t *testing.T) *resource.ValidateConfigResponse {
	t.Helper()
	config := programConfig(t, map[string]tftypes.Value{
		"name":      tftypes.NewValue(tftypes.String, "buzz"),
		"go_source": tftypes.NewValue(tftypes.String, "package main"),
	})
	resp := &resource.ValidateConfigResponse{}
	r := NewProgramResource().(*programResource)
	r.ValidateConfig(context.Background(), resource.ValidateConfigRequest{Config: config}, resp)
	return resp
}

func TestProgramResourceValidateConfigAcceptsObjectFile(t *testing.T) {
	config := programConfig(t, map[string]tftypes.Value{
		"name":        tftypes.NewValue(tftypes.String, "buzz"),
		"object_file": tftypes.NewValue(tftypes.String, "/tmp/prog.o"),
	})
	resp := &resource.ValidateConfigResponse{}
	r := NewProgramResource().(*programResource)
	r.ValidateConfig(context.Background(), resource.ValidateConfigRequest{Config: config}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
}
