package provider

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
		if !hasRequiresReplaceString(attr.PlanModifiers) {
			t.Fatalf("%s has no RequiresReplace plan modifier", name)
		}
	}
}

// hasRequiresReplaceString reports whether the modifiers include a
// RequiresReplace variant, matched by its description rather than by the
// mere presence of some modifier.
func hasRequiresReplaceString(mods []planmodifier.String) bool {
	for _, m := range mods {
		if strings.Contains(m.Description(context.Background()), "destroy and recreate the resource") {
			return true
		}
	}
	return false
}

func programObject(t *testing.T, s schema.Schema, values map[string]tftypes.Value) tftypes.Value {
	t.Helper()
	objType := s.Type().TerraformType(context.Background()).(tftypes.Object)
	full := map[string]tftypes.Value{}
	for name, attrType := range objType.AttributeTypes {
		if v, ok := values[name]; ok {
			full[name] = v
		} else {
			full[name] = tftypes.NewValue(attrType, nil)
		}
	}
	return tftypes.NewValue(objType, full)
}

func programConfig(t *testing.T, values map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := programSchema(t)
	return tfsdk.Config{Raw: programObject(t, s, values), Schema: s}
}

// TestProgramModifyPlanKeepsSourceHashWhenObjectFileMissing proves a
// cleaned build artifact does not force a perpetual "known after apply"
// diff: ModifyPlan keeps the recorded source_hash from state.
func TestProgramModifyPlanKeepsSourceHashWhenObjectFileMissing(t *testing.T) {
	s := programSchema(t)
	missing := filepath.Join(t.TempDir(), "gone.o")
	const priorHash = "abc123"

	fields := map[string]tftypes.Value{
		"name":        tftypes.NewValue(tftypes.String, "prog"),
		"object_file": tftypes.NewValue(tftypes.String, missing),
		"type":        tftypes.NewValue(tftypes.String, "kprobe"),
		"id":          tftypes.NewValue(tftypes.String, "/sys/fs/bpf/terrahive/program/prog"),
		"tag":         tftypes.NewValue(tftypes.String, "tag"),
	}
	planFields := map[string]tftypes.Value{}
	stateFields := map[string]tftypes.Value{}
	for k, v := range fields {
		planFields[k] = v
		stateFields[k] = v
	}
	planFields["source_hash"] = tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	stateFields["source_hash"] = tftypes.NewValue(tftypes.String, priorHash)

	planObj := programObject(t, s, planFields)
	req := resource.ModifyPlanRequest{
		Config: tfsdk.Config{Raw: programObject(t, s, planFields), Schema: s},
		Plan:   tfsdk.Plan{Raw: planObj, Schema: s},
		State:  tfsdk.State{Raw: programObject(t, s, stateFields), Schema: s},
	}
	resp := resource.ModifyPlanResponse{Plan: tfsdk.Plan{Raw: planObj, Schema: s}}

	r := NewProgramResource().(*programResource)
	r.ModifyPlan(context.Background(), req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	var got types.String
	resp.Diagnostics.Append(resp.Plan.GetAttribute(context.Background(), path.Root("source_hash"), &got)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("reading planned source_hash: %v", resp.Diagnostics)
	}
	if got.IsUnknown() || got.ValueString() != priorHash {
		t.Fatalf("planned source_hash = %v, want %q", got, priorHash)
	}
	if len(resp.RequiresReplace) != 0 {
		t.Fatalf("unexpected RequiresReplace: %v", resp.RequiresReplace)
	}
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
