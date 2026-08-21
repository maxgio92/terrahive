package provider

import (
	"context"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

var attachmentConstructors = map[string]func() resource.Resource{
	"ebpf_kprobe":     newKprobeResource,
	"ebpf_tracepoint": newTracepointResource,
	"ebpf_tracing":    newTracingResource,
	"ebpf_xdp":        newXDPResource,
	"ebpf_tcx":        newTCXResource,
	"ebpf_cgroup":     newCgroupResource,
	"ebpf_netfilter":  newNetfilterResource,
	"ebpf_struct_ops": newStructOpsResource,
}

func resourceSchema(t *testing.T, r resource.Resource) schema.Schema {
	t.Helper()
	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}
	if diags := resp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatalf("schema implementation invalid: %v", diags)
	}
	return resp.Schema
}

func TestAttachmentResourceTypeNames(t *testing.T) {
	for want, newResource := range attachmentConstructors {
		var resp resource.MetadataResponse
		newResource().Metadata(context.Background(), resource.MetadataRequest{}, &resp)
		if resp.TypeName != want {
			t.Errorf("type name = %q, want %q", resp.TypeName, want)
		}
	}
}

// Every configurable attribute of an attachment must force replacement:
// a kernel bpf_link is immutable once created.
func TestAttachmentAttributesRequireReplace(t *testing.T) {
	for name, newResource := range attachmentConstructors {
		s := resourceSchema(t, newResource())
		for attrName, attr := range s.Attributes {
			if !attr.IsRequired() && !attr.IsOptional() {
				continue
			}
			var replaces bool
			switch a := attr.(type) {
			case schema.StringAttribute:
				replaces = len(a.PlanModifiers) > 0
			case schema.Int64Attribute:
				replaces = len(a.PlanModifiers) > 0
			default:
				t.Fatalf("%s.%s: unexpected attribute type %T", name, attrName, attr)
			}
			if !replaces {
				t.Errorf("%s.%s: configurable attribute without a RequiresReplace plan modifier", name, attrName)
			}
		}
	}
}

func TestAttachmentComputedAttributes(t *testing.T) {
	for name, newResource := range attachmentConstructors {
		s := resourceSchema(t, newResource())
		for _, attrName := range []string{"id", "link_id", "program_id"} {
			attr, ok := s.Attributes[attrName]
			if !ok {
				t.Errorf("%s: missing computed attribute %q", name, attrName)
				continue
			}
			if !attr.IsComputed() {
				t.Errorf("%s.%s: must be computed", name, attrName)
			}
		}
	}
}

// Every family except struct_ops references the program by pin path so
// that program replacement cascades into attachment replacement.
func TestAttachmentProgramReference(t *testing.T) {
	for name, newResource := range attachmentConstructors {
		s := resourceSchema(t, newResource())
		ref := "program"
		if name == "ebpf_struct_ops" {
			ref = "map"
		}
		attr, ok := s.Attributes[ref]
		if !ok {
			t.Errorf("%s: missing %q attribute", name, ref)
			continue
		}
		if !attr.IsRequired() {
			t.Errorf("%s.%s: must be required", name, ref)
		}
	}
}

func TestXDPModeFlags(t *testing.T) {
	tests := map[string]link.XDPAttachFlags{
		"":        0,
		"generic": link.XDPGenericMode,
		"driver":  link.XDPDriverMode,
		"offload": link.XDPOffloadMode,
	}
	for mode, want := range tests {
		if got := xdpModeFlags(mode); got != want {
			t.Errorf("xdpModeFlags(%q) = %v, want %v", mode, got, want)
		}
	}
}

func TestTCXAttachType(t *testing.T) {
	if got := tcxAttachType("ingress"); got != ebpf.AttachTCXIngress {
		t.Errorf("tcxAttachType(ingress) = %v", got)
	}
	if got := tcxAttachType("egress"); got != ebpf.AttachTCXEgress {
		t.Errorf("tcxAttachType(egress) = %v", got)
	}
}

func TestCgroupAttachTypeNamesSortedAndComplete(t *testing.T) {
	names := cgroupAttachTypeNames()
	if len(names) != len(cgroupAttachTypes) {
		t.Fatalf("got %d names, want %d", len(names), len(cgroupAttachTypes))
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("names not sorted: %q before %q", names[i-1], names[i])
		}
	}
	if cgroupAttachTypes["cgroup_inet_ingress"] != ebpf.AttachCGroupInetIngress {
		t.Error("cgroup_inet_ingress maps to the wrong attach type")
	}
}
