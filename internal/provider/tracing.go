package provider

import (
	"context"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/maxgio92/terrahive/internal/hive"
)

type tracingModel struct {
	Name      types.String `tfsdk:"name"`
	Program   types.String `tfsdk:"program"`
	Kind      types.String `tfsdk:"kind"`
	ID        types.String `tfsdk:"id"`
	LinkID    types.Int64  `tfsdk:"link_id"`
	ProgramID types.Int64  `tfsdk:"program_id"`
}

func newTracingResource() resource.Resource {
	return &attachmentResource{
		kind: "tracing",
		desc: "Attaches a BTF-powered tracing program (fentry, fexit, fmod_ret, lsm, iter) through a pinned bpf_link. The attach target is fixed at program load time.",
		extraAttributes: map[string]schema.Attribute{
			"program": programAttribute(),
			"kind": schema.StringAttribute{
				Required:      true,
				Description:   "Tracing flavor: fentry, fexit, fmod_ret, lsm, or iter.",
				Validators:    []validator.String{stringvalidator.OneOf("fentry", "fexit", "fmod_ret", "lsm", "iter")},
				PlanModifiers: replaceString(),
			},
		},
		attach: attachTracing,
	}
}

func attachTracing(ctx context.Context, h *hive.Hive, plan tfsdk.Plan) (link.Link, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m tracingModel
	diags.Append(plan.Get(ctx, &m)...)
	if diags.HasError() {
		return nil, diags
	}

	prog, err := h.LoadPinnedProgram(m.Program.ValueString())
	if err != nil {
		diags.AddError("loading pinned program "+m.Program.ValueString(), err.Error())
		return nil, diags
	}
	defer func() { _ = prog.Close() }()

	kind := m.Kind.ValueString()
	var l link.Link
	switch kind {
	case "fentry":
		l, err = link.AttachTracing(link.TracingOptions{Program: prog, AttachType: ebpf.AttachTraceFEntry})
	case "fexit":
		l, err = link.AttachTracing(link.TracingOptions{Program: prog, AttachType: ebpf.AttachTraceFExit})
	case "fmod_ret":
		l, err = link.AttachTracing(link.TracingOptions{Program: prog, AttachType: ebpf.AttachModifyReturn})
	case "lsm":
		l, err = link.AttachLSM(link.LSMOptions{Program: prog})
	case "iter":
		l, err = link.AttachIter(link.IterOptions{Program: prog})
	}
	if err != nil {
		diags.AddError("attaching "+kind, err.Error())
		return nil, diags
	}
	return l, diags
}
