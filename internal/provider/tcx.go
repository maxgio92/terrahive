package provider

import (
	"context"
	"fmt"
	"net"

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

type tcxModel struct {
	Name      types.String `tfsdk:"name"`
	Program   types.String `tfsdk:"program"`
	Interface types.String `tfsdk:"interface"`
	Direction types.String `tfsdk:"direction"`
	ID        types.String `tfsdk:"id"`
	LinkID    types.Int64  `tfsdk:"link_id"`
	ProgramID types.Int64  `tfsdk:"program_id"`
}

func newTCXResource() resource.Resource {
	return &attachmentResource{
		kind: "tcx",
		desc: "Attaches a tc program to a network interface via tcx through a pinned bpf_link. Requires kernel 6.6.",
		extraAttributes: map[string]schema.Attribute{
			"program": programAttribute(),
			"interface": schema.StringAttribute{
				Required:      true,
				Description:   "Network interface name to attach to.",
				PlanModifiers: replaceString(),
			},
			"direction": schema.StringAttribute{
				Required:      true,
				Description:   "Traffic direction: ingress or egress.",
				Validators:    []validator.String{stringvalidator.OneOf("ingress", "egress")},
				PlanModifiers: replaceString(),
			},
		},
		attach:  attachTCX,
		matches: tcxMatches,
	}
}

func tcxAttachType(direction string) ebpf.AttachType {
	if direction == "egress" {
		return ebpf.AttachTCXEgress
	}
	return ebpf.AttachTCXIngress
}

func attachTCX(ctx context.Context, h *hive.Hive, plan tfsdk.Plan) (link.Link, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m tcxModel
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

	iface, err := net.InterfaceByName(m.Interface.ValueString())
	if err != nil {
		diags.AddError("resolving interface "+m.Interface.ValueString(), err.Error())
		return nil, diags
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Interface: iface.Index,
		Attach:    tcxAttachType(m.Direction.ValueString()),
	})
	if err != nil {
		diags.AddError(fmt.Sprintf("attaching tcx %s to %s", m.Direction.ValueString(), iface.Name), err.Error())
		return nil, diags
	}
	return l, diags
}

func tcxMatches(ctx context.Context, state tfsdk.State, info *link.Info) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m tcxModel
	diags.Append(state.Get(ctx, &m)...)
	if diags.HasError() {
		return false, diags
	}
	t := info.TCX()
	if t == nil {
		return true, diags
	}
	if uint32(t.AttachType) != uint32(tcxAttachType(m.Direction.ValueString())) {
		return false, diags
	}
	iface, err := net.InterfaceByName(m.Interface.ValueString())
	if err != nil {
		return false, diags
	}
	return t.Ifindex == uint32(iface.Index), diags
}
