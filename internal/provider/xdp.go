package provider

import (
	"context"
	"fmt"
	"net"

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

type xdpModel struct {
	Name      types.String `tfsdk:"name"`
	Program   types.String `tfsdk:"program"`
	Interface types.String `tfsdk:"interface"`
	Mode      types.String `tfsdk:"mode"`
	ID        types.String `tfsdk:"id"`
	LinkID    types.Int64  `tfsdk:"link_id"`
	ProgramID types.Int64  `tfsdk:"program_id"`
}

func newXDPResource() resource.Resource {
	return &attachmentResource{
		kind: "xdp",
		desc: "Attaches an XDP program to a network interface through a pinned bpf_link.",
		extraAttributes: map[string]schema.Attribute{
			"program": programAttribute(),
			"interface": schema.StringAttribute{
				Required:      true,
				Description:   "Network interface name to attach to.",
				PlanModifiers: replaceString(),
			},
			"mode": schema.StringAttribute{
				Optional:      true,
				Description:   "XDP attach mode: generic, driver, or offload. Unset lets the kernel pick.",
				Validators:    []validator.String{stringvalidator.OneOf("generic", "driver", "offload")},
				PlanModifiers: replaceString(),
			},
		},
		attach:  attachXDP,
		matches: xdpMatches,
	}
}

func xdpModeFlags(mode string) link.XDPAttachFlags {
	switch mode {
	case "generic":
		return link.XDPGenericMode
	case "driver":
		return link.XDPDriverMode
	case "offload":
		return link.XDPOffloadMode
	}
	return 0
}

func attachXDP(ctx context.Context, h *hive.Hive, plan tfsdk.Plan) (link.Link, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m xdpModel
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

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     xdpModeFlags(m.Mode.ValueString()),
	})
	if err != nil {
		diags.AddError(fmt.Sprintf("attaching xdp to %s", iface.Name), err.Error())
		return nil, diags
	}
	return l, diags
}

func xdpMatches(ctx context.Context, state tfsdk.State, info *link.Info) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m xdpModel
	diags.Append(state.Get(ctx, &m)...)
	if diags.HasError() {
		return false, diags
	}
	x := info.XDP()
	if x == nil {
		return true, diags
	}
	iface, err := net.InterfaceByName(m.Interface.ValueString())
	if err != nil {
		// The interface is gone; the attachment target no longer exists.
		return false, diags
	}
	return x.Ifindex == uint32(iface.Index), diags
}
