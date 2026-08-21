package provider

import (
	"context"
	"fmt"

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

var netfilterFamilies = map[string]link.NetfilterProtocolFamily{
	"ipv4": link.NetfilterProtoIPv4,
	"ipv6": link.NetfilterProtoIPv6,
}

var netfilterHooks = map[string]link.NetfilterInetHook{
	"prerouting":  link.NetfilterInetPreRouting,
	"input":       link.NetfilterInetLocalIn,
	"forward":     link.NetfilterInetForward,
	"output":      link.NetfilterInetLocalOut,
	"postrouting": link.NetfilterInetPostRouting,
}

type netfilterModel struct {
	Name      types.String `tfsdk:"name"`
	Program   types.String `tfsdk:"program"`
	Family    types.String `tfsdk:"family"`
	Hook      types.String `tfsdk:"hook"`
	Priority  types.Int64  `tfsdk:"priority"`
	ID        types.String `tfsdk:"id"`
	LinkID    types.Int64  `tfsdk:"link_id"`
	ProgramID types.Int64  `tfsdk:"program_id"`
}

func newNetfilterResource() resource.Resource {
	return &attachmentResource{
		kind: "netfilter",
		desc: "Attaches a netfilter program to a hook through a pinned bpf_link. Requires kernel 6.4.",
		extraAttributes: map[string]schema.Attribute{
			"program": programAttribute(),
			"family": schema.StringAttribute{
				Required:      true,
				Description:   "Protocol family: ipv4 or ipv6.",
				Validators:    []validator.String{stringvalidator.OneOf("ipv4", "ipv6")},
				PlanModifiers: replaceString(),
			},
			"hook": schema.StringAttribute{
				Required:      true,
				Description:   "Netfilter hook: prerouting, input, forward, output, or postrouting.",
				Validators:    []validator.String{stringvalidator.OneOf("prerouting", "input", "forward", "output", "postrouting")},
				PlanModifiers: replaceString(),
			},
			"priority": schema.Int64Attribute{
				Optional:      true,
				Description:   "Priority within the hook. Defaults to 0.",
				PlanModifiers: replaceInt64(),
			},
		},
		attach:  attachNetfilter,
		matches: netfilterMatches,
	}
}

func attachNetfilter(ctx context.Context, h *hive.Hive, plan tfsdk.Plan) (link.Link, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m netfilterModel
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

	l, err := link.AttachNetfilter(link.NetfilterOptions{
		Program:        prog,
		ProtocolFamily: netfilterFamilies[m.Family.ValueString()],
		Hook:           netfilterHooks[m.Hook.ValueString()],
		Priority:       int32(m.Priority.ValueInt64()),
	})
	if err != nil {
		diags.AddError(fmt.Sprintf("attaching netfilter to %s %s", m.Family.ValueString(), m.Hook.ValueString()), err.Error())
		return nil, diags
	}
	return l, diags
}

func netfilterMatches(ctx context.Context, state tfsdk.State, info *link.Info) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m netfilterModel
	diags.Append(state.Get(ctx, &m)...)
	if diags.HasError() {
		return false, diags
	}
	nf := info.Netfilter()
	if nf == nil {
		return true, diags
	}
	return nf.ProtocolFamily == netfilterFamilies[m.Family.ValueString()] &&
		nf.Hook == netfilterHooks[m.Hook.ValueString()] &&
		nf.Priority == int32(m.Priority.ValueInt64()), diags
}
