package provider

import (
	"context"

	"github.com/cilium/ebpf/link"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/maxgio92/terrahive/internal/hive"
)

type structOpsModel struct {
	Name      types.String `tfsdk:"name"`
	Map       types.String `tfsdk:"map"`
	ID        types.String `tfsdk:"id"`
	LinkID    types.Int64  `tfsdk:"link_id"`
	ProgramID types.Int64  `tfsdk:"program_id"`
}

func newStructOpsResource() resource.Resource {
	return &attachmentResource{
		kind: "struct_ops",
		desc: "Registers a struct_ops map with the kernel through a pinned bpf_link.",
		extraAttributes: map[string]schema.Attribute{
			"map": schema.StringAttribute{
				Required:      true,
				Description:   "bpffs pin path of the struct_ops map to register.",
				PlanModifiers: replaceString(),
			},
		},
		attach: attachStructOps,
	}
}

func attachStructOps(ctx context.Context, h *hive.Hive, plan tfsdk.Plan) (link.Link, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m structOpsModel
	diags.Append(plan.Get(ctx, &m)...)
	if diags.HasError() {
		return nil, diags
	}

	opsMap, err := h.LoadPinnedMap(m.Map.ValueString())
	if err != nil {
		diags.AddError("loading pinned map "+m.Map.ValueString(), err.Error())
		return nil, diags
	}
	defer func() { _ = opsMap.Close() }()

	l, err := link.AttachStructOps(link.StructOpsOptions{Map: opsMap})
	if err != nil {
		diags.AddError("attaching struct_ops map "+m.Map.ValueString(), err.Error())
		return nil, diags
	}
	return l, diags
}
