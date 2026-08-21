package provider

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/maxgio92/terrahive/internal/hive"
)

type kprobeModel struct {
	Name         types.String `tfsdk:"name"`
	Program      types.String `tfsdk:"program"`
	Kind         types.String `tfsdk:"kind"`
	Symbol       types.String `tfsdk:"symbol"`
	Path         types.String `tfsdk:"path"`
	USDTProvider types.String `tfsdk:"usdt_provider"`
	Offset       types.Int64  `tfsdk:"offset"`
	ID           types.String `tfsdk:"id"`
	LinkID       types.Int64  `tfsdk:"link_id"`
	ProgramID    types.Int64  `tfsdk:"program_id"`
}

func newKprobeResource() resource.Resource {
	return &attachmentResource{
		kind: "kprobe",
		desc: "Attaches a program to a kernel or user probe through a pinned bpf_link.",
		extraAttributes: map[string]schema.Attribute{
			"program": programAttribute(),
			"kind": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Default:       stringdefault.StaticString("kprobe"),
				Description:   "Probe flavor: kprobe, kretprobe, uprobe, uretprobe, or usdt.",
				Validators:    []validator.String{stringvalidator.OneOf("kprobe", "kretprobe", "uprobe", "uretprobe", "usdt")},
				PlanModifiers: replaceString(),
			},
			"symbol": schema.StringAttribute{
				Required:      true,
				Description:   "Traced symbol; the probe name for usdt.",
				PlanModifiers: replaceString(),
			},
			"path": schema.StringAttribute{
				Optional:      true,
				Description:   "Executable path, required for uprobe, uretprobe, and usdt.",
				PlanModifiers: replaceString(),
			},
			"usdt_provider": schema.StringAttribute{
				Optional:      true,
				Description:   "USDT provider name, required for usdt.",
				PlanModifiers: replaceString(),
			},
			"offset": schema.Int64Attribute{
				Optional:      true,
				Description:   "Offset relative to the symbol.",
				PlanModifiers: replaceInt64(),
			},
		},
		attach:  attachKprobe,
		matches: kprobeMatches,
	}
}

func attachKprobe(ctx context.Context, h *hive.Hive, plan tfsdk.Plan) (link.Link, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m kprobeModel
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
	symbol := m.Symbol.ValueString()
	offset := uint64(m.Offset.ValueInt64())

	var l link.Link
	switch kind {
	case "kprobe", "kretprobe":
		var opts *link.KprobeOptions
		if offset != 0 {
			opts = &link.KprobeOptions{Offset: offset}
		}
		if kind == "kprobe" {
			l, err = link.Kprobe(symbol, prog, opts)
		} else {
			l, err = link.Kretprobe(symbol, prog, opts)
		}
	case "uprobe", "uretprobe", "usdt":
		if m.Path.IsNull() {
			diags.AddError("missing path", fmt.Sprintf("kind %q requires the path attribute", kind))
			return nil, diags
		}
		var ex *link.Executable
		ex, err = link.OpenExecutable(m.Path.ValueString())
		if err != nil {
			diags.AddError("opening executable "+m.Path.ValueString(), err.Error())
			return nil, diags
		}
		switch kind {
		case "uprobe":
			l, err = ex.Uprobe(symbol, prog, &link.UprobeOptions{Offset: offset})
		case "uretprobe":
			l, err = ex.Uretprobe(symbol, prog, &link.UprobeOptions{Offset: offset})
		default:
			if m.USDTProvider.IsNull() {
				diags.AddError("missing usdt_provider", "kind \"usdt\" requires the usdt_provider attribute")
				return nil, diags
			}
			var t *hive.USDT
			t, err = hive.ResolveUSDT(m.Path.ValueString(), m.USDTProvider.ValueString(), symbol)
			if err != nil {
				diags.AddError("resolving usdt probe", err.Error())
				return nil, diags
			}
			l, err = ex.Uprobe("", prog, &link.UprobeOptions{Address: t.Address, RefCtrOffset: t.SemaphoreOffset})
		}
	}
	if err != nil {
		diags.AddError(fmt.Sprintf("attaching %s to %s", kind, symbol), err.Error())
		return nil, diags
	}
	return l, diags
}

func kprobeMatches(ctx context.Context, state tfsdk.State, info *link.Info) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m kprobeModel
	diags.Append(state.Get(ctx, &m)...)
	if diags.HasError() {
		return false, diags
	}
	pe := info.PerfEvent()
	if pe == nil {
		return true, diags
	}
	switch m.Kind.ValueString() {
	case "kprobe", "kretprobe":
		if kp := pe.Kprobe(); kp != nil && kp.Function != "" {
			return kp.Function == m.Symbol.ValueString(), diags
		}
	case "uprobe", "uretprobe", "usdt":
		if up := pe.Uprobe(); up != nil && up.File != "" {
			return up.File == m.Path.ValueString(), diags
		}
	}
	return true, diags
}
