package provider

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/sys/unix"

	"github.com/maxgio92/terrahive/internal/hive"
)

type tracepointModel struct {
	Name       types.String `tfsdk:"name"`
	Program    types.String `tfsdk:"program"`
	Kind       types.String `tfsdk:"kind"`
	Group      types.String `tfsdk:"group"`
	Event      types.String `tfsdk:"event"`
	SampleFreq types.Int64  `tfsdk:"sample_freq"`
	CPU        types.Int64  `tfsdk:"cpu"`
	ID         types.String `tfsdk:"id"`
	LinkID     types.Int64  `tfsdk:"link_id"`
	ProgramID  types.Int64  `tfsdk:"program_id"`
}

func newTracepointResource() resource.Resource {
	return &attachmentResource{
		kind: "tracepoint",
		desc: "Attaches a program to a tracepoint, raw tracepoint, or perf event through a pinned bpf_link.",
		extraAttributes: map[string]schema.Attribute{
			"program": programAttribute(),
			"kind": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Default:       stringdefault.StaticString("tracepoint"),
				Description:   "Hook flavor: tracepoint, raw_tracepoint, or perf_event.",
				Validators:    []validator.String{stringvalidator.OneOf("tracepoint", "raw_tracepoint", "perf_event")},
				PlanModifiers: replaceString(),
			},
			"group": schema.StringAttribute{
				Optional:      true,
				Description:   "Tracepoint group (e.g. sched), required for tracepoint.",
				PlanModifiers: replaceString(),
			},
			"event": schema.StringAttribute{
				Optional:      true,
				Description:   "Tracepoint or raw tracepoint name, required for tracepoint and raw_tracepoint.",
				PlanModifiers: replaceString(),
			},
			"sample_freq": schema.Int64Attribute{
				Optional:      true,
				Description:   "CPU clock sampling frequency in Hz, required for perf_event.",
				PlanModifiers: replaceInt64(),
			},
			"cpu": schema.Int64Attribute{
				Optional:      true,
				Description:   "CPU to open the perf event on. Defaults to 0.",
				PlanModifiers: replaceInt64(),
			},
		},
		attach:  attachTracepoint,
		matches: tracepointMatches,
	}
}

func attachTracepoint(ctx context.Context, h *hive.Hive, plan tfsdk.Plan) (link.Link, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m tracepointModel
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
	case "tracepoint":
		if m.Group.IsNull() || m.Event.IsNull() {
			diags.AddError("missing tracepoint target", "kind \"tracepoint\" requires the group and event attributes")
			return nil, diags
		}
		l, err = link.Tracepoint(m.Group.ValueString(), m.Event.ValueString(), prog, nil)
	case "raw_tracepoint":
		if m.Event.IsNull() {
			diags.AddError("missing raw tracepoint target", "kind \"raw_tracepoint\" requires the event attribute")
			return nil, diags
		}
		l, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: m.Event.ValueString(), Program: prog})
	case "perf_event":
		if m.SampleFreq.IsNull() {
			diags.AddError("missing sample_freq", "kind \"perf_event\" requires the sample_freq attribute")
			return nil, diags
		}
		l, err = attachPerfEvent(prog, uint64(m.SampleFreq.ValueInt64()), int(m.CPU.ValueInt64()))
	}
	if err != nil {
		diags.AddError("attaching "+kind, err.Error())
		return nil, diags
	}
	return l, diags
}

// attachPerfEvent opens a software cpu-clock perf event and attaches
// the program with a bpf_link. The link holds its own reference to the
// perf event, so the local fd is closed on return.
func attachPerfEvent(prog *ebpf.Program, sampleFreq uint64, cpu int) (link.Link, error) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Sample: sampleFreq,
		Bits:   unix.PerfBitFreq,
	}
	fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("opening cpu-clock perf event on cpu %d: %w", cpu, err)
	}
	defer func() { _ = unix.Close(fd) }()
	l, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  fd,
		Program: prog,
		Attach:  ebpf.AttachPerfEvent,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching program to perf event: %w", err)
	}
	return l, nil
}

func tracepointMatches(ctx context.Context, state tfsdk.State, info *link.Info) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m tracepointModel
	diags.Append(state.Get(ctx, &m)...)
	if diags.HasError() {
		return false, diags
	}
	event := m.Event.ValueString()
	switch m.Kind.ValueString() {
	case "tracepoint":
		if pe := info.PerfEvent(); pe != nil {
			if tp := pe.Tracepoint(); tp != nil && tp.Tracepoint != "" {
				return tp.Tracepoint == event || tp.Tracepoint == m.Group.ValueString()+":"+event, diags
			}
		}
	case "raw_tracepoint":
		if rt := info.RawTracepoint(); rt != nil && rt.Name != "" {
			return rt.Name == event, diags
		}
	}
	return true, diags
}
