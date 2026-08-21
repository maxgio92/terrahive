package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/maxgio92/terrahive/internal/hive"
)

// mapResource manages a pinned BPF map. The pin path is the resource ID.
type mapResource struct {
	hive *hive.Hive
}

type mapResourceModel struct {
	ID         types.String `tfsdk:"id"`
	Name       types.String `tfsdk:"name"`
	Type       types.String `tfsdk:"type"`
	KeySize    types.Int64  `tfsdk:"key_size"`
	ValueSize  types.Int64  `tfsdk:"value_size"`
	MaxEntries types.Int64  `tfsdk:"max_entries"`
}

var (
	_ resource.Resource                = (*mapResource)(nil)
	_ resource.ResourceWithConfigure   = (*mapResource)(nil)
	_ resource.ResourceWithImportState = (*mapResource)(nil)
)

func newMapResource() resource.Resource {
	return &mapResource{}
}

func (r *mapResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "ebpf_map"
}

func (r *mapResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A BPF map created in the kernel and pinned under the provider pin_dir. " +
			"The pin path is the resource ID; any shape change forces replacement because " +
			"map dimensions are immutable in the kernel.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "bpffs pin path of the map.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the map; the last element of the pin path.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "Map type, for example hash, array, lru_hash, ringbuf.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_size": schema.Int64Attribute{
				Required:    true,
				Description: "Key size in bytes.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"value_size": schema.Int64Attribute{
				Required:    true,
				Description: "Value size in bytes.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"max_entries": schema.Int64Attribute{
				Required:    true,
				Description: "Maximum number of entries.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *mapResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	h, ok := req.ProviderData.(*hive.Hive)
	if !ok {
		resp.Diagnostics.AddError("unexpected provider data", fmt.Sprintf("expected *hive.Hive, got %T", req.ProviderData))
		return
	}
	r.hive = h
}

func (r *mapResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan mapResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	mt, err := parseMapType(plan.Type.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("type"), "invalid map type", err.Error())
		return
	}

	spec := &ebpf.MapSpec{
		Name:       kernelObjectName(plan.Name.ValueString()),
		Type:       mt,
		KeySize:    uint32(plan.KeySize.ValueInt64()),
		ValueSize:  uint32(plan.ValueSize.ValueInt64()),
		MaxEntries: uint32(plan.MaxEntries.ValueInt64()),
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		resp.Diagnostics.AddError("creating BPF map", err.Error())
		return
	}
	defer func() { _ = m.Close() }()

	pinPath := r.hive.PinPath("map", plan.Name.ValueString())
	if err := os.MkdirAll(filepath.Dir(pinPath), 0o755); err != nil {
		resp.Diagnostics.AddError("creating pin directory", err.Error())
		return
	}
	if err := m.Pin(pinPath); err != nil {
		resp.Diagnostics.AddError("pinning BPF map", fmt.Sprintf("pinning to %s: %s", pinPath, err))
		return
	}

	plan.ID = types.StringValue(pinPath)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mapResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state mapResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pinPath := state.ID.ValueString()
	m, err := r.hive.LoadPinnedMap(pinPath)
	if errors.Is(err, os.ErrNotExist) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("reading pinned BPF map", fmt.Sprintf("loading %s: %s", pinPath, err))
		return
	}
	defer func() { _ = m.Close() }()

	state.Name = types.StringValue(filepath.Base(pinPath))
	// Keep the state's spelling when it already names the kernel type, so
	// "lru_hash" in config does not diff against the canonical "lruhash".
	if mt, err := parseMapType(state.Type.ValueString()); err != nil || mt != m.Type() {
		state.Type = types.StringValue(mapTypeString(m.Type()))
	}
	state.KeySize = types.Int64Value(int64(m.KeySize()))
	state.ValueSize = types.Int64Value(int64(m.ValueSize()))
	state.MaxEntries = types.Int64Value(int64(m.MaxEntries()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is never called: every attribute forces replacement.
func (r *mapResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan mapResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mapResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state mapResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.hive.Unpin(state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("deleting BPF map", err.Error())
	}
}

func (r *mapResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// parseMapType maps a user-facing type name onto ebpf.MapType. It accepts
// the cilium/ebpf stringer names case-insensitively, with underscores
// ignored, so "hash", "lru_hash", and "LRUHash" all resolve.
func parseMapType(s string) (ebpf.MapType, error) {
	want := strings.ToLower(strings.ReplaceAll(s, "_", ""))
	for mt := ebpf.Hash; mt <= ebpf.Arena; mt++ {
		if strings.ToLower(mt.String()) == want {
			return mt, nil
		}
	}
	return ebpf.UnspecifiedMap, fmt.Errorf("unknown map type %q", s)
}

// mapTypeString renders an ebpf.MapType in the config-facing form, the
// lowercase of the cilium/ebpf stringer name, so Read output matches what
// parseMapType accepts.
func mapTypeString(mt ebpf.MapType) string {
	return strings.ToLower(mt.String())
}

// kernelObjectName truncates a resource name to the 15 bytes the kernel
// accepts for BPF object names and drops characters it rejects.
func kernelObjectName(name string) string {
	var b strings.Builder
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' {
			b.WriteRune(c)
		}
		if b.Len() == 15 {
			break
		}
	}
	return b.String()
}
