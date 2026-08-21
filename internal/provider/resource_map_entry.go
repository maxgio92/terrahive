package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/maxgio92/terrahive/internal/hive"
)

// mapEntryResource manages one key/value pair in a pinned BPF map.
// The ID is "<map pin path>:<base64 key>".
type mapEntryResource struct {
	hive *hive.Hive
}

type mapEntryResourceModel struct {
	ID    types.String `tfsdk:"id"`
	Map   types.String `tfsdk:"map"`
	Key   types.String `tfsdk:"key"`
	Value types.String `tfsdk:"value"`
}

var (
	_ resource.Resource                = (*mapEntryResource)(nil)
	_ resource.ResourceWithConfigure   = (*mapEntryResource)(nil)
	_ resource.ResourceWithImportState = (*mapEntryResource)(nil)
)

func newMapEntryResource() resource.Resource {
	return &mapEntryResource{}
}

func (r *mapEntryResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "ebpf_map_entry"
}

func (r *mapEntryResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A single key/value pair in a pinned BPF map. Key and value are " +
			"standard base64 with padding; drift is detected by looking the key up in the kernel.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Map pin path and base64 key, colon separated.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"map": schema.StringAttribute{
				Required:    true,
				Description: "bpffs pin path of the map, typically an ebpf_map ID.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key": schema.StringAttribute{
				Required:    true,
				Description: "Map key, base64 encoded, exactly key_size bytes.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"value": schema.StringAttribute{
				Required:    true,
				Description: "Map value, base64 encoded, exactly value_size bytes.",
			},
		},
	}
}

func (r *mapEntryResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *mapEntryResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan mapEntryResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.put(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = types.StringValue(mapEntryID(plan.Map.ValueString(), plan.Key.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mapEntryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state mapEntryResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pinPath, keyB64, err := splitMapEntryID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("invalid ebpf_map_entry ID", err.Error())
		return
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		resp.Diagnostics.AddError("invalid ebpf_map_entry ID", fmt.Sprintf("decoding key: %s", err))
		return
	}

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

	value, err := m.LookupBytes(key)
	if err != nil {
		resp.Diagnostics.AddError("looking up map entry", fmt.Sprintf("map %s: %s", pinPath, err))
		return
	}
	if value == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.Map = types.StringValue(pinPath)
	state.Key = types.StringValue(keyB64)
	state.Value = types.StringValue(base64.StdEncoding.EncodeToString(value[:m.ValueSize()]))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *mapEntryResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan mapEntryResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.put(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mapEntryResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state mapEntryResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pinPath := state.Map.ValueString()
	key, err := base64.StdEncoding.DecodeString(state.Key.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("key"), "invalid base64", err.Error())
		return
	}

	m, err := r.hive.LoadPinnedMap(pinPath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("reading pinned BPF map", fmt.Sprintf("loading %s: %s", pinPath, err))
		return
	}
	defer func() { _ = m.Close() }()

	if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		resp.Diagnostics.AddError("deleting map entry", fmt.Sprintf("map %s: %s", pinPath, err))
	}
}

func (r *mapEntryResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// put writes the planned key/value into the referenced map.
func (r *mapEntryResource) put(_ context.Context, plan *mapEntryResourceModel, diags *diag.Diagnostics) {
	key, err := base64.StdEncoding.DecodeString(plan.Key.ValueString())
	if err != nil {
		diags.AddAttributeError(path.Root("key"), "invalid base64", err.Error())
		return
	}
	value, err := base64.StdEncoding.DecodeString(plan.Value.ValueString())
	if err != nil {
		diags.AddAttributeError(path.Root("value"), "invalid base64", err.Error())
		return
	}

	pinPath := plan.Map.ValueString()
	m, err := r.hive.LoadPinnedMap(pinPath)
	if err != nil {
		diags.AddError("reading pinned BPF map", fmt.Sprintf("loading %s: %s", pinPath, err))
		return
	}
	defer func() { _ = m.Close() }()

	if err := m.Put(key, value); err != nil {
		diags.AddError("writing map entry", fmt.Sprintf("map %s: %s", pinPath, err))
	}
}

func mapEntryID(pinPath, keyB64 string) string {
	return pinPath + ":" + keyB64
}

// splitMapEntryID splits at the last colon: pin paths may contain colons,
// standard base64 never does.
func splitMapEntryID(id string) (pinPath, keyB64 string, err error) {
	i := strings.LastIndex(id, ":")
	if i < 1 || i == len(id)-1 {
		return "", "", fmt.Errorf("expected <pin path>:<base64 key>, got %q", id)
	}
	return id[:i], id[i+1:], nil
}
