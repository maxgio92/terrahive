package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/maxgio92/terrahive/internal/hive"
)

const goSourceUnsupported = "go_source requires the terrahive-bumble flavor, which embeds the TinyGo toolchain. " +
	"This is the lean terrahive binary: use object_file or c_source, or switch to the bumble flavor."

// pinDriftKey marks, in private state, that Read found the pin swapped
// out-of-band. ModifyPlan turns it into a replacement so Delete unpins
// the rogue pin before Create; dropping the resource from state instead
// would plan a pure create that fails on the existing pin path.
const pinDriftKey = "pin_drift"

type programResource struct {
	hive *hive.Hive
}

type programModel struct {
	ID         types.String `tfsdk:"id"`
	Name       types.String `tfsdk:"name"`
	ObjectFile types.String `tfsdk:"object_file"`
	CSource    types.String `tfsdk:"c_source"`
	GoSource   types.String `tfsdk:"go_source"`
	Type       types.String `tfsdk:"type"`
	Tag        types.String `tfsdk:"tag"`
	SourceHash types.String `tfsdk:"source_hash"`
}

var (
	_ resource.Resource                   = (*programResource)(nil)
	_ resource.ResourceWithConfigure      = (*programResource)(nil)
	_ resource.ResourceWithImportState    = (*programResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*programResource)(nil)
	_ resource.ResourceWithValidateConfig = (*programResource)(nil)
)

// NewProgramResource returns the ebpf_program resource.
func NewProgramResource() resource.Resource {
	return &programResource{}
}

func (r *programResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ebpf_program"
}

func (r *programResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Loads a BPF program into the kernel and pins it under the provider pin directory. " +
			"The program type is inferred from the ELF section name.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "bpffs pin path of the program.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Program name, used as the last pin path element.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"object_file": schema.StringAttribute{
				Optional:    true,
				Description: "Path to a compiled BPF ELF object containing exactly one program.",
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("object_file"),
						path.MatchRoot("c_source"),
						path.MatchRoot("go_source"),
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"c_source": schema.StringAttribute{
				Optional:    true,
				Description: "BPF C source, compiled with the system clang at apply time.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"go_source": schema.StringAttribute{
				Optional:    true,
				Description: "BPF Go source, compiled with the embedded TinyGo toolchain (terrahive-bumble flavor only).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Program type in lowercase (e.g. kprobe, xdp). Inferred from the ELF section; " +
					"when set, acts as an assertion against the inferred type.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
				},
			},
			"tag": schema.StringAttribute{
				Computed:    true,
				Description: "Kernel-computed program tag, used for drift detection.",
			},
			"source_hash": schema.StringAttribute{
				Computed:    true,
				Description: "SHA-256 of the program source; a change forces replacement.",
			},
		},
	}
}

func (r *programResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *programResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config programModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.GoSource.IsNull() && !config.GoSource.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("go_source"), "go_source not supported in this flavor", goSourceUnsupported)
	}
}

func (r *programResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan, config programModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hash := types.StringUnknown()
	inferred := ""
	switch {
	case known(plan.ObjectFile):
		obj, err := os.ReadFile(plan.ObjectFile.ValueString())
		if err != nil {
			// The file may be produced by another resource at apply time.
			break
		}
		hash = types.StringValue(hive.SourceHash(obj))
		spec, err := hive.LoadELF(obj)
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("object_file"), "invalid BPF object", err.Error())
			return
		}
		inferred = hive.ProgramTypeString(spec.Type)
	case known(plan.CSource):
		hash = types.StringValue(hive.SourceHash([]byte(plan.CSource.ValueString())))
	}

	if inferred != "" {
		if known(config.Type) && strings.ToLower(config.Type.ValueString()) != inferred {
			resp.Diagnostics.AddAttributeError(path.Root("type"), "program type assertion failed",
				fmt.Sprintf("type is set to %q but the ELF section implies %q", config.Type.ValueString(), inferred))
			return
		}
		if config.Type.IsNull() {
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("type"), inferred)...)
		}
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("source_hash"), hash)...)

	if req.State.Raw.IsNull() {
		return
	}
	var state programModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if known(hash) && known(state.SourceHash) && hash.ValueString() != state.SourceHash.ValueString() {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("source_hash"))
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("tag"), types.StringUnknown())...)
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("id"), types.StringUnknown())...)
	}

	drift, diags := req.Private.GetKey(ctx, pinDriftKey)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if drift != nil {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("tag"))
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("tag"), types.StringUnknown())...)
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("id"), types.StringUnknown())...)
	}
}

func (r *programResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan programModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var obj []byte
	switch {
	case known(plan.ObjectFile):
		var err error
		obj, err = os.ReadFile(plan.ObjectFile.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("object_file"), "reading object file failed", err.Error())
			return
		}
	case known(plan.CSource):
		var err error
		obj, err = hive.CompileC(plan.CSource.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("c_source"), "compiling c_source failed", err.Error())
			return
		}
	default:
		resp.Diagnostics.AddAttributeError(path.Root("go_source"), "go_source not supported in this flavor", goSourceUnsupported)
		return
	}

	spec, err := hive.LoadELF(obj)
	if err != nil {
		resp.Diagnostics.AddError("invalid BPF object", err.Error())
		return
	}
	inferred := hive.ProgramTypeString(spec.Type)
	if known(plan.Type) && strings.ToLower(plan.Type.ValueString()) != inferred {
		resp.Diagnostics.AddAttributeError(path.Root("type"), "program type assertion failed",
			fmt.Sprintf("type is set to %q but the ELF section implies %q", plan.Type.ValueString(), inferred))
		return
	}

	pinPath := r.hive.PinPath("program", plan.Name.ValueString())
	exists, err := r.hive.PinExists(pinPath)
	if err != nil {
		resp.Diagnostics.AddError("checking pin path failed", err.Error())
		return
	}
	if exists {
		resp.Diagnostics.AddError("pin path already in use",
			fmt.Sprintf("%s already exists; import it or pick another name", pinPath))
		return
	}

	tag, err := r.hive.LoadAndPinProgram(spec, pinPath)
	if err != nil {
		resp.Diagnostics.AddError("loading BPF program failed", err.Error())
		return
	}

	plan.ID = types.StringValue(pinPath)
	plan.Type = types.StringValue(inferred)
	plan.Tag = types.StringValue(tag)
	plan.SourceHash = types.StringValue(sourceHash(plan, obj))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *programResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state programModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pinPath := state.ID.ValueString()
	exists, err := r.hive.PinExists(pinPath)
	if err != nil {
		resp.Diagnostics.AddError("checking pin path failed", err.Error())
		return
	}
	if !exists {
		resp.State.RemoveResource(ctx)
		return
	}

	typ, tag, err := r.hive.PinnedProgramInfo(pinPath)
	if err != nil {
		resp.Diagnostics.AddError("reading pinned program failed", err.Error())
		return
	}
	// A different tag or type means the pin was swapped out-of-band:
	// refresh the observed values and mark the drift in private state so
	// ModifyPlan forces a replacement that unpins the rogue pin.
	drifted := (known(state.Tag) && state.Tag.ValueString() != tag) ||
		(known(state.Type) && state.Type.ValueString() != typ)
	var driftValue []byte
	if drifted {
		driftValue = []byte(`true`)
	}
	resp.Diagnostics.Append(resp.Private.SetKey(ctx, pinDriftKey, driftValue)...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.Tag = types.StringValue(tag)
	state.Type = types.StringValue(typ)
	if state.Name.IsNull() {
		state.Name = types.StringValue(filepath.Base(pinPath))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *programResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Every meaningful change forces replacement; an update can only
	// carry identical values through, so persist the plan as-is with
	// unknowns filled from prior state.
	var plan, state programModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Type.IsUnknown() {
		plan.Type = state.Type
	}
	if plan.Tag.IsUnknown() {
		plan.Tag = state.Tag
	}
	if plan.SourceHash.IsUnknown() {
		plan.SourceHash = state.SourceHash
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *programResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state programModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.hive.Unpin(state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("unpinning program failed", err.Error())
	}
}

func (r *programResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// sourceHash fingerprints the effective program source: the object
// bytes for object_file, the source text for c_source. ModifyPlan
// computes the same value at plan time.
func sourceHash(plan programModel, obj []byte) string {
	if known(plan.CSource) {
		return hive.SourceHash([]byte(plan.CSource.ValueString()))
	}
	return hive.SourceHash(obj)
}

func known(v types.String) bool {
	return !v.IsNull() && !v.IsUnknown()
}
