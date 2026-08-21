package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/cilium/ebpf/link"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/maxgio92/terrahive/internal/hive"
)

var pinNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// attachmentResource implements the CRUD shared by every link-family
// resource. A kernel bpf_link is immutable, so every attribute forces
// replacement: Create attaches and pins, Read detects drift through the
// pinned link, Delete unpins, which detaches without unloading the
// referenced program.
type attachmentResource struct {
	hive *hive.Hive
	kind string
	desc string
	// extraAttributes hold the family-specific target attributes, all
	// of which must force replacement.
	extraAttributes map[string]schema.Attribute
	// attach creates the kernel link for the planned configuration.
	attach func(ctx context.Context, h *hive.Hive, plan tfsdk.Plan) (link.Link, diag.Diagnostics)
	// matches reports whether the pinned link still targets what state
	// says. Nil when link and program IDs are the only verifiable state.
	matches func(ctx context.Context, state tfsdk.State, info *link.Info) (bool, diag.Diagnostics)
}

var _ resource.Resource = (*attachmentResource)(nil)
var _ resource.ResourceWithConfigure = (*attachmentResource)(nil)

func (r *attachmentResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "ebpf_" + r.kind
}

func (r *attachmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := map[string]schema.Attribute{
		"name": schema.StringAttribute{
			Required:      true,
			Description:   "Pin name of the link under the hive pin directory.",
			Validators:    []validator.String{stringvalidator.RegexMatches(pinNameRe, "must be a valid bpffs pin name")},
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"id": schema.StringAttribute{
			Computed:    true,
			Description: "bpffs pin path of the link.",
		},
		"link_id": schema.Int64Attribute{
			Computed:    true,
			Description: "Kernel ID of the bpf_link.",
		},
		"program_id": schema.Int64Attribute{
			Computed:    true,
			Description: "Kernel ID of the attached program.",
		},
	}
	for name, attr := range r.extraAttributes {
		attrs[name] = attr
	}
	resp.Schema = schema.Schema{
		Description: r.desc,
		Attributes:  attrs,
	}
}

func (r *attachmentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *attachmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var name types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("name"), &name)...)
	if resp.Diagnostics.HasError() {
		return
	}

	l, diags := r.attach(ctx, r.hive, req.Plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	defer func() { _ = l.Close() }()

	pinPath := r.hive.PinPath(r.kind, name.ValueString())
	if err := r.hive.PinLink(l, pinPath); err != nil {
		resp.Diagnostics.AddError("pinning "+r.kind+" link", err.Error())
		return
	}
	info, err := l.Info()
	if err != nil {
		_ = r.hive.Unpin(pinPath)
		resp.Diagnostics.AddError("reading "+r.kind+" link info", err.Error())
		return
	}

	resp.State.Raw = req.Plan.Raw
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), pinPath)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("link_id"), int64(info.ID))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("program_id"), int64(info.Program))...)
}

func (r *attachmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var id types.String
	var linkID, programID types.Int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("id"), &id)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("link_id"), &linkID)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("program_id"), &programID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	l, err := r.hive.LoadPinnedLink(id.ValueString())
	if errors.Is(err, os.ErrNotExist) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("loading pinned "+r.kind+" link", err.Error())
		return
	}
	defer func() { _ = l.Close() }()

	info, err := l.Info()
	if err != nil {
		resp.Diagnostics.AddError("reading "+r.kind+" link info", err.Error())
		return
	}
	if int64(info.ID) != linkID.ValueInt64() || int64(info.Program) != programID.ValueInt64() {
		resp.State.RemoveResource(ctx)
		return
	}
	if r.matches != nil {
		ok, diags := r.matches(ctx, req.State, info)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		if !ok {
			resp.State.RemoveResource(ctx)
			return
		}
	}
	resp.State.Raw = req.State.Raw
}

// Update only satisfies the interface: every attribute forces replacement.
func (r *attachmentResource) Update(_ context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.State.Raw = req.Plan.Raw
}

func (r *attachmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var id types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("id"), &id)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.hive.Unpin(id.ValueString()); err != nil {
		resp.Diagnostics.AddError("unpinning "+r.kind+" link", err.Error())
	}
}

// programAttribute is the program reference shared by the link families
// that attach a program. It is a bpffs pin path so that program
// replacement cascades into attachment replacement.
func programAttribute() schema.Attribute {
	return schema.StringAttribute{
		Required:      true,
		Description:   "bpffs pin path of the program to attach.",
		PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
	}
}

func replaceString() []planmodifier.String {
	return []planmodifier.String{stringplanmodifier.RequiresReplace()}
}

func replaceInt64() []planmodifier.Int64 {
	return []planmodifier.Int64{int64planmodifier.RequiresReplace()}
}
