package provider

import (
	"context"
	"fmt"
	"os"
	"sort"
	"syscall"

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

var cgroupAttachTypes = map[string]ebpf.AttachType{
	"cgroup_inet_ingress":      ebpf.AttachCGroupInetIngress,
	"cgroup_inet_egress":       ebpf.AttachCGroupInetEgress,
	"cgroup_inet_sock_create":  ebpf.AttachCGroupInetSockCreate,
	"cgroup_inet_sock_release": ebpf.AttachCgroupInetSockRelease,
	"cgroup_sock_ops":          ebpf.AttachCGroupSockOps,
	"cgroup_device":            ebpf.AttachCGroupDevice,
	"cgroup_inet4_bind":        ebpf.AttachCGroupInet4Bind,
	"cgroup_inet6_bind":        ebpf.AttachCGroupInet6Bind,
	"cgroup_inet4_post_bind":   ebpf.AttachCGroupInet4PostBind,
	"cgroup_inet6_post_bind":   ebpf.AttachCGroupInet6PostBind,
	"cgroup_inet4_connect":     ebpf.AttachCGroupInet4Connect,
	"cgroup_inet6_connect":     ebpf.AttachCGroupInet6Connect,
	"cgroup_udp4_sendmsg":      ebpf.AttachCGroupUDP4Sendmsg,
	"cgroup_udp6_sendmsg":      ebpf.AttachCGroupUDP6Sendmsg,
	"cgroup_udp4_recvmsg":      ebpf.AttachCGroupUDP4Recvmsg,
	"cgroup_udp6_recvmsg":      ebpf.AttachCGroupUDP6Recvmsg,
	"cgroup_sysctl":            ebpf.AttachCGroupSysctl,
	"cgroup_getsockopt":        ebpf.AttachCGroupGetsockopt,
	"cgroup_setsockopt":        ebpf.AttachCGroupSetsockopt,
}

func cgroupAttachTypeNames() []string {
	names := make([]string, 0, len(cgroupAttachTypes))
	for name := range cgroupAttachTypes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type cgroupModel struct {
	Name       types.String `tfsdk:"name"`
	Program    types.String `tfsdk:"program"`
	Cgroup     types.String `tfsdk:"cgroup"`
	AttachType types.String `tfsdk:"attach_type"`
	ID         types.String `tfsdk:"id"`
	LinkID     types.Int64  `tfsdk:"link_id"`
	ProgramID  types.Int64  `tfsdk:"program_id"`
}

func newCgroupResource() resource.Resource {
	return &attachmentResource{
		kind: "cgroup",
		desc: "Attaches a program to a cgroup through a pinned bpf_link.",
		extraAttributes: map[string]schema.Attribute{
			"program": programAttribute(),
			"cgroup": schema.StringAttribute{
				Required:      true,
				Description:   "Filesystem path of the cgroup to attach to.",
				PlanModifiers: replaceString(),
			},
			"attach_type": schema.StringAttribute{
				Required:      true,
				Description:   "Cgroup attach type, e.g. cgroup_inet_ingress.",
				Validators:    []validator.String{stringvalidator.OneOf(cgroupAttachTypeNames()...)},
				PlanModifiers: replaceString(),
			},
		},
		attach:  attachCgroup,
		matches: cgroupMatches,
	}
}

func attachCgroup(ctx context.Context, h *hive.Hive, plan tfsdk.Plan) (link.Link, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m cgroupModel
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

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    m.Cgroup.ValueString(),
		Attach:  cgroupAttachTypes[m.AttachType.ValueString()],
		Program: prog,
	})
	if err != nil {
		diags.AddError(fmt.Sprintf("attaching %s to cgroup %s", m.AttachType.ValueString(), m.Cgroup.ValueString()), err.Error())
		return nil, diags
	}
	return l, diags
}

func cgroupMatches(ctx context.Context, state tfsdk.State, info *link.Info) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	var m cgroupModel
	diags.Append(state.Get(ctx, &m)...)
	if diags.HasError() {
		return false, diags
	}
	cg := info.Cgroup()
	if cg == nil {
		return true, diags
	}
	if uint32(cg.AttachType) != uint32(cgroupAttachTypes[m.AttachType.ValueString()]) {
		return false, diags
	}
	// The kernel cgroup ID is the inode number of the cgroup directory.
	st, err := os.Stat(m.Cgroup.ValueString())
	if err != nil {
		return false, diags
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return cg.CgroupId == sys.Ino, diags
	}
	return true, diags
}
