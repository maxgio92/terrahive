// Package provider implements the terrahive Terraform provider.
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/maxgio92/terrahive/internal/hive"
)

// TerrahiveProvider manages kernel BPF objects on the local machine.
type TerrahiveProvider struct {
	version string
}

type terrahiveProviderModel struct {
	PinDir types.String `tfsdk:"pin_dir"`
}

var _ provider.Provider = (*TerrahiveProvider)(nil)

// New returns a provider factory for providerserver.Serve.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &TerrahiveProvider{version: version}
	}
}

func (p *TerrahiveProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "terrahive"
	resp.Version = p.version
}

func (p *TerrahiveProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage eBPF programs, maps, and attachments on the local Linux kernel.",
		Attributes: map[string]schema.Attribute{
			"pin_dir": schema.StringAttribute{
				Optional:    true,
				Description: "bpffs directory where managed objects are pinned. Defaults to " + hive.DefaultPinDir + ".",
			},
		},
	}
}

func (p *TerrahiveProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config terrahiveProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	h, err := hive.New(config.PinDir.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("terrahive provider configuration failed", err.Error())
		return
	}

	resp.ResourceData = h
	resp.DataSourceData = h
}

func (p *TerrahiveProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newKprobeResource,
		newTracepointResource,
		newTracingResource,
		newXDPResource,
		newTCXResource,
		newCgroupResource,
		newNetfilterResource,
		newStructOpsResource,
	}
}

func (p *TerrahiveProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
