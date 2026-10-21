package region

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// NetBirdTeardownResource is inventory for the existing teardown renderer. An
// identity in this list is never permission to delete it.
type NetBirdTeardownResource struct {
	Kind          string `json:"kind"`
	ID            string `json:"id"`
	CompartmentID string `json:"compartmentId"`
}

// VerifiedNetBirdNetworkTeardown seals observed provenance, not destructive
// authority. The current foundation grant still requires its manager to exist.
type VerifiedNetBirdNetworkTeardown struct {
	resources, keep                       []NetBirdTeardownResource
	blockers                              []string
	instanceID, operationID, intentDigest string
	generation                            uint64
	observedAt                            time.Time
	check                                 func(context.Context) error
}

func (v VerifiedNetBirdNetworkTeardown) Resources() []NetBirdTeardownResource {
	return slices.Clone(v.resources)
}
func (v VerifiedNetBirdNetworkTeardown) Keep() []NetBirdTeardownResource { return slices.Clone(v.keep) }
func (v VerifiedNetBirdNetworkTeardown) Blockers() []string              { return slices.Clone(v.blockers) }
func (v VerifiedNetBirdNetworkTeardown) InstanceID() string              { return v.instanceID }
func (v VerifiedNetBirdNetworkTeardown) OperationID() string             { return v.operationID }
func (v VerifiedNetBirdNetworkTeardown) Generation() uint64              { return v.generation }
func (v VerifiedNetBirdNetworkTeardown) ObservedAt() time.Time           { return v.observedAt }
func (v VerifiedNetBirdNetworkTeardown) CheckProvenance(ctx context.Context) error {
	if v.check == nil || len(v.resources) != 6 || v.generation == 0 {
		return errors.New("NetBird teardown has no authenticated observed provenance")
	}
	return v.check(ctx)
}

// ObserveNetBirdNetworkTeardown makes the six journal-owned network identities
// visible to teardown without treating tags, a stopped host or backup metadata
// as deletion authority. It performs no writes, including journal writes.
func ObserveNetBirdNetworkTeardown(ctx context.Context, factory *ociclient.Factory, resolver FoundationResolver) (VerifiedNetBirdNetworkTeardown, error) {
	if factory == nil || factory.Region() != foundationHomeRegion {
		return VerifiedNetBirdNetworkTeardown{}, errors.New("NetBird teardown requires authenticated GRU observation")
	}
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok {
		return VerifiedNetBirdNetworkTeardown{}, errors.New("NetBird teardown requires the current root-signed foundation")
	}
	intent, err := reader.authorizedNetBirdManager(ctx)
	if err != nil {
		return VerifiedNetBirdNetworkTeardown{}, err
	}
	record, err := resolver.Resolve(ctx, "GRU")
	if err != nil {
		return VerifiedNetBirdNetworkTeardown{}, err
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != record.TenancyID {
		return VerifiedNetBirdNetworkTeardown{}, errors.New("NetBird teardown observer belongs to another tenancy")
	}
	launch := record.NetBirdManager
	if launch == nil || launch.InstanceID == "" || launch.BootVolumeID == "" || launch.ProfileSHA256 != intent.profileDigest || launch.RecipeSHA256 != intent.recipeDigest {
		return VerifiedNetBirdNetworkTeardown{}, errors.New("NetBird teardown lacks the exact immutable manager and disk checkpoints")
	}
	footprint, err := reader.AuthorizedRegions(ctx)
	if err != nil {
		return VerifiedNetBirdNetworkTeardown{}, err
	}
	var plan map[string]any
	for _, region := range footprint.Regions {
		if region.Plan["cell"] == "GRU" {
			plan = region.Plan
		}
	}
	if plan == nil {
		return VerifiedNetBirdNetworkTeardown{}, errors.New("current footprint no longer proves the manager network provenance")
	}
	ids := map[string]any{}
	for key, id := range record.ResourceIDs {
		ids[key] = id
	}
	plan["resource_ids"] = ids
	deny := errors.New("NetBird teardown observation cannot create or adopt infrastructure")
	progress := FoundationProgress{OperationID: record.OperationID, AuxiliaryIDs: record.AuxiliaryIDs,
		BeforeWrite:         func(ctx context.Context, _ bool) (context.Context, func(), error) { return ctx, nil, deny },
		PrepareCreate:       func(context.Context, foundation.CreateIdentity, bool) error { return deny },
		CheckpointAuxiliary: func(context.Context, string, string) error { return deny }}
	subnet, nsg, err := ReconcileNetBirdNetwork(ctx, factory, plan, intent.intent.Profile, progress)
	if err != nil {
		return VerifiedNetBirdNetworkTeardown{}, err
	}
	v := VerifiedNetBirdNetworkTeardown{instanceID: launch.InstanceID, operationID: record.OperationID, intentDigest: record.IntentDigest, generation: record.Generation,
		blockers: []string{"current signed foundation requires the dedicated manager; no signed retirement intent exists", "protected backup and retention have no verified destructive authority"}}
	networkCompartment, controlCompartment := record.ResourceIDs["network_compartment"], record.ResourceIDs["control_compartment"]
	for _, resource := range []struct{ key, kind string }{{"subnet", "network-subnet"}, {"nsg", "network-nsg"}, {"security_list", "network-security-list"}, {"route", "network-route-table"}, {"internet_gateway", "network-internet-gateway"}, {"vcn", "network-vcn"}} {
		id := record.AuxiliaryIDs["netbird_manager_"+resource.key]
		if id == "" {
			return VerifiedNetBirdNetworkTeardown{}, errors.New("NetBird teardown has an incomplete network checkpoint")
		}
		v.resources = append(v.resources, NetBirdTeardownResource{Kind: resource.kind, ID: id, CompartmentID: networkCompartment})
	}
	v.keep = []NetBirdTeardownResource{{Kind: "boot-volume", ID: launch.BootVolumeID, CompartmentID: controlCompartment},
		{Kind: "kms-vault", ID: record.ResourceIDs["vault"], CompartmentID: controlCompartment}, {Kind: "kms-key", ID: record.ResourceIDs["key"], CompartmentID: controlCompartment},
		{Kind: "backup-bucket", ID: record.AuxiliaryIDs["backup_bucket"], CompartmentID: controlCompartment}, {Kind: "compartment", ID: networkCompartment}}
	for _, kept := range v.keep {
		if kept.ID == "" {
			return VerifiedNetBirdNetworkTeardown{}, errors.New("NetBird teardown cannot identify every retained recovery resource")
		}
	}
	compute, err := factory.Compute()
	if err != nil {
		return VerifiedNetBirdNetworkTeardown{}, err
	}
	instance, err := compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(launch.InstanceID)})
	if err != nil {
		return VerifiedNetBirdNetworkTeardown{}, err
	}
	p := intent.intent.Profile
	i := instance.Instance
	image, imageOK := i.SourceDetails.(core.InstanceSourceViaImageDetails)
	if value(i.Id) != launch.InstanceID || value(i.CompartmentId) != controlCompartment || value(i.AvailabilityDomain) != p.AvailabilityDomain || value(i.FaultDomain) != p.FaultDomain || value(i.Shape) != p.Shape ||
		i.ShapeConfig == nil || value(i.ShapeConfig.Ocpus) != p.OCPUs || value(i.ShapeConfig.MemoryInGBs) != p.MemoryGB || !imageOK || value(image.ImageId) != intent.intent.ImageOCID {
		return VerifiedNetBirdNetworkTeardown{}, errors.New("NetBird teardown observed a foreign or changed manager")
	}
	if i.LifecycleState != core.InstanceLifecycleStateTerminated {
		v.blockers = append(v.blockers, "the exact dedicated manager is not independently observed TERMINATED")
	}
	attachments, err := compute.ListVnicAttachments(ociclient.RequestContext(ctx), core.ListVnicAttachmentsRequest{CompartmentId: new(controlCompartment), InstanceId: new(launch.InstanceID)})
	if err != nil {
		return VerifiedNetBirdNetworkTeardown{}, err
	}
	if attachments.Items == nil || value(attachments.OpcNextPage) != "" {
		return VerifiedNetBirdNetworkTeardown{}, errors.New("NetBird teardown has unknown or incomplete instance attachments")
	}
	for _, attached := range attachments.Items {
		if value(attached.InstanceId) != launch.InstanceID || value(attached.CompartmentId) != controlCompartment {
			return VerifiedNetBirdNetworkTeardown{}, errors.New("NetBird teardown attachment belongs to another host or compartment")
		}
		if attached.LifecycleState != core.VnicAttachmentLifecycleStateDetached {
			v.blockers = append(v.blockers, "the manager still has a non-detached network attachment")
			break
		}
	}
	network, err := factory.Network()
	if err != nil {
		return VerifiedNetBirdNetworkTeardown{}, err
	}
	privateIPs, err := network.ListPrivateIps(ociclient.RequestContext(ctx), core.ListPrivateIpsRequest{SubnetId: new(subnet)})
	if err != nil {
		return VerifiedNetBirdNetworkTeardown{}, err
	}
	if privateIPs.Items == nil || value(privateIPs.OpcNextPage) != "" {
		return VerifiedNetBirdNetworkTeardown{}, errors.New("NetBird teardown has unknown or incomplete subnet users")
	}
	if len(privateIPs.Items) != 0 {
		v.blockers = append(v.blockers, "the manager subnet still contains private IP resources")
	}
	vnics, err := network.ListNetworkSecurityGroupVnics(ociclient.RequestContext(ctx), core.ListNetworkSecurityGroupVnicsRequest{NetworkSecurityGroupId: new(nsg)})
	if err != nil {
		return VerifiedNetBirdNetworkTeardown{}, err
	}
	if vnics.Items == nil || value(vnics.OpcNextPage) != "" {
		return VerifiedNetBirdNetworkTeardown{}, errors.New("NetBird teardown has unknown or incomplete NSG users")
	}
	if len(vnics.Items) != 0 {
		v.blockers = append(v.blockers, "the dedicated manager NSG still has VNIC users")
	}
	v.observedAt = time.Now().UTC()
	v.check = func(ctx context.Context) error {
		current, err := ObserveNetBirdNetworkTeardown(ctx, factory, resolver)
		if err != nil {
			return err
		}
		if current.instanceID != v.instanceID || current.operationID != v.operationID || current.intentDigest != v.intentDigest || current.generation != v.generation ||
			!reflect.DeepEqual(current.resources, v.resources) || !reflect.DeepEqual(current.keep, v.keep) || !slices.Equal(current.blockers, v.blockers) {
			return errors.New("current NetBird teardown provenance or observed safety state changed")
		}
		return ctx.Err()
	}
	return v, ctx.Err()
}
