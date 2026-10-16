package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// The foundation owner is also the singleton host owner. A lost launch response
// retains its original request and token; no discovery miss buys another host.
func reconcileNetBirdManager(ctx context.Context, factory *ociclient.Factory, plan map[string]any, progress FoundationProgress) error {
	if progress.ManagerAuthority == nil || progress.ManagerAllocation == nil || progress.CheckpointManager == nil {
		return errors.New("dedicated manager lacks same-grant authority and durable checkpoints")
	}
	intent, err := progress.ManagerAuthority(ctx)
	if err != nil {
		return err
	}
	ids, ok := plan["resource_ids"].(map[string]any)
	if !ok {
		return errors.New("dedicated manager foundation resource identities are absent")
	}
	compartment, _ := ids["control_compartment"].(string)
	slotID := BootstrapSlotID(intent.installationID, "GRU", NetBirdManagerRole, NetBirdManagerRole)
	allocation, err := progress.ManagerAllocation(ctx, slotID)
	if err != nil {
		return err
	}
	prices, err := capacityinventory.New(factory)
	if err != nil {
		return err
	}
	p := intent.intent.Profile
	quote, err := prices.Quote(ctx, allocation.Footprint(), "GRU", compartment, p.Shape, float64(p.OCPUs), float64(p.MemoryGB), float64(p.BootVolumeGB))
	if err != nil {
		return err
	}
	launch := NetBirdManagerLaunch{SlotID: slotID, OperationID: allocation.OperationID(), ProfileSHA256: intent.profileDigest,
		RecipeSHA256: intent.recipeDigest, StartedAt: time.Now().UTC(), StoreState: "empty"}
	if progress.NetBirdManager != nil {
		launch = *progress.NetBirdManager
		if launch.SlotID != slotID || launch.OperationID != allocation.OperationID() || launch.ProfileSHA256 != intent.profileDigest || launch.RecipeSHA256 != intent.recipeDigest {
			return errors.New("dedicated manager recipe changed while its singleton reservation exists")
		}
	}
	request := func(digest, token string) BootstrapLaunchRequest {
		return BootstrapLaunchRequest{SlotID: slotID, OperationID: launch.OperationID, Cell: "GRU", CompartmentID: compartment,
			ProfileSHA256: intent.profileDigest, RecipeSHA256: intent.recipeDigest, Shape: p.Shape, OCPUs: float64(p.OCPUs), MemoryGB: float64(p.MemoryGB), BootGB: float64(p.BootVolumeGB),
			RequestSHA256: digest, RetryToken: token, StartedAt: launch.StartedAt}
	}
	// Network OCIDs do not exist yet. Validate the finite logical allocation
	// before its first effect; the actual compute body is pinned after networking.
	preflightDigest := intent.recipeDigest
	preflightToken := BootstrapRetryToken(launch.OperationID, preflightDigest)
	if err := allocation.Validate(request(preflightDigest, preflightToken), quote, time.Now()); err != nil {
		return err
	}
	guard := progress.BeforeWrite
	progress.BeforeWrite = func(ctx context.Context, home bool) (context.Context, func(), error) {
		current, err := progress.ManagerAuthority(ctx)
		if err != nil {
			return ctx, nil, err
		}
		if current.installationID != intent.installationID || current.generation != intent.generation || current.profileDigest != intent.profileDigest || current.recipeDigest != intent.recipeDigest {
			return ctx, nil, ErrFoundationFenced
		}
		nextAllocation, err := progress.ManagerAllocation(ctx, slotID)
		if err != nil {
			return ctx, nil, err
		}
		if nextAllocation.GrantDigest() != allocation.GrantDigest() {
			return ctx, nil, ErrFoundationFenced
		}
		if err := nextAllocation.Validate(request(preflightDigest, preflightToken), quote, time.Now()); err != nil {
			return ctx, nil, err
		}
		return guard(ctx, home)
	}
	subnet, nsg, err := ReconcileNetBirdNetwork(ctx, factory, plan, p, progress)
	if err != nil {
		return err
	}
	details := netBirdLaunchDetails(intent.intent, compartment, subnet, nsg)
	digest, err := netBirdRequestDigest(details)
	if err != nil {
		return err
	}
	if launch.RequestDigest != "" && launch.RequestDigest != digest {
		return errors.New("actual dedicated manager SDK launch body differs from its immutable checkpoint")
	}
	launch.RequestDigest, launch.RetryToken = digest, BootstrapRetryToken(launch.OperationID, digest)
	if err := allocation.Validate(request(digest, launch.RetryToken), quote, time.Now()); err != nil {
		return err
	}
	if err := progress.CheckpointManager(ctx, launch); err != nil {
		return err
	}
	if launch.InstanceID == "" {
		compute, err := factory.Compute()
		if err != nil {
			return err
		}
		guardCtx, release, err := progress.BeforeWrite(ctx, false)
		if err != nil {
			return err
		}
		if guardCtx == nil || release == nil {
			return errors.New("dedicated manager has no leased effect context")
		}
		defer release()
		// Hash the exact SDK body again at the mutation boundary.
		actual, err := netBirdRequestDigest(details)
		if err != nil || actual != launch.RequestDigest {
			return errors.Join(errors.New("dedicated manager SDK body changed"), err)
		}
		if err := allocation.Validate(request(actual, launch.RetryToken), quote, time.Now()); err != nil {
			return err
		}
		policy := common.NoRetryPolicy()
		guardCtx = ociclient.WithAuthority(guardCtx, func(ctx context.Context) error {
			bodyDigest, err := netBirdRequestDigest(details)
			if err != nil || bodyDigest != launch.RequestDigest {
				return errors.Join(ErrFoundationFenced, err)
			}
			child, done, err := progress.BeforeWrite(ctx, false)
			if err != nil {
				return err
			}
			if child == nil || done == nil {
				return ErrFoundationFenced
			}
			defer done()
			return allocation.Validate(request(bodyDigest, launch.RetryToken), quote, time.Now())
		})
		response, err := compute.LaunchInstance(ociclient.RequestContext(guardCtx), core.LaunchInstanceRequest{LaunchInstanceDetails: details,
			OpcRetryToken: new(launch.RetryToken), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}})
		if err != nil {
			return err
		}
		if response.Id == nil || *response.Id == "" {
			return errors.New("dedicated manager launch returned no exact instance identity")
		}
		launch.InstanceID = *response.Id
		if err := progress.CheckpointManager(ctx, launch); err != nil {
			return err
		}
	}
	boot, err := observeNetBirdGeometry(ctx, factory, intent.intent, launch, compartment)
	if err != nil {
		return err
	}
	launch.BootVolumeID = boot
	return progress.CheckpointManager(ctx, launch)
}

func netBirdLaunchDetails(intent NetBirdManagerIntent, compartment, subnet, nsg string) core.LaunchInstanceDetails {
	p := intent.Profile
	return core.LaunchInstanceDetails{AvailabilityDomain: new(p.AvailabilityDomain), CompartmentId: new(compartment), FaultDomain: new(p.FaultDomain),
		DisplayName: new("gru-1-netbird-manager"), Shape: new(p.Shape),
		ShapeConfig:       &core.LaunchInstanceShapeConfigDetails{Ocpus: new(p.OCPUs), MemoryInGBs: new(p.MemoryGB)},
		SourceDetails:     core.InstanceSourceViaImageDetails{ImageId: new(intent.ImageOCID), BootVolumeSizeInGBs: new(p.BootVolumeGB), BootVolumeVpusPerGB: new(int64(10))},
		CreateVnicDetails: &core.CreateVnicDetails{SubnetId: new(subnet), NsgIds: []string{nsg}, PrivateIp: new(p.PrivateIP), AssignPublicIp: new(true)}}
}

func netBirdRequestDigest(details core.LaunchInstanceDetails) (string, error) {
	wire, err := json.Marshal(details, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

func observeNetBirdGeometry(ctx context.Context, factory *ociclient.Factory, intent NetBirdManagerIntent, launch NetBirdManagerLaunch, compartment string) (string, error) {
	compute, err := factory.Compute()
	if err != nil {
		return "", err
	}
	response, err := compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(launch.InstanceID)})
	if err != nil {
		return "", err
	}
	i, p := response.Instance, intent.Profile
	if i.Id == nil || *i.Id != launch.InstanceID || i.CompartmentId == nil || *i.CompartmentId != compartment ||
		i.AvailabilityDomain == nil || *i.AvailabilityDomain != p.AvailabilityDomain || i.FaultDomain == nil || *i.FaultDomain != p.FaultDomain ||
		i.Shape == nil || *i.Shape != p.Shape || i.ShapeConfig == nil || i.ShapeConfig.Ocpus == nil || *i.ShapeConfig.Ocpus != p.OCPUs ||
		i.ShapeConfig.MemoryInGBs == nil || *i.ShapeConfig.MemoryInGBs != p.MemoryGB || i.LifecycleState != core.InstanceLifecycleStateRunning || len(i.Metadata) != 0 || len(i.ExtendedMetadata) != 0 {
		return "", errors.New("dedicated manager observed instance geometry or boot metadata differs")
	}
	image, ok := i.SourceDetails.(core.InstanceSourceViaImageDetails)
	if !ok || image.ImageId == nil || *image.ImageId != intent.ImageOCID {
		return "", errors.New("dedicated manager exact instance image provenance is absent")
	}
	vnics, err := compute.ListVnicAttachments(ociclient.RequestContext(ctx), core.ListVnicAttachmentsRequest{CompartmentId: new(compartment), InstanceId: new(launch.InstanceID)})
	if err != nil {
		return "", err
	}
	if len(vnics.Items) != 1 || vnics.OpcNextPage != nil && *vnics.OpcNextPage != "" {
		return "", errors.New("dedicated manager must have exactly one network attachment")
	}
	attachment := vnics.Items[0]
	if attachment.InstanceId == nil || *attachment.InstanceId != launch.InstanceID || attachment.VnicId == nil || attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached {
		return "", errors.New("dedicated manager network attachment has no exact current instance")
	}
	network, err := factory.Network()
	if err != nil {
		return "", err
	}
	vnicResponse, err := network.GetVnic(ociclient.RequestContext(ctx), core.GetVnicRequest{VnicId: attachment.VnicId})
	if err != nil {
		return "", err
	}
	vnic := vnicResponse.Vnic
	public, publicErr := netip.ParseAddr(value(vnic.PublicIp))
	if vnic.Id == nil || *vnic.Id != *attachment.VnicId || vnic.IsPrimary == nil || !*vnic.IsPrimary || vnic.PrivateIp == nil || *vnic.PrivateIp != p.PrivateIP ||
		vnic.SkipSourceDestCheck == nil || *vnic.SkipSourceDestCheck || publicErr != nil || !public.Is4() || !public.IsGlobalUnicast() || public.IsPrivate() ||
		len(vnic.Ipv6Addresses) != 0 || vnic.LifecycleState != core.VnicLifecycleStateAvailable {
		return "", errors.New("dedicated manager public primary VNIC differs or permits forwarding")
	}
	attachments, err := compute.ListBootVolumeAttachments(ociclient.RequestContext(ctx), core.ListBootVolumeAttachmentsRequest{CompartmentId: new(compartment),
		AvailabilityDomain: new(p.AvailabilityDomain), InstanceId: new(launch.InstanceID)})
	if err != nil {
		return "", err
	}
	if len(attachments.Items) != 1 || attachments.OpcNextPage != nil && *attachments.OpcNextPage != "" {
		return "", errors.New("dedicated manager boot volume attachment is ambiguous")
	}
	a := attachments.Items[0]
	if a.InstanceId == nil || *a.InstanceId != launch.InstanceID || a.BootVolumeId == nil || a.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached ||
		launch.BootVolumeID != "" && *a.BootVolumeId != launch.BootVolumeID {
		return "", errors.New("dedicated manager boot volume differs from its checkpoint")
	}
	volume, err := factory.Blockstorage()
	if err != nil {
		return "", err
	}
	boot, err := volume.GetBootVolume(ociclient.RequestContext(ctx), core.GetBootVolumeRequest{BootVolumeId: a.BootVolumeId})
	if err != nil {
		return "", err
	}
	b := boot.BootVolume
	if b.Id == nil || *b.Id != *a.BootVolumeId || b.CompartmentId == nil || *b.CompartmentId != compartment || b.ImageId == nil || *b.ImageId != intent.ImageOCID ||
		b.SizeInGBs == nil || *b.SizeInGBs != p.BootVolumeGB || b.VpusPerGB == nil || *b.VpusPerGB != 10 || b.LifecycleState != core.BootVolumeLifecycleStateAvailable {
		return "", errors.New("dedicated manager boot volume image or billing geometry differs")
	}
	return *b.Id, nil
}

// netBirdObservedInstance checks the entire isolated network and exact disk
// before the generic local-instance admission can release a sealed claim.
type netBirdObservedInstance struct {
	factory  *ociclient.Factory
	resolver FoundationResolver
	reader   *SignedFootprint
	observer bootstrapstart.InstanceObserver
}

func (o netBirdObservedInstance) ObserveInstance(ctx context.Context, id string) (bootstrapstart.InstanceObservation, error) {
	intent, err := o.reader.authorizedNetBirdManager(ctx)
	if err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	record, err := o.resolver.Resolve(ctx, "GRU")
	if err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	if record.NetBirdManager == nil || record.NetBirdManager.InstanceID != id || record.NetBirdManager.BootVolumeID == "" {
		return bootstrapstart.InstanceObservation{}, errors.New("dedicated manager exact instance and disk checkpoints are absent")
	}
	footprint, err := o.reader.AuthorizedRegions(ctx)
	if err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	var plan map[string]any
	for _, r := range footprint.Regions {
		if r.Plan["cell"] == "GRU" {
			plan = r.Plan
		}
	}
	ids := map[string]any{}
	for key, value := range record.ResourceIDs {
		ids[key] = value
	}
	plan["resource_ids"] = ids
	progress := FoundationProgress{OperationID: record.OperationID, AuxiliaryIDs: record.AuxiliaryIDs,
		BeforeWrite: func(ctx context.Context, _ bool) (context.Context, func(), error) {
			return ctx, nil, errors.New("manager admission cannot create or repair network resources")
		},
		PrepareCreate: func(context.Context, foundation.CreateIdentity, bool) error {
			return errors.New("manager admission cannot prepare network creates")
		},
		CheckpointAuxiliary: func(context.Context, string, string) error {
			return errors.New("manager admission cannot adopt network resources")
		}}
	if _, _, err := ReconcileNetBirdNetwork(ctx, o.factory, plan, intent.intent.Profile, progress); err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	if _, err := observeNetBirdGeometry(ctx, o.factory, intent.intent, *record.NetBirdManager, record.ResourceIDs["control_compartment"]); err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	observed, err := o.observer.ObserveInstance(ctx, id)
	if err == nil && !slices.Equal(observed.NSGOCIDs, []string{record.AuxiliaryIDs["netbird_manager_nsg"]}) {
		return bootstrapstart.InstanceObservation{}, errors.New("dedicated manager network security attachment differs")
	}
	return observed, err
}
