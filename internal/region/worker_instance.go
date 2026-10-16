package region

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// VerifiedWorkerInstance requires provider-linked protected instance creation
// and current SDK facts matching the independent root policy and generated source.
type VerifiedWorkerInstance struct {
	pool                                  oci.VerifiedPoolInstance
	recipe                                VerifiedWorkerRecipe
	instanceID, privateIP, vnicID, bootID string
	expires                               time.Time
}

func (v VerifiedWorkerInstance) IsVerified() bool {
	return v.pool.IsVerified() && v.recipe.IsVerified() && v.instanceID != "" && time.Now().Before(v.expires)
}
func (v VerifiedWorkerInstance) InstanceID() string           { return v.instanceID }
func (v VerifiedWorkerInstance) PrivateIP() string            { return v.privateIP }
func (v VerifiedWorkerInstance) Recipe() VerifiedWorkerRecipe { return v.recipe }
func (v VerifiedWorkerInstance) ExpiresAt() time.Time         { return v.expires }

func (v VerifiedWorkerInstance) Revalidate(ctx context.Context) error {
	if !v.IsVerified() {
		return errors.New("worker instance has no current independent authority")
	}
	if err := v.recipe.Revalidate(ctx); err != nil {
		return err
	}
	resolver := FoundationResolver{Footprint: v.recipe.profile.reader}
	current, err := resolver.AuthorizeWorkerInstance(ctx, v.pool)
	if err != nil {
		return err
	}
	if current.instanceID != v.instanceID || current.privateIP != v.privateIP || current.vnicID != v.vnicID || current.bootID != v.bootID {
		return errors.New("worker instance attachment or address changed since admission")
	}
	return nil
}

// AuthorizeWorkerInstance never accepts instance tags, observed names or an
// enrollment assertion as a substitute for protected original create evidence.
func (r FoundationResolver) AuthorizeWorkerInstance(ctx context.Context, pool oci.VerifiedPoolInstance) (VerifiedWorkerInstance, error) {
	reader, ok := r.Footprint.(*SignedFootprint)
	if !ok || reader.factory == nil || !pool.IsVerified() {
		return VerifiedWorkerInstance{}, errors.New("worker instance requires independent OCI and protected instance creation authority")
	}
	if err := pool.Revalidate(ctx); err != nil {
		return VerifiedWorkerInstance{}, err
	}
	entry, known := catalog.Lookup(strings.ToUpper(pool.Cell()))
	if !known {
		return VerifiedWorkerInstance{}, errors.New("worker instance is outside the reviewed regional catalog")
	}
	factory, err := reader.factory.ForRegion(entry.OCIRegion)
	if err != nil {
		return VerifiedWorkerInstance{}, err
	}
	candidate, privateIP, vnicID, bootID, err := readWorkerInstance(ctx, factory, pool.InstanceID(), pool.ConfigurationID(), pool.Cell(), pool.Role(), pool.Architecture())
	if err != nil {
		return VerifiedWorkerInstance{}, err
	}
	recipe, err := r.AuthorizeWorkerRecipe(ctx, candidate)
	if err != nil {
		return VerifiedWorkerInstance{}, err
	}
	if recipe.Profile().GrantDigest() != pool.GrantDigest() || recipe.Profile().Generation() != pool.Generation() {
		return VerifiedWorkerInstance{}, errors.New("worker instance creation differs from the exact root grant generation")
	}
	if err := pool.Revalidate(ctx); err != nil {
		return VerifiedWorkerInstance{}, err
	}
	expires := recipe.Profile().ExpiresAt()
	for _, deadline := range []time.Time{recipe.source.ExpiresAt(), pool.ExpiresAt()} {
		if deadline.Before(expires) {
			expires = deadline
		}
	}
	verified := VerifiedWorkerInstance{pool: pool, recipe: recipe, instanceID: pool.InstanceID(), privateIP: privateIP, vnicID: vnicID, bootID: bootID, expires: expires}
	if !verified.IsVerified() {
		return VerifiedWorkerInstance{}, errors.New("worker authority expired during independent instance observations")
	}
	return verified, nil
}

func readWorkerInstance(ctx context.Context, factory *ociclient.Factory, instanceID, configurationID, cell, role, expectedArchitecture string) (WorkerRecipe, string, string, string, error) {
	fail := func(err error) (WorkerRecipe, string, string, string, error) { return WorkerRecipe{}, "", "", "", err }
	compute, err := factory.Compute()
	if err != nil {
		return fail(err)
	}
	response, err := compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(instanceID)})
	if err != nil {
		return fail(err)
	}
	instance := response.Instance
	if workerString(instance.Id) != instanceID || instance.LifecycleState != core.InstanceLifecycleStateRunning ||
		workerString(instance.InstanceConfigurationId) != configurationID || workerString(instance.CompartmentId) == "" ||
		workerString(instance.AvailabilityDomain) == "" || workerString(instance.Shape) == "" || instance.ShapeConfig == nil ||
		instance.ShapeConfig.Ocpus == nil || instance.ShapeConfig.MemoryInGBs == nil || instance.InstanceOptions == nil ||
		instance.InstanceOptions.AreLegacyImdsEndpointsDisabled == nil || !*instance.InstanceOptions.AreLegacyImdsEndpointsDisabled ||
		len(instance.ExtendedMetadata) != 0 || workerString(instance.IpxeScript) != "" {
		return fail(errors.New("worker SDK instance lacks exact running configuration and launch geometry"))
	}
	architecture, err := catalog.ShapeArchitecture(workerString(instance.ShapeConfig.ProcessorDescription))
	if err != nil || architecture != expectedArchitecture {
		return fail(errors.New("worker actual processor differs from protected native architecture"))
	}
	source, ok := instance.SourceDetails.(core.InstanceSourceViaImageDetails)
	if !ok || workerString(source.ImageId) == "" || workerString(instance.ImageId) != "" && workerString(instance.ImageId) != workerString(source.ImageId) {
		return fail(errors.New("worker instance has no exact image source"))
	}
	candidate := WorkerRecipe{Cell: strings.ToLower(cell), Environment: "production", Role: role, Architecture: architecture,
		ImageID: workerString(source.ImageId), CompartmentID: workerString(instance.CompartmentId), AvailabilityDomains: []string{workerString(instance.AvailabilityDomain)},
		Shape: workerString(instance.Shape), OCPUs: float64(*instance.ShapeConfig.Ocpus), MemoryGB: float64(*instance.ShapeConfig.MemoryInGBs), Metadata: maps.Clone(instance.Metadata)}
	bootID, bootGB, err := workerBootVolume(ctx, factory, compute, candidate, instanceID)
	if err != nil {
		return fail(err)
	}
	candidate.BootGB = bootGB
	privateIP, vnicID, subnetID, nsgIDs, err := workerPrimaryNetwork(ctx, factory, compute, candidate, instanceID)
	if err != nil {
		return fail(err)
	}
	candidate.SubnetID, candidate.NSGIDs = subnetID, nsgIDs
	return candidate, privateIP, vnicID, bootID, nil
}

func workerBootVolume(ctx context.Context, factory *ociclient.Factory, compute core.ComputeClient, recipe WorkerRecipe, instanceID string) (string, int64, error) {
	var page *string
	seen := map[string]bool{}
	bootID := ""
	count := 0
	for {
		response, err := compute.ListBootVolumeAttachments(ctx, core.ListBootVolumeAttachmentsRequest{CompartmentId: new(recipe.CompartmentID), AvailabilityDomain: new(recipe.AvailabilityDomains[0]), InstanceId: new(instanceID), Page: page})
		if err != nil {
			return "", 0, err
		}
		count += len(response.Items)
		if count > 64 {
			return "", 0, errors.New("worker boot attachment inventory exceeds its finite bound")
		}
		for _, attachment := range response.Items {
			if workerString(attachment.InstanceId) != instanceID || workerString(attachment.CompartmentId) != recipe.CompartmentID || workerString(attachment.AvailabilityDomain) != recipe.AvailabilityDomains[0] {
				return "", 0, errors.New("worker boot attachment belongs to a different recipient")
			}
			if attachment.LifecycleState == core.BootVolumeAttachmentLifecycleStateDetached {
				continue
			}
			if attachment.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached || bootID != "" || workerString(attachment.BootVolumeId) == "" {
				return "", 0, errors.New("worker needs exactly one stable attached boot volume")
			}
			bootID = workerString(attachment.BootVolumeId)
		}
		page, err = workerNextPage(response.OpcNextPage, seen)
		if err != nil {
			return "", 0, err
		}
		if page == nil {
			break
		}
	}
	if bootID == "" {
		return "", 0, errors.New("worker boot volume is absent")
	}
	blocks, err := factory.Blockstorage()
	if err != nil {
		return "", 0, err
	}
	volume, err := blocks.GetBootVolume(ctx, core.GetBootVolumeRequest{BootVolumeId: new(bootID)})
	if err != nil {
		return "", 0, err
	}
	boot := volume.BootVolume
	if workerString(boot.Id) != bootID || workerString(boot.CompartmentId) != recipe.CompartmentID || workerString(boot.AvailabilityDomain) != recipe.AvailabilityDomains[0] || workerString(boot.ImageId) != recipe.ImageID || boot.SizeInGBs == nil || boot.LifecycleState != core.BootVolumeLifecycleStateAvailable {
		return "", 0, errors.New("worker boot volume differs from the actual instance image or placement")
	}
	page, seen = nil, map[string]bool{}
	count = 0
	for {
		response, err := compute.ListVolumeAttachments(ctx, core.ListVolumeAttachmentsRequest{CompartmentId: new(recipe.CompartmentID), InstanceId: new(instanceID), Page: page})
		if err != nil {
			return "", 0, err
		}
		count += len(response.Items)
		if count > 64 {
			return "", 0, errors.New("worker data attachment inventory exceeds its finite bound")
		}
		for _, attachment := range response.Items {
			if attachment == nil || workerString(attachment.GetInstanceId()) != instanceID || attachment.GetLifecycleState() != core.VolumeAttachmentLifecycleStateDetached {
				return "", 0, errors.New("worker has data storage outside its signed launch recipe")
			}
		}
		page, err = workerNextPage(response.OpcNextPage, seen)
		if err != nil {
			return "", 0, err
		}
		if page == nil {
			break
		}
	}
	return bootID, *boot.SizeInGBs, nil
}

func workerPrimaryNetwork(ctx context.Context, factory *ociclient.Factory, compute core.ComputeClient, recipe WorkerRecipe, instanceID string) (string, string, string, []string, error) {
	fail := func(err error) (string, string, string, []string, error) { return "", "", "", nil, err }
	network, err := factory.Network()
	if err != nil {
		return fail(err)
	}
	var page *string
	seen := map[string]bool{}
	privateIP, vnicID, subnetID := "", "", ""
	var nsgIDs []string
	count := 0
	for {
		response, err := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{CompartmentId: new(recipe.CompartmentID), InstanceId: new(instanceID), Page: page})
		if err != nil {
			return fail(err)
		}
		count += len(response.Items)
		if count > 64 {
			return fail(errors.New("worker VNIC inventory exceeds its finite bound"))
		}
		for _, attachment := range response.Items {
			if workerString(attachment.InstanceId) != instanceID || workerString(attachment.CompartmentId) != recipe.CompartmentID {
				return fail(errors.New("worker VNIC attachment belongs to another recipient"))
			}
			if attachment.LifecycleState == core.VnicAttachmentLifecycleStateDetached {
				continue
			}
			if attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached || vnicID != "" || workerString(attachment.VnicId) == "" {
				return fail(errors.New("worker needs exactly one stable primary VNIC"))
			}
			observed, err := network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachment.VnicId})
			if err != nil {
				return fail(err)
			}
			vnic := observed.Vnic
			address, err := netip.ParseAddr(workerString(vnic.PrivateIp))
			if workerString(vnic.Id) != workerString(attachment.VnicId) || vnic.LifecycleState != core.VnicLifecycleStateAvailable || vnic.IsPrimary == nil || !*vnic.IsPrimary || workerString(vnic.PublicIp) != "" || vnic.SkipSourceDestCheck == nil || *vnic.SkipSourceDestCheck || workerString(vnic.SubnetId) != workerString(attachment.SubnetId) || workerString(vnic.AvailabilityDomain) != recipe.AvailabilityDomains[0] || err != nil || !address.Is4() || !address.IsPrivate() {
				return fail(errors.New("worker actual VNIC differs from its private primary launch topology"))
			}
			privateIP, vnicID, subnetID, nsgIDs = address.String(), workerString(vnic.Id), workerString(vnic.SubnetId), append([]string(nil), vnic.NsgIds...)
		}
		page, err = workerNextPage(response.OpcNextPage, seen)
		if err != nil {
			return fail(err)
		}
		if page == nil {
			break
		}
	}
	if vnicID == "" {
		return fail(errors.New("worker primary VNIC is absent"))
	}
	return privateIP, vnicID, subnetID, nsgIDs, nil
}

func workerNextPage(next *string, seen map[string]bool) (*string, error) {
	if next == nil || *next == "" {
		return nil, nil
	}
	if seen[*next] || len(seen) >= 64 {
		return nil, errors.New("worker instance inventory pagination repeats or exceeds its finite bound")
	}
	seen[*next] = true
	return new(*next), nil
}

func workerString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
