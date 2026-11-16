package bootstrapstart

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"maps"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
	"golang.org/x/sys/unix"
)

const OriginalStartupOriginFilename = "original-startup-origin.json"
const maxOriginalStartupOriginBytes = 2 << 20

// ErrNotOriginalStartup means both public origin transports are absent. Invalid
// present origin data must never route to ordinary startup.
var ErrNotOriginalStartup = errors.New("original startup provenance is absent")
var ErrOriginalStartup = errors.New("original startup provenance or local host differs")

type originalStartupOrigin struct {
	SchemaVersion int        `json:"schemaVersion"`
	Cell          oci.Region `json:"cell"`
	AnchorWire    []byte     `json:"anchorWire"`
	RootChainWire []byte     `json:"rootChainWire"`
	GrantWire     []byte     `json:"grantWire"`
	AuthorityWire []byte     `json:"authorityWire"`
}

func parseOriginalStartupOrigin(wire []byte) (originalStartupOrigin, error) {
	var origin originalStartupOrigin
	if protocol.DecodeStrict(wire, &origin, maxOriginalStartupOriginBytes) != nil || origin.SchemaVersion != 1 ||
		len(origin.AnchorWire) == 0 || len(origin.AnchorWire) > bootstrap.MaxBootstrapAnchorBytes ||
		len(origin.RootChainWire) == 0 || len(origin.RootChainWire) > trust.MaxRootChainBytes ||
		len(origin.GrantWire) == 0 || len(origin.GrantWire) > 256<<10 ||
		len(origin.AuthorityWire) == 0 || len(origin.AuthorityWire) > bootstrap.MaxManifestBytes {
		return originalStartupOrigin{}, ErrOriginalStartup
	}
	if _, err := origin.Cell.OCIRegion(); err != nil {
		return originalStartupOrigin{}, ErrOriginalStartup
	}
	canonical, err := protocol.EncodeJSON(origin)
	if err != nil || !bytes.Equal(wire, canonical) {
		return originalStartupOrigin{}, ErrOriginalStartup
	}
	return origin, nil
}

func (origin originalStartupOrigin) locator() originalStartupLocator {
	return originalStartupLocator{SchemaVersion: 1, Cell: origin.Cell, GrantSHA256: digest(origin.GrantWire), HomeAnchorSHA256: digest(origin.AnchorWire)}
}

func cloneOriginRoots(roots trust.Keyring) trust.Keyring {
	cloned := make(trust.Keyring, len(roots))
	for id, key := range roots {
		cloned[id] = bytes.Clone(key)
	}
	return cloned
}

func (store bakedStore) readOriginalOrigin() ([]byte, error) {
	dir, err := store.openDirectory(store.directory)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	return store.readFile(dir, OriginalStartupOriginFilename, maxOriginalStartupOriginBytes)
}

// LoadOriginalStartupAuthority restores only fixed local provenance or the
// compact fixed IMDS locator, then authenticates the current real OCI host.
func LoadOriginalStartupAuthority(ctx context.Context, now time.Time) (bootstrap.DerivedStartupAuthority, error) {
	store := bakedStore{directory: BakedDirectory, chainFile: RootChainFile}
	wire, err := store.readOriginalOrigin()
	var origin originalStartupOrigin
	var locator originalStartupLocator
	installed := err == nil
	if installed {
		origin, err = parseOriginalStartupOrigin(wire)
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		locator = origin.locator()
	} else if errors.Is(err, unix.ENOENT) {
		locator, err = NewIMDSClient().fetchOriginalStartup(ctx)
	}
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	region, err := locator.Cell.OCIRegion()
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	factory, err := ociclient.InstancePrincipalContext(ctx, region)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	template, err := bootstrap.LoadBoundOriginalStartupTemplate(ctx, factory, genesis, locator.Cell, locator.GrantSHA256, locator.HomeAnchorSHA256, now)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	home, err := template.OriginAnchor().FoundationScope()
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	homeFactory, err := factory.ForRegion(home.OCIRegion)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	objects, err := homeFactory.ObjectStorage()
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	descriptor, err := NewIMDSClient().FetchDescriptor(ctx)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	authority, err := bootstrap.LoadDerivedStartupAuthority(ctx, template, &objects, descriptor.Slot, now)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if installed && (!bytes.Equal(authority.Wire(), origin.AuthorityWire) || !bytes.Equal(template.GrantWire(), origin.GrantWire) ||
		!bytes.Equal(template.OriginAnchor().Wire(), origin.AnchorWire) || !bytes.Equal(template.OriginRootChainWire(), origin.RootChainWire)) {
		return bootstrap.DerivedStartupAuthority{}, ErrOriginalStartup
	}
	host := originalStartupHost{authority: authority, factory: factory}
	if _, err := host.observeCurrent(ctx); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	return authority, nil
}

// originalStartupHost is local implementation state, never a startup capability
// or a conversion to the ordinary source-founder proof.
type originalStartupHost struct {
	authority bootstrap.DerivedStartupAuthority
	factory   *ociclient.Factory
}

func (host originalStartupHost) observeCurrent(ctx context.Context) (InstanceObservation, error) {
	authority := host.authority
	launch, err := authority.OriginalLaunch()
	if err != nil || host.factory == nil || authority.VerifyCurrent(ctx, time.Now().UTC()) != nil {
		return InstanceObservation{}, ErrOriginalStartup
	}
	manifest := authority.Manifest()
	if host.factory.Region() != manifest.OCIRegion {
		return InstanceObservation{}, ErrOriginalStartup
	}
	imds := NewIMDSClient()
	id, err := imds.FetchInstanceID(ctx)
	if err != nil {
		return InstanceObservation{}, err
	}
	descriptor, err := imds.FetchDescriptor(ctx)
	if err != nil || descriptor.Slot != manifest.Slot {
		return InstanceObservation{}, ErrOriginalStartup
	}
	if _, err := VerifyCurrentRunningBinary(authority.Template().Image()); err != nil {
		return InstanceObservation{}, err
	}
	var grant struct {
		TenancyID string `json:"tenancyId"`
	}
	envelope, err := trust.DecodeEnvelope(authority.GrantWire())
	if err != nil || json.Unmarshal(envelope.Payload, &grant) != nil || grant.TenancyID == "" {
		return InstanceObservation{}, ErrOriginalStartup
	}
	tenancy, err := host.factory.Provider().TenancyOCID()
	if err != nil || tenancy != grant.TenancyID || VerifyInstancePrincipal(host.factory, id, tenancy) != nil {
		return InstanceObservation{}, ErrOriginalStartup
	}
	observer, err := NewOCIInstanceObserverWithFactory(manifest.Cell, host.factory)
	if err != nil {
		return InstanceObservation{}, err
	}
	observed, err := observer.ObserveInstance(ctx, id)
	if err != nil {
		return InstanceObservation{}, err
	}
	profile, ok := authority.Profile(manifest.Slot)
	ip, err := authority.Template().SlotPrivateIP(manifest.Slot)
	if !ok || err != nil || observed.InstanceOCID != id || observed.LifecycleState != "RUNNING" || observed.ImageOCID != manifest.ImageOCID ||
		observed.CompartmentOCID != profile.CompartmentOCID || observed.AvailabilityDomain != profile.AvailabilityDomain ||
		observed.FaultDomain != profile.FaultDomain || observed.Shape != profile.Shape || observed.SubnetOCID != profile.SubnetOCID ||
		!sameOCIDSet(observed.NSGOCIDs, profile.NetworkSecurityGroupOCIDs) || !observed.PrimaryVNIC ||
		!strings.HasPrefix(observed.PrimaryVNICOCID, "ocid1.vnic.") || observed.PrimaryPrivateIP != ip {
		return InstanceObservation{}, ErrOriginalStartup
	}
	if err := host.verifyResources(ctx, observed); err != nil {
		return InstanceObservation{}, err
	}
	if manifest.Slot == manifest.SeedSlot {
		if id != launch.InstanceOCID {
			return InstanceObservation{}, ErrOriginalStartup
		}
		if err := host.verifyRetainedLaunch(ctx, observed); err != nil {
			return InstanceObservation{}, err
		}
	} else {
		storageFactory, err := originalHomeFactory(authority, host.factory)
		if err != nil {
			return InstanceObservation{}, err
		}
		objects, err := storageFactory.ObjectStorage()
		if err != nil {
			return InstanceObservation{}, err
		}
		ledger, err := authority.OpenLedgerWithClient(ctx, authority.Template().Roots(), &objects)
		if err != nil {
			return InstanceObservation{}, err
		}
		state, err := ledger.ReadSlot(ctx, bootstrap.BootstrapScope{DeploymentID: manifest.DeploymentID, Cell: string(manifest.Cell), Slot: manifest.Slot})
		if err != nil {
			return InstanceObservation{}, err
		}
		// The signed exact result identifies managed peers; locator metadata
		// cannot select a candidate or create a receipt.
		checked, err := (Gate{Instances: observer}).observe(ctx, id, state, authority.Template().StartupIdentity())
		if err != nil {
			return InstanceObservation{}, err
		}
		observed = checked
	}
	return observed, nil
}

func (host originalStartupHost) verifyRetainedLaunch(ctx context.Context, observed InstanceObservation) error {
	details, err := host.authority.Template().OriginalLaunchRequest()
	if err != nil || details.CreateVnicDetails == nil || details.ShapeConfig == nil {
		return ErrOriginalStartup
	}
	compute, err := host.factory.Compute()
	if err != nil {
		return err
	}
	response, err := compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(observed.InstanceOCID)})
	if err != nil {
		return err
	}
	instance := response.Instance
	if value(instance.Id) != observed.InstanceOCID || value(instance.DisplayName) != value(details.DisplayName) ||
		value(instance.CompartmentId) != value(details.CompartmentId) || value(instance.AvailabilityDomain) != value(details.AvailabilityDomain) ||
		value(instance.FaultDomain) != value(details.FaultDomain) || value(instance.Shape) != value(details.Shape) ||
		!maps.Equal(instance.Metadata, details.Metadata) || !maps.Equal(instance.FreeformTags, details.FreeformTags) ||
		instance.ShapeConfig == nil || instance.ShapeConfig.Ocpus == nil || details.ShapeConfig.Ocpus == nil ||
		*instance.ShapeConfig.Ocpus != *details.ShapeConfig.Ocpus || instance.ShapeConfig.MemoryInGBs == nil || details.ShapeConfig.MemoryInGBs == nil ||
		*instance.ShapeConfig.MemoryInGBs != *details.ShapeConfig.MemoryInGBs ||
		observed.SubnetOCID != value(details.CreateVnicDetails.SubnetId) || observed.PrimaryPrivateIP != value(details.CreateVnicDetails.PrivateIp) ||
		!sameOCIDSet(observed.NSGOCIDs, details.CreateVnicDetails.NsgIds) || instance.Metadata[OperatorSSHKeyMetadataKey] != "" {
		return ErrOriginalStartup
	}
	if _, present := instance.Metadata[OperatorSSHKeyMetadataKey]; present {
		return ErrOriginalStartup
	}
	return nil
}

func originalHomeFactory(authority bootstrap.DerivedStartupAuthority, factory *ociclient.Factory) (*ociclient.Factory, error) {
	if _, err := authority.OriginalLaunch(); err != nil {
		return nil, err
	}
	home, err := authority.Template().OriginAnchor().FoundationScope()
	if err != nil {
		return nil, err
	}
	return factory.ForRegion(home.OCIRegion)
}

// Geometry comes from authenticated provider reads, never instance tags or IMDS.
func (host originalStartupHost) verifyResources(ctx context.Context, observed InstanceObservation) error {
	template := host.authority.Template().Template()
	if template.FounderResources == nil {
		return ErrOriginalStartup
	}
	var resource bootstrap.StartupSlotResources
	for _, row := range template.FounderResources.Slots {
		if row.Slot == host.authority.Manifest().Slot {
			resource = row
			break
		}
	}
	vpus, supported := resource.BootVolumeTier.VPUsPerGB()
	if resource.WholeOCPUs == 0 || resource.MemoryInGB == 0 || resource.BootVolumeGB == 0 || !supported {
		return ErrOriginalStartup
	}
	compute, err := host.factory.Compute()
	if err != nil {
		return err
	}
	instanceResponse, err := compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(observed.InstanceOCID)})
	if err != nil {
		return err
	}
	instance := instanceResponse.Instance
	if value(instance.Id) != observed.InstanceOCID || value(instance.ImageId) != observed.ImageOCID || value(instance.CompartmentId) != observed.CompartmentOCID ||
		value(instance.AvailabilityDomain) != observed.AvailabilityDomain || value(instance.FaultDomain) != observed.FaultDomain ||
		value(instance.Shape) != observed.Shape || instance.LifecycleState != core.InstanceLifecycleStateRunning || instance.ShapeConfig == nil ||
		instance.ShapeConfig.Ocpus == nil || float64(*instance.ShapeConfig.Ocpus) != float64(resource.WholeOCPUs) ||
		instance.ShapeConfig.MemoryInGBs == nil || float64(*instance.ShapeConfig.MemoryInGBs) != float64(resource.MemoryInGB) {
		return ErrOriginalStartup
	}
	imageResponse, err := compute.GetImage(ociclient.RequestContext(ctx), core.GetImageRequest{ImageId: new(template.ImageOCID)})
	if err != nil {
		return err
	}
	if value(imageResponse.Image.Id) != template.ImageOCID || value(imageResponse.Image.CompartmentId) != resource.ImageCompartmentOCID || imageResponse.Image.LifecycleState != core.ImageLifecycleStateAvailable {
		return ErrOriginalStartup
	}
	attachments, err := compute.ListBootVolumeAttachments(ociclient.RequestContext(ctx), core.ListBootVolumeAttachmentsRequest{
		AvailabilityDomain: new(observed.AvailabilityDomain), CompartmentId: new(observed.CompartmentOCID), InstanceId: new(observed.InstanceOCID), Limit: new(2)})
	if err != nil {
		return err
	}
	if value(attachments.OpcNextPage) != "" || len(attachments.Items) != 1 {
		return ErrOriginalStartup
	}
	attachment := attachments.Items[0]
	bootID := value(attachment.BootVolumeId)
	prefix := "ocid1.bootvolume.oc1." + host.factory.Region() + "."
	if !strings.HasPrefix(bootID, prefix) || len(bootID) <= len(prefix) || value(attachment.InstanceId) != observed.InstanceOCID ||
		value(attachment.CompartmentId) != observed.CompartmentOCID || value(attachment.AvailabilityDomain) != observed.AvailabilityDomain ||
		attachment.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached {
		return ErrOriginalStartup
	}
	volumes, err := host.factory.Blockstorage()
	if err != nil {
		return err
	}
	volumeResponse, err := volumes.GetBootVolume(ociclient.RequestContext(ctx), core.GetBootVolumeRequest{BootVolumeId: new(bootID)})
	if err != nil {
		return err
	}
	volume := volumeResponse.BootVolume
	if value(volume.Id) != bootID || value(volume.CompartmentId) != observed.CompartmentOCID || value(volume.AvailabilityDomain) != observed.AvailabilityDomain ||
		value(volume.ImageId) != template.ImageOCID || volume.LifecycleState != core.BootVolumeLifecycleStateAvailable ||
		volume.SizeInGBs == nil || *volume.SizeInGBs != int64(resource.BootVolumeGB) || volume.VpusPerGB == nil || *volume.VpusPerGB != int64(vpus) ||
		volume.IsAutoTuneEnabled != nil && *volume.IsAutoTuneEnabled || len(volume.AutotunePolicies) != 0 ||
		volume.AutoTunedVpusPerGB != nil && *volume.AutoTunedVpusPerGB != int64(vpus) {
		return errors.New("authenticated founder boot volume differs from its signed fixed size and performance tier")
	}
	return nil
}
