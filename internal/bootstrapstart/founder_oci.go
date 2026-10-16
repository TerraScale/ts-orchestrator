package bootstrapstart

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

var ErrFounderOCI = errors.New("founder OCI effect or observation is invalid")

const (
	founderMinBootVolumeGB = 50
	founderMaxBootVolumeGB = 32768
)

// FounderPeerRefresh must strongly read the current selected root authority and
// the current ledger HEAD and intent, then return a newly authorized peer and
// fresh OCI server time. It is called immediately before every SDK request.
type FounderPeerRefresh func(context.Context) (bootstrap.VerifiedFounderPeer, time.Time, time.Time, error)

// FounderOCIAttempt pins the original request and deadline across lost-response
// retries. A subsequent selected plan or ledger attempt cannot silently replace
// the retry token or extend the original 23-hour window.
type FounderOCIAttempt struct {
	request         bootstrap.FounderPeerLaunchRequest
	deadline        time.Time
	observationOnly bool
	candidateID     string
	valid           bool
}

// NewFounderOCIObservationAttempt permits only reobservation of the exact
// candidate named by an already durable delegated peer receipt. It cannot be
// passed to Launch to create another instance.
func NewFounderOCIObservationAttempt(peer bootstrap.VerifiedFounderPeer, now time.Time) (FounderOCIAttempt, error) {
	request, err := peer.ObservationRequest(now)
	if err != nil {
		return FounderOCIAttempt{}, err
	}
	if !peer.IsVerified() || peer.EffectDeadline().IsZero() || request.Launch.RetryToken == "" ||
		!instanceIDRE.MatchString(request.InstanceOCID) {
		return FounderOCIAttempt{}, ErrFounderOCI
	}
	return FounderOCIAttempt{request: request.Launch, deadline: peer.EffectDeadline(),
		observationOnly: true, candidateID: request.InstanceOCID, valid: true}, nil
}

func NewFounderOCIAttempt(peer bootstrap.VerifiedFounderPeer, now time.Time) (FounderOCIAttempt, error) {
	request, err := peer.LaunchRequest(now)
	if err != nil {
		return FounderOCIAttempt{}, err
	}
	if !peer.IsVerified() || peer.EffectDeadline().IsZero() || request.RetryToken == "" {
		return FounderOCIAttempt{}, ErrFounderOCI
	}
	return FounderOCIAttempt{request: request, deadline: peer.EffectDeadline(), valid: true}, nil
}

type founderComputeAPI interface {
	GetImage(context.Context, core.GetImageRequest) (core.GetImageResponse, error)
	LaunchInstance(context.Context, core.LaunchInstanceRequest) (core.LaunchInstanceResponse, error)
	GetInstance(context.Context, core.GetInstanceRequest) (core.GetInstanceResponse, error)
	ListVnicAttachments(context.Context, core.ListVnicAttachmentsRequest) (core.ListVnicAttachmentsResponse, error)
	ListBootVolumeAttachments(context.Context, core.ListBootVolumeAttachmentsRequest) (core.ListBootVolumeAttachmentsResponse, error)
}

type founderNetworkAPI interface {
	GetVnic(context.Context, core.GetVnicRequest) (core.GetVnicResponse, error)
	GetSubnet(context.Context, core.GetSubnetRequest) (core.GetSubnetResponse, error)
}

type founderVolumeAPI interface {
	GetBootVolume(context.Context, core.GetBootVolumeRequest) (core.GetBootVolumeResponse, error)
}

// FounderOCI is an offline-testable SDK seam. It makes no authority decision:
// every individual OCI request obtains a fresh peer from its caller's reader.
type FounderOCI struct {
	region   oci.Region
	material LaunchMaterial
	compute  founderComputeAPI
	network  founderNetworkAPI
	volume   founderVolumeAPI
}

// NewFounderOCI binds the founder's OCI clients to one region. Each peer it
// launches receives the same launch material this controller was admitted with.
func NewFounderOCI(region oci.Region, provider common.ConfigurationProvider, material LaunchMaterial) (*FounderOCI, error) {
	ociRegion, err := region.OCIRegion()
	if err != nil || provider == nil {
		return nil, ErrFounderOCI
	}
	providerRegion, err := provider.Region()
	if err != nil || providerRegion != ociRegion {
		return nil, ErrFounderOCI
	}
	compute, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create founder Compute client: %w", err)
	}
	network, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create founder Networking client: %w", err)
	}
	volume, err := core.NewBlockstorageClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create founder Block Storage client: %w", err)
	}
	compute.SetRegion(ociRegion)
	network.SetRegion(ociRegion)
	volume.SetRegion(ociRegion)
	if compute.HTTPClient, err = bootstrap.NewInstancePrincipalSDKHTTPClient(); err != nil {
		return nil, err
	}
	if network.HTTPClient, err = bootstrap.NewInstancePrincipalSDKHTTPClient(); err != nil {
		return nil, err
	}
	if volume.HTTPClient, err = bootstrap.NewInstancePrincipalSDKHTTPClient(); err != nil {
		return nil, err
	}
	return &FounderOCI{region: region, material: material, compute: &compute, network: &network, volume: &volume}, nil
}

func (adapter *FounderOCI) beforeEffect(ctx context.Context, attempt FounderOCIAttempt, refresh FounderPeerRefresh) (context.Context, context.CancelFunc, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if adapter == nil || adapter.compute == nil || adapter.network == nil || adapter.volume == nil ||
		!attempt.valid || refresh == nil || attempt.request.Cell != adapter.region {
		return nil, nil, ErrFounderOCI
	}
	refreshStarted := time.Now()
	peer, now, selectionExpiresAt, err := refresh(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("refresh founder authority: %w", err)
	}
	var current bootstrap.FounderPeerLaunchRequest
	if attempt.observationOnly {
		observation, observationErr := peer.ObservationRequest(now)
		if observationErr != nil || observation.InstanceOCID != attempt.candidateID {
			return nil, nil, ErrFounderOCI
		}
		current = observation.Launch
	} else {
		current, err = peer.LaunchRequest(now)
		if err != nil {
			return nil, nil, err
		}
	}
	if !sameFounderAttempt(attempt, current, peer.EffectDeadline(), now) {
		return nil, nil, ErrFounderOCI
	}
	if selectionExpiresAt.IsZero() || selectionExpiresAt.Location() != time.UTC {
		return nil, nil, ErrFounderOCI
	}
	remaining := min(peer.EffectDeadline().Sub(now), attempt.deadline.Sub(now), selectionExpiresAt.Sub(now)) -
		time.Since(refreshStarted)
	if remaining <= 0 {
		return nil, nil, bootstrap.ErrFounderPlanExpired
	}
	effectCtx, cancel := context.WithTimeout(ctx, remaining)
	return effectCtx, cancel, nil
}

func sameFounderAttempt(attempt FounderOCIAttempt, current bootstrap.FounderPeerLaunchRequest, deadline, now time.Time) bool {
	return attempt.valid && !attempt.deadline.IsZero() && !deadline.After(attempt.deadline) &&
		now.Location() == time.UTC && now.Before(attempt.deadline) && reflect.DeepEqual(current, attempt.request)
}

func noFounderSDKRetry() common.RequestMetadata {
	policy := common.NoRetryPolicy()
	return common.RequestMetadata{RetryPolicy: &policy}
}

func (adapter *FounderOCI) checkImage(ctx context.Context, attempt FounderOCIAttempt, refresh FounderPeerRefresh) error {
	effectCtx, cancel, err := adapter.beforeEffect(ctx, attempt, refresh)
	if err != nil {
		return err
	}
	defer cancel()
	row := attempt.request.Row
	response, err := adapter.compute.GetImage(effectCtx, core.GetImageRequest{
		ImageId: new(row.ImageOCID), RequestMetadata: noFounderSDKRetry(),
	})
	if err != nil {
		return fmt.Errorf("GetImage exact founder image: %w", err)
	}
	if !founderImageMatches(response.Image, row) {
		return ErrFounderOCI
	}
	return nil
}

// Launch performs one OCI LaunchInstance request. A lost response is ambiguous;
// retry only by calling Launch again with the same attempt and a fresh reader.
// No tag or display-name search can recover or adopt an instance here.
func (adapter *FounderOCI) Launch(ctx context.Context, attempt FounderOCIAttempt, refresh FounderPeerRefresh) (string, error) {
	if attempt.observationOnly {
		return "", ErrFounderOCI
	}
	if err := adapter.checkImage(ctx, attempt, refresh); err != nil {
		return "", err
	}
	effectCtx, cancel, err := adapter.beforeEffect(ctx, attempt, refresh)
	if err != nil {
		return "", err
	}
	defer cancel()
	request, err := founderLaunchSDKRequest(attempt.request, adapter.material)
	if err != nil {
		return "", err
	}
	if err := effectCtx.Err(); err != nil {
		return "", err
	}
	response, err := adapter.compute.LaunchInstance(effectCtx, request)
	if err != nil {
		return "", fmt.Errorf("LaunchInstance founder peer: %w", err)
	}
	id := value(response.Id)
	if !founderLaunchCandidateMatches(response.Instance, attempt.request.Row) {
		return "", ErrFounderOCI
	}
	return id, nil
}

func founderLaunchCandidateMatches(instance core.Instance, row bootstrap.FounderPeerRow) bool {
	_, imageValid := founderInstanceImageEvidence(instance, row)
	return instanceIDRE.MatchString(value(instance.Id)) &&
		value(instance.CompartmentId) == row.CompartmentOCID && imageValid
}

func founderLaunchSDKRequest(request bootstrap.FounderPeerLaunchRequest, material LaunchMaterial) (core.LaunchInstanceRequest, error) {
	row := request.Row
	manifestHash := sha256.Sum256(request.ManifestWire)
	manifestEnvelope, manifestErr := trust.DecodeEnvelope(request.ManifestWire)
	var manifest bootstrap.Manifest
	if manifestErr == nil {
		manifest, manifestErr = bootstrap.ManifestPayload(manifestEnvelope.Payload)
	}
	vpus, ok := row.BootVolumeTier.VPUsPerGB()
	if !ok || vpus != 10 || row.Slot != request.Slot || row.WholeOCPUs == 0 ||
		row.MemoryInGB == 0 || row.BootVolumeGB < founderMinBootVolumeGB ||
		row.BootVolumeGB > founderMaxBootVolumeGB || request.RetryToken == "" ||
		row.WholeOCPUs > 1<<24 || row.MemoryInGB > 1<<24 ||
		len(request.ManifestWire) == 0 || len(request.ManifestWire) > MaxControllerManifestMetadataBytes ||
		hex.EncodeToString(manifestHash[:]) != request.ManifestSHA256 || manifestErr != nil ||
		manifest.Slot != request.Slot || manifest.DeploymentID != request.DeploymentID ||
		manifest.Cell != request.Cell || manifest.Environment != request.Environment ||
		manifest.ImageOCID != row.ImageOCID ||
		len(material.Identity) == 0 || len(material.Anchor) == 0 || len(material.HostEnrollment) == 0 ||
		len(material.OperatorSSHKey) == 0 || len(material.ManagedHostImageReceipt) == 0 ||
		len(material.ManagedHostImageDelegation) == 0 {
		return core.LaunchInstanceRequest{}, ErrFounderOCI
	}
	descriptor, err := protocol.EncodeJSON(Descriptor{SchemaVersion: 1, Slot: request.Slot})
	if err != nil {
		return core.LaunchInstanceRequest{}, err
	}
	// The deployment ID stays in the manifest launch metadata, not the name.
	name, err := naming.RegionCell(string(request.Cell)).ControllerSlot(request.Slot)
	if err != nil {
		return core.LaunchInstanceRequest{}, ErrFounderOCI
	}
	metadata := material.ControllerMetadata()
	metadata["terrascale-bootstrap"] = string(descriptor)
	metadata["terrascale-controller-manifest-v1"] = string(request.ManifestWire)
	return core.LaunchInstanceRequest{
		OpcRetryToken: new(request.RetryToken), RequestMetadata: noFounderSDKRetry(),
		LaunchInstanceDetails: core.LaunchInstanceDetails{
			AvailabilityDomain: new(row.AvailabilityDomain), CompartmentId: new(row.CompartmentOCID),
			FaultDomain: new(row.FaultDomain), Shape: new(row.Shape),
			DisplayName: new(name),
			Metadata:    metadata,
			ShapeConfig: &core.LaunchInstanceShapeConfigDetails{
				Ocpus: new(float32(row.WholeOCPUs)), MemoryInGBs: new(float32(row.MemoryInGB)),
			},
			SourceDetails: core.InstanceSourceViaImageDetails{
				ImageId: new(row.ImageOCID), BootVolumeSizeInGBs: new(int64(row.BootVolumeGB)),
				BootVolumeVpusPerGB: new(int64(vpus)),
			},
			CreateVnicDetails: &core.CreateVnicDetails{
				SubnetId: new(row.SubnetOCID), NsgIds: slices.Clone(row.NetworkSecurityGroupOCIDs),
				PrivateIp: new(row.PrivateIP), AssignPublicIp: new(false),
			},
		},
	}, nil
}

// FounderOCIObservation is positive evidence for one exact returned instance
// OCID. It cannot be used to infer an instance from mutable OCI tags.
type FounderOCIObservation struct {
	InstanceOCID  string
	InstanceETag  string
	PrimaryVNICID string
	BootVolumeID  string
	CompartmentID string
	ImageID       string
	PrivateIP     string
	Shape         string
	WholeOCPUs    uint32
	MemoryInGB    uint32
	BootVolumeGB  uint32
	BootVPUsPerGB uint32
	ObservedAt    time.Time
	observedMono  time.Time
}

func (observed FounderOCIObservation) fresh() bool {
	if observed.InstanceOCID == "" || observed.ObservedAt.IsZero() || observed.observedMono.IsZero() {
		return false
	}
	age := time.Since(observed.observedMono)
	return age >= 0 && age <= bootstrap.ManagedPeerObservationMaxAge
}

// Observe rereads Compute, image, VNIC and boot-volume facts. Each OCI read is
// individually preceded by refresh; a partial observation is never evidence.
func (adapter *FounderOCI) Observe(ctx context.Context, attempt FounderOCIAttempt, refresh FounderPeerRefresh, instanceID string) (FounderOCIObservation, error) {
	started := time.Now()
	if !instanceIDRE.MatchString(instanceID) || attempt.observationOnly && instanceID != attempt.candidateID {
		return FounderOCIObservation{}, ErrFounderOCI
	}
	row := attempt.request.Row
	effectCtx, cancel, err := adapter.beforeEffect(ctx, attempt, refresh)
	if err != nil {
		return FounderOCIObservation{}, err
	}
	instanceResponse, err := adapter.compute.GetInstance(effectCtx, core.GetInstanceRequest{
		InstanceId: new(instanceID), RequestMetadata: noFounderSDKRetry(),
	})
	cancel()
	if err != nil {
		return FounderOCIObservation{}, fmt.Errorf("GetInstance exact founder candidate: %w", err)
	}
	instance := instanceResponse.Instance
	descriptor, err := protocol.EncodeJSON(Descriptor{SchemaVersion: 1, Slot: attempt.request.Slot})
	if err != nil {
		return FounderOCIObservation{}, err
	}
	if !founderInstanceMatches(instance, instanceID, row, string(descriptor)) || value(instanceResponse.Etag) == "" {
		return FounderOCIObservation{}, ErrFounderOCI
	}
	if err := adapter.checkImage(ctx, attempt, refresh); err != nil {
		return FounderOCIObservation{}, err
	}
	vnicID, err := adapter.observeFounderVNIC(ctx, attempt, refresh, instanceID)
	if err != nil {
		return FounderOCIObservation{}, err
	}
	bootID, volume, observedAt, err := adapter.observeFounderBootVolume(ctx, attempt, refresh, instanceID)
	if err != nil {
		return FounderOCIObservation{}, err
	}
	if !founderObservationImageProven(instance, volume, row) {
		return FounderOCIObservation{}, ErrFounderOCI
	}
	finished := time.Now()
	if finished.Sub(started) > bootstrap.ManagedPeerObservationMaxAge || observedAt.IsZero() || observedAt.Location() != time.UTC {
		return FounderOCIObservation{}, ErrFounderOCI
	}
	return FounderOCIObservation{
		InstanceOCID: instanceID, InstanceETag: value(instanceResponse.Etag), PrimaryVNICID: vnicID,
		BootVolumeID: bootID, CompartmentID: row.CompartmentOCID, ImageID: row.ImageOCID,
		PrivateIP: row.PrivateIP, Shape: row.Shape, WholeOCPUs: row.WholeOCPUs,
		MemoryInGB: row.MemoryInGB, BootVolumeGB: row.BootVolumeGB, BootVPUsPerGB: 10,
		ObservedAt: observedAt, observedMono: finished,
	}, nil
}

func founderImageMatches(image core.Image, row bootstrap.FounderPeerRow) bool {
	return value(image.Id) == row.ImageOCID && value(image.CompartmentId) == row.ImageCompartmentOCID &&
		image.LifecycleState == core.ImageLifecycleStateAvailable
}

func founderInstanceMatches(instance core.Instance, instanceID string, row bootstrap.FounderPeerRow, descriptor string) bool {
	_, imageValid := founderInstanceImageEvidence(instance, row)
	return value(instance.Id) == instanceID && value(instance.CompartmentId) == row.CompartmentOCID &&
		imageValid && value(instance.AvailabilityDomain) == row.AvailabilityDomain &&
		value(instance.FaultDomain) == row.FaultDomain && value(instance.Shape) == row.Shape &&
		instance.LifecycleState == core.InstanceLifecycleStateRunning && instance.ShapeConfig != nil &&
		instance.ShapeConfig.Ocpus != nil && *instance.ShapeConfig.Ocpus == float32(row.WholeOCPUs) &&
		instance.ShapeConfig.MemoryInGBs != nil && *instance.ShapeConfig.MemoryInGBs == float32(row.MemoryInGB) &&
		instance.Metadata["terrascale-bootstrap"] == descriptor
}

// OCI deprecates Instance.ImageId in favor of SourceDetails. Both are optional
// on GET; if present, neither may contradict the signed image. The attached
// boot volume must separately report the exact image that created it.
func founderInstanceImageEvidence(instance core.Instance, row bootstrap.FounderPeerRow) (known, valid bool) {
	if instance.ImageId != nil {
		if *instance.ImageId != row.ImageOCID {
			return false, false
		}
		known = true
	}
	if instance.SourceDetails != nil {
		source, ok := instance.SourceDetails.(core.InstanceSourceViaImageDetails)
		if !ok {
			return false, false
		}
		if source.ImageId != nil {
			if *source.ImageId != row.ImageOCID {
				return false, false
			}
			known = true
		}
	}
	return known, true
}

func founderObservationImageProven(instance core.Instance, volume core.BootVolume, row bootstrap.FounderPeerRow) bool {
	_, valid := founderInstanceImageEvidence(instance, row)
	return valid && volume.ImageId != nil && *volume.ImageId == row.ImageOCID
}

func (adapter *FounderOCI) observeFounderVNIC(ctx context.Context, attempt FounderOCIAttempt, refresh FounderPeerRefresh, instanceID string) (string, error) {
	row := attempt.request.Row
	effectCtx, cancel, err := adapter.beforeEffect(ctx, attempt, refresh)
	if err != nil {
		return "", err
	}
	attachments, err := adapter.compute.ListVnicAttachments(effectCtx, core.ListVnicAttachmentsRequest{
		CompartmentId: new(row.CompartmentOCID), InstanceId: new(instanceID),
		RequestMetadata: noFounderSDKRetry(),
	})
	cancel()
	if err != nil {
		return "", fmt.Errorf("ListVnicAttachments founder candidate: %w", err)
	}
	if value(attachments.OpcNextPage) != "" || len(attachments.Items) != 1 {
		return "", ErrFounderOCI
	}
	attachment := attachments.Items[0]
	vnicID := value(attachment.VnicId)
	if value(attachment.InstanceId) != instanceID || value(attachment.CompartmentId) != row.CompartmentOCID ||
		value(attachment.SubnetId) != row.SubnetOCID || attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached ||
		!strings.HasPrefix(vnicID, "ocid1.vnic.") {
		return "", ErrFounderOCI
	}
	effectCtx, cancel, err = adapter.beforeEffect(ctx, attempt, refresh)
	if err != nil {
		return "", err
	}
	response, err := adapter.network.GetVnic(effectCtx, core.GetVnicRequest{
		VnicId: new(vnicID), RequestMetadata: noFounderSDKRetry(),
	})
	cancel()
	if err != nil {
		return "", fmt.Errorf("GetVnic exact founder primary: %w", err)
	}
	vnic := response.Vnic
	if !founderVNICMatches(vnic, vnicID, row) {
		return "", ErrFounderOCI
	}
	effectCtx, cancel, err = adapter.beforeEffect(ctx, attempt, refresh)
	if err != nil {
		return "", err
	}
	subnetResponse, err := adapter.network.GetSubnet(effectCtx, core.GetSubnetRequest{
		SubnetId: new(row.SubnetOCID), RequestMetadata: noFounderSDKRetry(),
	})
	cancel()
	if err != nil {
		return "", fmt.Errorf("GetSubnet exact founder primary: %w", err)
	}
	if !vnicSubnetMatches(vnic, subnetResponse.Subnet, instanceID) {
		return "", ErrFounderOCI
	}
	return vnicID, nil
}

func (adapter *FounderOCI) observeFounderBootVolume(ctx context.Context, attempt FounderOCIAttempt, refresh FounderPeerRefresh, instanceID string) (string, core.BootVolume, time.Time, error) {
	row := attempt.request.Row
	effectCtx, cancel, err := adapter.beforeEffect(ctx, attempt, refresh)
	if err != nil {
		return "", core.BootVolume{}, time.Time{}, err
	}
	attachments, err := adapter.compute.ListBootVolumeAttachments(effectCtx, core.ListBootVolumeAttachmentsRequest{
		AvailabilityDomain: new(row.AvailabilityDomain), CompartmentId: new(row.CompartmentOCID),
		InstanceId: new(instanceID), RequestMetadata: noFounderSDKRetry(),
	})
	cancel()
	if err != nil {
		return "", core.BootVolume{}, time.Time{}, fmt.Errorf("ListBootVolumeAttachments founder candidate: %w", err)
	}
	if value(attachments.OpcNextPage) != "" || len(attachments.Items) != 1 {
		return "", core.BootVolume{}, time.Time{}, ErrFounderOCI
	}
	attachment := attachments.Items[0]
	bootID := value(attachment.BootVolumeId)
	if value(attachment.InstanceId) != instanceID || value(attachment.CompartmentId) != row.CompartmentOCID ||
		value(attachment.AvailabilityDomain) != row.AvailabilityDomain ||
		attachment.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached ||
		!strings.HasPrefix(bootID, "ocid1.bootvolume.") {
		return "", core.BootVolume{}, time.Time{}, ErrFounderOCI
	}
	effectCtx, cancel, err = adapter.beforeEffect(ctx, attempt, refresh)
	if err != nil {
		return "", core.BootVolume{}, time.Time{}, err
	}
	response, err := adapter.volume.GetBootVolume(effectCtx, core.GetBootVolumeRequest{
		BootVolumeId: new(bootID), RequestMetadata: noFounderSDKRetry(),
	})
	cancel()
	if err != nil {
		return "", core.BootVolume{}, time.Time{}, fmt.Errorf("GetBootVolume exact founder boot volume: %w", err)
	}
	volume := response.BootVolume
	if !founderBootVolumeMatches(volume, bootID, row) {
		return "", core.BootVolume{}, time.Time{}, ErrFounderOCI
	}
	if response.RawResponse == nil {
		return "", core.BootVolume{}, time.Time{}, ErrFounderOCI
	}
	observedAt, err := http.ParseTime(response.RawResponse.Header.Get("Date"))
	if err != nil || observedAt.IsZero() {
		return "", core.BootVolume{}, time.Time{}, ErrFounderOCI
	}
	return bootID, volume, observedAt.UTC(), nil
}

func founderVNICMatches(vnic core.Vnic, vnicID string, row bootstrap.FounderPeerRow) bool {
	nsgs := slices.Clone(vnic.NsgIds)
	slices.Sort(nsgs)
	return value(vnic.Id) == vnicID && strings.HasPrefix(value(vnic.CompartmentId), "ocid1.compartment.") &&
		value(vnic.AvailabilityDomain) == row.AvailabilityDomain && value(vnic.SubnetId) == row.SubnetOCID &&
		value(vnic.PrivateIp) == row.PrivateIP && vnic.IsPrimary != nil && *vnic.IsPrimary &&
		vnic.LifecycleState == core.VnicLifecycleStateAvailable && slices.Equal(nsgs, row.NetworkSecurityGroupOCIDs) &&
		value(vnic.PublicIp) == ""
}

func founderBootVolumeMatches(volume core.BootVolume, bootID string, row bootstrap.FounderPeerRow) bool {
	return value(volume.Id) == bootID && value(volume.CompartmentId) == row.CompartmentOCID &&
		value(volume.AvailabilityDomain) == row.AvailabilityDomain &&
		value(volume.ImageId) == row.ImageOCID &&
		volume.SizeInGBs != nil && *volume.SizeInGBs == int64(row.BootVolumeGB) &&
		volume.VpusPerGB != nil && *volume.VpusPerGB == 10 &&
		volume.LifecycleState == core.BootVolumeLifecycleStateAvailable
}
