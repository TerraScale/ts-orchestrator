package oci

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
)

const (
	maxFleetInstances             = 256
	maxCreateKeyBytes             = 128
	maxEvidenceBytes              = 64 << 10
	maxCreateRetryAge             = 23 * time.Hour
	minRetainedVolumeSizeGB int64 = 50

	retainedVolumeReadOnly            = false
	retainedVolumeShareable           = false
	retainedVolumeEncryptionInTransit = true

	// OCI returns a new attachment while it is still ATTACHING and changes its
	// ETag when it settles.
	attachmentSettleTimeout = 2 * time.Minute
	attachmentSettlePoll    = 2 * time.Second

	tagManagedBy              = "terrascale-managed-by"
	tagOwner                  = "terrascale-owner"
	tagRegion                 = "terrascale-region"
	tagGeneration             = "terrascale-generation"
	tagResource               = "terrascale-resource"
	tagCreateKey              = "terrascale-create-key"
	tagHostNode               = "terrascale-host-node"
	tagCordoned               = "terrascale-cordoned"
	tagVolumeSize             = "terrascale-volume-size-gib"
	tagPlacementProfileDigest = "terrascale-placement-profile-digest"
	tagPlacementGeneration    = "terrascale-placement-generation"

	resourceMemberHost = "member-host"
	resourceMemberData = "member-data"
	managedByValue     = "ts-orchestrator"

	actionLaunch       = "launch"
	actionCordon       = "cordon"
	actionDrain        = "drain"
	actionVolumeAttach = "volume-attach"
	actionVolumeDetach = "volume-detach"
	actionTerminate    = "terminate"
	actionVolumeCreate = "volume-create"
)

// NewFleet validates region intent and binds an injectable OCI provider to one
// regional owner, durable journal, and live authority fencer.
func NewFleet(
	config RegionConfig,
	intent RegionIntent,
	provider Provider,
	journal Journal,
	fencer authority.Fencer,
	drainRequester DrainRequester,
	writerStop WriterStopVerifier,
) (Fleet, error) {
	return newFleet(config, intent, provider, journal, fencer, drainRequester, writerStop, nil)
}

// NewFleetWithImageVerifier is the injected qualification seam for a verified
// image evidence source. A nil verifier is allowed for compatibility, but
// retained-volume creation and attachment will hold until one is configured.
func NewFleetWithImageVerifier(
	config RegionConfig,
	intent RegionIntent,
	provider Provider,
	journal Journal,
	fencer authority.Fencer,
	drainRequester DrainRequester,
	writerStop WriterStopVerifier,
	imageVerifier ImageQualificationVerifier,
) (Fleet, error) {
	return newFleet(config, intent, provider, journal, fencer, drainRequester, writerStop, imageVerifier)
}

func newFleet(
	config RegionConfig,
	intent RegionIntent,
	provider Provider,
	journal Journal,
	fencer authority.Fencer,
	drainRequester DrainRequester,
	writerStop WriterStopVerifier,
	imageVerifier ImageQualificationVerifier,
) (Fleet, error) {
	if err := config.Validate(intent); err != nil {
		return nil, err
	}
	if provider == nil || journal == nil || fencer == nil {
		return nil, errors.New("OCI fleet requires a provider, durable journal, and authority fencer")
	}
	return &fleet{
		config: config, provider: provider, journal: journal, fencer: fencer,
		drainRequester: drainRequester, writerStop: writerStop, imageVerifier: imageVerifier, now: time.Now,
		attachmentSettle: attachmentSettleTimeout,
	}, nil
}

// NewInstancePrincipalFleetWithImageVerifier builds official OCI Compute and
// Block Volume SDK clients using instance-principal authentication for one
// validated region. hostMetadata is added to every managed host launch.
func NewInstancePrincipalFleetWithImageVerifier(
	config RegionConfig,
	intent RegionIntent,
	journal Journal,
	fencer authority.Fencer,
	drainRequester DrainRequester,
	writerStop WriterStopVerifier,
	imageVerifier ImageQualificationVerifier,
	hostMetadata map[string]string,
) (Fleet, error) {
	if err := config.Validate(intent); err != nil {
		return nil, err
	}
	provider, err := newSDKProvider(config, hostMetadata)
	if err != nil {
		return nil, err
	}
	return NewFleetWithImageVerifier(config, intent, provider, journal, fencer, drainRequester, writerStop, imageVerifier)
}

type fleet struct {
	config         RegionConfig
	provider       Provider
	journal        Journal
	fencer         authority.Fencer
	drainRequester DrainRequester
	writerStop     WriterStopVerifier
	imageVerifier  ImageQualificationVerifier
	now            func() time.Time
	// attachmentSettle bounds the wait for a new attachment to leave ATTACHING.
	attachmentSettle time.Duration
}

// verifyLaunchImage proves that the image new hosts boot qualifies now.
func (f *fleet) verifyLaunchImage(ctx context.Context) error {
	_, err := f.qualifiedLaunchImage(ctx)
	return err
}

// launchChoice is the image a host boots. A new launch carries the cell
// spec version that chose it; a replay of a journaled image carries none.
type launchChoice struct {
	image, version string
	fresh          bool
}

// admitLaunch qualifies a launch's image right before the provider launch
// and holds the cell spec fence until release. A new launch the cell spec
// chose must still see the spec version that chose it; a replay of a
// journaled image, which may run hours later, qualifies under the current
// version. Either way no spec change lands until the launch returns.
func (f *fleet) admitLaunch(ctx context.Context, choice launchChoice) (func(), error) {
	allowList, ok := f.imageVerifier.(HostImageAllowList)
	if !ok {
		return func() {}, f.verifyImage(ctx, choice.image)
	}
	version := ""
	if choice.fresh {
		version = choice.version
	}
	release, err := allowList.AdmitLaunch(ctx, f.config.Region, choice.image, version)
	if err != nil {
		return func() {}, fmt.Errorf("%w: %w", ErrImageNotQualified, err)
	}
	return release, nil
}

func (f *fleet) verifyImage(ctx context.Context, imageID string) error {
	if f.imageVerifier == nil {
		return ErrImageQualificationUnavailable
	}
	if err := f.imageVerifier.VerifyImageQualified(ctx, f.config.Region, imageID); err != nil {
		return fmt.Errorf("%w: %w", ErrImageNotQualified, err)
	}
	return nil
}

// qualifiedLaunchImage is the image new hosts boot, qualified now: the cell
// spec's launch image when its version allows it, else the pin.
func (f *fleet) qualifiedLaunchImage(ctx context.Context) (launchChoice, error) {
	allowList, ok := f.imageVerifier.(HostImageAllowList)
	if !ok {
		return launchChoice{image: f.config.ImageID, fresh: true}, f.verifyImage(ctx, f.config.ImageID)
	}
	image, version, err := allowList.QualifiedLaunchImage(ctx, f.config.Region, f.config.ImageID)
	if err != nil {
		return launchChoice{}, fmt.Errorf("%w: %w", ErrImageNotQualified, err)
	}
	return launchChoice{image: image, version: version, fresh: true}, nil
}

// launchImage is the image the host of createKey boots. A launch already
// journaled keeps its image while that stays allowed, so a retry never
// conflicts with it after the launch image moves. A new launch boots the
// current launch image, the pin included, only after it proves its current
// qualification, before it is journaled. EnsureHost qualifies the image
// again right before any provider launch, never to recover an existing host.
func (f *fleet) launchImage(ctx context.Context, createKey string) (launchChoice, error) {
	prior, found, err := f.journal.GetOperation(ctx, OperationScope{Action: actionLaunch, Key: createKey,
		Region: f.config.Region, Generation: f.config.Generation, Owner: f.config.Owner})
	if err != nil {
		return launchChoice{}, fmt.Errorf("read OCI host launch intent: %w", err)
	}
	if found && !f.imageAllowed(prior.ImageID) {
		return launchChoice{}, createRecoveryHold(resourceMemberHost, createKey, "the journaled launch image is no longer allowed")
	}
	if found {
		return launchChoice{image: prior.ImageID}, nil
	}
	return f.qualifiedLaunchImage(ctx)
}

// VerifyHostImage rechecks a member host's own image through the injected
// qualification source. It authorizes no mutation by itself.
func (f *fleet) VerifyHostImage(ctx context.Context, imageID string) error {
	return f.verifyImage(ctx, imageID)
}

// imageAllowed reports whether a host running imageID is a fleet member: the
// pinned image, or one the cell's signed allow-list qualifies.
func (f *fleet) imageAllowed(imageID string) bool {
	if imageID == f.config.ImageID {
		return true
	}
	allowList, ok := f.imageVerifier.(HostImageAllowList)
	if !ok {
		return false
	}
	allowed, _ := allowList.HostImages()
	return slices.Contains(allowed, imageID)
}

func (f *fleet) verifyRetainedVolumeHostImage(cloud CloudInstance) error {
	if !f.imageAllowed(cloud.ImageID) || cloud.ConsistentVolumeNamingEnabled == nil || !*cloud.ConsistentVolumeNamingEnabled {
		return fmt.Errorf("%w: instance %s does not report an allowed image and consistent volume naming", ErrImageNotQualified, cloud.ID)
	}
	return nil
}

func (f *fleet) Region() Region { return f.config.Region }

func (f *fleet) Observe(ctx context.Context) ([]Instance, error) {
	return f.observe(ctx, nil)
}

// ObserveSelected lists the fleet once and fully verifies only the managed
// instances whose ID or host node select accepts. Admission paths that need
// one host use it instead of verifying every host: with verification costing
// several Compute reads per host, a fleet-wide scan does not fit an
// admission deadline under the shared OCI rate limit. Every selected
// instance gets exactly the verification Observe gives it, so a caller still
// sees every verified instance that shares the selected ID or node.
func (f *fleet) ObserveSelected(ctx context.Context, selectInstance func(id, node string) bool) ([]Instance, error) {
	if selectInstance == nil {
		return nil, errors.New("selective OCI observation requires a selector")
	}
	return f.observe(ctx, selectInstance)
}

func (f *fleet) observe(ctx context.Context, selectInstance func(id, node string) bool) ([]Instance, error) {
	cloudInstances, err := f.provider.ListInstances(ctx, f.config.CompartmentID)
	if err != nil {
		return nil, err
	}
	if len(cloudInstances) > maxFleetInstances {
		return nil, errors.New("OCI member host list exceeds its safety bound")
	}
	// A complete sweep also counts the fleet by lifecycle state for the
	// dashboard; the tally never changes what the sweep returns.
	var tally *inventoryTally
	if selectInstance == nil {
		tally = newInventoryTally()
		ctx = withInventoryTally(ctx, tally)
	}
	instances := make([]Instance, 0, len(cloudInstances))
	for _, listed := range cloudInstances {
		tags := listed.FreeformTags
		if tags[tagManagedBy] != managedByValue || tags[tagOwner] != f.config.Owner {
			continue
		}
		createKey := tags[tagCreateKey]
		if tags[tagRegion] != string(f.config.Region) || tags[tagGeneration] != fmt.Sprint(f.config.Generation) ||
			tags[tagResource] != resourceMemberHost || !validCreateKey(createKey) || tags[tagHostNode] != hostNode(f.config, createKey) {
			slog.WarnContext(ctx, "withholding OCI instance with out-of-scope identity tags", "instance_id", listed.ID, "region", f.config.Region)
			continue
		}
		tally.instance(listed.LifecycleState)
		if selectInstance != nil && !selectInstance(listed.ID, tags[tagHostNode]) {
			continue
		}
		cloud, identity, err := f.reobserveInstance(ctx, listed.ID)
		if err != nil {
			if errors.Is(err, ErrForeignResource) {
				slog.WarnContext(ctx, "withholding OCI instance without a verified regional identity", "instance_id", listed.ID, "region", f.config.Region)
				continue
			}
			return nil, err
		}
		owned, err := f.journal.IsOwnedInstance(ctx, identity)
		if err != nil {
			return nil, fmt.Errorf("read OCI host ownership journal: %w", err)
		}
		if !owned {
			slog.WarnContext(ctx, "withholding OCI instance without durable controller ownership", "instance_id", cloud.ID, "region", f.config.Region, "create_key", identity.CreateKey)
			continue
		}
		profileIntent, found, err := f.journal.GetOperation(ctx, OperationScope{
			Action: actionLaunch, Key: identity.CreateKey, Region: identity.Region,
			Generation: identity.Generation, Owner: identity.Owner,
		})
		if err != nil {
			return nil, fmt.Errorf("read OCI host placement profile: %w", err)
		}
		if !found || profileIntent.Shape != f.config.Shape || !cloudMatchesLaunchBinding(cloud, profileIntent) {
			slog.WarnContext(ctx, "withholding OCI instance that does not match its signed placement compute profile", "instance_id", cloud.ID, "region", f.config.Region, "create_key", identity.CreateKey)
			continue
		}
		instance, err := f.instanceFromCloud(ctx, cloud, identity, profileIntent)
		if err != nil {
			if errors.Is(err, ErrAttachmentRecoveryHold) || errors.Is(err, ErrForeignResource) ||
				errors.Is(err, ErrRetainedVolumeUnknown) {
				slog.WarnContext(ctx, "withholding OCI instance with an unverified retained volume attachment", "instance_id", cloud.ID, "region", f.config.Region, "error", err)
				continue
			}
			return nil, err
		}
		instances = append(instances, instance)
	}
	if tally != nil {
		publishInventory(f.config.Region, tally, f.now())
	}
	return instances, nil
}

func (f *fleet) EnsureHost(ctx context.Context, request EnsureRequest) (Instance, error) {
	if !validCreateKey(request.CreateKey) || !slices.Contains(f.config.FaultDomains, request.FaultDomain) {
		return Instance{}, errors.New("OCI host launch has an invalid create key or unsupported fault domain")
	}
	if !f.memberName(request.Name, false) {
		return Instance{}, fmt.Errorf("OCI host launch name %q is not a member name of this cell", request.Name)
	}
	if !validManagedPrivateIP(request.PrivateIP) {
		return Instance{}, errors.New("OCI host launch requires a signed private IPv4 address")
	}
	if request.Shape != f.config.Shape || !validComputeProfile(request.Shape, request.WholeOCPUs,
		request.MemoryInGBs, request.PlacementProfileDigest, request.PlacementGeneration) {
		return Instance{}, ErrPlacementProfileMismatch
	}
	choice, err := f.launchImage(ctx, request.CreateKey)
	if err != nil {
		return Instance{}, err
	}
	image := choice.image
	descriptor, err := f.hostBootDescriptor(request, image)
	if err != nil {
		return Instance{}, fmt.Errorf("%w: %v", ErrHostBootBindingMismatch, err)
	}
	descriptorWire, err := descriptor.CanonicalBytes()
	if err != nil {
		return Instance{}, fmt.Errorf("%w: encode descriptor: %v", ErrHostBootBindingMismatch, err)
	}
	descriptorDigest, err := descriptor.Digest()
	if err != nil {
		return Instance{}, fmt.Errorf("%w: digest descriptor: %v", ErrHostBootBindingMismatch, err)
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return Instance{}, err
	}
	release, err := f.beginActiveWorkloadEffect(ctx, epoch, descriptor.DatabaseID, descriptor.PartitionID)
	if err != nil {
		return Instance{}, err
	}
	defer release()
	if err := f.verifyLaunchScope(ctx, descriptor, request.CreateKey); err != nil {
		return Instance{}, err
	}
	intent := f.intent(actionLaunch, request.CreateKey, "", request.CreateKey, "", request.FaultDomain, "")
	intent.Shape = request.Shape
	intent.PrivateIP = request.PrivateIP
	intent.WholeOCPUs = request.WholeOCPUs
	intent.MemoryInGBs = request.MemoryInGBs
	intent.PlacementProfileDigest = request.PlacementProfileDigest
	intent.PlacementGeneration = request.PlacementGeneration
	intent.ImageID = image
	intent.BootDescriptor = string(descriptorWire)
	intent.BootDescriptorSHA256 = descriptorDigest
	if err := f.recordIntent(ctx, epoch, intent); err != nil {
		return Instance{}, err
	}
	priorResult, hasPriorResult, err := f.journal.GetResult(ctx, intent)
	if err != nil {
		return Instance{}, fmt.Errorf("read OCI host operation result: %w", err)
	}
	operationIntent := priorResult.Intent
	if operationIntent.CreatedAt.IsZero() {
		operationIntent = intent
	}
	cloud, identity, found, err := f.findByCreateKey(ctx, request.CreateKey)
	if err != nil {
		if hasPriorResult && !priorResult.Unknown && isNotFound(err) {
			return Instance{}, createRecoveryHold(resourceMemberHost, request.CreateKey, "the previously confirmed instance is missing")
		}
		return Instance{}, err
	}
	if found {
		owned, err := f.journal.IsOwnedInstance(ctx, identity)
		if err != nil {
			return Instance{}, fmt.Errorf("read OCI host ownership journal: %w", err)
		}
		if owned {
			if hasPriorResult && !priorResult.Unknown && priorResult.ResourceID != cloud.ID {
				return Instance{}, createRecoveryHold(resourceMemberHost, request.CreateKey, "the observed instance differs from the immutable confirmed result")
			}
			if cloud.FaultDomain != request.FaultDomain {
				return Instance{}, fmt.Errorf("%w: create key is bound to a different fault domain", ErrForeignResource)
			}
			if !cloudMatchesPlacementProfile(cloud, operationIntent) {
				return Instance{}, fmt.Errorf("%w: observed instance does not match the immutable launch intent", ErrPlacementProfileMismatch)
			}
			if cloud.PrivateIP != operationIntent.PrivateIP {
				return Instance{}, fmt.Errorf("%w: observed private IP differs from immutable launch intent", ErrPlacementProfileMismatch)
			}
			// The launch receipt is immutable; the live ETag belongs to this
			// observation and will fence the next tag/termination operation.
			if err := f.captureBootBinding(ctx, epoch, cloud, identity); err != nil {
				return Instance{}, err
			}
			return f.instanceFromCloud(ctx, cloud, identity, operationIntent)
		}
		if !hasPriorResult || !priorResult.Unknown {
			if hasPriorResult && !priorResult.Unknown {
				return Instance{}, createRecoveryHold(resourceMemberHost, request.CreateKey, "the confirmed instance is no longer positively owned")
			}
			return Instance{}, fmt.Errorf("%w: instance %s has matching tags but no durable provider attempt or ownership", ErrForeignResource, cloud.ID)
		}
	} else if hasPriorResult && !priorResult.Unknown {
		return Instance{}, createRecoveryHold(resourceMemberHost, request.CreateKey, "the previously confirmed instance is missing")
	}
	if err := checkCreateRetryWindow(resourceMemberHost, request.CreateKey, operationIntent, f.now()); err != nil {
		return Instance{}, err
	}
	node := hostNode(f.config, request.CreateKey)
	launch := LaunchRequest{
		DisplayName: request.Name,
		CreateKey:   request.CreateKey,
		Node:        node,
		RetryToken: retryToken(strings.Join([]string{
			f.config.Owner, string(f.config.Region), fmt.Sprint(f.config.Generation), request.CreateKey,
		}, ":")),
		FaultDomain:            operationIntent.FaultDomain,
		PrivateIP:              operationIntent.PrivateIP,
		Shape:                  operationIntent.Shape,
		WholeOCPUs:             operationIntent.WholeOCPUs,
		MemoryInGBs:            operationIntent.MemoryInGBs,
		PlacementProfileDigest: operationIntent.PlacementProfileDigest,
		PlacementGeneration:    operationIntent.PlacementGeneration,
		ImageID:                operationIntent.ImageID,
		BootVolumeGB:           f.config.BootVolumeGB,
		BootVolumeVPUsPerGB:    f.config.BootVolumeVPUsPerGB,
		BootDescriptor:         operationIntent.BootDescriptor,
		FreeformTags: placementProfileTags(
			hostTags(f.config, request.CreateKey), operationIntent.PlacementProfileDigest, operationIntent.PlacementGeneration,
		),
	}
	// The image must still be allowed and qualify right before the provider
	// launch: a replay may run hours after it was journaled, and the cell
	// spec may change between a new launch's choice and this launch.
	if choice.image != operationIntent.ImageID {
		choice = launchChoice{image: operationIntent.ImageID}
	}
	releaseFence, err := f.admitLaunch(ctx, choice)
	if err != nil {
		return Instance{}, err
	}
	fenced := true
	defer func() {
		if fenced {
			releaseFence()
		}
	}()
	if err := f.guard(ctx, epoch); err != nil {
		return Instance{}, err
	}
	if err := checkCreateRetryWindow(resourceMemberHost, request.CreateKey, operationIntent, f.now()); err != nil {
		return Instance{}, err
	}
	created, launchErr := f.provider.LaunchInstance(ctx, launch)
	if launchErr != nil {
		if err := f.guard(ctx, epoch); err != nil {
			return Instance{}, errors.Join(ErrOutcomeUnknown, launchErr, err, f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, Unknown: true}))
		}
		if err := checkCreateRetryWindow(resourceMemberHost, request.CreateKey, operationIntent, f.now()); err != nil {
			return Instance{}, errors.Join(err, launchErr, f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, Unknown: true}))
		}
		created, launchErr = f.provider.LaunchInstance(ctx, launch)
	}
	fenced = false
	releaseFence()
	if launchErr != nil || created.ID == "" {
		unknownErr := errors.Join(ErrOutcomeUnknown, launchErr, errors.New("OCI launch response did not confirm an instance ID"))
		return Instance{}, errors.Join(unknownErr, f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, Unknown: true}))
	}
	cloud, identity, found, err = f.findByCreateKey(ctx, request.CreateKey)
	if err != nil {
		unknownErr := errors.Join(ErrOutcomeUnknown, err)
		return Instance{}, errors.Join(unknownErr, f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, Unknown: true}))
	}
	if !found || cloud.ID != created.ID {
		unknownErr := fmt.Errorf("%w: launched instance was not positively re-observed by create key", ErrOutcomeUnknown)
		return Instance{}, errors.Join(unknownErr, f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, Unknown: true}))
	}
	if cloud.FaultDomain != request.FaultDomain {
		return Instance{}, fmt.Errorf("%w: create key is bound to a different fault domain", ErrForeignResource)
	}
	if !cloudMatchesPlacementProfile(cloud, operationIntent) {
		unknownErr := fmt.Errorf("%w: %w: launched instance does not match the immutable launch intent", ErrOutcomeUnknown, ErrPlacementProfileMismatch)
		return Instance{}, errors.Join(unknownErr, f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, Unknown: true}))
	}
	if cloud.PrivateIP != operationIntent.PrivateIP {
		unknownErr := fmt.Errorf("%w: %w: launched private IP differs from immutable launch intent", ErrOutcomeUnknown, ErrPlacementProfileMismatch)
		return Instance{}, errors.Join(unknownErr, f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, Unknown: true}))
	}
	if err := f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, ResourceID: cloud.ID, ETag: cloud.ETag}); err != nil {
		return Instance{}, err
	}
	if err := f.captureBootBinding(ctx, epoch, cloud, identity); err != nil {
		return Instance{}, err
	}
	return f.instanceFromCloud(ctx, cloud, identity, operationIntent)
}

func (f *fleet) captureBootBinding(ctx context.Context, epoch uint64, cloud CloudInstance, identity ResourceIdentity) error {
	if cloud.LifecycleState == "TERMINATING" || cloud.LifecycleState == "TERMINATED" {
		binding, found, err := f.journal.GetBootBinding(ctx, cloud.ID)
		if err != nil || !found || binding.InstanceID != cloud.ID {
			return fmt.Errorf("%w: terminated host lacks its active-instance boot binding: %v", ErrHostBootBindingMismatch, err)
		}
		return nil
	}
	boot, err := f.provider.GetAttachedBootVolume(ctx, cloud.ID)
	if err != nil {
		return fmt.Errorf("capture active OCI boot attachment: %w", err)
	}
	if !f.imageAllowed(cloud.ImageID) || !f.terminalBootMatches(boot, boot.ID, cloud.ImageID) {
		return ErrHostBootBindingMismatch
	}
	if err := f.guard(ctx, epoch); err != nil {
		return err
	}
	return f.journal.RecordBootBinding(ctx, BootBinding{
		InstanceID: cloud.ID, BootVolumeID: boot.ID, Region: f.config.Region,
		Generation: f.config.Generation, Owner: f.config.Owner, CreateKey: identity.CreateKey,
		CompartmentID: boot.CompartmentID, AvailabilityDomain: boot.AvailabilityDomain,
		ImageID: boot.ImageID, SizeGB: boot.SizeGB, VPUsPerGB: boot.VPUsPerGB,
	})
}

// CreateRetainedVolume creates or recovers one region-pinned member data
// volume. An existing volume is accepted only when the durable journal proves
// ownership or a prior Unknown result authorizes a stable-token replay. If a
// process stops after OCI accepts a mutation but before Unknown is recorded,
// the resource remains withheld for operator inspection instead of being
// adopted from tags alone.
func (f *fleet) CreateRetainedVolume(ctx context.Context, request VolumeCreateRequest) (RetainedVolume, error) {
	if !validCreateKey(request.CreateKey) {
		return RetainedVolume{}, errors.New("retained OCI volume requires a valid create key")
	}
	if !f.memberName(request.Name, true) {
		return RetainedVolume{}, fmt.Errorf("retained OCI volume name %q is not a member data name of this cell", request.Name)
	}
	if request.SizeGB < minRetainedVolumeSizeGB || request.SizeGB > f.config.MaxDataVolumeGB {
		return RetainedVolume{}, fmt.Errorf("retained OCI volume size must be between %d GiB and the configured fleet bound %d GiB", minRetainedVolumeSizeGB, f.config.MaxDataVolumeGB)
	}
	if err := f.verifyLaunchImage(ctx); err != nil {
		return RetainedVolume{}, err
	}
	if request.AvailabilityDomain == "" {
		request.AvailabilityDomain = f.config.AvailabilityDomain
	}
	if request.AvailabilityDomain != f.config.AvailabilityDomain {
		return RetainedVolume{}, fmt.Errorf("retained OCI volume availability domain must be %q", f.config.AvailabilityDomain)
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return RetainedVolume{}, err
	}
	release, err := f.beginActiveWorkloadEffect(ctx, epoch, request.DatabaseID, request.PartitionID)
	if err != nil {
		return RetainedVolume{}, err
	}
	defer release()
	if err := f.verifyDataCreateScope(ctx, request); err != nil {
		return RetainedVolume{}, err
	}
	stored, hasStored, err := f.journal.GetOperation(ctx, OperationScope{
		Action: actionVolumeCreate, Key: request.CreateKey, Region: f.config.Region,
		Generation: f.config.Generation, Owner: f.config.Owner,
	})
	if err != nil {
		return RetainedVolume{}, fmt.Errorf("read OCI retained volume create intent: %w", err)
	}
	if hasStored && stored.SizeGB != request.SizeGB && stored.AvailabilityDomain == request.AvailabilityDomain {
		// The create intent is immutable. A later desired size never issues a
		// second create; the caller grows the owned volume through
		// ResizeRetainedVolume instead.
		request.SizeGB = stored.SizeGB
	}
	intent := f.intent(actionVolumeCreate, request.CreateKey, "", request.CreateKey, "", "", "")
	intent.AvailabilityDomain = request.AvailabilityDomain
	intent.SizeGB = request.SizeGB
	if err := f.recordIntent(ctx, epoch, intent); err != nil {
		return RetainedVolume{}, err
	}
	priorResult, hasPriorResult, err := f.journal.GetResult(ctx, intent)
	if err != nil {
		return RetainedVolume{}, fmt.Errorf("read OCI retained volume operation result: %w", err)
	}

	cloud, identity, found, err := f.findVolumeByCreateKey(ctx, request.CreateKey)
	if err != nil {
		if hasPriorResult && !priorResult.Unknown && isNotFound(err) {
			return RetainedVolume{}, createRecoveryHold(resourceMemberData, request.CreateKey, "the previously confirmed volume is missing")
		}
		return RetainedVolume{}, err
	}
	if found {
		owned, err := f.journal.IsOwnedVolume(ctx, identity)
		if err != nil {
			return RetainedVolume{}, fmt.Errorf("read OCI retained volume ownership journal: %w", err)
		}
		if owned {
			if hasPriorResult && !priorResult.Unknown && priorResult.ResourceID != cloud.ID {
				return RetainedVolume{}, createRecoveryHold(resourceMemberData, request.CreateKey, "the observed volume differs from the immutable confirmed result")
			}
			// The journal-owned identity proves the observed size; a volume
			// grown by a confirmed resize is still the same owned volume.
			if cloud.SizeGB < request.SizeGB || cloud.AvailabilityDomain != request.AvailabilityDomain {
				return RetainedVolume{}, fmt.Errorf("%w: create key is bound to a retained volume with a different profile", ErrForeignResource)
			}
			return retainedVolumeFromCloud(cloud, identity), nil
		}
		if !hasPriorResult || !priorResult.Unknown {
			if hasPriorResult && !priorResult.Unknown {
				return RetainedVolume{}, createRecoveryHold(resourceMemberData, request.CreateKey, "the confirmed volume is no longer positively owned")
			}
			return RetainedVolume{}, fmt.Errorf("%w: retained volume %s has matching tags but no durable provider attempt or ownership", ErrRetainedVolumeUnknown, cloud.ID)
		}
	} else if hasPriorResult && !priorResult.Unknown {
		return RetainedVolume{}, createRecoveryHold(resourceMemberData, request.CreateKey, "the previously confirmed volume is missing")
	}
	operationIntent := priorResult.Intent
	if err := checkCreateRetryWindow(resourceMemberData, request.CreateKey, operationIntent, f.now()); err != nil {
		return RetainedVolume{}, err
	}

	retry := retryToken(strings.Join([]string{
		f.config.Owner, string(f.config.Region), fmt.Sprint(f.config.Generation), request.CreateKey,
	}, ":"))
	if err := f.guard(ctx, epoch); err != nil {
		return RetainedVolume{}, err
	}
	if err := checkCreateRetryWindow(resourceMemberData, request.CreateKey, operationIntent, f.now()); err != nil {
		return RetainedVolume{}, err
	}
	created, createErr := f.provider.CreateVolume(ctx, request, volumeTags(f.config, request), retry)
	if createErr != nil {
		// Replay the stable OCI retry token to obtain a positive response for a
		// mutation whose first response may have been lost. A matching tag alone
		// is never enough to establish controller ownership.
		if err := f.guard(ctx, epoch); err != nil {
			return RetainedVolume{}, errors.Join(ErrOutcomeUnknown, createErr, err, f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, Unknown: true}))
		}
		if err := checkCreateRetryWindow(resourceMemberData, request.CreateKey, operationIntent, f.now()); err != nil {
			return RetainedVolume{}, errors.Join(err, createErr, f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, Unknown: true}))
		}
		created, createErr = f.provider.CreateVolume(ctx, request, volumeTags(f.config, request), retry)
	}
	observed, observedIdentity, wasObserved, observeErr := f.findVolumeByCreateKey(ctx, request.CreateKey)
	if observeErr != nil {
		unknownErr := errors.Join(ErrOutcomeUnknown, createErr, observeErr)
		return RetainedVolume{}, errors.Join(unknownErr, f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, Unknown: true}))
	}
	if !wasObserved {
		unknownErr := errors.Join(ErrOutcomeUnknown, createErr, errors.New("retained OCI volume was not positively re-observed"))
		return RetainedVolume{}, errors.Join(unknownErr, f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, Unknown: true}))
	}
	if createErr != nil || created.ID == "" || observed.ID != created.ID {
		// A matching pre-existing item without durable ownership is not adopted
		// when the provider call failed or returned a different resource.
		unknownErr := errors.Join(ErrOutcomeUnknown, createErr, errors.New("OCI create response did not prove the observed retained volume"))
		return RetainedVolume{}, errors.Join(unknownErr, f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, Unknown: true}))
	}
	if observed.SizeGB != request.SizeGB || observed.AvailabilityDomain != request.AvailabilityDomain {
		return RetainedVolume{}, fmt.Errorf("%w: created retained volume does not match its requested profile", ErrForeignResource)
	}
	if err := f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, ResourceID: observed.ID}); err != nil {
		return RetainedVolume{}, err
	}
	return retainedVolumeFromCloud(observed, observedIdentity), nil
}

func (f *fleet) Cordon(ctx context.Context, instanceID, expectedETag string) error {
	epoch, err := f.currentEpoch()
	if err != nil {
		return err
	}
	cloud, identity, err := f.ownedInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	if expectedETag == "" || cloud.ETag != expectedETag {
		return ErrStaleETag
	}
	if cloud.FreeformTags[tagCordoned] == "true" {
		return nil
	}
	intent := f.intent(actionCordon, digest(instanceID, expectedETag), instanceID, identity.CreateKey, expectedETag, "", "")
	if err := f.recordIntent(ctx, epoch, intent); err != nil {
		return err
	}
	tags := cloneStringMap(cloud.FreeformTags)
	tags[tagCordoned] = "true"
	if err := f.guard(ctx, epoch); err != nil {
		return err
	}
	_, updateErr := f.provider.UpdateInstanceTags(ctx, instanceID, cloud.ETag, tags)
	confirmed, observedIdentity, observeErr := f.reobserveInstance(ctx, instanceID)
	if observeErr != nil || confirmed.FreeformTags[tagCordoned] != "true" {
		if updateErr != nil {
			return errors.Join(ErrOutcomeUnknown, updateErr, observeErr)
		}
		return errors.Join(ErrOutcomeUnknown, observeErr, errors.New("OCI cordon tag was not observed"))
	}
	if observedIdentity != identity {
		return ErrForeignResource
	}
	return f.recordResult(ctx, epoch, OperationResult{Intent: intent, ResourceID: instanceID, ETag: confirmed.ETag})
}

func (f *fleet) RequestDrain(ctx context.Context, instanceID, expectedETag string) error {
	epoch, err := f.currentEpoch()
	if err != nil {
		return err
	}
	if f.drainRequester == nil {
		return errors.New("OCI host draining requires a durable regional host-command writer")
	}
	cloud, identity, err := f.ownedInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	if expectedETag == "" || cloud.ETag != expectedETag {
		return ErrStaleETag
	}
	key := digest(instanceID, expectedETag)
	intent := f.intent(actionDrain, key, instanceID, identity.CreateKey, expectedETag, "", "")
	if err := f.recordIntent(ctx, epoch, intent); err != nil {
		return err
	}
	if err := f.guard(ctx, epoch); err != nil {
		return err
	}
	if err := f.drainRequester.RequestDrain(ctx, DrainRequest{
		Region: f.config.Region, InstanceID: instanceID, Node: hostNode(f.config, identity.CreateKey),
		CreateKey: identity.CreateKey, IdempotencyKey: key, ExpectedETag: expectedETag, Epoch: epoch,
	}); err != nil {
		return errors.Join(ErrOutcomeUnknown, fmt.Errorf("persist host drain request: %w", err))
	}
	return f.recordResult(ctx, epoch, OperationResult{Intent: intent, ResourceID: instanceID, ETag: expectedETag})
}

func (f *fleet) AttachRetainedVolume(ctx context.Context, request VolumeAttachRequest) (Attachment, error) {
	if request.VolumeID == "" || request.InstanceID == "" || !validCreateKey(request.IdempotencyKey) {
		return Attachment{}, errors.New("retained volume attach request is incomplete")
	}
	if f.imageVerifier == nil {
		return Attachment{}, ErrImageQualificationUnavailable
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return Attachment{}, err
	}
	release, err := f.beginActiveWorkloadEffect(ctx, epoch, request.DatabaseID, request.PartitionID)
	if err != nil {
		return Attachment{}, err
	}
	defer release()
	instance, identity, err := f.ownedInstance(ctx, request.InstanceID)
	if err != nil {
		return Attachment{}, err
	}
	if err := f.verifyRetainedVolumeHostImage(instance); err != nil {
		return Attachment{}, err
	}
	// The image the host boots, not the launch image, must qualify now: a
	// retained volume attaches only to a host of a currently approved image.
	if err := f.verifyImage(ctx, instance.ImageID); err != nil {
		return Attachment{}, err
	}
	volume, err := f.ownedVolume(ctx, request.VolumeID)
	if err != nil {
		return Attachment{}, err
	}
	if err := f.verifyAttachScope(ctx, request.DatabaseID, request.PartitionID, request.InstanceID, volume); err != nil {
		return Attachment{}, err
	}

	scope := OperationScope{
		Action: actionVolumeAttach, Key: request.IdempotencyKey,
		Region: f.config.Region, Generation: f.config.Generation, Owner: f.config.Owner,
	}
	intent, hasIntent, err := f.journal.GetOperation(ctx, scope)
	if err != nil {
		return Attachment{}, fmt.Errorf("read OCI volume attachment intent: %w", err)
	}
	var retryWindowErr error
	if hasIntent {
		retryWindowErr = checkCreateRetryWindow("volume attachment", request.IdempotencyKey, intent, f.now())
		if intent.ResourceID != request.InstanceID || intent.VolumeID != request.VolumeID || intent.CreateKey != identity.CreateKey {
			return Attachment{}, fmt.Errorf("%w: operation key is bound to a different instance or volume", ErrAttachmentRecoveryHold)
		}
		if !validDevicePath(intent.Device) || intent.IsReadOnly != retainedVolumeReadOnly ||
			intent.IsShareable != retainedVolumeShareable ||
			intent.IsPvEncryptionInTransitEnabled != retainedVolumeEncryptionInTransit {
			err := fmt.Errorf("%w: durable operation has no complete device and attachment policy", ErrAttachmentRecoveryHold)
			return Attachment{}, errors.Join(retryWindowErr, err)
		}
	} else {
		// Do not create a new journal operation around an attachment that was
		// already present. Only a prior durable operation can bind that resource.
		attachments, err := f.attachAttachments(ctx, request)
		if err != nil {
			return Attachment{}, err
		}
		if len(attachments) != 0 {
			return Attachment{}, fmt.Errorf("%w: retained volume already has an unbound attachment", ErrAttachmentRecoveryHold)
		}
		device, err := f.selectRetainedVolumeDevice(ctx, request.InstanceID)
		if err != nil {
			return Attachment{}, err
		}
		intent = f.intent(actionVolumeAttach, request.IdempotencyKey, request.InstanceID, identity.CreateKey, instance.ETag, "", request.VolumeID)
		intent.Device = device
		intent.IsReadOnly = retainedVolumeReadOnly
		intent.IsShareable = retainedVolumeShareable
		intent.IsPvEncryptionInTransitEnabled = retainedVolumeEncryptionInTransit
		if err := f.recordIntent(ctx, epoch, intent); err != nil {
			return Attachment{}, err
		}
		storedIntent, stored, err := f.journal.GetOperation(ctx, scope)
		if err != nil {
			return Attachment{}, fmt.Errorf("confirm OCI volume attachment intent: %w", err)
		}
		if !stored || !sameIntent(storedIntent, intent) {
			return Attachment{}, fmt.Errorf("%w: persisted attachment intent changed during creation", ErrAttachmentRecoveryHold)
		}
		intent = storedIntent
	}
	retryWindowErr = checkCreateRetryWindow("volume attachment", request.IdempotencyKey, intent, f.now())

	priorResult, hasPriorResult, err := f.journal.GetResult(ctx, intent)
	if err != nil {
		return Attachment{}, fmt.Errorf("read OCI volume attachment result: %w", err)
	}
	attachments, err := f.attachAttachments(ctx, request)
	if err != nil {
		return Attachment{}, errors.Join(retryWindowErr, err)
	}
	if len(attachments) > 1 {
		return Attachment{}, errors.Join(retryWindowErr,
			fmt.Errorf("%w: volume has multiple attachments", ErrAttachmentRecoveryHold))
	}
	if len(attachments) == 1 {
		if attachments[0].InstanceID != request.InstanceID {
			return Attachment{}, errors.Join(retryWindowErr, ErrRetainedVolumeInUse)
		}
		attachment, err := f.awaitAttached(ctx, attachments[0].ID, request.VolumeID, request.InstanceID, intent.Device)
		if err != nil {
			return Attachment{}, errors.Join(retryWindowErr, ErrAttachmentRecoveryHold, err)
		}
		if hasPriorResult && !priorResult.Unknown &&
			(priorResult.ResourceID != attachment.ID || priorResult.ETag != attachment.ETag) {
			return Attachment{}, fmt.Errorf("%w: observed attachment differs from its confirmed journal result", ErrAttachmentRecoveryHold)
		}
		// Re-recording the exact immutable receipt also repairs its attachment
		// ownership projection after an interrupted journal projection write.
		if err := f.recordResult(ctx, epoch, OperationResult{Intent: intent, ResourceID: attachment.ID, ETag: attachment.ETag}); err != nil {
			return Attachment{}, err
		}
		return attachment, nil
	}
	if hasPriorResult && !priorResult.Unknown {
		return Attachment{}, fmt.Errorf("%w: confirmed attachment %s is missing", ErrAttachmentRecoveryHold, priorResult.ResourceID)
	}
	if retryWindowErr != nil {
		return Attachment{}, retryWindowErr
	}
	if err := f.guard(ctx, epoch); err != nil {
		return Attachment{}, err
	}
	if err := checkCreateRetryWindow("volume attachment", request.IdempotencyKey, intent, f.now()); err != nil {
		return Attachment{}, err
	}
	created, attachErr := f.provider.AttachVolume(ctx, CloudVolumeAttachRequest{
		VolumeID: request.VolumeID, InstanceID: request.InstanceID,
		RetryToken: retryToken(strings.Join([]string{
			f.config.Owner, string(f.config.Region), fmt.Sprint(f.config.Generation), request.IdempotencyKey,
		}, ":")),
		Device:     intent.Device,
		IsReadOnly: intent.IsReadOnly, IsShareable: intent.IsShareable,
		IsPvEncryptionInTransitEnabled: intent.IsPvEncryptionInTransitEnabled,
	})
	attachments, observeErr := f.attachAttachments(ctx, request)
	if observeErr != nil {
		return Attachment{}, errors.Join(ErrOutcomeUnknown, attachErr, observeErr,
			f.recordResult(ctx, epoch, OperationResult{Intent: intent, Unknown: true}))
	}
	if len(attachments) > 1 {
		return Attachment{}, errors.Join(ErrOutcomeUnknown, ErrAttachmentRecoveryHold,
			f.recordResult(ctx, epoch, OperationResult{Intent: intent, Unknown: true}))
	}
	if len(attachments) == 0 {
		return Attachment{}, errors.Join(ErrOutcomeUnknown, attachErr, errors.New("retained volume attachment was not observed"),
			f.recordResult(ctx, epoch, OperationResult{Intent: intent, Unknown: true}))
	}
	if attachments[0].InstanceID != request.InstanceID || attachments[0].VolumeID != request.VolumeID {
		return Attachment{}, errors.Join(ErrRetainedVolumeInUse,
			f.recordResult(ctx, epoch, OperationResult{Intent: intent, Unknown: true}))
	}
	attachment, err := f.awaitAttached(ctx, attachments[0].ID, request.VolumeID, request.InstanceID, intent.Device)
	if err != nil {
		return Attachment{}, errors.Join(ErrOutcomeUnknown, err,
			f.recordResult(ctx, epoch, OperationResult{Intent: intent, Unknown: true}))
	}
	// The response describes the ATTACHING attachment; only its ID must match
	// the settled one, whose ETag becomes the confirmed ownership fence.
	if created.ID != "" && created.ID != attachment.ID || attachErr == nil && created.ID == "" {
		return Attachment{}, errors.Join(ErrOutcomeUnknown, errors.New("OCI attachment response and re-observation disagree"),
			f.recordResult(ctx, epoch, OperationResult{Intent: intent, Unknown: true}))
	}
	if err := f.recordResult(ctx, epoch, OperationResult{Intent: intent, ResourceID: attachment.ID, ETag: attachment.ETag}); err != nil {
		return Attachment{}, err
	}
	return attachment, nil
}

func (f *fleet) Detach(ctx context.Context, attachmentID, expectedETag, instanceID string, evidence WriterStopEvidence) error {
	if attachmentID == "" || instanceID == "" || expectedETag == "" || len(evidence) == 0 || len(evidence) > maxEvidenceBytes {
		return errors.New("retained volume detach requires an attachment fence and writer-stop evidence")
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return err
	}
	attachment, err := f.provider.GetVolumeAttachment(ctx, attachmentID)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if attachment.InstanceID != instanceID || attachment.ETag != expectedETag {
		return ErrStaleETag
	}
	instance, identity, err := f.ownedInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	if _, err := f.ownedVolume(ctx, attachment.VolumeID); err != nil {
		return err
	}
	if f.writerStop == nil || f.writerStop.VerifyVolumeWriterStopped(ctx, f.config.Region, instanceID, attachment.VolumeID, evidence) != nil {
		return ErrWriterStopUnverified
	}
	intent := f.intent(actionVolumeDetach, digest(attachmentID, expectedETag), attachmentID, identity.CreateKey, expectedETag, "", attachment.VolumeID)
	if err := f.recordIntent(ctx, epoch, intent); err != nil {
		return err
	}
	if err := f.guard(ctx, epoch); err != nil {
		return err
	}
	detachErr := f.provider.DetachVolume(ctx, attachmentID, expectedETag)
	current, observeErr := f.provider.GetVolumeAttachment(ctx, attachmentID)
	if isNotFound(observeErr) {
		return f.recordResult(ctx, epoch, OperationResult{Intent: intent, ResourceID: attachment.VolumeID, ETag: expectedETag})
	}
	if observeErr != nil {
		return errors.Join(ErrOutcomeUnknown, detachErr, observeErr)
	}
	if detachErr != nil || current.ID != attachmentID || current.InstanceID != instanceID || current.LifecycleState != "DETACHED" {
		return errors.Join(ErrOutcomeUnknown, detachErr, errors.New("volume detach has not reached a confirmed detached state"))
	}
	if err := f.recordResult(ctx, epoch, OperationResult{Intent: intent, ResourceID: attachment.VolumeID, ETag: current.ETag}); err != nil {
		return err
	}
	_ = instance
	return nil
}

func (f *fleet) Terminate(ctx context.Context, instanceID, expectedETag string, evidence WriterStopEvidence) error {
	if instanceID == "" || expectedETag == "" || len(evidence) == 0 || len(evidence) > maxEvidenceBytes {
		return errors.New("OCI termination requires an instance ETag and writer-stop evidence")
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return err
	}
	cloud, identity, err := f.ownedInstance(ctx, instanceID)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cloud.ETag != expectedETag {
		return ErrStaleETag
	}
	attachments, err := f.provider.ListVolumeAttachments(ctx, f.config.CompartmentID, instanceID)
	if err != nil {
		return fmt.Errorf("verify retained volumes before termination: %w", err)
	}
	if len(attachments) != 0 {
		return errors.New("detach and retain every data volume before terminating its host")
	}
	if f.writerStop == nil || f.writerStop.VerifyInstanceWritersStopped(ctx, f.config.Region, instanceID, evidence) != nil {
		return ErrWriterStopUnverified
	}
	intent := f.intent(actionTerminate, digest(instanceID, expectedETag), instanceID, identity.CreateKey, expectedETag, "", "")
	if err := f.recordIntent(ctx, epoch, intent); err != nil {
		return err
	}
	if err := f.guard(ctx, epoch); err != nil {
		return err
	}
	terminateErr := f.provider.TerminateInstance(ctx, instanceID, expectedETag)
	current, observeErr := f.provider.GetInstance(ctx, instanceID)
	if isNotFound(observeErr) || observeErr == nil && (current.LifecycleState == "TERMINATING" || current.LifecycleState == "TERMINATED") {
		return f.recordResult(ctx, epoch, OperationResult{Intent: intent, ResourceID: instanceID, ETag: expectedETag})
	}
	if observeErr != nil || terminateErr != nil {
		return errors.Join(ErrOutcomeUnknown, terminateErr, observeErr)
	}
	return fmt.Errorf("%w: OCI termination was accepted but state is %q", ErrOutcomeUnknown, current.LifecycleState)
}

// terminatedForeign reports a terminated resource of another fleet. Create
// keys derive from placement identity and repeat across cells; a live foreign
// resource still fails closed, a terminated one can no longer collide.
func (f *fleet) terminatedForeign(tags map[string]string, state string) bool {
	return state == "TERMINATED" && tags[tagOwner] != f.config.Owner
}

func (f *fleet) findByCreateKey(ctx context.Context, createKey string) (CloudInstance, ResourceIdentity, bool, error) {
	instances, err := f.provider.ListInstances(ctx, f.config.CompartmentID)
	if err != nil {
		return CloudInstance{}, ResourceIdentity{}, false, err
	}
	var ids []string
	for _, instance := range instances {
		if instance.FreeformTags[tagCreateKey] == createKey && !f.terminatedForeign(instance.FreeformTags, instance.LifecycleState) {
			ids = append(ids, instance.ID)
		}
	}
	if len(ids) > 1 {
		return CloudInstance{}, ResourceIdentity{}, false, ErrDuplicateCreateKey
	}
	if len(ids) == 0 {
		return CloudInstance{}, ResourceIdentity{}, false, nil
	}
	cloud, identity, err := f.reobserveInstance(ctx, ids[0])
	if err != nil {
		return CloudInstance{}, ResourceIdentity{}, false, err
	}
	if identity.CreateKey != createKey {
		return CloudInstance{}, ResourceIdentity{}, false, ErrForeignResource
	}
	return cloud, identity, true, nil
}

func (f *fleet) reobserveInstance(ctx context.Context, instanceID string) (CloudInstance, ResourceIdentity, error) {
	return f.reobserveLaunch(ctx, instanceID, true)
}

// reobserveLaunch binds an instance to its immutable launch intent. With
// allowedImage, its launch image must also be the pin or allowed; teardown
// passes false, so revoking an image never strands its hosts' cleanup.
func (f *fleet) reobserveLaunch(ctx context.Context, instanceID string, allowedImage bool) (CloudInstance, ResourceIdentity, error) {
	cloud, err := f.provider.GetInstance(ctx, instanceID)
	if err != nil {
		return CloudInstance{}, ResourceIdentity{}, err
	}
	tags := cloud.FreeformTags
	createKey := tags[tagCreateKey]
	identity := ResourceIdentity{
		ID: cloud.ID, Region: f.config.Region, Generation: f.config.Generation,
		Owner: f.config.Owner, CreateKey: createKey,
	}
	if cloud.ID != instanceID || cloud.CompartmentID != f.config.CompartmentID || cloud.ETag == "" ||
		tags[tagManagedBy] != managedByValue || tags[tagOwner] != f.config.Owner ||
		tags[tagRegion] != string(f.config.Region) || tags[tagGeneration] != fmt.Sprint(f.config.Generation) ||
		tags[tagResource] != resourceMemberHost || !validCreateKey(createKey) ||
		tags[tagHostNode] != hostNode(f.config, createKey) || !slices.Contains(f.config.FaultDomains, cloud.FaultDomain) ||
		cloud.AvailabilityDomain != f.config.AvailabilityDomain || !validLifecycleState(cloud.LifecycleState) {
		return CloudInstance{}, ResourceIdentity{}, fmt.Errorf("%w: instance %s has missing or mismatched scope tags", ErrForeignResource, instanceID)
	}
	operation, found, err := f.journal.GetOperation(ctx, OperationScope{
		Action: actionLaunch, Key: createKey, Region: f.config.Region,
		Generation: f.config.Generation, Owner: f.config.Owner,
	})
	if err != nil {
		return CloudInstance{}, ResourceIdentity{}, fmt.Errorf("read OCI host launch binding: %w", err)
	}
	if !found || (allowedImage && !f.imageAllowed(operation.ImageID)) {
		return CloudInstance{}, ResourceIdentity{}, fmt.Errorf("%w: %w: instance %s has no matching durable image and boot descriptor", ErrForeignResource, ErrHostBootBindingMismatch, instanceID)
	}
	if cloud.ImageID != operation.ImageID {
		return CloudInstance{}, ResourceIdentity{}, fmt.Errorf("%w: %w: instance %s image differs from immutable launch intent", ErrForeignResource, ErrImageNotQualified, instanceID)
	}
	if !cloudMatchesPlacementProfile(cloud, operation) {
		return CloudInstance{}, ResourceIdentity{}, fmt.Errorf("%w: %w: instance %s compute profile differs from immutable launch intent", ErrForeignResource, ErrPlacementProfileMismatch, instanceID)
	}
	if !cloudMatchesLaunchBinding(cloud, operation) {
		return CloudInstance{}, ResourceIdentity{}, fmt.Errorf("%w: %w: instance %s metadata differs from immutable launch intent", ErrForeignResource, ErrHostBootBindingMismatch, instanceID)
	}
	return cloud, identity, nil
}

func (f *fleet) ownedInstance(ctx context.Context, instanceID string) (CloudInstance, ResourceIdentity, error) {
	return f.ownedLaunch(ctx, instanceID, true)
}

func (f *fleet) ownedLaunch(ctx context.Context, instanceID string, allowedImage bool) (CloudInstance, ResourceIdentity, error) {
	cloud, identity, err := f.reobserveLaunch(ctx, instanceID, allowedImage)
	if err != nil {
		return CloudInstance{}, ResourceIdentity{}, err
	}
	owned, err := f.journal.IsOwnedInstance(ctx, identity)
	if err != nil {
		return CloudInstance{}, ResourceIdentity{}, fmt.Errorf("read OCI host ownership journal: %w", err)
	}
	if !owned {
		return CloudInstance{}, ResourceIdentity{}, fmt.Errorf("%w: instance %s has no durable controller ownership", ErrForeignResource, instanceID)
	}
	return cloud, identity, nil
}

func (f *fleet) instanceFromCloud(ctx context.Context, cloud CloudInstance, identity ResourceIdentity, profile OperationIntent) (Instance, error) {
	observedDescriptor, err := hostboot.Parse([]byte(cloud.Metadata[hostboot.MetadataKey]))
	if err != nil {
		return Instance{}, fmt.Errorf("%w: observed descriptor: %v", ErrHostBootBindingMismatch, err)
	}
	observedDigest, err := observedDescriptor.Digest()
	if err != nil || cloud.Metadata[hostboot.MetadataKey] != profile.BootDescriptor ||
		observedDigest != profile.BootDescriptorSHA256 || cloud.ImageID != profile.ImageID {
		return Instance{}, ErrHostBootBindingMismatch
	}
	attachments, err := f.provider.ListVolumeAttachments(ctx, f.config.CompartmentID, cloud.ID)
	if err != nil {
		return Instance{}, fmt.Errorf("observe OCI host volume attachments: %w", err)
	}
	if len(attachments) > maxProviderItems {
		return Instance{}, errors.New("OCI host volume attachment list exceeds its safety bound")
	}
	result := Instance{
		ID: cloud.ID, Node: hostNode(f.config, identity.CreateKey), CreateKey: identity.CreateKey,
		Region: f.config.Region, Generation: f.config.Generation, Owner: f.config.Owner,
		FaultDomain: cloud.FaultDomain, Shape: profile.Shape, WholeOCPUs: profile.WholeOCPUs,
		MemoryInGBs: profile.MemoryInGBs, PlacementProfileDigest: profile.PlacementProfileDigest,
		PlacementGeneration: profile.PlacementGeneration, ImageID: cloud.ImageID,
		PrivateIP:            cloud.PrivateIP,
		BootDescriptorSHA256: observedDigest, ETag: cloud.ETag,
		State: cloud.LifecycleState,
	}
	volumeStates := make([]string, 0, len(attachments))
	for _, listed := range attachments {
		if listed.InstanceID != cloud.ID || listed.VolumeID == "" || listed.ID == "" {
			return Instance{}, fmt.Errorf("%w: OCI attachment scope changed", ErrForeignResource)
		}
		volume, err := f.ownedVolume(ctx, listed.VolumeID)
		if err != nil {
			return Instance{}, err
		}
		attachment, err := f.reobserveAttachment(ctx, listed.ID, listed.VolumeID, cloud.ID, "")
		if err != nil {
			return Instance{}, err
		}
		attachmentIdentity := AttachmentIdentity{
			ID: attachment.ID, InstanceID: attachment.InstanceID, VolumeID: attachment.VolumeID,
			Device: attachment.Device, ETag: attachment.ETag, Region: f.config.Region,
			Generation: f.config.Generation, Owner: f.config.Owner, CreateKey: identity.CreateKey,
			IsReadOnly: attachment.IsReadOnly, IsShareable: attachment.IsShareable,
			IsPvEncryptionInTransitEnabled: attachment.IsPvEncryptionInTransitEnabled,
		}
		owned, err := f.journal.IsOwnedAttachment(ctx, attachmentIdentity)
		if err != nil {
			return Instance{}, fmt.Errorf("read OCI attachment ownership journal: %w", err)
		}
		if !owned {
			return Instance{}, fmt.Errorf("%w: attachment %s has no matching confirmed operation", ErrAttachmentRecoveryHold, attachment.ID)
		}
		volumeStates = append(volumeStates, volume.LifecycleState)
		result.DataVolumes = append(result.DataVolumes, attachment.VolumeID)
		result.Attachments = append(result.Attachments, attachment)
	}
	// Count the host's volumes and attachments only once every attachment
	// verified: a host withheld partway through is not in the inventory.
	if tally := inventoryTallyFrom(ctx); tally != nil {
		for index, attachment := range result.Attachments {
			tally.volume(volumeStates[index])
			tally.attachment(attachment.State)
		}
	}
	return result, nil
}

func (f *fleet) selectRetainedVolumeDevice(ctx context.Context, instanceID string) (string, error) {
	devices, err := f.provider.ListInstanceDevices(ctx, instanceID)
	if err != nil {
		return "", fmt.Errorf("list OCI instance device candidates: %w", err)
	}
	available := make([]string, 0, len(devices))
	for _, device := range devices {
		if device.IsAvailable == nil || !*device.IsAvailable {
			continue
		}
		if !validDevicePath(device.Name) {
			return "", errors.New("OCI reported an invalid available device path")
		}
		available = append(available, device.Name)
	}
	if len(available) == 0 {
		return "", errors.New("OCI instance has no available retained-volume device")
	}
	// OCI device paths name virtio-scsi LUNs in order a, b, ..., z, aa, ...,
	// af; the shortest name first selects the lowest free LUN (oraclevdb for
	// the first data volume), not oraclevdaa.
	slices.SortFunc(available, func(left, right string) int {
		return cmp.Or(cmp.Compare(len(left), len(right)), strings.Compare(left, right))
	})
	return available[0], nil
}

// awaitAttached waits, bounded by attachmentSettle, for an attachment to leave
// ATTACHING and then re-observes its complete attached scope.
func (f *fleet) awaitAttached(ctx context.Context, attachmentID, volumeID, instanceID, expectedDevice string) (Attachment, error) {
	settleCtx, cancel := context.WithTimeout(ctx, f.attachmentSettle)
	defer cancel()
	for {
		cloud, err := f.provider.GetVolumeAttachment(settleCtx, attachmentID)
		if err != nil {
			return Attachment{}, err
		}
		if cloud.LifecycleState != "ATTACHING" {
			return f.reobserveAttachment(ctx, attachmentID, volumeID, instanceID, expectedDevice)
		}
		select {
		case <-settleCtx.Done():
			return Attachment{}, fmt.Errorf("OCI volume attachment %s is still ATTACHING: %w", attachmentID, settleCtx.Err())
		case <-time.After(attachmentSettlePoll):
		}
	}
}

func (f *fleet) reobserveAttachment(ctx context.Context, attachmentID, volumeID, instanceID, expectedDevice string) (Attachment, error) {
	cloud, err := f.provider.GetVolumeAttachment(ctx, attachmentID)
	if err != nil {
		return Attachment{}, err
	}
	if cloud.ID != attachmentID || cloud.VolumeID != volumeID || cloud.InstanceID != instanceID || cloud.ETag == "" ||
		cloud.LifecycleState != "ATTACHED" || !validDevicePath(cloud.Device) ||
		expectedDevice != "" && cloud.Device != expectedDevice ||
		cloud.IsReadOnly == nil || *cloud.IsReadOnly != retainedVolumeReadOnly ||
		cloud.IsShareable == nil || *cloud.IsShareable != retainedVolumeShareable ||
		cloud.IsPvEncryptionInTransitEnabled == nil || *cloud.IsPvEncryptionInTransitEnabled != retainedVolumeEncryptionInTransit {
		return Attachment{}, fmt.Errorf("%w: OCI volume attachment scope or state changed", ErrForeignResource)
	}
	return Attachment{
		ID: cloud.ID, VolumeID: cloud.VolumeID, InstanceID: cloud.InstanceID,
		ETag: cloud.ETag, State: cloud.LifecycleState, Device: cloud.Device,
		IsReadOnly: *cloud.IsReadOnly, IsShareable: *cloud.IsShareable,
		IsPvEncryptionInTransitEnabled: *cloud.IsPvEncryptionInTransitEnabled,
	}, nil
}

func validDevicePath(value string) bool {
	return len(value) > len("/dev/") && len(value) <= 255 && strings.HasPrefix(value, "/dev/") &&
		path.Clean(value) == value && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, " \t\r\n\x00")
}

// findVolumeAttachments lists every attachment record of one volume. OCI
// filters by VolumeId server-side when the provider supports it; the result
// is still filtered here so a provider bug cannot widen the scope.
func (f *fleet) findVolumeAttachments(ctx context.Context, volumeID string) ([]CloudAttachment, error) {
	var attachments []CloudAttachment
	var err error
	if lister, ok := f.provider.(VolumeAttachmentLister); ok {
		attachments, err = lister.ListVolumeAttachmentsByVolume(ctx, f.config.CompartmentID, f.config.AvailabilityDomain, volumeID)
	} else {
		attachments, err = f.provider.ListVolumeAttachments(ctx, f.config.CompartmentID, "")
	}
	if err != nil {
		return nil, err
	}
	var found []CloudAttachment
	for _, attachment := range attachments {
		if attachment.VolumeID == volumeID {
			found = append(found, attachment)
		}
	}
	return found, nil
}

func (f *fleet) ownedVolume(ctx context.Context, volumeID string) (CloudVolume, error) {
	volume, identity, err := f.reobserveVolume(ctx, volumeID)
	if err != nil {
		return CloudVolume{}, err
	}
	owned, err := f.journal.IsOwnedVolume(ctx, identity)
	if err != nil {
		return CloudVolume{}, fmt.Errorf("read OCI retained volume ownership journal: %w", err)
	}
	if !owned {
		return CloudVolume{}, fmt.Errorf("%w: %s", ErrRetainedVolumeUnknown, volumeID)
	}
	return volume, nil
}

func (f *fleet) findVolumeByCreateKey(ctx context.Context, createKey string) (CloudVolume, ResourceIdentity, bool, error) {
	volumes, err := f.provider.ListVolumes(ctx, f.config.CompartmentID, f.config.AvailabilityDomain)
	if err != nil {
		return CloudVolume{}, ResourceIdentity{}, false, err
	}
	var ids []string
	for _, volume := range volumes {
		if volume.FreeformTags[tagCreateKey] == createKey && !f.terminatedForeign(volume.FreeformTags, volume.LifecycleState) {
			ids = append(ids, volume.ID)
		}
	}
	if len(ids) > 1 {
		return CloudVolume{}, ResourceIdentity{}, false, ErrDuplicateCreateKey
	}
	if len(ids) == 0 {
		return CloudVolume{}, ResourceIdentity{}, false, nil
	}
	volume, identity, err := f.reobserveVolume(ctx, ids[0])
	if err != nil {
		return CloudVolume{}, ResourceIdentity{}, false, err
	}
	if identity.CreateKey != createKey {
		return CloudVolume{}, ResourceIdentity{}, false, ErrForeignResource
	}
	return volume, identity, true, nil
}

func (f *fleet) reobserveVolume(ctx context.Context, volumeID string) (CloudVolume, ResourceIdentity, error) {
	return f.reobserveVolumeResource(ctx, volumeID, resourceMemberData)
}

// reobserveVolumeResource checks the same regional volume pins for explicitly
// selected resource kinds. Normal fleet reads accept only member data.
func (f *fleet) reobserveVolumeResource(ctx context.Context, volumeID string, resources ...string) (CloudVolume, ResourceIdentity, error) {
	volume, err := f.provider.GetVolume(ctx, volumeID)
	if err != nil {
		return CloudVolume{}, ResourceIdentity{}, err
	}
	tags := volume.FreeformTags
	createKey := tags[tagCreateKey]
	identity := ResourceIdentity{
		ID: volume.ID, Region: f.config.Region, Generation: f.config.Generation,
		Owner: f.config.Owner, CreateKey: createKey,
		AvailabilityDomain: volume.AvailabilityDomain, SizeGB: volume.SizeGB,
	}
	if volume.ID != volumeID || volume.CompartmentID != f.config.CompartmentID ||
		volume.AvailabilityDomain != f.config.AvailabilityDomain || volume.SizeGB < minRetainedVolumeSizeGB ||
		volume.SizeGB > f.config.MaxDataVolumeGB ||
		volume.VPUsPerGB != int64(f.config.DataVolumeVPUsPerGB) ||
		tags[tagManagedBy] != managedByValue || tags[tagOwner] != f.config.Owner ||
		tags[tagRegion] != string(f.config.Region) || tags[tagGeneration] != fmt.Sprint(f.config.Generation) ||
		!slices.Contains(resources, tags[tagResource]) || tags[tagVolumeSize] != fmt.Sprint(volume.SizeGB) ||
		!validCreateKey(createKey) || !validVolumeLifecycleState(volume.LifecycleState) {
		return CloudVolume{}, ResourceIdentity{}, fmt.Errorf("%w: retained volume %s has missing or mismatched scope tags, size, domain, or state", ErrForeignResource, volumeID)
	}
	return volume, identity, nil
}

func retainedVolumeFromCloud(cloud CloudVolume, identity ResourceIdentity) RetainedVolume {
	return RetainedVolume{
		ID: cloud.ID, CreateKey: identity.CreateKey, Region: identity.Region,
		Generation: identity.Generation, Owner: identity.Owner,
		AvailabilityDomain: cloud.AvailabilityDomain, SizeGB: cloud.SizeGB, State: cloud.LifecycleState,
	}
}

func (f *fleet) currentEpoch() (uint64, error) {
	snapshot := f.fencer.Current()
	if !snapshot.CanMutate() {
		return 0, authority.ErrNotLeader
	}
	return snapshot.Epoch, nil
}

type activeWorkloadFencer interface {
	BeginActiveWorkloadEffect(context.Context, uint64, authority.WorkloadScope) (func(), error)
}

func (f *fleet) beginActiveWorkloadEffect(ctx context.Context, epoch uint64, databaseID, partitionID string) (func(), error) {
	gate, ok := f.fencer.(activeWorkloadFencer)
	if !ok || databaseID == "" || partitionID == "" {
		return nil, errors.New("OCI active workload effect requires a terminal-aware authority gate and workload scope")
	}
	return gate.BeginActiveWorkloadEffect(ctx, epoch, authority.WorkloadScope{DatabaseID: databaseID, PartitionID: partitionID})
}

func checkCreateRetryWindow(resource, createKey string, intent OperationIntent, now time.Time) error {
	if intent.CreatedAt.IsZero() || now.Before(intent.CreatedAt) || now.Sub(intent.CreatedAt) >= maxCreateRetryAge {
		return createRecoveryHold(resource, createKey, "the immutable OCI create intent is outside the 23-hour automatic retry window")
	}
	return nil
}

func createRecoveryHold(resource, createKey, reason string) error {
	return &CreateRecoveryHoldError{Resource: resource, CreateKey: createKey, Reason: reason}
}

func (f *fleet) guard(ctx context.Context, epoch uint64) error {
	if err := f.fencer.Guard(ctx, epoch); err != nil {
		return fmt.Errorf("OCI mutation authority was fenced: %w", err)
	}
	return nil
}

func (f *fleet) recordIntent(ctx context.Context, epoch uint64, intent OperationIntent) error {
	if err := f.guard(ctx, epoch); err != nil {
		return err
	}
	if err := f.journal.RecordIntent(ctx, intent); err != nil {
		return fmt.Errorf("persist OCI mutation intent: %w", err)
	}
	return nil
}

func (f *fleet) recordResult(ctx context.Context, epoch uint64, result OperationResult) error {
	if err := f.guard(ctx, epoch); err != nil {
		return err
	}
	if err := f.journal.RecordResult(ctx, result); err != nil {
		return fmt.Errorf("record OCI mutation result: %w", err)
	}
	return nil
}

func (f *fleet) intent(action, key, resourceID, createKey, expectedETag, faultDomain, volumeID string) OperationIntent {
	return OperationIntent{
		Action: action, Key: key, Region: f.config.Region, Generation: f.config.Generation,
		Owner: f.config.Owner, ResourceID: resourceID, CreateKey: createKey,
		ExpectedETag: expectedETag, FaultDomain: faultDomain, VolumeID: volumeID,
		CreatedAt: f.now().UTC(),
	}
}

func placementProfileTags(tags map[string]string, profileDigest string, generation uint64) map[string]string {
	updated := cloneStringMap(tags)
	if updated == nil {
		updated = make(map[string]string, 2)
	}
	updated[tagPlacementProfileDigest] = profileDigest
	updated[tagPlacementGeneration] = fmt.Sprint(generation)
	return updated
}

func cloudMatchesPlacementProfile(cloud CloudInstance, intent OperationIntent) bool {
	if !validComputeProfile(intent.Shape, intent.WholeOCPUs, intent.MemoryInGBs,
		intent.PlacementProfileDigest, intent.PlacementGeneration) {
		return false
	}
	wantOCPUs, _ := exactFloat32(intent.WholeOCPUs)
	wantMemory, _ := exactFloat32(intent.MemoryInGBs)
	return cloud.PrivateIP == intent.PrivateIP && cloud.Shape == intent.Shape && cloud.Ocpus != nil && *cloud.Ocpus == wantOCPUs &&
		cloud.MemoryInGBs != nil && *cloud.MemoryInGBs == wantMemory &&
		cloud.FreeformTags[tagPlacementProfileDigest] == intent.PlacementProfileDigest &&
		cloud.FreeformTags[tagPlacementGeneration] == fmt.Sprint(intent.PlacementGeneration)
}

func hostTags(config RegionConfig, createKey string) map[string]string {
	return map[string]string{
		tagManagedBy:  managedByValue,
		tagOwner:      config.Owner,
		tagRegion:     string(config.Region),
		tagGeneration: fmt.Sprint(config.Generation),
		tagResource:   resourceMemberHost,
		tagCreateKey:  createKey,
		tagHostNode:   hostNode(config, createKey),
	}
}

func volumeTags(config RegionConfig, request VolumeCreateRequest) map[string]string {
	return map[string]string{
		tagManagedBy:  managedByValue,
		tagOwner:      config.Owner,
		tagRegion:     string(config.Region),
		tagGeneration: fmt.Sprint(config.Generation),
		tagResource:   resourceMemberData,
		tagCreateKey:  request.CreateKey,
		tagVolumeSize: fmt.Sprint(request.SizeGB),
	}
}

// memberName reports whether name is a member host name of this fleet's cell
// or, with data, a member data volume name. Display names carry no owner,
// generation or digest; those stay in the resource tags.
func (f *fleet) memberName(name string, data bool) bool {
	cell, err := naming.RegionCell(string(f.config.Region)).Name()
	return err == nil && naming.Validate(name) == nil && strings.HasPrefix(name, cell+"-"+naming.Member+"-") &&
		strings.HasSuffix(name, "-data") == data
}

func hostNode(config RegionConfig, createKey string) string {
	return "host-" + digest(config.Owner, string(config.Region), fmt.Sprint(config.Generation), createKey)[:24]
}

func retryToken(value string) string { return digest(value) }

func validCreateKey(value string) bool {
	return entityid.Valid(value)
}

func validManagedPrivateIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.IsPrivate() && address.String() == value
}

func validLifecycleState(state string) bool {
	switch state {
	case "PROVISIONING", "RUNNING", "STARTING", "STOPPING", "STOPPED", "TERMINATING", "TERMINATED", "MOVING", "CREATING_IMAGE":
		return true
	default:
		return false
	}
}

func validVolumeLifecycleState(state string) bool {
	switch state {
	case "PROVISIONING", "RESTORING", "AVAILABLE", "TERMINATING", "TERMINATED", "FAULTY":
		return true
	default:
		return false
	}
}

func isNotFound(err error) bool {
	serviceError, ok := errors.AsType[interface {
		error
		GetHTTPStatusCode() int
	}](err)
	return ok && serviceError.GetHTTPStatusCode() == 404
}
