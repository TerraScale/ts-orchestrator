package oci

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
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
	}, nil
}

// NewInstancePrincipalFleet builds official OCI Compute and Block Volume SDK
// clients using instance-principal authentication for one validated region.
func NewInstancePrincipalFleet(
	config RegionConfig,
	intent RegionIntent,
	journal Journal,
	fencer authority.Fencer,
	drainRequester DrainRequester,
	writerStop WriterStopVerifier,
) (Fleet, error) {
	return NewInstancePrincipalFleetWithImageVerifier(config, intent, journal, fencer, drainRequester, writerStop, nil)
}

// NewInstancePrincipalFleetWithImageVerifier preserves instance-principal
// construction while allowing an approved image qualification source to be
// injected when one is available.
func NewInstancePrincipalFleetWithImageVerifier(
	config RegionConfig,
	intent RegionIntent,
	journal Journal,
	fencer authority.Fencer,
	drainRequester DrainRequester,
	writerStop WriterStopVerifier,
	imageVerifier ImageQualificationVerifier,
) (Fleet, error) {
	if err := config.Validate(intent); err != nil {
		return nil, err
	}
	provider, err := newSDKProvider(config)
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
}

func (f *fleet) verifyPinnedImage(ctx context.Context) error {
	if f.imageVerifier == nil {
		return ErrImageQualificationUnavailable
	}
	if err := f.imageVerifier.VerifyImageQualified(ctx, f.config.Region, f.config.ImageID); err != nil {
		return fmt.Errorf("%w: %w", ErrImageNotQualified, err)
	}
	return nil
}

func (f *fleet) verifyRetainedVolumeHostImage(cloud CloudInstance) error {
	if cloud.ImageID != f.config.ImageID || cloud.ConsistentVolumeNamingEnabled == nil || !*cloud.ConsistentVolumeNamingEnabled {
		return fmt.Errorf("%w: instance %s does not report the pinned image and consistent volume naming", ErrImageNotQualified, cloud.ID)
	}
	return nil
}

func (f *fleet) Region() Region { return f.config.Region }

func (f *fleet) Observe(ctx context.Context) ([]Instance, error) {
	cloudInstances, err := f.provider.ListInstances(ctx, f.config.CompartmentID)
	if err != nil {
		return nil, err
	}
	if len(cloudInstances) > maxFleetInstances {
		return nil, errors.New("OCI member host list exceeds its safety bound")
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
			slog.Warn("withholding OCI instance with out-of-scope identity tags", "instance_id", listed.ID, "region", f.config.Region)
			continue
		}
		cloud, identity, err := f.reobserveInstance(ctx, listed.ID)
		if err != nil {
			if errors.Is(err, ErrForeignResource) {
				slog.Warn("withholding OCI instance without a verified regional identity", "instance_id", listed.ID, "region", f.config.Region)
				continue
			}
			return nil, err
		}
		owned, err := f.journal.IsOwnedInstance(ctx, identity)
		if err != nil {
			return nil, fmt.Errorf("read OCI host ownership journal: %w", err)
		}
		if !owned {
			slog.Warn("withholding OCI instance without durable controller ownership", "instance_id", cloud.ID, "region", f.config.Region, "create_key", identity.CreateKey)
			continue
		}
		profileIntent, found, err := f.journal.GetOperation(ctx, OperationScope{
			Action: actionLaunch, Key: identity.CreateKey, Region: identity.Region,
			Generation: identity.Generation, Owner: identity.Owner,
		})
		if err != nil {
			return nil, fmt.Errorf("read OCI host placement profile: %w", err)
		}
		if !found || profileIntent.Shape != f.config.Shape || !cloudMatchesPlacementProfile(cloud, profileIntent) {
			slog.Warn("withholding OCI instance that does not match its signed placement compute profile", "instance_id", cloud.ID, "region", f.config.Region, "create_key", identity.CreateKey)
			continue
		}
		instance, err := f.instanceFromCloud(ctx, cloud, identity, profileIntent)
		if err != nil {
			if errors.Is(err, ErrAttachmentRecoveryHold) {
				slog.Warn("withholding OCI instance with an unbound retained volume attachment", "instance_id", cloud.ID, "region", f.config.Region)
				continue
			}
			return nil, err
		}
		instances = append(instances, instance)
	}
	return instances, nil
}

func (f *fleet) EnsureHost(ctx context.Context, request EnsureRequest) (Instance, error) {
	if !validCreateKey(request.CreateKey) || !slices.Contains(f.config.FaultDomains, request.FaultDomain) {
		return Instance{}, errors.New("OCI host launch has an invalid create key or unsupported fault domain")
	}
	if request.Shape != f.config.Shape || !validComputeProfile(request.Shape, request.WholeOCPUs,
		request.MemoryInGBs, request.PlacementProfileDigest, request.PlacementGeneration) {
		return Instance{}, ErrPlacementProfileMismatch
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return Instance{}, err
	}
	intent := f.intent(actionLaunch, request.CreateKey, "", request.CreateKey, "", request.FaultDomain, "")
	intent.Shape = request.Shape
	intent.WholeOCPUs = request.WholeOCPUs
	intent.MemoryInGBs = request.MemoryInGBs
	intent.PlacementProfileDigest = request.PlacementProfileDigest
	intent.PlacementGeneration = request.PlacementGeneration
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
			// The launch receipt is immutable; the live ETag belongs to this
			// observation and will fence the next tag/termination operation.
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
		CreateKey: request.CreateKey,
		Node:      node,
		RetryToken: retryToken(strings.Join([]string{
			f.config.Owner, string(f.config.Region), fmt.Sprint(f.config.Generation), request.CreateKey,
		}, ":")),
		FaultDomain:            operationIntent.FaultDomain,
		Shape:                  operationIntent.Shape,
		WholeOCPUs:             operationIntent.WholeOCPUs,
		MemoryInGBs:            operationIntent.MemoryInGBs,
		PlacementProfileDigest: operationIntent.PlacementProfileDigest,
		PlacementGeneration:    operationIntent.PlacementGeneration,
		FreeformTags: placementProfileTags(
			hostTags(f.config, request.CreateKey), operationIntent.PlacementProfileDigest, operationIntent.PlacementGeneration,
		),
	}
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
	if err := f.recordResult(ctx, epoch, OperationResult{Intent: operationIntent, ResourceID: cloud.ID, ETag: cloud.ETag}); err != nil {
		return Instance{}, err
	}
	return f.instanceFromCloud(ctx, cloud, identity, operationIntent)
}

// CreateRetainedVolume creates or recovers one region-pinned member data
// volume. An existing volume is accepted only when the durable journal proves
// ownership or a prior Unknown result authorizes a stable-token replay. If a
// process stops after OCI accepts a mutation but before Unknown is recorded,
// the resource remains withheld for operator inspection instead of being
// adopted from tags alone.
func (f *fleet) CreateRetainedVolume(ctx context.Context, request VolumeCreateRequest) (RetainedVolume, error) {
	if !validCreateKey(request.CreateKey) || request.SizeGB < minRetainedVolumeSizeGB {
		return RetainedVolume{}, errors.New("retained OCI volume requires a valid create key and at least 50 GiB")
	}
	if err := f.verifyPinnedImage(ctx); err != nil {
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
			if cloud.SizeGB != request.SizeGB || cloud.AvailabilityDomain != request.AvailabilityDomain {
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
	if err := f.verifyPinnedImage(ctx); err != nil {
		return Attachment{}, err
	}
	epoch, err := f.currentEpoch()
	if err != nil {
		return Attachment{}, err
	}
	instance, identity, err := f.ownedInstance(ctx, request.InstanceID)
	if err != nil {
		return Attachment{}, err
	}
	if err := f.verifyRetainedVolumeHostImage(instance); err != nil {
		return Attachment{}, err
	}
	if _, err := f.ownedVolume(ctx, request.VolumeID); err != nil {
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
		attachments, err := f.findVolumeAttachments(ctx, request.VolumeID)
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
	attachments, err := f.findVolumeAttachments(ctx, request.VolumeID)
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
		attachment, err := f.reobserveAttachment(ctx, attachments[0].ID, request.VolumeID, request.InstanceID, intent.Device)
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
		IdempotencyKey: request.IdempotencyKey, Device: intent.Device,
		IsReadOnly: intent.IsReadOnly, IsShareable: intent.IsShareable,
		IsPvEncryptionInTransitEnabled: intent.IsPvEncryptionInTransitEnabled,
	})
	attachments, observeErr := f.findVolumeAttachments(ctx, request.VolumeID)
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
	attachment, err := f.reobserveAttachment(ctx, attachments[0].ID, request.VolumeID, request.InstanceID, intent.Device)
	if err != nil {
		return Attachment{}, errors.Join(ErrOutcomeUnknown, err,
			f.recordResult(ctx, epoch, OperationResult{Intent: intent, Unknown: true}))
	}
	if created.ID != "" && created.ID != attachment.ID ||
		created.ETag != "" && created.ETag != attachment.ETag ||
		attachErr == nil && (created.ID == "" || created.ETag == "") {
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

func (f *fleet) findByCreateKey(ctx context.Context, createKey string) (CloudInstance, ResourceIdentity, bool, error) {
	instances, err := f.provider.ListInstances(ctx, f.config.CompartmentID)
	if err != nil {
		return CloudInstance{}, ResourceIdentity{}, false, err
	}
	var ids []string
	for _, instance := range instances {
		if instance.FreeformTags[tagCreateKey] == createKey {
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
	return cloud, identity, nil
}

func (f *fleet) ownedInstance(ctx context.Context, instanceID string) (CloudInstance, ResourceIdentity, error) {
	cloud, identity, err := f.reobserveInstance(ctx, instanceID)
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
		PlacementGeneration: profile.PlacementGeneration, ETag: cloud.ETag,
		State: cloud.LifecycleState,
	}
	for _, listed := range attachments {
		if listed.InstanceID != cloud.ID || listed.VolumeID == "" || listed.ID == "" {
			return Instance{}, fmt.Errorf("%w: OCI attachment scope changed", ErrForeignResource)
		}
		if _, err := f.ownedVolume(ctx, listed.VolumeID); err != nil {
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
		result.DataVolumes = append(result.DataVolumes, attachment.VolumeID)
		result.Attachments = append(result.Attachments, attachment)
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
	slices.Sort(available)
	return available[0], nil
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

func (f *fleet) findVolumeAttachments(ctx context.Context, volumeID string) ([]CloudAttachment, error) {
	attachments, err := f.provider.ListVolumeAttachments(ctx, f.config.CompartmentID, "")
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
		if volume.FreeformTags[tagCreateKey] == createKey {
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
		tags[tagManagedBy] != managedByValue || tags[tagOwner] != f.config.Owner ||
		tags[tagRegion] != string(f.config.Region) || tags[tagGeneration] != fmt.Sprint(f.config.Generation) ||
		tags[tagResource] != resourceMemberData || tags[tagVolumeSize] != fmt.Sprint(volume.SizeGB) ||
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
	return cloud.Shape == intent.Shape && cloud.Ocpus != nil && *cloud.Ocpus == wantOCPUs &&
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

func hostNode(config RegionConfig, createKey string) string {
	return "host-" + digest(config.Owner, string(config.Region), fmt.Sprint(config.Generation), createKey)[:24]
}

func retryToken(value string) string { return digest(value) }

func validCreateKey(value string) bool {
	return len(value) > 0 && len(value) <= maxCreateKeyBytes &&
		!strings.ContainsAny(value, " \t\r\n") && strings.TrimSpace(value) == value
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
