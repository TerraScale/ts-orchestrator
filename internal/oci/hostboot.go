package oci

import (
	"fmt"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
)

// hostBootDescriptor combines the durable placement attempt with only this
// Fleet's pinned OCI identity. The descriptor is a public hint, not authority.
func (f *fleet) hostBootDescriptor(request EnsureRequest) (hostboot.Descriptor, error) {
	return hostboot.Descriptor{
		SchemaVersion:            1,
		Cell:                     strings.ToLower(string(f.config.Region)),
		Region:                   string(f.config.Region),
		Node:                     hostNode(f.config, request.CreateKey),
		Owner:                    f.config.Owner,
		FleetGeneration:          f.config.Generation,
		CreateKey:                request.CreateKey,
		ImageID:                  f.config.ImageID,
		DatabaseID:               request.BootPins.DatabaseID,
		PartitionID:              request.BootPins.PartitionID,
		SeatID:                   request.BootPins.SeatID,
		HostAttempt:              request.BootPins.HostAttempt,
		IntentGeneration:         request.PlacementGeneration,
		IntentPayloadDigest:      request.BootPins.IntentPayloadDigest,
		CanonicalRosterDigest:    request.BootPins.CanonicalRosterDigest,
		ManagedHostProfileDigest: request.PlacementProfileDigest,
		RuntimeManifestDigest:    request.BootPins.RuntimeManifestDigest,
	}, nil
}

// launchIntentDescriptor checks the complete immutable journal binding. Older
// launches without a descriptor cannot become positively observed hosts.
func launchIntentDescriptor(intent OperationIntent) (hostboot.Descriptor, error) {
	if intent.Action != actionLaunch || !isOCID(intent.ImageID, "image") ||
		!isLowerHexSHA256(intent.BootDescriptorSHA256) {
		return hostboot.Descriptor{}, ErrHostBootBindingMismatch
	}
	descriptor, err := hostboot.Parse([]byte(intent.BootDescriptor))
	if err != nil {
		return hostboot.Descriptor{}, fmt.Errorf("%w: %v", ErrHostBootBindingMismatch, err)
	}
	digest, err := descriptor.Digest()
	if err != nil || digest != intent.BootDescriptorSHA256 {
		return hostboot.Descriptor{}, ErrHostBootBindingMismatch
	}
	if descriptor.Cell != strings.ToLower(string(intent.Region)) || descriptor.Region != string(intent.Region) ||
		descriptor.Node != hostNode(RegionConfig{Region: intent.Region, Generation: intent.Generation, Owner: intent.Owner}, intent.CreateKey) ||
		descriptor.Owner != intent.Owner || descriptor.FleetGeneration != intent.Generation ||
		descriptor.CreateKey != intent.CreateKey || descriptor.ImageID != intent.ImageID ||
		descriptor.IntentGeneration != intent.PlacementGeneration ||
		descriptor.ManagedHostProfileDigest != intent.PlacementProfileDigest {
		return hostboot.Descriptor{}, ErrHostBootBindingMismatch
	}
	return descriptor, nil
}

func cloudMatchesLaunchBinding(cloud CloudInstance, intent OperationIntent) bool {
	if _, err := launchIntentDescriptor(intent); err != nil {
		return false
	}
	return cloudMatchesPlacementProfile(cloud, intent) && cloud.FaultDomain == intent.FaultDomain &&
		cloud.ImageID == intent.ImageID && cloud.Metadata[hostboot.MetadataKey] == intent.BootDescriptor
}
