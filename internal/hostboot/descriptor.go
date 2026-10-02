// Package hostboot defines the bounded public metadata hint used to identify
// one managed host launch. A parsed descriptor is untrusted data and grants no
// enrollment, OCI mutation, or launch authority by itself.
package hostboot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	SchemaVersion      = 1
	MetadataKey        = "terrascale_hostboot_v1"
	MaxDescriptorBytes = 4096
	// EnrollmentMetadataKey carries the exact public host enrollment bundle.
	// Controllers deliver it at launch so the host image stays deployment-neutral.
	EnrollmentMetadataKey = "terrascale-host-enrollment-v1"
)

var (
	ErrInvalidDescriptor = errors.New("managed host boot descriptor is invalid")
	descriptorToken      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	descriptorCreateKey  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?$`)
	descriptorDigest     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	descriptorImageID    = regexp.MustCompile(`^ocid1\.image\.[A-Za-z0-9][A-Za-z0-9._-]{0,242}$`)
)

// Descriptor is a strict public hint for one managed-host launch. OCI values
// are supplied by the region-pinned Fleet and placement values by its durable
// member record. Instance identity is not known until after launch.
type Descriptor struct {
	SchemaVersion            int    `json:"schema_version"`
	Cell                     string `json:"cell"`
	Region                   string `json:"region"`
	Node                     string `json:"node"`
	Owner                    string `json:"owner"`
	FleetGeneration          uint64 `json:"fleet_generation"`
	CreateKey                string `json:"create_key"`
	ImageID                  string `json:"image_id"`
	DatabaseID               string `json:"database_id"`
	PartitionID              string `json:"partition_id"`
	SeatID                   string `json:"seat_id"`
	HostAttempt              uint64 `json:"host_attempt"`
	IntentGeneration         uint64 `json:"intent_generation"`
	IntentPayloadDigest      string `json:"intent_payload_digest"`
	CanonicalRosterDigest    string `json:"canonical_roster_digest"`
	ManagedHostProfileDigest string `json:"managed_host_profile_digest"`
	RuntimeManifestDigest    string `json:"runtime_manifest_digest"`
}

// Validate checks the closed v1 identity and digest bindings and the bounded
// canonical wire size. It performs no signature or live-resource checks.
func (descriptor Descriptor) Validate() error {
	_, err := descriptor.CanonicalBytes()
	return err
}

// CanonicalBytes returns the deterministic v1 JSON representation used in OCI
// instance metadata and retry binding.
func (descriptor Descriptor) CanonicalBytes() ([]byte, error) {
	if err := descriptor.validateFields(); err != nil {
		return nil, err
	}
	wire, err := protocol.EncodeJSON(descriptor)
	if err != nil {
		return nil, fmt.Errorf("%w: encode canonical JSON: %v", ErrInvalidDescriptor, err)
	}
	if len(wire) == 0 || len(wire) > MaxDescriptorBytes {
		return nil, fmt.Errorf("%w: canonical JSON exceeds %d bytes", ErrInvalidDescriptor, MaxDescriptorBytes)
	}
	return wire, nil
}

// Digest returns the lowercase SHA-256 digest of CanonicalBytes.
func (descriptor Descriptor) Digest() (string, error) {
	wire, err := descriptor.CanonicalBytes()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

// Parse decodes one exact canonical v1 descriptor. Unknown members, duplicate
// names, oversized input, and alternate noncanonical encodings are rejected.
func Parse(wire []byte) (Descriptor, error) {
	if len(wire) == 0 || len(wire) > MaxDescriptorBytes {
		return Descriptor{}, fmt.Errorf("%w: wire is absent or exceeds %d bytes", ErrInvalidDescriptor, MaxDescriptorBytes)
	}
	var descriptor Descriptor
	if err := protocol.DecodeStrict(wire, &descriptor, MaxDescriptorBytes); err != nil {
		return Descriptor{}, fmt.Errorf("%w: decode strict JSON: %v", ErrInvalidDescriptor, err)
	}
	canonical, err := descriptor.CanonicalBytes()
	if err != nil {
		return Descriptor{}, err
	}
	if !bytes.Equal(wire, canonical) {
		return Descriptor{}, fmt.Errorf("%w: wire is not the exact canonical representation", ErrInvalidDescriptor)
	}
	return descriptor, nil
}

func (descriptor Descriptor) validateFields() error {
	if descriptor.SchemaVersion != SchemaVersion || !validCellRegion(descriptor.Cell, descriptor.Region) ||
		!descriptorToken.MatchString(descriptor.Node) || !descriptorToken.MatchString(descriptor.Owner) ||
		!validCreateKey(descriptor.CreateKey) || !descriptorImageID.MatchString(descriptor.ImageID) ||
		descriptor.FleetGeneration == 0 || descriptor.HostAttempt == 0 || descriptor.IntentGeneration == 0 ||
		!descriptorToken.MatchString(descriptor.DatabaseID) || !descriptorToken.MatchString(descriptor.PartitionID) ||
		!descriptorToken.MatchString(descriptor.SeatID) ||
		!descriptorDigest.MatchString(descriptor.IntentPayloadDigest) ||
		!descriptorDigest.MatchString(descriptor.CanonicalRosterDigest) ||
		!descriptorDigest.MatchString(descriptor.ManagedHostProfileDigest) ||
		!descriptorDigest.MatchString(descriptor.RuntimeManifestDigest) {
		return fmt.Errorf("%w: required identity, generation, image, or digest binding", ErrInvalidDescriptor)
	}
	return nil
}

func validCellRegion(cell, region string) bool {
	return catalog.MatchesName(cell, region)
}

func validCreateKey(value string) bool {
	return descriptorCreateKey.MatchString(value)
}
