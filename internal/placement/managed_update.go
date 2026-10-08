package placement

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	ManagedUpdateSchemaVersion        = 1
	ManagedCompatibilitySchemaVersion = 1
	ManagedUpdateEnvelopeKind         = "terrabase.managed-update.prepare"
	ManagedCompatibilityEnvelopeKind  = "terrabase.managed-update.compatibility"
)

// ManagedUpdateIntent is the operator-signed Prepare request that moves one
// seat of a two-member placement from its current artifact to a candidate.
// A rolling release is one operation per seat: the canary first, then the
// peer once the canary serves, whose own operation then sees the canary seat
// already on the candidate. Rolling a held seat back to the artifact it
// replaced is the same request with that artifact as the candidate. It never
// changes the immutable placement or its material.
type ManagedUpdateIntent struct {
	SchemaVersion           int                            `json:"schema_version"`
	Cell                    string                         `json:"cell"`
	DatabaseID              string                         `json:"database_id"`
	PartitionID             string                         `json:"partition_id"`
	PlacementGeneration     uint64                         `json:"placement_generation"`
	PlacementPayloadDigest  string                         `json:"placement_payload_digest"`
	PlacementSequence       uint64                         `json:"placement_sequence"`
	AuthorityEpoch          uint64                         `json:"authority_epoch"`
	OperationID             string                         `json:"operation_id"`
	Role                    string                         `json:"role"`
	Environment             string                         `json:"environment"`
	OldArtifactDigest       string                         `json:"old_artifact_digest"`
	CandidateArtifactDigest string                         `json:"candidate_artifact_digest"`
	CandidateManifestDigest string                         `json:"candidate_manifest_digest"`
	CandidateSourceDigest   string                         `json:"candidate_source_digest"`
	CanarySeatID            string                         `json:"canary_seat_id"`
	CanaryDesiredGeneration uint64                         `json:"canary_desired_generation"`
	DurabilityProfile       ManagedUpdateDurabilityProfile `json:"durability_profile"`
	Seats                   []ManagedUpdateSeat            `json:"seats"`
	CompatibilityEvidence   protocol.Envelope              `json:"compatibility_evidence"`
}

// ManagedUpdateSeat pins the observed predecessor for one continuing member.
// ArtifactDigest is the artifact the seat currently runs. The immutable
// RuntimeManifestDigest prevents an update from rewriting boot, material,
// filesystem, replication, or other initial placement inputs.
type ManagedUpdateSeat struct {
	SeatID                string     `json:"seat_id"`
	Region                oci.Region `json:"region"`
	MemberID              string     `json:"member_id"`
	Incarnation           string     `json:"incarnation"`
	TLSLeafSHA256         string     `json:"tls_leaf_sha256"`
	RuntimeManifestDigest string     `json:"runtime_manifest_digest"`
	HostNode              string     `json:"host_node"`
	HostGeneration        uint64     `json:"host_generation"`
	HostAttempt           uint64     `json:"host_attempt"`
	OCIInstanceID         string     `json:"oci_instance_id"`
	OCIOwner              string     `json:"oci_owner"`
	OCIFleetGeneration    uint64     `json:"oci_fleet_generation"`
	CreateKey             string     `json:"create_key"`
	VolumeID              string     `json:"volume_id"`
	AttachmentID          string     `json:"attachment_id"`
	AttachmentETag        string     `json:"attachment_etag"`
	AttachmentDevice      string     `json:"attachment_device"`
	DesiredGeneration     uint64     `json:"desired_generation"`
	ArtifactDigest        string     `json:"artifact_digest"`
}

// ManagedUpdateDurabilityProfile is the selected persistent-data contract
// that compatibility evidence must cover. Per-seat volume formats are ordered
// by seat ID and are checked against current durable placement state before
// this profile can authorize a canary.
type ManagedUpdateDurabilityProfile struct {
	SchemaVersion         int                          `json:"schema_version"`
	Region                oci.Region                   `json:"region"`
	Volumes               []ManagedUpdateVolumeProfile `json:"volumes"`
	SQLSchemaBundleSHA256 string                       `json:"sql_schema_bundle_sha256,omitzero"`
	LiveS3ConfigSHA256    string                       `json:"live_s3_config_sha256"`
	LiveS3TargetSHA256    string                       `json:"live_s3_target_sha256"`
	LiveS3Credential      oci.SecretVersionReference   `json:"live_s3_credential"`
}

// ManagedUpdateVolumeProfile identifies the exact retained filesystem whose
// persistent format is covered by compatibility evidence.
type ManagedUpdateVolumeProfile struct {
	SeatID         string `json:"seat_id"`
	VolumeID       string `json:"volume_id"`
	FileSystemUUID string `json:"filesystem_uuid"`
	FileSystemType string `json:"filesystem_type"`
}

// ManagedCompatibilityEvidence is the independently signed payload carried
// by ManagedUpdateIntent. Its booleans are accepted only after the containing
// protocol envelope has been verified against a trusted compatibility signer.
type ManagedCompatibilityEvidence struct {
	SchemaVersion                    int    `json:"schema_version"`
	Cell                             string `json:"cell"`
	OperationID                      string `json:"operation_id"`
	OldArtifactDigest                string `json:"old_artifact_digest"`
	CandidateArtifactDigest          string `json:"candidate_artifact_digest"`
	CandidateManifestDigest          string `json:"candidate_manifest_digest"`
	DurabilityProfileSHA256          string `json:"durability_profile_sha256"`
	MixedVersionReplicationSupported bool   `json:"mixed_version_replication_supported"`
	ClientDataCompatibilitySupported bool   `json:"client_data_compatibility_supported"`
	PersistentFormatReadSupported    bool   `json:"persistent_format_read_supported"`
	PersistentFormatWriteSupported   bool   `json:"persistent_format_write_supported"`
}

// Validate checks all request structure and cross-field pins. Cryptographic
// envelope verification remains the responsibility of the admission boundary.
func (intent ManagedUpdateIntent) Validate() error {
	if intent.SchemaVersion != ManagedUpdateSchemaVersion || !validToken(intent.Cell) ||
		!validDatabaseKeyID(intent.DatabaseID) || !entityid.Valid(intent.PartitionID) ||
		intent.PlacementGeneration == 0 || !validLowerSHA256Digest(intent.PlacementPayloadDigest) ||
		intent.PlacementSequence == 0 || intent.AuthorityEpoch == 0 || !entityid.Valid(intent.OperationID) ||
		intent.Role != "terrabase" || !validToken(intent.Environment) ||
		!validLowerSHA256Digest(intent.OldArtifactDigest) ||
		!validLowerSHA256Digest(intent.CandidateArtifactDigest) ||
		intent.CandidateArtifactDigest == intent.OldArtifactDigest ||
		!validLowerSHA256Digest(intent.CandidateManifestDigest) ||
		!validLowerSHA256Digest(intent.CandidateSourceDigest) ||
		!entityid.Valid(intent.CanarySeatID) || intent.CanaryDesiredGeneration == 0 ||
		len(intent.Seats) != 2 {
		return errors.New("invalid managed TerraBase update intent")
	}
	if err := intent.DurabilityProfile.Validate(); err != nil {
		return fmt.Errorf("invalid managed update durability profile: %w", err)
	}
	profileDigest, err := intent.DurabilityProfile.Digest()
	if err != nil {
		return fmt.Errorf("digest managed update durability profile: %w", err)
	}
	if !strings.EqualFold(string(intent.DurabilityProfile.Region), intent.Cell) {
		return errors.New("managed update durability profile cell differs from the signed cell")
	}
	if !slices.IsSortedFunc(intent.Seats, func(left, right ManagedUpdateSeat) int {
		return strings.Compare(left.SeatID, right.SeatID)
	}) || !slices.IsSortedFunc(intent.DurabilityProfile.Volumes, func(left, right ManagedUpdateVolumeProfile) int {
		return strings.Compare(left.SeatID, right.SeatID)
	}) {
		return errors.New("managed update seats and durability volumes must be sorted by seat ID")
	}
	canaryFound := false
	seatIDs := make([]string, len(intent.Seats))
	for index, seat := range intent.Seats {
		if err := seat.validate(intent); err != nil {
			return fmt.Errorf("invalid managed update seat %q: %w", seat.SeatID, err)
		}
		if index > 0 && (intent.Seats[index-1].SeatID == seat.SeatID || intent.Seats[index-1].MemberID == seat.MemberID) {
			return errors.New("managed update seats must identify distinct members")
		}
		if index > 0 && (intent.Seats[index-1].HostNode == seat.HostNode ||
			intent.Seats[index-1].OCIInstanceID == seat.OCIInstanceID ||
			intent.Seats[index-1].VolumeID == seat.VolumeID ||
			intent.Seats[index-1].AttachmentID == seat.AttachmentID) {
			return errors.New("managed update seats must retain distinct hosts and volumes")
		}
		seatIDs[index] = seat.SeatID
		if seat.SeatID == intent.CanarySeatID {
			canaryFound = true
			if seat.DesiredGeneration == ^uint64(0) || intent.CanaryDesiredGeneration != seat.DesiredGeneration+1 {
				return errors.New("managed update canary generation must follow its exact predecessor")
			}
		}
	}
	if !canaryFound || len(intent.DurabilityProfile.Volumes) != len(intent.Seats) {
		return errors.New("managed update canary or durability seat set is incomplete")
	}
	for index, volume := range intent.DurabilityProfile.Volumes {
		if volume.SeatID != seatIDs[index] || volume.VolumeID != intent.Seats[index].VolumeID {
			return errors.New("managed update durability profile differs from the pinned seat volumes")
		}
	}
	var evidence ManagedCompatibilityEvidence
	if err := protocol.DecodeStrict(intent.CompatibilityEvidence.Payload, &evidence, protocol.MaxPayloadBytes); err != nil {
		return fmt.Errorf("decode signed managed compatibility evidence: %w", err)
	}
	canonical, err := protocol.EncodeJSON(evidence)
	if err != nil || !bytes.Equal(canonical, intent.CompatibilityEvidence.Payload) {
		return errors.New("signed managed compatibility evidence is not canonical")
	}
	canonicalCell, err := protocol.CanonicalRegion(intent.Cell)
	if err != nil || intent.CompatibilityEvidence.Region != canonicalCell || intent.CompatibilityEvidence.Kind != ManagedCompatibilityEnvelopeKind ||
		intent.CompatibilityEvidence.OperationID != intent.OperationID ||
		intent.CompatibilityEvidence.Generation != intent.CanaryDesiredGeneration ||
		intent.CompatibilityEvidence.Epoch == 0 || intent.CompatibilityEvidence.Actor == "" ||
		intent.CompatibilityEvidence.KeyID == "" || intent.CompatibilityEvidence.Signature == "" ||
		evidence.SchemaVersion != ManagedCompatibilitySchemaVersion || evidence.Cell != intent.Cell ||
		evidence.OperationID != intent.OperationID || evidence.OldArtifactDigest != intent.OldArtifactDigest ||
		evidence.CandidateArtifactDigest != intent.CandidateArtifactDigest ||
		evidence.CandidateManifestDigest != intent.CandidateManifestDigest ||
		evidence.DurabilityProfileSHA256 != profileDigest ||
		!evidence.MixedVersionReplicationSupported || !evidence.ClientDataCompatibilitySupported ||
		!evidence.PersistentFormatReadSupported || !evidence.PersistentFormatWriteSupported {
		return errors.New("signed managed compatibility evidence does not affirm the exact update and durability profile")
	}
	for _, seat := range intent.Seats {
		if seat.SeatID == intent.CanarySeatID && seat.ArtifactDigest != intent.OldArtifactDigest ||
			seat.ArtifactDigest != intent.OldArtifactDigest && seat.ArtifactDigest != intent.CandidateArtifactDigest {
			return errors.New("managed update canary must run the prior artifact and its peer the prior or candidate artifact")
		}
	}
	return nil
}

func (seat ManagedUpdateSeat) validate(intent ManagedUpdateIntent) error {
	if !entityid.Valid(seat.SeatID) || !knownRegion(seat.Region) || !strings.EqualFold(string(seat.Region), intent.Cell) ||
		!entityid.Valid(seat.MemberID) || !entityid.Valid(seat.Incarnation) || allZeroHex(seat.Incarnation) ||
		!validLowerSHA256Digest(seat.TLSLeafSHA256) || !validLowerSHA256Digest(seat.RuntimeManifestDigest) ||
		!validToken(seat.HostNode) || seat.HostGeneration == 0 || seat.HostAttempt == 0 ||
		!validOCID(seat.OCIInstanceID, "instance") || !validToken(seat.OCIOwner) || seat.OCIFleetGeneration == 0 ||
		!entityid.Valid(seat.CreateKey) || !validOCID(seat.VolumeID, "volume") ||
		!validOCID(seat.AttachmentID, "volumeattachment") || seat.AttachmentETag == "" ||
		strings.ContainsAny(seat.AttachmentETag, "\r\n\x00") || !validManagedDevicePath(seat.AttachmentDevice) ||
		seat.DesiredGeneration == 0 || !validLowerSHA256Digest(seat.ArtifactDigest) {
		return errors.New("incomplete managed seat predecessor identity")
	}
	return nil
}

// Validate checks the persistent-format profile before it is signed into a
// managed update. Exact correspondence to the active placement is checked by
// the regional admission handler.
func (profile ManagedUpdateDurabilityProfile) Validate() error {
	if profile.SchemaVersion != ManagedUpdateSchemaVersion || !knownRegion(profile.Region) ||
		len(profile.Volumes) != 2 ||
		(profile.SQLSchemaBundleSHA256 != "" && !validLowerSHA256Digest(profile.SQLSchemaBundleSHA256)) ||
		!validLowerSHA256Digest(profile.LiveS3ConfigSHA256) ||
		!validLowerSHA256Digest(profile.LiveS3TargetSHA256) || profile.LiveS3Credential.Validate() != nil {
		return errors.New("incomplete managed durability profile")
	}
	if !slices.IsSortedFunc(profile.Volumes, func(left, right ManagedUpdateVolumeProfile) int {
		return strings.Compare(left.SeatID, right.SeatID)
	}) {
		return errors.New("managed durability volumes must be sorted by seat ID")
	}
	for index, volume := range profile.Volumes {
		if !entityid.Valid(volume.SeatID) || (index > 0 && profile.Volumes[index-1].SeatID == volume.SeatID) ||
			!validOCID(volume.VolumeID, "volume") || !validFilesystemUUID(volume.FileSystemUUID) ||
			volume.FileSystemType != "ext4" && volume.FileSystemType != "xfs" {
			return errors.New("invalid managed durability volume profile")
		}
	}
	if profile.LiveS3Credential.Validate() != nil {
		return errors.New("managed durability profile requires an exact ObjectDurable credential version")
	}
	return nil
}

// Digest returns the lower-case SHA-256 of the canonical selected profile.
func (profile ManagedUpdateDurabilityProfile) Digest() (string, error) {
	if err := profile.Validate(); err != nil {
		return "", err
	}
	encoded, err := protocol.EncodeJSON(profile)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// Digest returns the canonical SHA-256 used as the authority operation
// fingerprint and in receipts. Compatibility evidence signatures are part of
// the request bytes and therefore part of this digest.
func (intent ManagedUpdateIntent) Digest() (string, error) {
	if err := intent.Validate(); err != nil {
		return "", err
	}
	encoded, err := protocol.EncodeJSON(intent)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validOCID(value, kind string) bool {
	prefix := "ocid1." + kind + "."
	return len(value) > len(prefix) && len(value) <= 255 && strings.HasPrefix(value, prefix) &&
		!strings.ContainsAny(value, " \t\r\n\x00")
}

func validManagedDevicePath(value string) bool {
	return len(value) <= 255 && filepath.IsAbs(value) && filepath.Clean(value) == value &&
		!strings.ContainsAny(value, " \t\r\n\x00")
}
