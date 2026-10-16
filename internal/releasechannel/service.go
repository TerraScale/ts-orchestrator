package releasechannel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// A service release channel (TS-610) carries one release of a native role
// such as terrabase or ts-auth: CI uploads the binary under its digest and
// replaces release.json with the delivery artifact claim it signed with the
// role's scoped release key. The region's authority leader admits the claim
// and rolls the role out through the release gate; it reports in
// status.json, which CI polls.
const (
	ServiceStatusSchema = "terrascale.orchestrator.service-release-status"
	servicePrefix       = "releases/services/"
	// MaxServiceClaimBytes bounds release.json: one signed artifact claim.
	MaxServiceClaimBytes = 8 << 10
	// MaxServiceBinaryBytes bounds a service binary, the artifact store's
	// own bound.
	MaxServiceBinaryBytes = 512 << 20
)

// ServiceReleaseObject, ServiceStatusObject and ServiceBinaryObject are a
// role's objects in the region's head bucket.
func ServiceReleaseObject(role string) string { return servicePrefix + role + "/release.json" }
func ServiceStatusObject(role string) string  { return servicePrefix + role + "/status.json" }
func ServiceBinaryObject(role, sha256 string) string {
	return servicePrefix + role + "/binaries/" + sha256
}

// ClaimClockSkew bounds how far ahead of a reader's clock a claim may be
// issued. A leader refuses a claim issued later; a publisher never keeps
// one as the channel's ordering floor.
const ClaimClockSkew = 5 * time.Minute

// ServiceStatusKey is the leader's state of a role's release in Bucket.
func ServiceStatusKey(cell, role string) string { return "service." + role + "." + cell }

// ServiceStatus is the region leader's report on a role's release: the
// release is the claim's digest and issuance instant.
type ServiceStatus struct {
	ReleaseSequence uint64       `json:"release_sequence,omitzero"`
	SourceRevision  string       `json:"source_revision,omitempty"`
	Schema          string       `json:"schema"`
	Cell            string       `json:"cell"`
	Role            string       `json:"role"`
	Digest          string       `json:"digest"`
	IssuedAt        time.Time    `json:"issued_at"`
	State           State        `json:"state"`
	Reason          string       `json:"reason,omitempty"`
	UpdatedAt       time.Time    `json:"updated_at"`
	Pins            *ReleasePins `json:"pins,omitempty"`
}

// ClaimIssuedAt returns when a signed artifact claim was issued.
func ClaimIssuedAt(claim []byte) (time.Time, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(claim, &envelope, MaxServiceClaimBytes); err != nil {
		return time.Time{}, fmt.Errorf("%w: release claim: %w", ErrInvalid, err)
	}
	return envelope.IssuedAt, nil
}

// PublishService replaces role's release.json with claim by
// compare-and-swap. A claim issued earlier than the one in the channel, or
// another claim issued at the same instant, never replaces it, unless that
// one is issued more than ClaimClockSkew ahead; the same claim may be
// published again.
func PublishService(ctx context.Context, location Location, role string, claim []byte) error {
	record, _, err := serviceClaimOrder(claim)
	if err != nil {
		return err
	}
	if record.ReleaseSequence > 0 {
		return fmt.Errorf("%w: sequenced service requires verified migration", ErrInvalid)
	}
	return publishService(ctx, location, role, claim, nil, nil)
}

// PublishServiceSequenced transports the root-authorized migration separately
// so existing readers continue to receive the original signed artifact claim.
func PublishServiceSequenced(ctx context.Context, location Location, role string, claim []byte, envelope trust.Envelope, roots trust.Keyring, now time.Time) error {
	record, _, err := serviceClaimOrder(claim)
	if err != nil {
		return err
	}
	migration, err := release.VerifySequenceMigrationHistorical(envelope, roots, role, record.Environment)
	if err != nil {
		return err
	}
	var claimEnvelope protocol.Envelope
	if err := protocol.DecodeStrict(claim, &claimEnvelope, MaxServiceClaimBytes); err != nil {
		return err
	}
	if claimEnvelope.KeyID != migration.SignerKeyID {
		return fmt.Errorf("%w: claim signer does not own release order", ErrInvalid)
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		return err
	}
	if record.Role != role || record.ReleaseSequence <= migration.SequenceFloor || record.SequenceMigrationSHA256 != fingerprint {
		return fmt.Errorf("%w: service sequence migration", ErrInvalid)
	}
	if err := verifyServiceSequenceClaim(ctx, claim, migration); err != nil {
		return err
	}
	expectedBucket, err := BucketName(strings.ToUpper(record.Cell))
	if err != nil {
		return err
	}
	if expectedBucket != location.Bucket || migration.Namespace != location.Namespace {
		return fmt.Errorf("%w: service publication target scope", ErrInvalid)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	if err := location.put(ctx, SequenceMigrationObject(fingerprint), wire, ""); err != nil {
		if !errors.Is(err, ErrConflict) {
			return err
		}
		if _, found, err := ReadSequenceMigration(ctx, location, fingerprint); err != nil || !found {
			return fmt.Errorf("%w: existing sequence migration: %w", ErrInvalid, err)
		}
	}
	return publishService(ctx, location, role, claim, &migration, roots)
}

func serviceClaimOrder(claim []byte) (delivery.ArtifactRecord, time.Time, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(claim, &envelope, MaxServiceClaimBytes); err != nil {
		return delivery.ArtifactRecord{}, time.Time{}, err
	}
	var record delivery.ArtifactRecord
	if err := protocol.DecodeStrict(envelope.Payload, &record, MaxServiceClaimBytes); err != nil {
		return record, time.Time{}, err
	}
	return record, envelope.IssuedAt, nil
}

func publishService(ctx context.Context, location Location, role string, claim []byte, migration *release.SequenceMigration, roots trust.Keyring) error {
	record, issued, err := serviceClaimOrder(claim)
	if err != nil {
		return err
	}
	name := ServiceReleaseObject(role)
	for range 3 {
		current, etag, found, err := location.get(ctx, name, MaxServiceClaimBytes)
		if err != nil {
			return err
		}
		if found {
			existing, existingIssued, err := serviceClaimOrder(current)
			if err != nil {
				return fmt.Errorf("decode current service release: %w", err)
			}
			switch {
			case existing.ReleaseSequence > 0:
				if record.ReleaseSequence > 0 {
					envelope, found, err := ReadSequenceMigration(ctx, location, existing.SequenceMigrationSHA256)
					if err != nil {
						return err
					}
					if !found {
						return fmt.Errorf("%w: existing migration missing", ErrInvalid)
					}
					existingMigration, err := release.VerifySequenceMigrationHistorical(envelope, roots, role, existing.Environment)
					if err != nil {
						return err
					}
					if err := verifyServiceSequenceClaim(ctx, current, existingMigration); err != nil {
						return err
					}
				}
				if record.ReleaseSequence < existing.ReleaseSequence {
					return ErrStale
				}
				if record.ReleaseSequence == existing.ReleaseSequence && record.ManifestDigest != existing.ManifestDigest {
					return fmt.Errorf("%w: sequence already names another artifact", ErrInvalid)
				}
			case record.ReleaseSequence > 0:
				if migration == nil || !migration.AdmitsLegacyFloor(strings.ToUpper(record.Cell), 0, existingIssued) {
					return fmt.Errorf("%w: migration does not cover retained service floor", ErrStale)
				}
			case existingIssued.After(time.Now().Add(ClaimClockSkew)):
			case existingIssued.After(issued):
				return ErrStale
			case existingIssued.Equal(issued) && !bytes.Equal(current, claim):
				return fmt.Errorf("%w: another release shares issuance instant", ErrInvalid)
			}
		}
		if err := location.put(ctx, name, claim, etag); !errors.Is(err, ErrConflict) {
			return err
		}
	}
	return ErrConflict
}

// ReadServiceClaim returns role's release.json; found is false when the
// role has none.
func ReadServiceClaim(ctx context.Context, location Location, role string) ([]byte, bool, error) {
	data, _, found, err := location.get(ctx, ServiceReleaseObject(role), MaxServiceClaimBytes)
	return data, found, err
}

// ReadServiceStatus returns role's status; found is false when it has none.
func ReadServiceStatus(ctx context.Context, location Location, role string) (ServiceStatus, bool, error) {
	var status ServiceStatus
	found, err := location.read(ctx, ServiceStatusObject(role), maxStatusBytes, &status)
	return status, found, err
}

// WriteServiceStatus replaces role's status; only the region's authority
// leader writes it.
func WriteServiceStatus(ctx context.Context, location Location, status ServiceStatus) error {
	status.Schema, status.Reason = ServiceStatusSchema, Clip(status.Reason)
	wire, err := json.Marshal(status, json.Deterministic(true))
	if err != nil {
		return err
	}
	return location.write(ctx, ServiceStatusObject(status.Role), wire)
}

// ReadServiceBinary copies role's binary with digest to dst, at most
// MaxServiceBinaryBytes. The caller checks the bytes against the claim.
func ReadServiceBinary(ctx context.Context, location Location, role, digest string, dst io.Writer) error {
	name := ServiceBinaryObject(role, digest)
	response, err := location.Client.GetObject(ctx, objectstorage.GetObjectRequest{
		NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name,
	})
	if err != nil {
		return fmt.Errorf("read %s/%s: %w", location.Bucket, name, err)
	}
	defer response.Content.Close()
	read, err := io.Copy(dst, io.LimitReader(response.Content, MaxServiceBinaryBytes+1))
	if err != nil {
		return fmt.Errorf("read %s/%s: %w", location.Bucket, name, err)
	}
	if read > MaxServiceBinaryBytes {
		return fmt.Errorf("%w: %s/%s exceeds %d bytes", ErrInvalid, location.Bucket, name, MaxServiceBinaryBytes)
	}
	return nil
}

// AwaitService polls role's status every poll until it reports the release
// with digest issued at issued complete. It fails when the region reports it
// failed or a newer release replaced it, or when deadline passes. Each status
// change is written to progress.
func AwaitService(ctx context.Context, location Location, cell, role, digest string, issued time.Time,
	poll time.Duration, deadline time.Time, progress io.Writer,
) error {
	return awaitService(ctx, location, cell, role, digest, issued, 0, poll, deadline, progress)
}

func AwaitServiceSequenced(ctx context.Context, location Location, cell, role, digest string, issued time.Time, sequence uint64, poll time.Duration, deadline time.Time, progress io.Writer) error {
	if sequence == 0 {
		return fmt.Errorf("%w: missing service sequence", ErrInvalid)
	}
	return awaitService(ctx, location, cell, role, digest, issued, sequence, poll, deadline, progress)
}

func awaitService(ctx context.Context, location Location, cell, role, digest string, issued time.Time, sequence uint64, poll time.Duration, deadline time.Time, progress io.Writer) error {
	// The deadline also bounds a stalled read.
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var last string
	for {
		status, found, err := ReadServiceStatus(ctx, location, role)
		line := "waiting for the region to report"
		switch {
		case err != nil:
			line = "status read failed: " + err.Error()
		case !found || sequence > 0 && status.ReleaseSequence < sequence || sequence == 0 && status.ReleaseSequence == 0 && status.IssuedAt.Before(issued):
		case status.ReleaseSequence > sequence || sequence == 0 && status.IssuedAt.After(issued):
			return fmt.Errorf("%w: %s moved on to a %s release issued at %s", ErrFailed, cell, role, status.IssuedAt)
		case status.State == StateFailed && status.Cell == cell && (status.Digest == "" || status.Digest == digest):
			return fmt.Errorf("%w: %s did not release %s %s: %s", ErrFailed, cell, role, digest, Clip(status.Reason))
		case status.Digest == "" && status.State == StateRolling:
			// A leader that has not decoded the claim yet names no digest.
			line = Clip(string(status.State) + " " + status.Reason)
		case status.Cell != cell || status.Role != role || status.Digest != digest:
			return fmt.Errorf("%w: %s reports %s %s for %s", ErrFailed, cell, Clip(status.Role), Clip(status.Digest), Clip(status.Cell))
		case status.State == StateComplete:
			fmt.Fprintf(progress, "%s %s complete: %s\n", cell, role, digest)
			return nil
		default:
			line = Clip(string(status.State) + " " + status.Reason)
		}
		if line != last {
			fmt.Fprintf(progress, "%s %s %s\n", cell, role, line)
			last = line
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%w: %s did not complete %s %s in time (%s)", ErrFailed, cell, role, digest, line)
		}
		select {
		case <-ctx.Done():
			if !time.Now().Before(deadline) {
				return fmt.Errorf("%w: %s did not complete %s %s in time (%s)", ErrFailed, cell, role, digest, line)
			}
			return ctx.Err()
		case <-time.After(min(poll, time.Until(deadline))):
		}
	}
}

func verifyServiceSequenceClaim(ctx context.Context, claim []byte, migration release.SequenceMigration) error {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(claim, &envelope, MaxServiceClaimBytes); err != nil {
		return err
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(migration.SignerPublicKey)
	if err != nil {
		return err
	}
	codec := delivery.Ed25519Codec{Cell: strings.ToLower(envelope.Region), MaxLifetime: release.MaxReceiptLifetime, Trusted: map[string]delivery.TrustedSigner{migration.SignerKeyID: {Actor: envelope.Actor, PublicKey: ed25519.PublicKey(public)}}}
	record, _, err := codec.VerifyArchivedArtifact(ctx, claim)
	if err != nil {
		return err
	}
	if record.Role != migration.Role || record.Environment != migration.Environment || record.ReleaseSequence <= migration.SequenceFloor {
		return fmt.Errorf("%w: signed service sequence scope", ErrInvalid)
	}
	return nil
}
