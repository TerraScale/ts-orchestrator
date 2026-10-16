package releasechannel

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"io"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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
	SourceRevision string       `json:"source_revision,omitempty"`
	Schema         string       `json:"schema"`
	Cell           string       `json:"cell"`
	Role           string       `json:"role"`
	Digest         string       `json:"digest"`
	IssuedAt       time.Time    `json:"issued_at"`
	State          State        `json:"state"`
	Reason         string       `json:"reason,omitempty"`
	UpdatedAt      time.Time    `json:"updated_at"`
	Pins           *ReleasePins `json:"pins,omitempty"`
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
	issued, err := ClaimIssuedAt(claim)
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
			existing, err := ClaimIssuedAt(current)
			switch {
			case err == nil && existing.After(time.Now().Add(ClaimClockSkew)):
				// The leader refuses it: a corrected clock must be able to
				// replace it.
			case err == nil && existing.After(issued):
				return fmt.Errorf("%w: %s holds a %s release issued at %s", ErrStale, location.Bucket, role, existing)
			case err == nil && existing.Equal(issued) && !bytes.Equal(current, claim):
				return fmt.Errorf("%w: %s holds another %s release issued at %s", ErrInvalid, location.Bucket, role, existing)
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
	response, err := ociclient.ReadObject(ctx, location.Client, objectstorage.GetObjectRequest{
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
		case !found || status.IssuedAt.Before(issued):
		case status.IssuedAt.After(issued):
			return fmt.Errorf("%w: %s moved on to a %s release issued at %s", ErrFailed, cell, role, status.IssuedAt)
		case status.State == StateFailed && status.Cell == cell && (status.Digest == "" || status.Digest == digest):
			return fmt.Errorf("%w: %s did not release %s %s: %s", ErrFailed, cell, role, digest, Clip(status.Reason))
		case status.Digest == "" && status.State == StateRolling:
			// A leader that has not decoded the claim yet names no digest.
			line = Clip(string(status.State) + " " + status.Reason)
		case status.Cell != cell || status.Digest != digest:
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
