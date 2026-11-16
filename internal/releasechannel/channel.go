// Package releasechannel is the per-region orchestrator release channel in
// OCI Object Storage. CI cannot reach a cell's private NATS, so it publishes
// each CI-qualified release to the region's head bucket: the binaries by
// digest, then channel.json, the region's current release, with one
// leaf-signed binary update receipt per architecture. The region's leader
// reads the channel, verifies it and rolls the release out; it reports
// progress in status.json, which CI polls before it moves on to the next
// region.
//
// The channel document itself is unsigned: every byte a node acts on is
// bound by the update receipts it carries, which Verify checks against the
// consumer's own roots, environment and cell. Status is telemetry for CI and
// operators, never admission evidence.
package releasechannel

import (
	"context"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const (
	ChannelSchema = "terrascale.orchestrator.release-channel"
	StatusSchema  = "terrascale.orchestrator.release-status"

	// ChannelObject, StatusObject and BinaryPrefix live in the region's
	// head bucket. Bootstrap every cell with these paths before publishing;
	// retain ordering state across publisher and signer migrations.
	ChannelObject = "releases/orchestrator/channel.json"
	StatusObject  = "releases/orchestrator/status.json"
	BinaryPrefix  = "releases/orchestrator/binaries/"

	// MaxChannelBytes bounds a channel: one delegation and two receipts.
	MaxChannelBytes = 4 * trust.MaxEnvelopeBytes
	maxStatusBytes  = MaxValueBytes
	maxReason       = 512
)

// Inside a cell the channel travels over NATS, not Object Storage: Bucket
// holds each cell's channel document under ChannelKey, and its leader's
// newest report under StatusKey, which the leader also publishes on
// protocol.ReleaseStatusSubject. TS-562 replicates the bucket between
// orchestrators; until it does, the region leader copies CI's channel.json
// in and its report back out to status.json.
const (
	Bucket = "TS_RELEASE_CHANNEL"
	// MaxValueBytes bounds a channel or report in the bucket.
	MaxValueBytes = 1 << 20
)

var (
	ErrInvalid = errors.New("invalid release channel")
	// ErrConflict reports a conditional write that lost to another writer.
	ErrConflict = errors.New("release channel changed concurrently")
	// ErrStale refuses to replace a newer release in a channel.
	ErrStale = errors.New("release channel already holds a newer run")
	// ErrFailed reports a region that rolled the release back.
	ErrFailed = errors.New("region did not complete the release")
)

// Channel is a region's current orchestrator release.
type Channel struct {
	ReleaseSequence   uint64         `json:"release_sequence,omitzero"`
	SequenceMigration jsontext.Value `json:"sequence_migration,omitempty"`
	Schema            string         `json:"schema"`
	Cell              string         `json:"cell"`
	Environment       string         `json:"environment"`
	SourceRevision    string         `json:"source_revision"`
	// RunNumber preserves CI provenance; ReleaseSequence orders migrated channels.
	RunNumber int64 `json:"run_number"`
	// Delegation is the root-signed binary update delegation of the leaf
	// that signed Receipts, one binary update receipt per architecture.
	Delegation jsontext.Value   `json:"delegation"`
	Receipts   []jsontext.Value `json:"receipts"`
}

// BucketName is the head bucket of the cell's region, e.g. gru-1-head.
func BucketName(cell string) (string, error) {
	if !release.ValidRegion(cell) {
		return "", fmt.Errorf("%w: cell %q", ErrInvalid, cell)
	}
	name, err := naming.RegionCell(cell).Name()
	if err != nil {
		return "", err
	}
	return name + "-head", nil
}

// Verify checks every receipt against the consumer's roots, environment and
// cell, and that all of them name the channel's source revision and run.
// It returns the verified binaries by architecture.
func (channel Channel) Verify(roots trust.Keyring, cell, environment string, now time.Time) (map[string]release.VerifiedBinary, error) {
	if channel.Schema != ChannelSchema || channel.Cell != cell || channel.Environment != environment ||
		!release.ValidSourceRevision(channel.SourceRevision) || channel.RunNumber <= 0 ||
		len(channel.Receipts) == 0 || len(channel.Receipts) > 2 {
		return nil, fmt.Errorf("%w: channel scope", ErrInvalid)
	}
	var migrationDigest, sequenceSigner string
	if channel.ReleaseSequence > 0 {
		envelope, err := trust.DecodeEnvelope(channel.SequenceMigration)
		if err != nil {
			return nil, err
		}
		migration, err := release.VerifySequenceMigrationHistorical(envelope, roots, "orchestrator", environment)
		if err != nil {
			return nil, err
		}
		if channel.ReleaseSequence <= migration.SequenceFloor {
			return nil, fmt.Errorf("%w: release sequence does not exceed migration floor", ErrInvalid)
		}
		sequenceSigner = migration.SignerKeyID
		migrationDigest, err = trust.Fingerprint(envelope)
		if err != nil {
			return nil, err
		}
	} else if len(channel.SequenceMigration) > 0 {
		return nil, fmt.Errorf("%w: legacy channel carries sequence migration", ErrInvalid)
	}
	verified := make(map[string]release.VerifiedBinary, len(channel.Receipts))
	for _, wire := range channel.Receipts {
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return nil, err
		}
		if channel.ReleaseSequence > 0 && envelope.KeyID != sequenceSigner {
			return nil, fmt.Errorf("%w: receipt signer does not own release order", ErrInvalid)
		}
		architecture, _ := strings.CutPrefix(envelope.Scope.Slot, "linux-")
		if _, seen := verified[architecture]; seen {
			return nil, fmt.Errorf("%w: two receipts for %s", ErrInvalid, architecture)
		}
		binary, err := release.VerifyQualifiedBinaryUpdateCurrent(wire, channel.Delegation, roots,
			release.UpdateExpectation{Environment: environment, Cell: cell, Architecture: architecture}, now)
		if err != nil {
			return nil, err
		}
		// The payload is authentic now; its lineage carries the signed run.
		var receipt release.BinaryUpdateReceipt
		if err := protocol.DecodeStrict(envelope.Payload, &receipt, trust.MaxPayloadBytes); err != nil {
			return nil, err
		}
		if binary.Receipt().SourceRevision != channel.SourceRevision || receipt.Lineage.QualificationRunNum != channel.RunNumber || receipt.ReleaseSequence != channel.ReleaseSequence || receipt.SequenceMigrationSHA256 != migrationDigest {
			return nil, fmt.Errorf("%w: receipt for %s names another release", ErrInvalid, architecture)
		}
		verified[architecture] = binary
	}
	return verified, nil
}

// State is a region's progress on its channel's release.
type State string

const (
	StateRolling  State = "rolling"
	StateComplete State = "complete"
	// StateFailed: the region rolled the release back, or froze or aborted it.
	StateFailed State = "failed"
)

// Status is the region leader's report on the release in its channel.
type Status struct {
	ReleaseSequence uint64 `json:"release_sequence,omitzero"`
	Schema          string `json:"schema"`
	Cell            string `json:"cell"`
	// Deployment scope comes from the running controller, not the desired channel.
	Environment    string       `json:"environment,omitempty"`
	Architectures  []string     `json:"architectures,omitempty"`
	SourceRevision string       `json:"source_revision"`
	RunNumber      int64        `json:"run_number"`
	State          State        `json:"state"`
	Reason         string       `json:"reason,omitempty"`
	UpdatedAt      time.Time    `json:"updated_at"`
	Pins           *ReleasePins `json:"pins,omitempty"`
}

// ReleasePins protects rollback targets and withdrawn binaries from CI
// pruning. A nil pointer means the leader has not published pins yet;
// an empty value means it read the cell's state and found none.
type ReleasePins struct {
	Rollback []string `json:"rollback"`
	KnownBad []string `json:"known_bad"`
}

func (pins *ReleasePins) Equal(other *ReleasePins) bool {
	if pins == nil || other == nil {
		return pins == other
	}
	return slices.Equal(pins.Rollback, other.Rollback) && slices.Equal(pins.KnownBad, other.KnownBad)
}

// Validate refuses an absent inventory or digests the pruning script would
// silently skip. Status comes from a remote bucket, not trusted cell state.
func (pins *ReleasePins) Validate() error {
	if pins == nil {
		return fmt.Errorf("%w: release pins are missing", ErrInvalid)
	}
	for _, digests := range [][]string{pins.Rollback, pins.KnownBad} {
		for _, digest := range digests {
			if _, err := hex.DecodeString(digest); err != nil || len(digest) != 64 || strings.ToLower(digest) != digest {
				return fmt.Errorf("%w: release pin %q", ErrInvalid, digest)
			}
		}
	}
	return nil
}

// ObjectClient is the part of the OCI Object Storage client the channel
// uses; objectstorage.ObjectStorageClient implements it.
type ObjectClient interface {
	PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
	GetObject(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
}

// Location is one region's head bucket.
type Location struct {
	Client    ObjectClient
	Namespace string
	Bucket    string
}

func (location Location) read(ctx context.Context, name string, limit int64, value any) (bool, error) {
	data, _, found, err := location.get(ctx, name, limit)
	if err != nil || !found {
		return found, err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return true, fmt.Errorf("%w: decode %s: %w", ErrInvalid, name, err)
	}
	return true, nil
}

func (location Location) get(ctx context.Context, name string, limit int64) ([]byte, string, bool, error) {
	response, err := ociclient.ReadObject(ctx, location.Client, objectstorage.GetObjectRequest{
		NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name,
	})
	if httpStatus(err) == http.StatusNotFound {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, fmt.Errorf("read %s/%s: %w", location.Bucket, name, err)
	}
	defer response.Content.Close()
	data, err := io.ReadAll(io.LimitReader(response.Content, limit+1))
	if err != nil {
		return nil, "", false, fmt.Errorf("read %s/%s: %w", location.Bucket, name, err)
	}
	if int64(len(data)) > limit {
		return nil, "", false, fmt.Errorf("%w: %s/%s exceeds %d bytes", ErrInvalid, location.Bucket, name, limit)
	}
	if response.ETag == nil || *response.ETag == "" {
		return nil, "", false, fmt.Errorf("read %s/%s: no ETag", location.Bucket, name)
	}
	return data, *response.ETag, true, nil
}

func httpStatus(err error) int {
	if serviceErr, ok := errors.AsType[interface {
		error
		GetHTTPStatusCode() int
	}](err); ok {
		return serviceErr.GetHTTPStatusCode()
	}
	return 0
}
