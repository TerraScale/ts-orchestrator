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
	"bytes"
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
	"unicode"

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
	// discard retired release state (docs/continuous-delivery.md).
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

// ChannelKey and StatusKey are a cell's keys in Bucket; cell is the logical
// cell, e.g. GRU.
func ChannelKey(cell string) string { return "orchestrator.channel." + cell }
func StatusKey(cell string) string  { return "orchestrator.status." + cell }

var (
	ErrInvalid = errors.New("invalid release channel")
	// ErrConflict reports a conditional write that lost to another writer.
	ErrConflict = errors.New("release channel changed concurrently")
	// ErrStale refuses to replace a newer run in a channel.
	ErrStale = errors.New("release channel already holds a newer run")
	// ErrFailed reports a region that rolled the release back.
	ErrFailed = errors.New("region did not complete the release")
)

// Channel is a region's current orchestrator release.
type Channel struct {
	Schema         string `json:"schema"`
	Cell           string `json:"cell"`
	Environment    string `json:"environment"`
	SourceRevision string `json:"source_revision"`
	// RunNumber is the qualifying ci.yml run; a channel only moves forward.
	RunNumber int64 `json:"run_number"`
	// Delegation is the root-signed binary update delegation of the leaf
	// that signed Receipts, one binary update receipt per architecture.
	Delegation jsontext.Value   `json:"delegation"`
	Receipts   []jsontext.Value `json:"receipts"`
}

// BinaryObject is the object name of the binary with digest sha256.
func BinaryObject(sha256 string) string { return BinaryPrefix + sha256 }

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
	verified := make(map[string]release.VerifiedBinary, len(channel.Receipts))
	for _, wire := range channel.Receipts {
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return nil, err
		}
		architecture, _ := strings.CutPrefix(envelope.Scope.Slot, "linux-")
		if _, seen := verified[architecture]; seen {
			return nil, fmt.Errorf("%w: two receipts for %s", ErrInvalid, architecture)
		}
		binary, err := release.VerifyBinaryUpdateCurrent(wire, channel.Delegation, roots,
			release.UpdateExpectation{Environment: environment, Cell: cell, Architecture: architecture}, now)
		if err != nil {
			return nil, err
		}
		// The payload is authentic now; its lineage carries the signed run.
		var receipt release.BinaryUpdateReceipt
		if err := protocol.DecodeStrict(envelope.Payload, &receipt, trust.MaxPayloadBytes); err != nil {
			return nil, err
		}
		if binary.Receipt().SourceRevision != channel.SourceRevision || receipt.Lineage.QualificationRunNum != channel.RunNumber {
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
	Schema string `json:"schema"`
	Cell   string `json:"cell"`
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

// Publish replaces the region's channel with channel by compare-and-swap. A
// newer run is never replaced, and a run is only ever replaced by the same
// revision (a repeated deployment renews its receipts). A channel that does
// not decode stops publication until an operator inspects it.
func Publish(ctx context.Context, location Location, channel Channel) error {
	wire, err := json.Marshal(channel, json.Deterministic(true))
	if err != nil {
		return err
	}
	for range 3 {
		current, etag, found, err := location.get(ctx, ChannelObject, MaxChannelBytes)
		if err != nil {
			return err
		}
		if found {
			var existing Channel
			if err := json.Unmarshal(current, &existing); err != nil {
				return fmt.Errorf("decode the current release channel: %w", err)
			}
			switch {
			case existing.RunNumber > channel.RunNumber:
				return fmt.Errorf("%w: %s holds run %d", ErrStale, location.Bucket, existing.RunNumber)
			case existing.RunNumber == channel.RunNumber && existing.SourceRevision != channel.SourceRevision:
				return fmt.Errorf("%w: %s holds run %d of another revision", ErrInvalid, location.Bucket, existing.RunNumber)
			}
		}
		if err := location.put(ctx, ChannelObject, wire, etag); !errors.Is(err, ErrConflict) {
			return err
		}
	}
	return ErrConflict
}

// ReadChannel returns the region's channel; found is false when it has none.
func ReadChannel(ctx context.Context, location Location) (Channel, bool, error) {
	var channel Channel
	found, err := location.read(ctx, ChannelObject, MaxChannelBytes, &channel)
	return channel, found, err
}

// ReadStatus returns the region's status; found is false when it has none.
// Unknown fields are ignored: a region may run an older or newer binary.
func ReadStatus(ctx context.Context, location Location) (Status, bool, error) {
	var status Status
	found, err := location.read(ctx, StatusObject, maxStatusBytes, &status)
	return status, found, err
}

// WriteStatus replaces the region's status. Only the region's authority
// leader writes it, and a report is telemetry, so it is not conditional.
func WriteStatus(ctx context.Context, location Location, status Status) error {
	status.Schema, status.Reason = StatusSchema, Clip(status.Reason)
	wire, err := json.Marshal(status, json.Deterministic(true))
	if err != nil {
		return err
	}
	return location.write(ctx, StatusObject, wire)
}

// write replaces name unconditionally.
func (location Location) write(ctx context.Context, name string, wire []byte) error {
	if len(wire) > maxStatusBytes {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, name, maxStatusBytes)
	}
	_, err := location.Client.PutObject(ctx, objectstorage.PutObjectRequest{
		NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name,
		ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire)),
		ContentType: new("application/json"),
	})
	if err != nil {
		return fmt.Errorf("write %s/%s: %w", location.Bucket, name, err)
	}
	return nil
}

// ReadBinary copies the region's binary with digest to dst. The caller
// checks the bytes against the digest; a node stages them only after its
// receipt verifies.
func ReadBinary(ctx context.Context, location Location, digest string, dst io.Writer) error {
	name := BinaryObject(digest)
	response, err := location.Client.GetObject(ctx, objectstorage.GetObjectRequest{
		NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name,
	})
	if err != nil {
		return fmt.Errorf("read %s/%s: %w", location.Bucket, name, err)
	}
	defer response.Content.Close()
	if _, err := io.Copy(dst, response.Content); err != nil {
		return fmt.Errorf("read %s/%s: %w", location.Bucket, name, err)
	}
	return nil
}

// Await polls the region's status every poll until it reports channel's
// release complete. It fails when the region reports the release failed or
// moved past it, or when deadline passes. Each status change is written to
// progress.
func Await(ctx context.Context, location Location, channel Channel, poll time.Duration, deadline time.Time,
	progress io.Writer,
) error {
	var last string
	for {
		status, found, err := ReadStatus(ctx, location)
		line := "waiting for the region to report"
		switch {
		case err != nil:
			line = "status read failed: " + err.Error()
		case !found || status.RunNumber < channel.RunNumber:
		case status.RunNumber > channel.RunNumber:
			return fmt.Errorf("%w: %s moved on to run %d", ErrFailed, channel.Cell, status.RunNumber)
		case status.Cell != channel.Cell || status.SourceRevision != channel.SourceRevision:
			return fmt.Errorf("%w: %s reports run %d for %s %s", ErrFailed, channel.Cell, status.RunNumber,
				Clip(status.Cell), Clip(status.SourceRevision))
		case status.State == StateComplete:
			fmt.Fprintf(progress, "%s complete: run %d %s\n", channel.Cell, channel.RunNumber, channel.SourceRevision)
			return nil
		case status.State == StateFailed:
			return fmt.Errorf("%w: %s rolled back run %d: %s", ErrFailed, channel.Cell, channel.RunNumber, Clip(status.Reason))
		default:
			line = Clip(string(status.State) + " " + status.Reason)
		}
		if line != last {
			fmt.Fprintf(progress, "%s %s\n", channel.Cell, line)
			last = line
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%w: %s did not complete run %d in time (%s)", ErrFailed, channel.Cell, channel.RunNumber, line)
		}
		select {
		case <-ctx.Done():
			if !time.Now().Before(deadline) {
				return fmt.Errorf("%w: %s did not complete run %d in time (%s)", ErrFailed, channel.Cell, channel.RunNumber, line)
			}
			return ctx.Err()
		case <-time.After(min(poll, time.Until(deadline))):
		}
	}
}

// Clip makes region-written text safe for a CI log: one line, no control
// or bidirectional formatting characters, at most maxReason characters.
func Clip(text string) string {
	runes := []rune(text)
	if len(runes) > maxReason {
		runes = append(runes[:maxReason], []rune("...")...)
	}
	for index, r := range runes {
		if unicode.IsControl(r) || unicode.In(r, unicode.Bidi_Control, unicode.Zl, unicode.Zp) {
			runes[index] = ' '
		}
	}
	return string(runes)
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
	response, err := location.Client.GetObject(ctx, objectstorage.GetObjectRequest{
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

// put writes data only if the object still has etag, or does not exist when
// etag is empty.
func (location Location) put(ctx context.Context, name string, data []byte, etag string) error {
	request := objectstorage.PutObjectRequest{
		NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name,
		ContentLength: new(int64(len(data))), PutObjectBody: io.NopCloser(bytes.NewReader(data)),
		ContentType: new("application/json"),
	}
	if etag == "" {
		request.IfNoneMatch = new("*")
	} else {
		request.IfMatch = &etag
	}
	_, err := location.Client.PutObject(ctx, request)
	if httpStatus(err) == http.StatusPreconditionFailed {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("write %s/%s: %w", location.Bucket, name, err)
	}
	return nil
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
