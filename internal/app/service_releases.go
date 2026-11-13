package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
)

// serviceReleaseRoles are the first-party roles followed by the regional
// release controller, in the order the leader checks them.
var serviceReleaseRoles = []string{terrabase.Role, tsauth.Role}

// serviceReleases follows first-party release channels in the region's head
// bucket. TSAuth uses signed OCI intents; TerraBase retains its native
// readiness and rollback path while qualified stateful admission is pending.
type serviceReleases struct {
	js         jetstream.JetStream
	cell       string // the NATS cell, e.g. gru
	channel    *channelSource
	deliveries *delivery.Service
	hosts      seatrollout.Hosts
	profiles   func() map[string]WorkloadProfile
	fencer     authority.Fencer
	history    *nativeHistory
	// fences restarts each release one node at a time when the cell spec
	// has a release fence; nil restarts every replica at once.
	fences *releaseFence
	// interval is how often the channels are read; zero means
	// defaultChannelInterval.
	interval time.Duration
	// wait overrides the readiness gate's wait in tests.
	wait time.Duration
	// policy holds the root-delegated release key the channel carries.
	policy signerPolicy
	// roots and environment verify that delegation for this cell.
	roots       func() trust.Keyring
	environment string
	// logged is the status last logged at INFO per role, and warned the error
	// text last logged at WARN per role. Only the pass loop reads or writes them.
	logged map[string]serviceLog
	warned map[string]string
}

// serviceLog is the part of a role's status that an INFO record shows.
type serviceLog struct {
	digest, reason string
	state          releasechannel.State
}

// serviceReleaseState is the leader's record of a role's newest release,
// under releasechannel.ServiceStatusKey in the release channel bucket, so a
// new leader resumes the release instead of starting it again.
type serviceReleaseState struct {
	SourceRevision string    `json:"source_revision,omitempty"`
	Claim          string    `json:"claim"` // SHA-256 of release.json
	IssuedAt       time.Time `json:"issued_at"`
	Digest         string    `json:"digest,omitempty"`
	Actor          string    `json:"actor,omitempty"`
	Previous       string    `json:"previous,omitempty"`
	// Retained protects the last release while a newer claim is refused
	// before the leader resolves its actual serving rollback target.
	Retained []string         `json:"retained,omitempty"`
	Intent   *delivery.Intent `json:"intent,omitempty"` // persisted before submission
	// Preparation is persisted before native CAS; its exact request survives
	// either side of the native/channel handoff, including epoch refreshes.
	Preparation *nativePrepareRequest `json:"preparation,omitempty"`
	// Rollback is set once the release failed its gate and the rollback
	// to Previous is submitted; a new leader finishes it.
	Rollback *delivery.Intent `json:"rollback,omitempty"`

	// claim and location are the channel's claim while it is admitted;
	// they are never stored.
	claim    []byte
	location releasechannel.Location
	State    releasechannel.State `json:"state"`
	Reason   string               `json:"reason,omitempty"`
}

// verify authenticates role's claim for this cell and returns its record,
// signer and issuance instant.
func (r *serviceReleases) verify(ctx context.Context, kv jetstream.KeyValue, role string, claim []byte) (delivery.ArtifactRecord, string, time.Time, error) {
	issued, err := releasechannel.ClaimIssuedAt(claim)
	if err != nil {
		return delivery.ArtifactRecord{}, "", time.Time{}, fmt.Errorf("%w: %w", delivery.ErrInvalid, err)
	}
	if err := r.trustReleaseDelegation(ctx, kv); err != nil {
		return delivery.ArtifactRecord{}, "", time.Time{}, err
	}
	record, actor, err := r.deliveries.VerifyClaim(ctx, claim)
	if err == nil && record.Role != role {
		err = fmt.Errorf("%w: the claim is for role %s", delivery.ErrInvalid, record.Role)
	}
	return record, actor, issued, err
}

// trustReleaseDelegation makes the cell's root-delegated release key the
// current release signer. An absent or unverifiable delegation clears it, so
// the claim verifies through the cell signers alone; a failed read is returned
// so the pass retries instead of failing the claim.
func (r *serviceReleases) trustReleaseDelegation(ctx context.Context, kv jetstream.KeyValue) error {
	if r.policy.release == nil {
		return nil
	}
	entry, err := kv.Get(ctx, releasechannel.ChannelKey(strings.ToUpper(r.cell)))
	if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		return fmt.Errorf("read the release delegation: %w", err)
	}
	if err == nil {
		var channel releasechannel.Channel
		if err = protocol.DecodeStrict(entry.Value(), &channel, releasechannel.MaxValueBytes); err == nil {
			var delegation release.BinaryUpdateDelegation
			var key ed25519.PublicKey
			var expires time.Time
			delegation, key, expires, err = release.VerifyReleaseDelegationCurrent(channel.Delegation, r.roots(), r.environment, time.Now())
			if err == nil {
				err = r.policy.setReleaseDelegation(delegation, key, expires)
			}
		}
	}
	if err != nil {
		slog.Warn("release delegation refused; claims verify through cell signers only", observability.ComponentKey, "rollout",
			"cell", r.cell, "error", err)
		r.policy.release.Store(nil)
	}
	return nil
}

func knownBadKey(role, digest string) string { return "knownbad." + role + "." + digest }
