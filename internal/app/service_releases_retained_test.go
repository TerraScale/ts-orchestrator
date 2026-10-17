package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oklog/ulid/v2"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

const servicePinsActor = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

func loadServiceRelease(ctx context.Context, kv jetstream.KeyValue, key string) (serviceReleaseState, uint64, error) {
	entry, err := kv.Get(ctx, key)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return serviceReleaseState{}, 0, nil
	}
	if err != nil {
		return serviceReleaseState{}, 0, err
	}
	var state serviceReleaseState
	if err := json.Unmarshal(entry.Value(), &state); err != nil {
		return serviceReleaseState{}, 0, fmt.Errorf("decode %s: %w", key, err)
	}
	return state, entry.Revision(), nil
}

func servicePinsSignedFixture(t *testing.T) (*serviceReleases, jetstream.KeyValue, *channelBucket, func(string, time.Time) delivery.ArtifactRecord) {
	t.Helper()
	ctx, js := t.Context(), testRolloutJetStream(t)
	kv, err := openChannelBucket(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	codec := delivery.Ed25519Codec{Cell: "gru", Actor: servicePinsActor, PrivateKey: private,
		Trusted:  map[string]delivery.TrustedSigner{keyID: {Actor: servicePinsActor, PublicKey: public}},
		Lifetime: time.Minute, MaxLifetime: time.Minute}
	service, err := delivery.Open(ctx, delivery.Config{Conn: js.Conn(), JS: js, Cell: "gru", Replicas: 1,
		ArtifactVerifier: codec, AuthorizeArtifact: func(context.Context, string, delivery.ArtifactRecord) error { return nil },
		Authorize: func(context.Context, string, delivery.Intent) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	bucket := newChannelBucket()
	location := releasechannel.Location{Client: bucket, Namespace: "ns", Bucket: "gru-1-head"}
	r := &serviceReleases{js: js, cell: "gru", channel: &channelSource{location: &location}, deliveries: service,
		fencer: rolloutTestFence{epoch: 7}, profiles: func() map[string]WorkloadProfile { return nil }}
	publish := func(data string, issued time.Time) delivery.ArtifactRecord {
		t.Helper()
		sum := sha256.Sum256([]byte(data))
		record, err := delivery.NewArtifactRecord(delivery.ArtifactClaimRequest{Cell: "gru", Role: terrabase.Role, Environment: "test",
			Source: delivery.ArtifactSource{Repository: terrabase.Repository, Commit: strings.Repeat("a", 40), TreeDigest: strings.Repeat("b", 64)}},
			hex.EncodeToString(sum[:]), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		signer := codec
		signer.Now = func() time.Time { return issued }
		claim, err := signer.SignArtifact(ctx, record)
		if err != nil {
			t.Fatal(err)
		}
		bucket.objects[releasechannel.ServiceBinaryObject(terrabase.Role, record.Digest)] = []byte(data)
		bucket.objects[releasechannel.ServiceReleaseObject(terrabase.Role)] = claim
		bucket.etags[releasechannel.ServiceReleaseObject(terrabase.Role)] = record.Digest
		return record
	}
	return r, kv, bucket, publish
}

func TestServiceReleasePinsRefusedClaimsDoNotAccumulate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     releasechannel.State
		submitted bool
		rollback  bool
	}{
		{name: "completed", state: releasechannel.StateComplete, submitted: true},
		{name: "failed after submission", state: releasechannel.StateFailed, submitted: true},
		{name: "rolled back", state: releasechannel.StateFailed, submitted: true, rollback: true},
		{name: "first claim refused", state: releasechannel.StateFailed},
		{name: "first claim awaiting admission", state: releasechannel.StateRolling},
		{name: "no initial state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, kv, bucket, publish := servicePinsSignedFixture(t)
			ctx, role := t.Context(), terrabase.Role
			location := *r.channel.location
			key := releasechannel.ServiceStatusKey("GRU", role)
			issued := time.Now().UTC().Add(-time.Minute)
			prior := publish("predecessor release", issued)
			rollback := strings.Repeat("c", 64)
			state := serviceReleaseState{}
			var retained, pins []string
			if tc.state != "" {
				sum := sha256.Sum256(bucket.objects[releasechannel.ServiceReleaseObject(role)])
				state = serviceReleaseState{Claim: hex.EncodeToString(sum[:]), IssuedAt: issued, Digest: prior.Digest, State: tc.state}
				if tc.submitted {
					intent := nativeIntent(prior, nativeRelease{Role: role, Replicas: 1}, 1)
					intent.SchemaVersion, intent.OperationID, intent.AuthorityEpoch = delivery.SchemaVersion, ulid.Make().String(), 7
					if err := r.deliveries.SubmitVerified(ctx, intent, servicePinsActor); err != nil {
						t.Fatal(err)
					}
					state.Intent, state.Previous = &intent, rollback
					retained, pins = []string{prior.Digest}, []string{prior.Digest, rollback}
					slices.Sort(pins)
					if tc.rollback {
						back := intent
						back.OperationID, back.ArtifactDigest, back.Generation = ulid.Make().String(), rollback, 2
						state.Rollback = &back
					}
				}
				if _, err := saveServiceRelease(ctx, kv, key, state, 0); err != nil {
					t.Fatal(err)
				}
			}
			bad := strings.Repeat("d", 64)
			if err := markKnownBad(ctx, kv, role, bad, errors.New("withdrawn earlier")); err != nil {
				t.Fatal(err)
			}
			profiles := terraBaseSeats("gru-1-db-1=10.251.0.21:9443")
			// Each path refuses a valid, newer claim before an intent is persisted.
			for i := range 64 {
				candidate := publish(fmt.Sprintf("unsent candidate %d", i), issued.Add(time.Duration(i+1)*time.Millisecond))
				r.profiles = func() map[string]WorkloadProfile { return profiles }
				r.hosts = terraBaseMembers{reports: []host.Report{{Role: role, Environment: "test", State: "running", Digest: rollback}}}
				var reason string
				switch i % 4 {
				case 0:
					r.profiles = func() map[string]WorkloadProfile { return nil }
					reason = "has no terrabase profile"
				case 1:
					bucket.objects[releasechannel.ServiceBinaryObject(role, candidate.Digest)] = []byte("wrong binary")
					reason = "the artifact bytes are not the claimed ones"
				case 2:
					r.hosts = terraBaseMembers{reports: []host.Report{
						{Role: role, Environment: "test", State: "running", Digest: prior.Digest},
						{Role: role, Environment: "test", State: "running", Digest: rollback}}}
					reason = "finish the previous release first"
				case 3:
					reason = "native signed profile history is unavailable"
				}
				if err := r.nativePass(ctx, kv, role); err != nil {
					t.Fatalf("claim %d: %v", i, err)
				}
				persisted, _, err := loadServiceRelease(ctx, kv, key)
				if err != nil || persisted.Intent != nil || persisted.State != releasechannel.StateFailed ||
					persisted.Digest != candidate.Digest || persisted.Previous != state.Previous ||
					!slices.Equal(persisted.Retained, retained) || !strings.Contains(persisted.Reason, reason) {
					t.Fatalf("claim %d retained unsent proposals or lost serving pins: %+v: %v", i, persisted, err)
				}
				status, found, err := releasechannel.ReadServiceStatus(ctx, location, role)
				if err != nil || !found || status.Pins == nil || !slices.Equal(status.Pins.Rollback, pins) ||
					!slices.Equal(status.Pins.KnownBad, []string{bad}) {
					t.Fatalf("claim %d pins %+v: %v", i, status.Pins, err)
				}
			}
			// A new service instance reports only the pins recovered from durable state.
			restarted := *r
			if err := restarted.nativePass(ctx, kv, role); err != nil {
				t.Fatal(err)
			}
			status, found, err := releasechannel.ReadServiceStatus(ctx, location, role)
			if err != nil || !found || status.Pins == nil || !slices.Equal(status.Pins.Rollback, pins) ||
				!slices.Equal(status.Pins.KnownBad, []string{bad}) {
				t.Fatalf("restart lost durable pins: %+v: %v", status.Pins, err)
			}
		})
	}
}

func TestServiceReleasePinsUnprovenProfileRefusedBeforeSubmission(t *testing.T) {
	r, kv, bucket, publish := servicePinsSignedFixture(t)
	ctx, role := t.Context(), terrabase.Role
	location := *r.channel.location
	issued := time.Now().UTC().Add(-time.Minute)
	serving := publish("actual serving release", issued)
	if _, _, err := r.admit(ctx, kv, location, role, bucket.objects[releasechannel.ServiceReleaseObject(role)]); err != nil {
		t.Fatal(err)
	}
	candidate := publish("next release", issued.Add(time.Second))
	r.profiles = func() map[string]WorkloadProfile { return terraBaseSeats("gru-1-db-1=10.251.0.21:9443") }
	r.hosts = terraBaseMembers{reports: []host.Report{{Role: role, Environment: "test", State: "running", Digest: serving.Digest}}}
	state := serviceReleaseState{Digest: candidate.Digest, IssuedAt: issued.Add(time.Second), Previous: strings.Repeat("c", 64), Retained: []string{strings.Repeat("d", 64)},
		State: releasechannel.StateRolling, claim: bucket.objects[releasechannel.ServiceReleaseObject(role)], location: location}
	finished, err := r.release(ctx, kv, role, state, r.fencer.Current().Epoch, func(next serviceReleaseState) error {
		t.Fatal("unproven serving profile was persisted for submission")
		return nil
	})
	if err != nil || finished.State != releasechannel.StateFailed || finished.Intent != nil ||
		!slices.Equal(finished.Retained, state.Retained) || !strings.Contains(finished.Reason, "native signed profile history is unavailable") {
		t.Fatalf("unproven serving profile was selected: %+v, %v", finished, err)
	}
}

func TestServiceReleasePinsDeposedLeaderPreservesSubmittedIntent(t *testing.T) {
	r, kv, _, publish := servicePinsSignedFixture(t)
	ctx, role := t.Context(), terrabase.Role
	issued := time.Now().UTC().Add(-time.Minute)
	prior := publish("submitted release", issued)
	intent := nativeIntent(prior, nativeRelease{Role: role, Replicas: 1}, 1)
	intent.SchemaVersion, intent.OperationID, intent.AuthorityEpoch = delivery.SchemaVersion, ulid.Make().String(), 7
	if err := r.deliveries.SubmitVerified(ctx, intent, servicePinsActor); err != nil {
		t.Fatal(err)
	}
	key := releasechannel.ServiceStatusKey("GRU", role)
	state := serviceReleaseState{Claim: strings.Repeat("a", 64), Digest: prior.Digest, Actor: servicePinsActor, IssuedAt: issued,
		State: releasechannel.StateRolling, Intent: &intent}
	revision, err := saveServiceRelease(ctx, kv, key, state, 0)
	if err != nil {
		t.Fatal(err)
	}
	publish("newer proposal", issued.Add(time.Second))
	snapshot := r.fencer.Current()
	snapshot.Leader = false
	r.fencer = observedAuthority{snapshot: snapshot}
	r.wait = time.Millisecond
	if err := r.nativePass(ctx, kv, role); err == nil || !strings.Contains(err.Error(), "lost the authority lease") {
		t.Fatalf("deposed release = %v", err)
	}
	persisted, gotRevision, err := loadServiceRelease(ctx, kv, key)
	if err != nil || gotRevision != revision || persisted.Intent == nil || persisted.Intent.OperationID != intent.OperationID ||
		persisted.Digest != prior.Digest || persisted.Claim != state.Claim || persisted.State != releasechannel.StateRolling {
		t.Fatalf("newer claim replaced a deposed leader's submitted release: %+v revision %d: %v", persisted, gotRevision, err)
	}
}
