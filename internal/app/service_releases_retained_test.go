package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oklog/ulid/v2"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
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
