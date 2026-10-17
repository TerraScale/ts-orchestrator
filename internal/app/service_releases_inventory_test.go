package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oklog/ulid/v2"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
)

func TestServiceReleaseInventoryAbsentInitialClaim(t *testing.T) {
	for _, role := range []string{terrabase.Role, tsauth.Role} {
		t.Run(role, func(t *testing.T) {
			r, kv, bucket, location := servicePinsFixture(t)
			for _, bad := range []string{"", strings.Repeat("b", 64)} {
				if bad != "" {
					if err := markKnownBad(t.Context(), kv, role, bad, errors.New("withdrawn baked release")); err != nil {
						t.Fatal(err)
					}
				}
				if err := r.nativePass(t.Context(), kv, role); err != nil {
					t.Fatal(err)
				}
				status := serviceInventoryStatus(t, location, role)
				var wantBad []string
				if bad != "" {
					wantBad = []string{bad}
				}
				if status.Cell != "GRU" || status.Role != role || status.Digest != "" || !status.IssuedAt.IsZero() ||
					status.State != releasechannel.StateRolling || !strings.Contains(status.Reason, "no claim") ||
					status.Pins == nil || len(status.Pins.Rollback) != 0 || !slices.Equal(status.Pins.KnownBad, wantBad) || status.UpdatedAt.IsZero() {
					t.Fatalf("absent initial claim status = %+v, pins = %+v", status, status.Pins)
				}
				persisted, revision, err := loadServiceRelease(t.Context(), kv, releasechannel.ServiceStatusKey("GRU", role))
				if err != nil || revision != 0 || !reflect.DeepEqual(persisted, serviceReleaseState{}) {
					t.Fatalf("absent claim created durable release state: %+v, revision %d: %v", persisted, revision, err)
				}
			}
			if bucket.puts[releasechannel.ServiceStatusObject(role)] != 2 {
				t.Fatal("known-bad-only inventory change was not published")
			}
		})
	}
}

func TestServiceReleaseInventoryRemovedClaimPreservesState(t *testing.T) {
	for _, phase := range []releasechannel.State{releasechannel.StateComplete, releasechannel.StateFailed, releasechannel.StateRolling} {
		t.Run(string(phase), func(t *testing.T) {
			r, kv, bucket, location := servicePinsFixture(t)
			ctx, role := t.Context(), terrabase.Role
			state := serviceReleaseState{Claim: strings.Repeat("1", 64), Digest: strings.Repeat("f", 64),
				SourceRevision: strings.Repeat("d", 40),
				IssuedAt:       time.Now().UTC().Add(-time.Minute), Previous: strings.Repeat("a", 64),
				Retained: []string{strings.Repeat("b", 64)}, State: phase, Reason: "persisted release outcome"}
			if phase != releasechannel.StateRolling {
				state.Intent = &delivery.Intent{OperationID: ulid.Make().String(), ArtifactDigest: state.Digest,
					Role: role, Environment: "production", Generation: 1, DesiredReplicas: 1}
				r.hosts = terraBaseMembers{reports: []host.Report{{Role: role, Environment: "production",
					Generation: 1, Digest: state.Digest, State: "running", ObservedAt: time.Now()}}}
				state.Rollback = &delivery.Intent{OperationID: ulid.Make().String(), ArtifactDigest: state.Previous}
			}
			key := releasechannel.ServiceStatusKey("GRU", role)
			revision, err := saveServiceRelease(ctx, kv, key, state, 0)
			if err != nil {
				t.Fatal(err)
			}
			claimObject := releasechannel.ServiceReleaseObject(role)
			bucket.objects[claimObject] = []byte("removed claim")
			bucket.etags[claimObject] = "removed-claim"
			if err := r.report(ctx, kv, role, state); err != nil {
				t.Fatal(err)
			}
			delete(bucket.objects, claimObject)
			delete(bucket.etags, claimObject)
			bad := strings.Repeat("c", 64)
			if err := markKnownBad(ctx, kv, role, bad, errors.New("withdrawn after removing the claim")); err != nil {
				t.Fatal(err)
			}
			if err := r.nativePass(ctx, kv, role); err != nil {
				t.Fatal(err)
			}
			status := serviceInventoryStatus(t, location, role)
			wantPhase, wantReason := phase, state.Reason
			if phase == releasechannel.StateComplete {
				wantPhase, wantReason = releasechannel.StateRolling, "waiting for fresh target proofs from every service replica"
			}
			if status.State != wantPhase || status.SourceRevision != state.SourceRevision || status.Digest != state.Digest || !status.IssuedAt.Equal(state.IssuedAt) || status.Reason != wantReason ||
				status.Pins == nil || !slices.Equal(status.Pins.Rollback, []string{state.Previous, state.Retained[0]}) ||
				!slices.Equal(status.Pins.KnownBad, []string{bad}) || bucket.puts[releasechannel.ServiceStatusObject(role)] != 2 {
				t.Fatalf("removed claim lost inventory: %+v, pins %+v", status, status.Pins)
			}
			persisted, gotRevision, err := loadServiceRelease(ctx, kv, key)
			if err != nil || gotRevision != revision || !reflect.DeepEqual(persisted, state) {
				t.Fatalf("removed claim changed durable state: %+v, revision %d: %v", persisted, gotRevision, err)
			}
		})
	}
}

func TestServiceReleaseInventoryUnchangedRefresh(t *testing.T) {
	for _, tc := range []struct {
		name string
		age  time.Duration
		due  bool
	}{
		{name: "fresh", due: false},
		{name: "aged", age: time.Minute, due: true},
		{name: "zero", due: true},
		{name: "future", age: -time.Hour, due: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, kv, bucket, location := servicePinsFixture(t)
			ctx, role := t.Context(), terrabase.Role
			at := time.Now().UTC().Add(-tc.age)
			if tc.name == "zero" {
				at = time.Time{}
			}
			state, status := serviceInventoryCompleted(t, kv, bucket, at)
			if err := releasechannel.WriteServiceStatus(ctx, location, status); err != nil {
				t.Fatal(err)
			}
			before := time.Now().UTC()
			if err := r.nativePass(ctx, kv, role); err != nil {
				t.Fatal(err)
			}
			refreshed := serviceInventoryStatus(t, location, role)
			if refreshed.Digest != state.Digest || refreshed.State != state.State || !refreshed.Pins.Equal(status.Pins) {
				t.Fatalf("refresh changed release or inventory: %+v", refreshed)
			}
			wantWrites := 1
			if tc.due {
				wantWrites++
				if refreshed.UpdatedAt.Before(before) || refreshed.UpdatedAt.After(time.Now().UTC()) {
					t.Fatalf("refresh timestamp = %s, want this successful pass", refreshed.UpdatedAt)
				}
			} else if !refreshed.UpdatedAt.Equal(at) {
				t.Fatalf("fresh timestamp changed from %s to %s", at, refreshed.UpdatedAt)
			}
			if err := r.nativePass(ctx, kv, role); err != nil {
				t.Fatal(err)
			}
			if got := bucket.puts[releasechannel.ServiceStatusObject(role)]; got != wantWrites {
				t.Fatalf("unchanged report writes = %d, want %d", got, wantWrites)
			}
		})
	}
}

func TestServiceReleaseInventoryRepairsInvalidStatus(t *testing.T) {
	for _, role := range []string{terrabase.Role, tsauth.Role} {
		for _, corruption := range []string{"malformed", "updated_at", "oversized"} {
			t.Run(role+"/"+corruption, func(t *testing.T) {
				r, kv, bucket, location := servicePinsFixture(t)
				ctx := t.Context()
				state := serviceReleaseState{Claim: strings.Repeat("1", 64), Digest: strings.Repeat("f", 64),
					IssuedAt: time.Now().UTC().Add(-time.Minute), Previous: strings.Repeat("a", 64),
					Retained: []string{strings.Repeat("b", 64)}, State: releasechannel.StateComplete, Reason: "persisted release outcome"}
				key := releasechannel.ServiceStatusKey("GRU", role)
				revision, err := saveServiceRelease(ctx, kv, key, state, 0)
				if err != nil {
					t.Fatal(err)
				}
				bad := strings.Repeat("c", 64)
				if err := markKnownBad(ctx, kv, role, bad, errors.New("withdrawn")); err != nil {
					t.Fatal(err)
				}
				want := releasechannel.ServiceStatus{Schema: releasechannel.ServiceStatusSchema, Cell: "GRU", Role: role,
					Digest: state.Digest, IssuedAt: state.IssuedAt, State: state.State, Reason: state.Reason, UpdatedAt: time.Now().UTC(),
					Pins: &releasechannel.ReleasePins{Rollback: []string{state.Previous, state.Retained[0]}, KnownBad: []string{bad}}}
				wire, err := json.Marshal(want)
				if err != nil {
					t.Fatal(err)
				}
				switch corruption {
				case "malformed":
					// The object decodes completely before trailing junk fails, so it could otherwise dedupe.
					wire = append(wire, 'x')
				case "updated_at":
					wire = []byte(strings.Replace(string(wire), want.UpdatedAt.Format(time.RFC3339Nano), "invalid", 1))
				case "oversized":
					wire = append(wire, strings.Repeat(" ", releasechannel.MaxValueBytes)...)
				}
				object := releasechannel.ServiceStatusObject(role)
				bucket.objects[object], bucket.etags[object] = wire, "invalid-status"
				stored, found, err := releasechannel.ReadServiceStatus(ctx, location, role)
				if err == nil {
					t.Fatal("corrupt status was readable")
				}
				if corruption == "malformed" && (!found || !reflect.DeepEqual(stored, want)) {
					t.Fatalf("malformed status must leave a fully populated dedupe candidate: %+v, found %v: %v", stored, found, err)
				}
				before := time.Now().UTC()
				if err := r.nativePass(ctx, kv, role); err != nil {
					t.Fatal(err)
				}
				repaired := serviceInventoryStatus(t, location, role)
				if repaired.UpdatedAt.Before(before) || repaired.UpdatedAt.After(time.Now().UTC()) {
					t.Fatalf("repair timestamp = %s, want this successful pass", repaired.UpdatedAt)
				}
				want.UpdatedAt = repaired.UpdatedAt
				if !reflect.DeepEqual(repaired, want) || bucket.puts[object] != 1 {
					t.Fatalf("repair status = %+v, pins %+v, writes %d", repaired, repaired.Pins, bucket.puts[object])
				}
				if err := r.nativePass(ctx, kv, role); err != nil {
					t.Fatal(err)
				}
				if got := serviceInventoryStatus(t, location, role); !reflect.DeepEqual(got, repaired) || bucket.puts[object] != 1 {
					t.Fatalf("fresh repaired status was rewritten: %+v, writes %d", got, bucket.puts[object])
				}
				persisted, gotRevision, err := loadServiceRelease(ctx, kv, key)
				if err != nil || gotRevision != revision || !reflect.DeepEqual(persisted, state) {
					t.Fatalf("repair changed durable state: %+v, revision %d: %v", persisted, gotRevision, err)
				}
			})
		}
	}
}

type serviceInventoryWatch struct {
	jetstream.KeyValue
	started chan time.Time
	updates chan jetstream.KeyValueEntry
}

func (kv serviceInventoryWatch) WatchFiltered(_ context.Context, _ []string, _ ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	kv.started <- time.Now().UTC()
	return servicePinsWatcher{updates: kv.updates}, nil
}

func TestServiceReleaseInventoryRefreshWaitsForCompleteInventory(t *testing.T) {
	r, kv, bucket, location := servicePinsFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	role := terrabase.Role
	state, old := serviceInventoryCompleted(t, kv, bucket, time.Now().UTC().Add(-time.Minute))
	if err := releasechannel.WriteServiceStatus(ctx, location, old); err != nil {
		t.Fatal(err)
	}
	watch := serviceInventoryWatch{KeyValue: kv, started: make(chan time.Time, 1), updates: make(chan jetstream.KeyValueEntry)}
	done := make(chan error, 1)
	before := time.Now().UTC()
	go func() { done <- r.report(ctx, watch, role, state) }()
	var started time.Time
	select {
	case started = <-watch.started:
	case err := <-done:
		t.Fatalf("report returned without collecting inventory: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	send := func(entry jetstream.KeyValueEntry) {
		t.Helper()
		select {
		case watch.updates <- entry:
		case err := <-done:
			t.Fatalf("report returned before inventory completion: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	send(servicePinsEntry{key: knownBadKey(role, old.Pins.KnownBad[0])})
	if got := serviceInventoryStatus(t, location, role); !got.UpdatedAt.Equal(old.UpdatedAt) {
		t.Fatalf("incomplete inventory renewed timestamp: %s", got.UpdatedAt)
	}
	send(nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	refreshed := serviceInventoryStatus(t, location, role)
	if !refreshed.Pins.Equal(old.Pins) || refreshed.UpdatedAt.Before(before) || refreshed.UpdatedAt.After(started) ||
		bucket.puts[releasechannel.ServiceStatusObject(role)] != 2 {
		t.Fatalf("refresh must use inventory start time %s..%s: %+v", before, started, refreshed)
	}
}

type serviceInventoryBucket struct {
	*channelBucket
	readObject string
	readErr    error
	writeErr   error
	writes     int
}

func (b *serviceInventoryBucket) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	if *request.ObjectName == b.readObject && b.readErr != nil {
		return objectstorage.GetObjectResponse{}, b.readErr
	}
	return b.channelBucket.GetObject(ctx, request)
}

func (b *serviceInventoryBucket) PutObject(ctx context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	b.writes++
	if b.writeErr != nil {
		return objectstorage.PutObjectResponse{}, b.writeErr
	}
	return b.channelBucket.PutObject(ctx, request)
}

func TestServiceReleaseInventoryReadErrorsDoNotPublish(t *testing.T) {
	for _, source := range []string{"durable state", "channel discovery", "claim", "status"} {
		t.Run(source, func(t *testing.T) {
			r, kv, bucket, location := servicePinsFixture(t)
			ctx, role := t.Context(), terrabase.Role
			_, old := serviceInventoryCompleted(t, kv, bucket, time.Now().UTC().Add(-time.Minute))
			if err := releasechannel.WriteServiceStatus(ctx, location, old); err != nil {
				t.Fatal(err)
			}
			want := errors.New("inventory source unavailable")
			client := &serviceInventoryBucket{channelBucket: bucket, readErr: want}
			failing := location
			failing.Client = client
			r.channel.location = &failing
			switch source {
			case "durable state":
				r.js.Conn().Close()
				want = nats.ErrConnectionClosed
			case "channel discovery":
				r.channel = &channelSource{open: func(context.Context) (releasechannel.Location, error) { return releasechannel.Location{}, want }}
			case "claim":
				client.readObject = releasechannel.ServiceReleaseObject(role)
			case "status":
				client.readObject = releasechannel.ServiceStatusObject(role)
			}
			if err := r.nativePass(ctx, kv, role); !errors.Is(err, want) {
				t.Fatalf("read failure = %v, want %v", err, want)
			}
			if got := serviceInventoryStatus(t, location, role); !reflect.DeepEqual(got, old) || client.writes != 0 {
				t.Fatalf("failed read changed report: %+v, write attempts %d", got, client.writes)
			}
		})
	}
}

func TestServiceReleaseInventoryFailedRefreshPreservesTimestamp(t *testing.T) {
	for _, failure := range []string{"watcher", "incomplete", "invalid key", "object write"} {
		t.Run(failure, func(t *testing.T) {
			r, kv, bucket, location := servicePinsFixture(t)
			ctx, role := t.Context(), terrabase.Role
			_, old := serviceInventoryCompleted(t, kv, bucket, time.Now().UTC().Add(-time.Minute))
			if err := releasechannel.WriteServiceStatus(ctx, location, old); err != nil {
				t.Fatal(err)
			}
			want := errors.New("inventory refresh unavailable")
			watch := servicePinsWatch{KeyValue: kv, keys: []string{knownBadKey(role, old.Pins.KnownBad[0])}}
			client := &serviceInventoryBucket{channelBucket: bucket}
			failing := location
			failing.Client = client
			r.channel.location = &failing
			switch failure {
			case "watcher":
				watch.err = want
			case "incomplete":
				watch.incomplete = true
			case "invalid key":
				watch.keys = []string{knownBadKey(role, "invalid")}
			case "object write":
				client.writeErr = want
			}
			for range 2 {
				if err := r.nativePass(ctx, watch, role); err == nil || (failure == "watcher" || failure == "object write") && !errors.Is(err, want) {
					t.Fatalf("failed refresh = %v", err)
				}
				if got := serviceInventoryStatus(t, location, role); !reflect.DeepEqual(got, old) || bucket.puts[releasechannel.ServiceStatusObject(role)] != 1 {
					t.Fatalf("failed refresh changed report: %+v", got)
				}
			}
			wantWrites := 0
			if failure == "object write" {
				wantWrites = 2
			}
			if client.writes != wantWrites {
				t.Fatalf("failed refresh write attempts = %d, want %d", client.writes, wantWrites)
			}
		})
	}
}

func serviceInventoryCompleted(t *testing.T, kv jetstream.KeyValue, bucket *channelBucket, at time.Time) (serviceReleaseState, releasechannel.ServiceStatus) {
	t.Helper()
	role := terrabase.Role
	claim := []byte("persisted completed inventory claim")
	sum := sha256.Sum256(claim)
	state := serviceReleaseState{Claim: hex.EncodeToString(sum[:]), Digest: strings.Repeat("f", 64),
		Previous: strings.Repeat("a", 64), IssuedAt: time.Now().UTC(), State: releasechannel.StateComplete}
	if _, err := saveServiceRelease(t.Context(), kv, releasechannel.ServiceStatusKey("GRU", role), state, 0); err != nil {
		t.Fatal(err)
	}
	bucket.objects[releasechannel.ServiceReleaseObject(role)] = claim
	bucket.etags[releasechannel.ServiceReleaseObject(role)] = "completed-inventory-claim"
	bad := strings.Repeat("b", 64)
	if err := markKnownBad(t.Context(), kv, role, bad, errors.New("withdrawn")); err != nil {
		t.Fatal(err)
	}
	return state, releasechannel.ServiceStatus{Schema: releasechannel.ServiceStatusSchema, Cell: "GRU", Role: role,
		Digest: state.Digest, IssuedAt: state.IssuedAt, State: state.State, UpdatedAt: at,
		Pins: &releasechannel.ReleasePins{Rollback: []string{state.Previous}, KnownBad: []string{bad}}}
}

func serviceInventoryStatus(t *testing.T, location releasechannel.Location, role string) releasechannel.ServiceStatus {
	t.Helper()
	status, found, err := releasechannel.ReadServiceStatus(t.Context(), location, role)
	if err != nil || !found {
		t.Fatalf("inventory status found = %v: %v", found, err)
	}
	return status
}

func TestServiceReleaseCompleteRevisionRequiresFreshReplicaProofs(t *testing.T) {
	r, kv, _, location := servicePinsFixture(t)
	state := serviceReleaseState{SourceRevision: strings.Repeat("a", 40), Digest: strings.Repeat("b", 64),
		State: releasechannel.StateComplete, Intent: &delivery.Intent{Role: terrabase.Role,
			ArtifactDigest: strings.Repeat("b", 64), Environment: "production", Generation: 1, DesiredReplicas: 1}}
	for _, tc := range []struct {
		name   string
		age    time.Duration
		digest string
		want   releasechannel.State
	}{
		{"unsigned snapshot", 0, state.Digest, releasechannel.StateRolling},
		{"stale", time.Hour, state.Digest, releasechannel.StateRolling},
		{"old build", 0, strings.Repeat("c", 64), releasechannel.StateRolling},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r.hosts = terraBaseMembers{reports: []host.Report{{Role: terrabase.Role, Environment: "production",
				Generation: 1, Digest: tc.digest, State: "running", ObservedAt: time.Now().Add(-tc.age)}}}
			if err := r.report(t.Context(), kv, terrabase.Role, state); err != nil {
				t.Fatal(err)
			}
			status := serviceInventoryStatus(t, location, terrabase.Role)
			if status.State != tc.want || status.SourceRevision != state.SourceRevision {
				t.Fatalf("reported stale source as complete: %+v", status)
			}
		})
	}
}
