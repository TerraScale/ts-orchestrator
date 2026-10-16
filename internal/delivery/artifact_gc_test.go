package delivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/artifact"
	"github.com/nats-io/nats.go/jetstream"
)

func storeTestArtifact(t *testing.T, s *Service, ctx context.Context, role, body string, admit bool) (string, []byte) {
	t.Helper()
	source := ArtifactSource{Repository: "https://github.com/TerraScale/ts-orchestrator", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TreeDigest: hex.EncodeToString(sha256.New().Sum(nil))}
	record, claim, err := s.PrepareArtifact(ctx, bytes.NewReader([]byte(body)), ArtifactClaimRequest{Source: source, Cell: "lab", Role: role, Environment: "production"})
	if err != nil {
		t.Fatal(err)
	}
	if admit {
		if _, err := s.AcceptArtifactClaim(ctx, claim); err != nil {
			t.Fatal(err)
		}
	}
	return record.Digest, claim
}

// recordTestDelivery stores a delivery operation of digest at generation;
// an empty status leaves it undecided.
func recordTestDelivery(t *testing.T, s *Service, ctx context.Context, id, role, digest string, generation uint64, status string) {
	t.Helper()
	op := operation{Intent: Intent{OperationID: id, Cell: "lab", Role: role, Environment: "production", ArtifactDigest: digest, Generation: generation}}
	if status != "" {
		op.Receipt = &Receipt{OperationID: id, Status: status, ArtifactDigest: digest}
	}
	data, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.operations.Put(ctx, operationKey(id), data); err != nil {
		t.Fatal(err)
	}
}

func storedArtifacts(t *testing.T, s *Service, ctx context.Context, digests ...string) []string {
	t.Helper()
	var stored []string
	for _, digest := range digests {
		_, err := s.artifacts.GetInfo(ctx, artifactKey(digest))
		if err == nil {
			stored = append(stored, digest)
		} else if !errors.Is(err, jetstream.ErrObjectNotFound) {
			t.Fatal(err)
		}
	}
	return stored
}

// The collector keeps what desired names, the rollback target (the newest
// delivered digest not in use), an undecided delivery's digest, the two
// newest admissions of a role no delivery released, and anything recent.
// It deletes the rest and purges chunks of failed uploads. A reference made
// after it read an object's metadata keeps that object.
func TestCollectArtifactsKeepsRunningRollbackAndRecent(t *testing.T) {
	s, ctx := testService(t, &testWriter{})
	a, _ := storeTestArtifact(t, s, ctx, "worker", "a", true)
	b, _ := storeTestArtifact(t, s, ctx, "worker", "b", true)
	c, _ := storeTestArtifact(t, s, ctx, "worker", "c", true)
	d, _ := storeTestArtifact(t, s, ctx, "worker", "d", true)
	unadmitted, claim := storeTestArtifact(t, s, ctx, "worker", "e", false)
	f, _ := storeTestArtifact(t, s, ctx, "idle", "f", true)
	g, _ := storeTestArtifact(t, s, ctx, "idle", "g", true)
	h, _ := storeTestArtifact(t, s, ctx, "idle", "h", true)
	all := []string{a, b, c, d, unadmitted, f, g, h}
	// a ran, then desired jumped to c; b was admitted but never released;
	// d's delivery is undecided; a rejected delivery of b changed nothing.
	recordTestDelivery(t, s, ctx, "0000000000NBCYX286D4RHE6ZP", "worker", a, 1, "accepted")
	recordTestDelivery(t, s, ctx, "0000000000A16YGSP64YK28MAE", "worker", b, 2, "rejected")
	recordTestDelivery(t, s, ctx, "release-c", "worker", c, 3, "accepted")
	recordTestDelivery(t, s, ctx, "release-d", "worker", d, 4, "")
	// An obsolete preparation copy must not turn the rejected delivery back into a pending one.
	prepared := operation{Intent: Intent{OperationID: "0000000000A16YGSP64YK28MAE", Cell: "lab", Role: "worker",
		Environment: "production", ArtifactDigest: b, Generation: 2}}
	preparedWire, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.operations.Put(ctx, "w_prepared", preparedWire); err != nil {
		t.Fatal(err)
	}
	// A failed upload's chunks: no object references them.
	orphan := artifactChunkPrefix + "failedupload"
	if _, err := s.js.Publish(ctx, orphan, []byte("partial")); err != nil {
		t.Fatal(err)
	}
	running := func(context.Context) ([]ArtifactUse, error) {
		return []ArtifactUse{{Digest: c, Role: "worker", Environment: "production"}}, nil
	}
	guard := func(context.Context) error { return nil }

	// Within the grace everything stays: a release may be mid-flight.
	collection, err := s.CollectArtifacts(ctx, running, time.Now(), guard)
	if err != nil || len(collection.Deleted)+len(collection.Purged) != 0 {
		t.Fatalf("fresh collection = %+v, %v; want nothing removed", collection, err)
	}
	// A refused guard stops before the first effect.
	later := time.Now().Add(2 * artifactGCGrace)
	fenced := errors.New("fenced")
	if _, err := s.CollectArtifacts(ctx, running, later, func(context.Context) error { return fenced }); !errors.Is(err, fenced) {
		t.Fatalf("fenced collection = %v", err)
	}
	if stored := storedArtifacts(t, s, ctx, all...); len(stored) != len(all) {
		t.Fatalf("fenced collection removed artifacts: %d of %d stored", len(stored), len(all))
	}
	// References made after the collector read the metadata: a desired
	// names b (touching it) and an admission admits the unadmitted upload.
	// Both stay; the others go.
	racing := func(ctx context.Context) ([]ArtifactUse, error) {
		legacy, err := s.config.Conn.JetStream()
		if err != nil {
			return nil, err
		}
		if err := artifact.Touch(ctx, legacy, ArtifactBucket, artifactKey(b)); err != nil {
			return nil, err
		}
		if _, err := s.AcceptArtifactClaim(ctx, claim); err != nil {
			return nil, err
		}
		return running(ctx)
	}
	collection, err = s.CollectArtifacts(ctx, racing, later, guard)
	if err != nil || !slices.Equal(collection.Deleted, []string{f}) || !slices.Equal(collection.Purged, []string{orphan}) {
		t.Fatalf("collection with racing references = %+v, %v; want %s deleted and %s purged", collection, err, f, orphan)
	}
	if stored := storedArtifacts(t, s, ctx, all...); !slices.Equal(stored, []string{a, b, c, d, unadmitted, g, h}) {
		t.Fatalf("stored after collection = %v", stored)
	}
	stream, err := s.js.Stream(ctx, "OBJ_"+ArtifactBucket)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(ctx, jetstream.WithSubjectFilter(artifactChunkPrefix+">"))
	if err != nil || info.State.Subjects[orphan] != 0 || len(info.State.Subjects) != 7 {
		t.Fatalf("chunk subjects after collection: %v, %v", info.State.Subjects, err)
	}
	// Once their touches age past the grace, b (never released) and the
	// late admission go; the rollback target a and the undecided d stay
	// and still read back whole.
	collection, err = s.CollectArtifacts(ctx, running, later, guard)
	wantDeleted := []string{b, unadmitted}
	slices.Sort(wantDeleted)
	collected := slices.Sorted(slices.Values(collection.Deleted))
	if err != nil || !slices.Equal(collected, wantDeleted) {
		t.Fatalf("collection after the grace = %+v, %v; want %v deleted", collection, err, wantDeleted)
	}
	if _, err := s.ResolveAdmittedArtifact(ctx, a, "worker", "production"); err != nil {
		t.Fatalf("rollback target after collection: %v", err)
	}
	// Once d runs, c is the rollback target and a goes.
	inUse := func(context.Context) ([]ArtifactUse, error) {
		return []ArtifactUse{{Digest: d, Role: "worker", Environment: "production"}}, nil
	}
	recordTestDelivery(t, s, ctx, "release-d", "worker", d, 4, "accepted")
	if collection, err = s.CollectArtifacts(ctx, inUse, later, guard); err != nil || !slices.Equal(collection.Deleted, []string{a}) {
		t.Fatalf("collection after the next release = %+v, %v; want %s deleted", collection, err, a)
	}
}

func TestCollectArtifactsReconcilesHistoricalPreparationsWithoutLosingRollback(t *testing.T) {
	t.Parallel()
	s, ctx := testService(t, &testWriter{})
	obsolete, _ := storeTestArtifact(t, s, ctx, "worker", "obsolete", true)
	rollback, _ := storeTestArtifact(t, s, ctx, "worker", "rollback", true)
	current, _ := storeTestArtifact(t, s, ctx, "worker", "current", true)
	pending, _ := storeTestArtifact(t, s, ctx, "worker", "pending", true)
	for _, entry := range []struct {
		key, id, digest string
		generation      uint64
		status          string
	}{
		{"o_obsolete", "historical-obsolete", obsolete, 1, "accepted"},
		{"w_obsolete", "historical-obsolete", obsolete, 1, ""},
		{"o_rollback", "historical-rollback", rollback, 2, "accepted"},
		{"w_rollback", "historical-rollback", rollback, 2, ""},
		{operationKey("current"), "current", current, 3, "accepted"},
		// Sharing an ID does not make a distinct intent an obsolete preparation.
		{"w_pending", "historical-rollback", pending, 4, ""},
	} {
		op := operation{Intent: Intent{OperationID: entry.id, Cell: "lab", Role: "worker",
			Environment: "production", ArtifactDigest: entry.digest, Generation: entry.generation}}
		if entry.status != "" {
			op.Receipt = &Receipt{OperationID: entry.id, Status: entry.status, ArtifactDigest: entry.digest}
		}
		wire, err := json.Marshal(op)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.operations.Put(ctx, entry.key, wire); err != nil {
			t.Fatal(err)
		}
	}
	inUse := func(context.Context) ([]ArtifactUse, error) {
		return []ArtifactUse{{Digest: current, Role: "worker", Environment: "production"}}, nil
	}
	collection, err := s.CollectArtifacts(ctx, inUse, time.Now().Add(2*artifactGCGrace), func(context.Context) error { return nil })
	if err != nil || !slices.Equal(collection.Deleted, []string{obsolete}) {
		t.Fatalf("historical collection = %+v, %v; want only obsolete artifact deleted", collection, err)
	}
	for _, digest := range []string{rollback, current, pending} {
		if _, err := s.ResolveAdmittedArtifact(ctx, digest, "worker", "production"); err != nil {
			t.Fatalf("retained historical artifact %s: %v", digest, err)
		}
	}
}

// A restart with the signed config's smaller quota keeps the larger one the
// cell spec set; a larger configured quota still applies.
func TestOpenKeepsALargerArtifactStoreQuota(t *testing.T) {
	s, r, ctx := testServiceWithRuntime(t, &testWriter{})
	if err := s.ResizeArtifactStore(ctx, 128<<20); err != nil {
		t.Fatal(err)
	}
	reopen := func(configured int64) int64 {
		t.Helper()
		reopened, err := Open(ctx, Config{Conn: r.Conn(), JS: r.JetStream(), Cell: "lab", Replicas: 1, ArtifactStoreMaxBytes: configured})
		if err != nil {
			t.Fatal(err)
		}
		quota, _, err := reopened.ArtifactStoreSize(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return quota
	}
	if quota := reopen(64 << 20); quota != 128<<20 {
		t.Fatalf("quota after a restart with a smaller config = %d, want %d", quota, 128<<20)
	}
	if quota := reopen(256 << 20); quota != 256<<20 {
		t.Fatalf("quota after a restart with a larger config = %d, want %d", quota, 256<<20)
	}
}
