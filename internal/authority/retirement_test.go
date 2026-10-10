package authority

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHostRetirementIsTimestampedAndFencedInControlLog(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "0000000000C66H81REBS854264", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	retired := []byte(`{"retired":true}`)
	sequence, err := runtime.CommitHostMutation(ctx, epoch, MutationRetirement, "gru.node-a", "0000000000FHEQV98X4ASD7RXW", 0, retired)
	if err != nil {
		t.Fatal(err)
	}
	first, err := runtime.ReadHostMutation(ctx, MutationRetirement, "gru.node-a")
	if err != nil || first.Sequence != sequence || first.CreatedAt.IsZero() || first.Kind != MutationRetirement || string(first.Payload) != string(retired) {
		t.Fatalf("retirement history = %+v, %v", first, err)
	}
	if _, err := runtime.CommitHostMutation(ctx, epoch+1, MutationRetirement, "gru.node-a", "000000000082B6JM3GHXKNG2CR", sequence, []byte(`{"retired":false}`)); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale authority changed retirement: %v", err)
	}
	if _, err := runtime.CommitHostMutation(ctx, epoch, MutationRetirement, "gru.node-a", "000000000082B6JM3GHXKNG2CR", 0, []byte(`{"retired":false}`)); !errors.Is(err, ErrConflict) {
		t.Fatalf("retirement CAS was bypassed: %v", err)
	}
	sequence, err = runtime.CommitHostMutation(ctx, epoch, MutationRetirement, "gru.node-a", "000000000082B6JM3GHXKNG2CR", sequence, []byte(`{"retired":false}`))
	if err != nil {
		t.Fatal(err)
	}
	last, err := runtime.ReadHostMutation(ctx, MutationRetirement, "gru.node-a")
	if err != nil || last.Sequence != sequence || !last.CreatedAt.After(first.CreatedAt) || string(last.Payload) != `{"retired":false}` {
		t.Fatalf("unretirement history = %+v, %v", last, err)
	}
}
