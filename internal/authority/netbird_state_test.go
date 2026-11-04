package authority

import (
	"bytes"
	"errors"
	"testing"
)

func TestNetBirdStateRejectsStaleTransitionAndReadsThroughFollower(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	runtime, err := Start(t.Context(), js, Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "25N2M1ND48SN1GD1DNCM8BTJFP", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	epoch := runtime.Current().Epoch
	before, err := runtime.CommitNetBirdState(t.Context(), epoch, "0B2R51XPY68AE7SVFGZAGC8DGC", 0, []byte(`{"record":"install","command":"install"}`))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"record":"rollback","command":"rollback"}`)
	written, err := runtime.CommitNetBirdState(t.Context(), epoch, "2R6BD8J8358JYCZ2CXGD7KCE9M", before, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.CommitNetBirdState(t.Context(), epoch, "31AMKHTEKXAE8T964Z9TXZKCSG", before, []byte(`{"record":"confirm","command":"confirm"}`)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale transition error = %v, want conflict", err)
	}
	reader, err := OpenReader(t.Context(), js, "gru")
	if err != nil {
		t.Fatal(err)
	}
	state, err := reader.ReadNetBirdState(t.Context())
	if err != nil || state.Sequence != written || state.Epoch != epoch || !bytes.Equal(state.Payload, payload) {
		t.Fatalf("read-only follower state = %+v, %v", state, err)
	}
	if _, err := runtime.CommitHostMutation(t.Context(), epoch, MutationNetBirdState, netbirdStateKey, "generic-write", written, payload); err == nil {
		t.Fatal("generic host mutation accepted NetBird state")
	}
}
