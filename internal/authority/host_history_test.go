package authority

import (
	"encoding/json/v2"
	"testing"
	"time"
)

func TestHostMutationWindowPinsWatermarkAndRejectsInvalidRecords(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	stream, err := openControlStream(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	subject := mutationSubject("gru", MutationDesired, "gru.node.api")
	record := controlRecord{Version: 1, Scope: "gru", Kind: MutationDesired, SubjectKey: "gru.node.api", OperationID: "first", Epoch: 1, Payload: []byte("active")}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	first, err := js.Publish(t.Context(), subject, data)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := stream.GetMsg(t.Context(), first.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	// This invalid later record must be invisible to the pinned read.
	invalid, err := js.Publish(t.Context(), subject, []byte(`{"version":0}`))
	if err != nil {
		t.Fatal(err)
	}
	from, to := entry.Time.Add(time.Nanosecond), entry.Time.Add(time.Minute)
	got, err := ReadHostMutationWindow(t.Context(), stream, "gru", MutationDesired, from, to, first.Sequence)
	if err != nil || len(got) != 1 || got[0].Sequence != first.Sequence || string(got[0].Payload) != "active" {
		t.Fatalf("pinned baseline = %+v, %v", got, err)
	}
	if _, err := ReadHostMutationWindow(t.Context(), stream, "gru", MutationDesired, from, to, invalid.Sequence); err == nil {
		t.Fatal("invalid committed history became an inventory answer")
	}
}
