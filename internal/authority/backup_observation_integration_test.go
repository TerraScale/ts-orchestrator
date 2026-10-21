package authority

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"
)

func TestBackupObservationRetainsExactCommittedMetadata(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: "gru", CandidateID: "0000000000SBF32FW762VKS7H4", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	record := backupRecordFixture()
	if _, _, err := ReadBackupObservation(ctx, runtime, record.DatabaseID, record.PartitionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing record: %v", err)
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	mutationID := "0000000000SQ81DF1FR1ZA1QQB"
	key := record.DatabaseID + "." + record.PartitionID
	outer, err := json.Marshal(controlRecord{Version: 1, Kind: MutationBackupOperation,
		Scope: "gru", SubjectKey: key, OperationID: mutationID, Epoch: runtime.Current().Epoch, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	subject := mutationSubject("gru", MutationBackupOperation, key)
	ack, err := js.Publish(ctx, subject, outer)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := js.Stream(ctx, ControlStreamName)
	if err != nil {
		t.Fatal(err)
	}
	message, err := stream.GetMsg(ctx, ack.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	observed, entry, err := ReadBackupObservation(ctx, runtime, record.DatabaseID, record.PartitionID)
	if err != nil {
		t.Fatal(err)
	}
	if observed.OperationID != record.OperationID || entry.OperationID != mutationID ||
		entry.OperationID == observed.OperationID || entry.Sequence != ack.Sequence ||
		entry.Epoch != runtime.Current().Epoch || entry.CreatedAt.IsZero() || !entry.CreatedAt.Equal(message.Time) || len(entry.Payload) != 0 {
		t.Fatalf("record or exact commit metadata lost: operation=%q metadata=%+v", observed.OperationID, entry)
	}
	if _, _, err := ReadBackupObservation(ctx, runtime, "invalid", record.PartitionID); err == nil {
		t.Fatal("invalid database accepted")
	}
	other := record
	other.PartitionID = "0000000000CBFCJRYSV24E2Z96"
	wrong, err := json.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	corrupt, err := json.Marshal(controlRecord{Version: 1, Kind: MutationBackupOperation,
		Scope: "gru", SubjectKey: key, OperationID: mutationID, Epoch: runtime.Current().Epoch, Payload: wrong})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, subject, corrupt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadBackupObservation(ctx, runtime, record.DatabaseID, record.PartitionID); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-partition payload was accepted or hidden as missing: %v", err)
	}
}
