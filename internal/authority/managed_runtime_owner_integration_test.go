package authority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats.go/jetstream"
)

func TestManagedRuntimeOwnerPersistsVerifiedVolumeFloorAcrossAuthorityRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	js := newAuthorityTestJetStream(t)
	config := Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: entityid.New(), Replicas: 1}
	runtime, err := Start(ctx, js, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("close original authority: %v", err)
		}
	})
	epoch := runtime.Current().Epoch
	stream, err := js.Stream(ctx, ControlStreamName)
	if err != nil {
		t.Fatal(err)
	}
	volumeID := "ocid1.volume.oc1.sa-saopaulo-1.managed-owner-fixture"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(volumeID)))
	key := "gru.volume." + digest
	subject := "ts.control.gru.host.managed-runtime-owner." + key
	// Opaque authority payloads prove ordered retention, not a physical writer stop.
	initial := []byte("opaque native owner floor")
	fenced := []byte("opaque permanent fence floor")
	verify := func(check context.Context) error { return runtime.Guard(check, epoch) }
	if sequence, err := runtime.CommitHostMutation(ctx, epoch, MutationManagedRuntimeOwner, key, entityid.New(), 0, initial); err == nil || sequence != 0 {
		t.Fatalf("unverified managed owner write: sequence=%d error=%v", sequence, err)
	}
	if sequence, err := runtime.CommitHostMutationVerified(ctx, epoch, MutationManagedRuntimeOwner, key, entityid.New(), 0, initial, nil); err == nil || sequence != 0 {
		t.Fatalf("managed owner write without verifier: sequence=%d error=%v", sequence, err)
	}
	denied := errors.New("independent managed admission refused")
	if sequence, err := runtime.CommitHostMutationVerified(ctx, epoch, MutationManagedRuntimeOwner, key, entityid.New(), 0, initial,
		func(context.Context) error { return denied }); !errors.Is(err, denied) || sequence != 0 {
		t.Fatalf("managed owner ignored failed final verification: sequence=%d error=%v", sequence, err)
	}
	for _, invalid := range []string{
		"gru.volume", "gru.volume." + digest + ".terrabase", "gru.native." + digest,
		"gru.volume." + digest[:63], "gru.volume." + digest + "0",
		"gru.volume." + strings.Repeat("g", 64), "gru.volume." + digest[:63] + "-",
		"gru.volume." + strings.ToUpper(digest), strings.Repeat("g", 64) + ".volume." + digest,
	} {
		if sequence, err := runtime.CommitHostMutationVerified(ctx, epoch, MutationManagedRuntimeOwner, invalid, entityid.New(), 0, initial, verify); err == nil || sequence != 0 {
			t.Fatalf("invalid volume owner key %q committed: sequence=%d error=%v", invalid, sequence, err)
		}
		if _, err := runtime.ReadHostMutation(ctx, MutationManagedRuntimeOwner, invalid); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("invalid volume owner key %q reached readback: %v", invalid, err)
		}
	}
	if sequence, err := runtime.CommitHostMutationVerified(ctx, epoch, MutationManagedRuntimeOwner, "iad.volume."+digest, entityid.New(), 0, initial, verify); err == nil || sequence != 0 {
		t.Fatalf("out-of-scope volume owner committed: sequence=%d error=%v", sequence, err)
	}
	for _, kind := range []HostMutationKind{MutationDesired, MutationRuntimeOwner} {
		if sequence, err := runtime.CommitHostMutationVerified(ctx, epoch, kind, key, entityid.New(), 0, initial, verify); err == nil || sequence != 0 {
			t.Fatalf("non-managed kind %q accepted a volume digest: sequence=%d error=%v", kind, sequence, err)
		}
		if _, err := runtime.ReadHostMutation(ctx, kind, key); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("non-managed kind %q accepted a volume digest for readback: %v", kind, err)
		}
	}
	if sequence, err := runtime.CommitHostMutationVerified(ctx, epoch+1, MutationManagedRuntimeOwner, key, entityid.New(), 0, initial, verify); !errors.Is(err, ErrFenced) || sequence != 0 {
		t.Fatalf("wrong owner epoch committed: sequence=%d error=%v", sequence, err)
	}
	if _, err := stream.GetLastMsgForSubject(ctx, subject); !errors.Is(err, jetstream.ErrMsgNotFound) {
		t.Fatalf("rejected writes left a durable owner: %v", err)
	}

	other, err := Start(ctx, js, Config{DeploymentID: config.DeploymentID, Scope: "iad", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := other.Close(); err != nil {
			t.Errorf("close interleaving authority: %v", err)
		}
	})
	operation := entityid.New()
	var verifyCalls int
	var interleaved uint64
	var checked context.Context
	first, err := runtime.CommitHostMutationVerified(ctx, epoch, MutationManagedRuntimeOwner, key, operation, 0, initial,
		func(check context.Context) error {
			verifyCalls++
			checked = check
			if err := runtime.Guard(check, epoch); err != nil {
				return err
			}
			if interleaved == 0 {
				var err error
				interleaved, err = other.CommitHostMutation(ctx, other.Current().Epoch, MutationRegistration, "iad.node-b", entityid.New(), 0, []byte("independent region registration"))
				return err
			}
			return nil
		})
	if err != nil || interleaved == 0 || first <= interleaved || verifyCalls < 2 {
		t.Fatalf("owner append did not reverify after real global CAS conflict: first=%d interleaved=%d checks=%d error=%v", first, interleaved, verifyCalls, err)
	}
	if checked == nil || checked.Err() == nil || !errors.Is(runtime.Guard(checked, epoch), ErrFenced) {
		t.Fatal("managed owner verification authority escaped its final callback")
	}
	if replay, err := runtime.CommitHostMutationVerified(ctx, epoch, MutationManagedRuntimeOwner, key, operation, 0, initial, verify); err != nil || replay != first {
		t.Fatalf("exact owner replay changed its persisted sequence: sequence=%d error=%v", replay, err)
	}
	if sequence, err := runtime.CommitHostMutationVerified(ctx, epoch, MutationManagedRuntimeOwner, key, operation, first, fenced, verify); !errors.Is(err, ErrOperationConflict) || sequence != 0 {
		t.Fatalf("operation identity accepted changed owner bytes: sequence=%d error=%v", sequence, err)
	}
	if sequence, err := runtime.CommitHostMutationVerified(ctx, epoch, MutationManagedRuntimeOwner, key, entityid.New(), 0, fenced, verify); !errors.Is(err, ErrConflict) || sequence != 0 {
		t.Fatalf("same physical volume acquired a second initial owner: sequence=%d error=%v", sequence, err)
	}
	fenceOperation := entityid.New()
	second, err := runtime.CommitHostMutationVerified(ctx, epoch, MutationManagedRuntimeOwner, key, fenceOperation, first, fenced, verify)
	if err != nil || second <= first {
		t.Fatalf("exact owner predecessor did not advance: sequence=%d error=%v", second, err)
	}
	if sequence, err := runtime.CommitHostMutationVerified(ctx, epoch, MutationManagedRuntimeOwner, key, entityid.New(), first, initial, verify); !errors.Is(err, ErrConflict) || sequence != 0 {
		t.Fatalf("stale owner predecessor rewrote the floor: sequence=%d error=%v", sequence, err)
	}
	for _, expected := range []struct {
		sequence  uint64
		operation string
		payload   []byte
	}{{first, operation, initial}, {second, fenceOperation, fenced}} {
		raw, err := stream.GetMsg(ctx, expected.sequence)
		if err != nil {
			t.Fatal(err)
		}
		record, err := decodeControlRecord(raw.Data)
		if err != nil || raw.Subject != subject || raw.Time.IsZero() || record.Kind != MutationManagedRuntimeOwner || record.Scope != "gru" || record.SubjectKey != key || record.Epoch != epoch || record.OperationID != expected.operation || !bytes.Equal(record.Payload, expected.payload) {
			t.Fatalf("persisted owner identity changed: raw=%+v record=%+v error=%v", raw, record, err)
		}
	}
	before, err := runtime.ReadHostMutation(ctx, MutationManagedRuntimeOwner, key)
	if err != nil || before.Sequence != second || before.OperationID != fenceOperation || before.Epoch != epoch || before.Kind != MutationManagedRuntimeOwner || before.SubjectKey != key || !bytes.Equal(before.Payload, fenced) || before.CreatedAt.IsZero() {
		t.Fatalf("owner readback lost the exact fence floor: %+v error=%v", before, err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	config.CandidateID = entityid.New()
	restarted, err := Start(ctx, js, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := restarted.Close(); err != nil {
			t.Errorf("close restarted authority: %v", err)
		}
	})
	newEpoch := restarted.Current().Epoch
	if newEpoch <= epoch {
		t.Fatalf("authority restart did not advance epoch: before=%d after=%d", epoch, newEpoch)
	}
	after, err := restarted.ReadHostMutation(ctx, MutationManagedRuntimeOwner, key)
	if err != nil || after.Kind != before.Kind || after.SubjectKey != before.SubjectKey || after.OperationID != before.OperationID || after.Epoch != before.Epoch || after.Sequence != before.Sequence || !after.CreatedAt.Equal(before.CreatedAt) || !bytes.Equal(after.Payload, before.Payload) {
		t.Fatalf("authority restart changed the persisted volume floor: before=%+v after=%+v error=%v", before, after, err)
	}
	for _, attempt := range []struct {
		epoch    uint64
		previous uint64
		want     error
	}{{epoch, second, ErrFenced}, {newEpoch, 0, ErrConflict}, {newEpoch, first, ErrConflict}} {
		if sequence, err := restarted.CommitHostMutationVerified(ctx, attempt.epoch, MutationManagedRuntimeOwner, key, entityid.New(), attempt.previous, initial,
			func(check context.Context) error { return restarted.Guard(check, newEpoch) }); !errors.Is(err, attempt.want) || sequence != 0 {
			t.Fatalf("restart bypassed epoch/predecessor floor: epoch=%d previous=%d sequence=%d error=%v", attempt.epoch, attempt.previous, sequence, err)
		}
	}

	lease, err := stream.GetLastMsgForSubject(ctx, "ts.control.gru.lease")
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reset := IdentityReset{Version: 1, OperationID: entityid.New(), DeploymentID: entityid.New(), ClusterID: entityid.New(), Scope: "gru", Environment: "canary",
		CheckpointSHA256: resetDigest([]byte("checkpoint")), HostStatePlanSHA256: resetDigest([]byte("empty typed host plan")),
		LastSequence: info.State.LastSeq, PreviousSequence: lease.Sequence, PreviousSHA256: resetDigest(lease.Data), EpochFloor: newEpoch, Epoch: newEpoch + 1,
		Records: []IdentityResetRecord{
			{Action: IdentityResetReplaceKV, Bucket: "TS_SERVICE_SET", Key: "current", SHA256: resetDigest([]byte("replacement spec"))},
			{Action: IdentityResetReplaceKV, Bucket: "TS_TRUST_ROOTS", Key: "chain", SHA256: resetDigest([]byte("replacement roots"))},
			{Action: IdentityResetReplaceKV, Bucket: "TS_TRUST_ROOTS", Key: "material-generations", SHA256: resetDigest([]byte("replacement material"))},
		}}
	if err := reset.Validate(); err != nil {
		t.Fatalf("typed reset baseline is invalid: %v", err)
	}
	owner, err := stream.GetMsg(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []IdentityResetAction{IdentityResetAppendHostHead, IdentityResetDeleteKV, IdentityResetReplaceKV} {
		record := IdentityResetRecord{Action: action, Bucket: ControlStreamName, Key: subject, PreviousRevision: second, PreviousSHA256: resetDigest(owner.Data)}
		if action != IdentityResetDeleteKV {
			record.SHA256 = resetDigest(owner.Data)
		}
		candidate := reset
		candidate.Records = append(slices.Clone(reset.Records), record)
		if allowedIdentityHostRecord("gru", record) || candidate.Validate() == nil {
			t.Fatalf("typed identity reset admitted managed owner action %q", action)
		}
	}
	retained, err := restarted.ReadHostMutation(ctx, MutationManagedRuntimeOwner, key)
	if err != nil || retained.Sequence != second || retained.Epoch != epoch || retained.OperationID != fenceOperation || !bytes.Equal(retained.Payload, fenced) || !retained.CreatedAt.Equal(before.CreatedAt) {
		t.Fatalf("rejected reset or stale writer changed the permanent owner floor: %+v error=%v", retained, err)
	}
	if sequence, err := restarted.CommitHostMutationVerified(ctx, newEpoch, MutationManagedRuntimeOwner, key, fenceOperation, second, fenced,
		func(check context.Context) error { return restarted.Guard(check, newEpoch) }); !errors.Is(err, ErrOperationConflict) || sequence != 0 {
		t.Fatalf("a new epoch reused an old owner operation: sequence=%d error=%v", sequence, err)
	}
	thirdOperation := entityid.New()
	third, err := restarted.CommitHostMutationVerified(ctx, newEpoch, MutationManagedRuntimeOwner, key, thirdOperation, second, fenced,
		func(check context.Context) error { return restarted.Guard(check, newEpoch) })
	if err != nil || third <= second {
		t.Fatalf("new epoch could not advance the exact retained fence floor: sequence=%d error=%v", third, err)
	}
	advanced, err := restarted.ReadHostMutation(ctx, MutationManagedRuntimeOwner, key)
	if err != nil || advanced.Sequence != third || advanced.Epoch != newEpoch || advanced.OperationID != thirdOperation || advanced.Kind != MutationManagedRuntimeOwner || advanced.SubjectKey != key || !bytes.Equal(advanced.Payload, fenced) {
		t.Fatalf("new epoch lost the retained volume identity or fence bytes: %+v error=%v", advanced, err)
	}
}
