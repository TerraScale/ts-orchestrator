package authority

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const authorityTestDeployment = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

func TestDeploymentRetainedAcrossRenewReleaseAndRecovery(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	config := Config{Scope: "gru", DeploymentID: authorityTestDeployment,
		CandidateID: "0000000000C66H81REBS854264", Replicas: 1}
	runtime, err := Start(ctx, js, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	initial := runtime.Current()
	if initial.DeploymentID != config.DeploymentID || !initial.CanMutate() {
		t.Fatalf("initial lease lost its deployment: %+v", initial)
	}
	if err := runtime.Guard(ctx, initial.Epoch); err != nil {
		t.Fatal(err)
	}
	if renewed := runtime.Current(); renewed.DeploymentID != initial.DeploymentID || renewed.Epoch != initial.Epoch || renewed.Revision <= initial.Revision {
		t.Fatalf("renewal changed binding or failed to advance revision: %+v", renewed)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	released, err := Observe(ctx, js, config.Scope)
	if err != nil || released.DeploymentID != initial.DeploymentID || released.Ready || released.Epoch != initial.Epoch {
		t.Fatalf("release lost its binding: %+v, %v", released, err)
	}
	entry, err := runtime.stream.GetLastMsgForSubject(ctx, runtime.leaseSub)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := decodeLease(entry.Data)
	if err != nil || !lease.Released {
		t.Fatalf("read released lease: %+v, %v", lease, err)
	}
	if err := runtime.resolveLeaseAppend(ctx, lease, jetstream.ErrNoStreamResponse); err != nil || runtime.Current().DeploymentID != config.DeploymentID {
		t.Fatalf("recovering an ambiguous release lost deployment: %v", err)
	}
	config.CandidateID = "0000000000SF1REEJJX6TC691V"
	successor, err := Start(ctx, js, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = successor.Close() })
	if recovered := successor.Current(); recovered.DeploymentID != initial.DeploymentID || recovered.Epoch != initial.Epoch+1 || !recovered.CanMutate() {
		t.Fatalf("successor changed deployment or failed to advance epoch: %+v", recovered)
	}

	{
		// Stop renewal before publishing the exact historical decoder fixture.
		if err := successor.Close(); err != nil {
			t.Fatal(err)
		}
		readerConn, err := nats.Connect(js.Conn().ConnectedUrl(), nats.Timeout(5*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		defer readerConn.Close()
		readerJS, err := jetstream.New(readerConn)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := readerJS.Stream(ctx, ControlStreamName)
		if err != nil {
			t.Fatal(err)
		}
		info, err := reader.Info(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if info.Config.Storage != jetstream.FileStorage || info.Config.Replicas != 1 {
			t.Fatalf("lease storage = %+v", info.Config)
		}
		baseline, err := reader.GetLastMsgForSubject(ctx, successor.leaseSub)
		if err != nil {
			t.Fatal(err)
		}
		baselineLease, err := decodeLease(baseline.Data)
		if err != nil || baseline.Sequence == 0 || baseline.Sequence != info.State.LastSeq ||
			baseline.Subject != successor.leaseSub || baselineLease.Scope != config.Scope ||
			baselineLease.DeploymentID != config.DeploymentID || baselineLease.CandidateID != config.CandidateID ||
			baselineLease.OwnerID != successor.ownerID || baselineLease.Epoch != initial.Epoch+1 ||
			baselineLease.LeaseDuration != int64(successor.config.LeaseDuration) || !baselineLease.Released {
			t.Fatalf("released successor baseline = %+v at %d: %v", baselineLease, baseline.Sequence, err)
		}

		lease := leaseRecord{Version: 1, Scope: "gru", DeploymentID: authorityTestDeployment,
			CandidateID: "0000000000C66H81REBS854264", OwnerID: "0000000000DXKPTGJCKZVQAP63",
			Epoch: 7, LeaseDuration: int64(5 * time.Second), TransitionID: "0000000000C66H81REBS854264"}
		wire, err := json.Marshal(lease)
		if err != nil {
			t.Fatal(err)
		}
		ack, err := js.Publish(ctx, successor.leaseSub, wire,
			jetstream.WithExpectLastSequence(info.State.LastSeq),
			jetstream.WithExpectLastSequenceForSubject(baseline.Sequence, successor.leaseSub))
		if err != nil {
			t.Fatal(err)
		}
		if ack.Stream != ControlStreamName || ack.Sequence <= baseline.Sequence || ack.Duplicate {
			t.Fatalf("version-one fixture publish = %+v after %d", ack, baseline.Sequence)
		}
		stored, err := reader.GetLastMsgForSubject(ctx, successor.leaseSub)
		if err != nil || stored.Sequence != ack.Sequence || stored.Subject != successor.leaseSub || !bytes.Equal(stored.Data, wire) {
			t.Fatalf("persisted version-one fixture = %+v, want sequence %d: %v", stored, ack.Sequence, err)
		}
		wire = stored.Data
		decoded, err := decodeLease(wire)
		if err != nil || decoded != lease {
			t.Fatalf("version-one deployment lease did not round trip: %+v, %v", decoded, err)
		}
		// This fixture preserves the pre-binding wire contract and its strict decoder.
		var legacy struct {
			Version       int    `json:"version"`
			Scope         string `json:"scope"`
			CandidateID   string `json:"candidate_id"`
			OwnerID       string `json:"owner_id"`
			Epoch         uint64 `json:"epoch"`
			LeaseDuration int64  `json:"lease_duration_ns"`
			TransitionID  string `json:"transition_id"`
			Released      bool   `json:"released"`
		}
		if err := json.Unmarshal(wire, &legacy, json.RejectUnknownMembers(true)); err == nil {
			t.Fatal("legacy strict decoder accepted the deployment-bound lease")
		}
		var fields map[string]any
		if err := json.Unmarshal(wire, &fields); err != nil {
			t.Fatal(err)
		}
		observed, err := Observe(ctx, readerJS, lease.Scope)
		if err != nil || observed.Scope != lease.Scope || observed.DeploymentID != lease.DeploymentID ||
			observed.CandidateID != lease.CandidateID || observed.OwnerID != lease.OwnerID ||
			observed.Epoch != lease.Epoch || observed.Revision != ack.Sequence || observed.Leader {
			t.Fatalf("persisted version-one observer = %+v at %d: %v", observed, ack.Sequence, err)
		}
		delete(fields, "deployment_id")
		oldWire, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		legacyAck, err := js.Publish(ctx, successor.leaseSub, oldWire,
			jetstream.WithExpectLastSequence(ack.Sequence),
			jetstream.WithExpectLastSequenceForSubject(ack.Sequence, successor.leaseSub))
		if err != nil {
			t.Fatal(err)
		}
		if legacyAck.Stream != ControlStreamName || legacyAck.Sequence <= ack.Sequence || legacyAck.Duplicate {
			t.Fatalf("legacy fixture publish = %+v after %d", legacyAck, ack.Sequence)
		}
		stored, err = reader.GetLastMsgForSubject(ctx, successor.leaseSub)
		if err != nil || stored.Sequence != legacyAck.Sequence || stored.Subject != successor.leaseSub || !bytes.Equal(stored.Data, oldWire) {
			t.Fatalf("persisted legacy fixture = %+v, want sequence %d: %v", stored, legacyAck.Sequence, err)
		}
		oldWire = stored.Data
		if err := json.Unmarshal(oldWire, &legacy, json.RejectUnknownMembers(true)); err != nil {
			t.Fatalf("legacy decoder fixture rejected its original contract: %v", err)
		}
		if _, err := decodeLease(oldWire); !errors.Is(err, ErrLeaseCorrupt) {
			t.Fatalf("new decoder admitted a lease without deployment_id: %v", err)
		}
		observed, err = Observe(ctx, readerJS, lease.Scope)
		if !errors.Is(err, ErrLeaseCorrupt) || observed.Revision != legacyAck.Sequence || observed.Reason != "lease-corrupt" {
			t.Fatalf("persisted legacy observer = %+v at %d: %v", observed, legacyAck.Sequence, err)
		}
		info, err = reader.Info(ctx)
		if err != nil || info.State.LastSeq != legacyAck.Sequence {
			t.Fatalf("decoder fixture acquired an unexpected writer: %+v, %v", info, err)
		}
		confirmed, err := reader.GetLastMsgForSubject(ctx, successor.leaseSub)
		if err != nil || confirmed.Sequence != legacyAck.Sequence || confirmed.Subject != successor.leaseSub || !bytes.Equal(confirmed.Data, oldWire) {
			t.Fatalf("decoder fixture changed after refusal: %+v, %v", confirmed, err)
		}
	}
}
