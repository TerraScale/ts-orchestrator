package authority

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestIdentityResetRekeysExactTombstonesFromCompletedOperation(t *testing.T) {
	for _, operation := range []string{"DEL", "PURGE"} {
		t.Run(operation, func(t *testing.T) {
			f := newIdentityHostRecordsFixture(t)
			for i, record := range f.reset.Records {
				if record.Key == "report.gru.ts-gru-2.terrabase" {
					f.reset.Records[i].Key = "retirement-cutover.gru"
				}
			}
			f.envelope = signIdentityResetForTest(t, f.reset, f.key)
			f.barrier(t)
			if _, err := f.replace(t, f.js, t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err != nil {
				t.Fatal(err)
			}

			// A reviewed tombstone can also precede a replacement, not just cleanup.
			deleted := nats.NewMsg(identityRecordSubject(f.reset.Records[0]))
			deleted.Header.Set("KV-Operation", operation)
			if operation == "PURGE" {
				deleted.Header.Set(nats.MsgRollup, nats.MsgRollupSubject)
			}
			if _, err := f.js.PublishMsg(t.Context(), deleted); err != nil {
				t.Fatal(err)
			}
			floor, err := ObserveIdentityResetFloor(t.Context(), f.js, f.reset.Scope, f.target.Replicas)
			if err != nil {
				t.Fatal(err)
			}
			f.reset.OperationID = entityid.New()
			f.target.OperationID = f.reset.OperationID
			f.reset.EpochFloor, f.reset.Epoch = f.reset.Epoch, f.reset.Epoch+1
			f.reset.LastSequence, f.reset.PreviousSequence, f.reset.PreviousSHA256 = floor.LastSequence, floor.PreviousSequence, floor.PreviousSHA256
			reader, err := identityRecordReader(f.js)
			if err != nil {
				t.Fatal(err)
			}
			for i := range f.reset.Records {
				record := &f.reset.Records[i]
				stream := "KV_" + record.Bucket
				if record.Action == IdentityResetAppendHostHead {
					stream = ControlStreamName
					head, err := decodeControlRecord(f.values[i])
					if err != nil {
						t.Fatal(err)
					}
					head.Epoch = f.reset.Epoch
					f.values[i], err = jsonMarshal(head)
					if err != nil {
						t.Fatal(err)
					}
					record.SHA256 = resetDigest(f.values[i])
				}
				previous, err := reader.GetLastMsg(stream, identityRecordSubject(*record), nats.Context(t.Context()))
				if err != nil {
					t.Fatal(err)
				}
				record.PreviousRevision, record.PreviousSHA256 = previous.Sequence, resetDigest(previous.Data)
				record.PreviousOperation = previous.Header.Get("KV-Operation")
			}
			if err := VerifyIdentityResetPredecessors(t.Context(), f.js, f.reset, f.target.Replicas); err != nil {
				t.Fatalf("reviewed tombstone preflight: %v", err)
			}
			for _, fault := range []string{"omitted operation", "wrong operation", "claimed absence"} {
				bad := f.reset
				bad.Records = slices.Clone(f.reset.Records)
				switch fault {
				case "omitted operation":
					bad.Records[0].PreviousOperation = ""
				case "wrong operation":
					bad.Records[0].PreviousOperation = "DEL"
					if operation == "DEL" {
						bad.Records[0].PreviousOperation = "PURGE"
					}
				case "claimed absence":
					bad.Records[0].PreviousRevision, bad.Records[0].PreviousSHA256, bad.Records[0].PreviousOperation = 0, "", ""
				}
				if err := VerifyIdentityResetPredecessors(t.Context(), f.js, bad, f.target.Replicas); !errors.Is(err, ErrConflict) {
					t.Fatalf("%s admitted: %v", fault, err)
				}
				if current := f.last(t, 0); current.Sequence != f.reset.Records[0].PreviousRevision {
					t.Fatal("preflight refusal changed predecessor")
				}
			}
			f.envelope = signIdentityResetForTest(t, f.reset, f.key)
			f.barrier(t)
			if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); !errors.Is(err, ErrConflict) {
				t.Fatalf("earlier operation's tombstones completed this reset: %v", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			wrapped := &identityRecordPublisher{JetStream: f.js}
			wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
				ack, err := f.js.PublishMsg(ctx, msg, opts...)
				if err == nil && msg.Subject == deleted.Subject && msg.Header.Get("KV-Operation") == "PURGE" {
					cancel()
				}
				return ack, err
			}
			if _, err := f.replace(t, wrapped, ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("interrupted replacement of tombstone: %v", err)
			}
			revisions, err := f.replace(t, f.js, t.Context())
			if err != nil {
				t.Fatal(err)
			}
			assertIdentityHostRecords(t, f, revisions)
			if retry, err := f.replace(t, f.js, t.Context()); err != nil || !slices.Equal(retry, revisions) {
				t.Fatalf("retry rewrote exact completed records: %v, %v", retry, err)
			}
			if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIdentityResetRejectsInvalidTombstonePredecessorPins(t *testing.T) {
	_, reset, _, _, _ := identityResetFixture(t)
	for _, fault := range []string{"operation", "nonempty data", "zero revision", "control head"} {
		bad := reset
		bad.Records = slices.Clone(reset.Records)
		bad.Records[0].PreviousRevision = 1
		bad.Records[0].PreviousSHA256 = resetDigest(nil)
		bad.Records[0].PreviousOperation = "PURGE"
		switch fault {
		case "operation":
			bad.Records[0].PreviousOperation = "PUT"
		case "nonempty data":
			bad.Records[0].PreviousSHA256 = resetDigest([]byte("not a tombstone"))
		case "zero revision":
			bad.Records[0].PreviousRevision, bad.Records[0].PreviousSHA256 = 0, ""
		case "control head":
			bad.Records = append(bad.Records, IdentityResetRecord{Action: IdentityResetAppendHostHead,
				Bucket: ControlStreamName, Key: controlSubjectRoot + ".gru.host.registration.gru.ts-gru-2",
				PreviousRevision: 1, PreviousSHA256: resetDigest(nil), PreviousOperation: "PURGE", SHA256: resetDigest([]byte("head"))})
		}
		if err := bad.Validate(); err == nil {
			t.Fatalf("invalid %s predecessor admitted", fault)
		}
	}
}
