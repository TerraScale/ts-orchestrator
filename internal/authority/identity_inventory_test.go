package authority

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats.go/jetstream"
)

func TestIdentityResetRejectsOmittedHostInventoryBeforeBarrier(t *testing.T) {
	for _, destination := range [][2]string{
		{ControlStreamName, "ts.control.gru.host.registration.gru.inactive"},
		{ControlStreamName, "ts.control.gru.host.desired.gru.inactive.terrabase"},
		{ControlStreamName, "ts.control.gru.host.retirement.gru.inactive"},
		{"TS_HOST_STATE", "retired.gru.inactive"},
		{"TS_HOST_STATE", "retirement-quarantine.gru.inactive"},
		{"TS_HOST_STATE", "session.gru.inactive"},
		{"TS_HOST_STATE", entityid.Derive("terrabase-format", "gru", "inactive", "volume")},
		{"TS_HOST_ENROLLMENT", resetDigest([]byte("inactive instance"))},
		{"TS_HOST_ENROLLMENT", entityid.Derive("host-enrollment", "inactive instance")},
	} {
		t.Run(destination[0]+"/"+destination[1], func(t *testing.T) {
			f := newIdentityHostRecordsFixture(t)
			value := []byte("opaque omitted host; never decode as authority")
			if destination[0] == ControlStreamName {
				ack, err := f.js.Publish(t.Context(), destination[1], value)
				if err != nil {
					t.Fatal(err)
				}
				f.reset.LastSequence = ack.Sequence
			} else if _, err := f.buckets[destination[0]].Put(t.Context(), destination[1], value); err != nil {
				t.Fatal(err)
			}
			f.envelope = signIdentityResetForTest(t, f.reset, f.key)
			if err := VerifyIdentityResetPredecessors(t.Context(), f.js, f.reset, f.target.Replicas); !errors.Is(err, ErrConflict) {
				t.Fatalf("preflight admitted omitted host: %v", err)
			}
			if _, err := ResetIdentityLease(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); !errors.Is(err, ErrConflict) {
				t.Fatalf("barrier admitted omitted host: %v", err)
			}
			stream, err := f.js.Stream(t.Context(), ControlStreamName)
			if err != nil {
				t.Fatal(err)
			}
			info, err := stream.Info(t.Context())
			if err != nil || info.State.LastSeq != f.reset.LastSequence {
				t.Fatalf("omission refusal changed shared history: %v", err)
			}
		})
	}
}

func TestIdentityResetRejectsAggregateEvictionBeforeBarrier(t *testing.T) {
	for _, bucket := range []string{"TS_SERVICE_SET", "TS_TRUST_ROOTS", "TS_HOST_STATE", "TS_HOST_ENROLLMENT"} {
		for _, limit := range []string{"messages", "bytes"} {
			t.Run(bucket+"/"+limit, func(t *testing.T) {
				f := newIdentityHostRecordsFixture(t)
				stream, err := f.js.Stream(t.Context(), "KV_"+bucket)
				if err != nil {
					t.Fatal(err)
				}
				info, err := stream.Info(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				config := info.Config
				config.Discard = jetstream.DiscardOld
				if limit == "messages" {
					config.MaxMsgs = 10000
				} else {
					config.MaxBytes = 1 << 20
				}
				if _, err := f.js.UpdateStream(t.Context(), config); err != nil {
					t.Fatal(err)
				}
				if err := VerifyIdentityResetPredecessors(t.Context(), f.js, f.reset, f.target.Replicas); err == nil {
					t.Fatal("preflight admitted aggregate eviction")
				}
				if _, err := ResetIdentityLease(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err == nil {
					t.Fatal("barrier admitted aggregate eviction")
				}
				control, err := f.js.Stream(t.Context(), ControlStreamName)
				if err != nil {
					t.Fatal(err)
				}
				current, err := control.Info(t.Context())
				if err != nil || current.State.LastSeq != f.reset.LastSequence {
					t.Fatal("unsafe bucket committed a hold")
				}
				config.Discard = jetstream.DiscardNew
				if _, err := f.js.UpdateStream(t.Context(), config); err != nil {
					t.Fatal(err)
				}
				if err := VerifyIdentityResetPredecessors(t.Context(), f.js, f.reset, f.target.Replicas); err != nil {
					t.Fatal(err)
				}
				f.barrier(t)
				if _, err := f.replace(t, f.js, t.Context()); err != nil {
					t.Fatal(err)
				}
				current, err = stream.Info(t.Context())
				if err != nil || current.Config.MaxMsgsPerSubject != info.Config.MaxMsgsPerSubject {
					t.Fatal("replacement changed per-key history")
				}
			})
		}
	}
}

func TestIdentityResetInventoryRetainsForeignCellAndRefusesLateTombstone(t *testing.T) {
	f := newIdentityHostRecordsFixture(t)
	foreign := []byte("foreign cell record must remain opaque and unchanged")
	if _, err := f.js.Publish(t.Context(), "ts.control.gru.host.audit", foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := f.js.Publish(t.Context(), "ts.control.sjc.host.registration.sjc.node-a", foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := f.buckets["TS_HOST_STATE"].Put(t.Context(), "retired.sjc.node-a", foreign); err != nil {
		t.Fatal(err)
	}
	floor, err := ObserveIdentityResetFloor(t.Context(), f.js, f.reset.Scope, f.target.Replicas)
	if err != nil {
		t.Fatal(err)
	}
	f.reset.LastSequence = floor.LastSequence
	f.envelope = signIdentityResetForTest(t, f.reset, f.key)
	if err := VerifyIdentityResetPredecessors(t.Context(), f.js, f.reset, f.target.Replicas); err != nil {
		t.Fatal(err)
	}
	f.barrier(t)
	if _, err := f.replace(t, f.js, t.Context()); err != nil {
		t.Fatal(err)
	}
	kv := f.buckets["TS_HOST_STATE"]
	if _, err := kv.Put(t.Context(), "retired.gru.omitted", []byte("late inventory")); err != nil {
		t.Fatal(err)
	}
	if err := kv.Delete(t.Context(), "retired.gru.omitted"); err != nil {
		t.Fatal(err)
	}
	if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatalf("unreviewed tombstone released held authority: %v", err)
	}
	entry, err := kv.Get(t.Context(), "retired.sjc.node-a")
	if err != nil || !bytes.Equal(entry.Value(), foreign) {
		t.Fatalf("foreign cell key changed: %v", err)
	}
	if _, err := kv.Get(t.Context(), "retired.gru.omitted"); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("inventory check modified unreviewed tombstone: %v", err)
	}
}
