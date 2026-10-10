package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type identityRecordsFixture struct {
	js       jetstream.JetStream
	reset    IdentityReset
	target   IdentityResetTarget
	roots    trust.Keyring
	key      ed25519.PrivateKey
	envelope trust.Envelope
	values   [][]byte
	buckets  map[string]jetstream.KeyValue
}

func TestCommittedIdentityResetResumesAfterGrantExpiry(t *testing.T) {
	f := newIdentityRecordsFixture(t, 8)
	f.barrier(t)
	ctx, cancel := context.WithCancel(t.Context())
	wrapped := &identityRecordPublisher{JetStream: f.js}
	wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		ack, err := f.js.PublishMsg(ctx, msg, opts...)
		if err == nil {
			cancel()
		}
		return ack, err
	}
	if _, err := f.replace(t, wrapped, ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("partial reset: %v", err)
	}
	expired := f.envelope.ExpiresAt.Add(time.Second)
	if _, err := ResetIdentityLease(t.Context(), f.js, f.envelope, f.roots, f.target, expired); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired initiation admitted: %v", err)
	}
	if committed, err := IdentityResetCommitted(t.Context(), f.js, f.envelope, f.roots, f.target); err != nil || !committed {
		t.Fatalf("original committed authority lost: %t, %v", committed, err)
	}
	revisions, err := ReplaceIdentityRecords(t.Context(), f.js, f.envelope, f.roots, f.target, f.values, expired)
	if err != nil {
		t.Fatal(err)
	}
	f.assertReplaced(t, revisions)
	if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, expired); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityResetCommittedRejectsBarrierOutsideGrantLifetime(t *testing.T) {
	now := time.Now()
	for _, issuance := range []time.Time{now.Add(-2 * time.Hour), now.Add(time.Hour)} {
		f := newIdentityRecordsFixture(t, 8)
		envelope, err := SignIdentityReset(f.reset, issuance, issuance.Add(time.Minute), f.key)
		if err != nil {
			t.Fatal(err)
		}
		barrier, err := identityResetLease(f.reset, resetDigest(envelope.Payload))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.js.Publish(t.Context(), controlSubjectRoot+".gru.lease", barrier); err != nil {
			t.Fatal(err)
		}
		if committed, err := IdentityResetCommitted(t.Context(), f.js, envelope, f.roots, f.target); err == nil || committed {
			t.Fatal("barrier committed outside its signed lifetime authorized recovery")
		}
	}
}

func newIdentityRecordsFixture(t *testing.T, history uint8) *identityRecordsFixture {
	t.Helper()
	return newIdentityRecordsFixtureWithJetStream(t, history, newAuthorityTestJetStream(t), 1)
}

func newIdentityRecordsFixtureWithJetStream(t *testing.T, history uint8, js jetstream.JetStream, replicas int) *identityRecordsFixture {
	t.Helper()
	js, reset, target, roots, key := identityResetFixtureWithJetStream(t, js, replicas)
	f := &identityRecordsFixture{js: js, reset: reset, target: target, roots: roots, key: key,
		buckets: make(map[string]jetstream.KeyValue)}
	for index, record := range f.reset.Records {
		kv := f.buckets[record.Bucket]
		if kv == nil {
			var err error
			kv, err = js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{
				Bucket: record.Bucket, History: history, Replicas: replicas, Storage: jetstream.FileStorage,
			})
			if err != nil {
				t.Fatalf("create %s: %v", record.Bucket, err)
			}
			f.buckets[record.Bucket] = kv
			if _, err := kv.Put(t.Context(), "unrelated", []byte(`{"version":1,"audit":"keep"}`)); err != nil {
				t.Fatalf("put unrelated %s: %v", record.Bucket, err)
			}
		}
		if _, err := kv.Put(t.Context(), record.Key, []byte(`{"version":1,"identity":"superseded"}`)); err != nil {
			t.Fatalf("put predecessor %s/%s: %v", record.Bucket, record.Key, err)
		}
		old := fmt.Appendf(nil, `{"version":1,"obsolete_identity":%d}`, index)
		revision, err := kv.Put(t.Context(), record.Key, old)
		if err != nil {
			t.Fatal(err)
		}
		value := fmt.Appendf(nil, `{"version":1,"replacement_identity":%d}`, index)
		f.values = append(f.values, value)
		f.reset.Records[index].PreviousRevision = revision
		f.reset.Records[index].PreviousSHA256 = resetDigest(old)
		f.reset.Records[index].SHA256 = resetDigest(value)
	}
	ack, err := js.Publish(t.Context(), controlSubjectRoot+".gru.audit.test", []byte(`{"version":1,"history":"keep"}`))
	if err != nil {
		t.Fatal(err)
	}
	f.reset.LastSequence = ack.Sequence
	f.envelope = signIdentityResetForTest(t, f.reset, f.key)
	return f
}

func (f *identityRecordsFixture) barrier(t *testing.T) uint64 {
	t.Helper()
	sequence, err := ResetIdentityLease(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return sequence
}

func (f *identityRecordsFixture) replace(t *testing.T, js jetstream.JetStream, ctx context.Context) ([]uint64, error) {
	t.Helper()
	return ReplaceIdentityRecords(ctx, js, f.envelope, f.roots, f.target, f.values, time.Now())
}

func (f *identityRecordsFixture) last(t *testing.T, index int) *nats.RawStreamMsg {
	t.Helper()
	reader, err := f.js.Conn().JetStream()
	if err != nil {
		t.Fatal(err)
	}
	record := f.reset.Records[index]
	msg, err := reader.GetLastMsg("KV_"+record.Bucket, "$KV."+record.Bucket+"."+record.Key, nats.Context(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func (f *identityRecordsFixture) assertReplaced(t *testing.T, revisions []uint64) {
	t.Helper()
	if len(revisions) != 3 {
		t.Fatalf("replacement revisions = %v, want exactly three", revisions)
	}
	reader, err := f.js.Conn().JetStream()
	if err != nil {
		t.Fatal(err)
	}
	for index, record := range f.reset.Records {
		msg := f.last(t, index)
		if msg.Sequence != revisions[index] || msg.Sequence <= record.PreviousRevision ||
			!bytes.Equal(msg.Data, f.values[index]) || msg.Header.Get("KV-Operation") != "" ||
			msg.Header.Get(rekeyPinsHeader) != resetDigest(f.envelope.Payload) {
			t.Fatalf("replacement %s/%s lost bytes, revision or root pin: %+v", record.Bucket, record.Key, msg)
		}
		for _, sequence := range []uint64{record.PreviousRevision - 1, record.PreviousRevision} {
			if _, err := reader.GetMsg("KV_"+record.Bucket, sequence, nats.Context(t.Context())); !errors.Is(err, nats.ErrMsgNotFound) {
				t.Fatalf("obsolete %s/%s revision %d remains readable: %v", record.Bucket, record.Key, sequence, err)
			}
		}
		entry, err := f.buckets[record.Bucket].Get(t.Context(), "unrelated")
		if err != nil || string(entry.Value()) != `{"version":1,"audit":"keep"}` {
			t.Fatalf("exact-key purge affected unrelated %s entry: %v", record.Bucket, err)
		}
	}
	for bucket, kv := range f.buckets {
		keys, err := kv.Keys(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"current", "unrelated"}
		if bucket == "TS_TRUST_ROOTS" {
			want = []string{"chain", "material-generations", "unrelated"}
		}
		slices.Sort(keys)
		if !slices.Equal(keys, want) {
			t.Fatalf("replacement added migration keys in %s: %v, want %v", bucket, keys, want)
		}
	}
}

type identityRecordPublisher struct {
	jetstream.JetStream
	publish func(context.Context, *nats.Msg, ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

func (js *identityRecordPublisher) PublishMsg(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	return js.publish(ctx, msg, opts...)
}

func TestReplaceIdentityRecordsPurgesCurrentKeysAndPreservesHistory(t *testing.T) {
	for _, history := range []uint8{1, 8, 64} {
		t.Run(fmt.Sprintf("history-%d", history), func(t *testing.T) {
			f := newIdentityRecordsFixture(t, history)
			barrier := f.barrier(t)
			revisions, err := f.replace(t, f.js, t.Context())
			if err != nil {
				t.Fatal(err)
			}
			f.assertReplaced(t, revisions)
			for _, record := range f.reset.Records {
				entries, err := f.buckets[record.Bucket].History(t.Context(), record.Key)
				want := 2
				if history == 1 {
					want = 1
				}
				if err != nil || len(entries) != want {
					t.Fatalf("%s/%s history = %v, %v; want %d purge/create records", record.Bucket, record.Key, entries, err, want)
				}
				if entries[len(entries)-1].Operation() != jetstream.KeyValuePut || want == 2 && entries[0].Operation() != jetstream.KeyValuePurge {
					t.Fatalf("obsolete identity was updated without PURGE: %v", entries)
				}
			}
			stream, err := f.js.Stream(t.Context(), ControlStreamName)
			if err != nil {
				t.Fatal(err)
			}
			info, err := stream.Info(t.Context())
			if err != nil || info.State.LastSeq != barrier || info.State.Msgs != barrier {
				t.Fatalf("identity record replacement changed immutable history: %+v, %v", info, err)
			}
			old, err := stream.GetMsg(t.Context(), f.reset.PreviousSequence)
			if err != nil || resetDigest(old.Data) != f.reset.PreviousSHA256 {
				t.Fatalf("old lease audit bytes lost: %v", err)
			}
			audit, err := stream.GetMsg(t.Context(), f.reset.LastSequence)
			if err != nil || string(audit.Data) != `{"version":1,"history":"keep"}` {
				t.Fatalf("non-lease history lost: %v", err)
			}
			retry, err := f.replace(t, f.js, t.Context())
			if err != nil || !slices.Equal(retry, revisions) {
				t.Fatalf("exact retry rewrote completed records: %v, %v", retry, err)
			}
			if sequence, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err != nil || sequence <= barrier {
				t.Fatalf("complete verified replacements: sequence=%d, error=%v", sequence, err)
			}
		})
	}
}

func TestReplaceIdentityRecordsResumesAfterCommittedPurgeOrCreate(t *testing.T) {
	for _, history := range []uint8{1, 8} {
		for _, phase := range []string{"PURGE", ""} {
			t.Run(fmt.Sprintf("history-%d/operation-%q", history, phase), func(t *testing.T) {
				f := newIdentityRecordsFixture(t, history)
				f.barrier(t)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var checkpoint uint64
				wrapped := &identityRecordPublisher{JetStream: f.js}
				wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
					ack, err := f.js.PublishMsg(ctx, msg, opts...)
					if err == nil && checkpoint == 0 && msg.Header.Get("KV-Operation") == phase {
						checkpoint = ack.Sequence
						cancel()
					}
					return ack, err
				}
				if _, err := f.replace(t, wrapped, ctx); !errors.Is(err, context.Canceled) {
					t.Fatalf("interrupted replacement = %v, want canceled", err)
				}
				partial := f.last(t, 0)
				if checkpoint == 0 || partial.Sequence != checkpoint || partial.Header.Get("KV-Operation") != phase {
					t.Fatalf("crash did not leave its committed %q boundary: %+v", phase, partial)
				}
				if phase == "PURGE" {
					if _, err := f.buckets["TS_SERVICE_SET"].Get(t.Context(), "current"); !errors.Is(err, jetstream.ErrKeyNotFound) {
						t.Fatalf("PURGE left current identity visible: %v", err)
					}
				}
				if untouched := f.last(t, 1); untouched.Sequence != f.reset.Records[1].PreviousRevision {
					t.Fatal("canceled replacement proceeded to the next key")
				}
				if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err == nil {
					t.Fatal("completion released authority with partial replacements")
				}
				config := Config{Scope: f.target.Scope, DeploymentID: f.target.DeploymentID, CandidateID: entityid.New(), Replicas: 1}
				blocked, err := Start(t.Context(), f.js, config)
				if err != nil {
					t.Fatal(err)
				}
				blocked.cancel()
				<-blocked.done
				t.Cleanup(func() { _ = blocked.Close() })
				if current := blocked.Current(); current.Ready || current.CanMutate() || current.Reason != "identity-reset-pending" {
					t.Fatalf("runtime acquired while identity replacement was partial: %+v", current)
				}
				revisions, err := f.replace(t, f.js, t.Context())
				if err != nil {
					t.Fatal(err)
				}
				f.assertReplaced(t, revisions)
				if phase == "" && revisions[0] != checkpoint {
					t.Fatalf("resume rewrote an already-created record: %v, checkpoint %d", revisions, checkpoint)
				}
				if err := blocked.reconcile(t.Context()); err != nil || blocked.Current().CanMutate() {
					t.Fatalf("runtime acquired before explicit completion: %+v, %v", blocked.Current(), err)
				}
				if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err != nil {
					t.Fatal(err)
				}
				if err := blocked.reconcile(t.Context()); err != nil || !blocked.Current().CanMutate() || blocked.Current().Epoch <= f.reset.Epoch {
					t.Fatalf("completed reset did not release newer authority: %+v, %v", blocked.Current(), err)
				}
			})
		}
	}
}

func TestReplaceIdentityRecordsResolvesLostPublishResponses(t *testing.T) {
	f := newIdentityRecordsFixture(t, 8)
	f.barrier(t)
	calls := 0
	wrapped := &identityRecordPublisher{JetStream: f.js}
	wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		ack, err := f.js.PublishMsg(ctx, msg, opts...)
		if err != nil {
			return ack, err
		}
		calls++
		return nil, jetstream.ErrNoStreamResponse
	}
	revisions, err := f.replace(t, wrapped, t.Context())
	if err != nil || calls != 6 {
		t.Fatalf("lost purge/create replies were not resolved: revisions=%v, calls=%d, error=%v", revisions, calls, err)
	}
	f.assertReplaced(t, revisions)
}

func TestReplaceIdentityRecordsRefusesForeignOrIncompleteProofMarkers(t *testing.T) {
	for _, name := range []string{"unmarked create", "foreign create", "foreign purge", "wrong bytes"} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityRecordsFixture(t, 8)
			f.barrier(t)
			msg := nats.NewMsg("$KV.TS_SERVICE_SET.current")
			msg.Data = f.values[0]
			switch name {
			case "foreign create", "foreign purge":
				msg.Header.Set(rekeyPinsHeader, strings.Repeat("0", 64))
			case "wrong bytes":
				msg.Header.Set(rekeyPinsHeader, resetDigest(f.envelope.Payload))
				msg.Data = []byte(`{"version":1,"wrong_identity":true}`)
			}
			if name == "foreign purge" {
				msg.Data = nil
				msg.Header.Set("KV-Operation", "PURGE")
				msg.Header.Set(nats.MsgRollup, nats.MsgRollupSubject)
			}
			ack, err := f.js.PublishMsg(t.Context(), msg, jetstream.WithExpectLastSequencePerSubject(f.reset.Records[0].PreviousRevision))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.replace(t, f.js, t.Context()); !errors.Is(err, ErrConflict) {
				t.Fatalf("%s was mistaken for this operation's checkpoint: %v", name, err)
			}
			if current := f.last(t, 0); current.Sequence != ack.Sequence || !bytes.Equal(current.Data, msg.Data) {
				t.Fatal("refusing a foreign checkpoint overwrote it")
			}
		})
	}
}

func TestReplaceIdentityRecordsDoesNotPurgePredecessorChangedAfterRead(t *testing.T) {
	f := newIdentityRecordsFixture(t, 8)
	f.barrier(t)
	var changed uint64
	wrapped := &identityRecordPublisher{JetStream: f.js}
	wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		if changed == 0 {
			var err error
			changed, err = f.buckets["TS_SERVICE_SET"].Update(ctx, "current", []byte(`{"version":1,"concurrent_identity":true}`), f.reset.Records[0].PreviousRevision)
			if err != nil {
				return nil, err
			}
		}
		return f.js.PublishMsg(ctx, msg, opts...)
	}
	if _, err := f.replace(t, wrapped, t.Context()); !errors.Is(err, ErrConflict) || changed == 0 {
		t.Fatalf("predecessor changed between read and purge was admitted: %v", err)
	}
	if msg := f.last(t, 0); msg.Sequence != changed || string(msg.Data) != `{"version":1,"concurrent_identity":true}` {
		t.Fatalf("CAS purged the concurrent writer's bytes: %+v", msg)
	}
}

func TestPublishIdentityRecordHoldsWhenConfirmationIsUnavailable(t *testing.T) {
	f := newIdentityRecordsFixture(t, 8)
	f.barrier(t)
	msg := nats.NewMsg("$KV.TS_SERVICE_SET.current")
	msg.Header.Set("KV-Operation", "PURGE")
	msg.Header.Set(nats.MsgRollup, nats.MsgRollupSubject)
	msg.Header.Set(rekeyPinsHeader, resetDigest(f.envelope.Payload))
	readErr := errors.New("confirmation connection lost")
	if _, err := publishIdentityRecord(t.Context(), f.js, msg, f.reset.Records[0].PreviousRevision,
		func(context.Context) (*nats.RawStreamMsg, error) { return nil, readErr }); !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, readErr) {
		t.Fatalf("unconfirmed committed purge = %v, want unknown outcome and original read failure", err)
	}
	if current := f.last(t, 0); current.Header.Get("KV-Operation") != "PURGE" {
		t.Fatal("fault did not exercise a committed, unconfirmed purge")
	}
	revisions, err := f.replace(t, f.js, t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.assertReplaced(t, revisions)
}

func TestReplaceIdentityRecordsFencesDelayedOldCASWrites(t *testing.T) {
	for _, history := range []uint8{1, 8} {
		for _, phase := range []string{"PURGE", ""} {
			t.Run(fmt.Sprintf("history-%d/operation-%q", history, phase), func(t *testing.T) {
				f := newIdentityRecordsFixture(t, history)
				f.barrier(t)
				release := make(chan struct{})
				ready := make(chan error, 1)
				result := make(chan error, 1)
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				// Hold a real writer after it has read the old revision, until the
				// reset's PURGE or create has committed at the server.
				go func() {
					entry, err := f.buckets["TS_SERVICE_SET"].Get(ctx, "current")
					ready <- err
					if err != nil {
						return
					}
					select {
					case <-release:
						_, err := f.buckets["TS_SERVICE_SET"].Update(ctx, "current", []byte(`{"version":1,"stale_writer":true}`), entry.Revision())
						result <- err
					case <-ctx.Done():
						result <- ctx.Err()
					}
				}()
				if err := <-ready; err != nil {
					t.Fatal(err)
				}
				armed := true
				var staleErr error
				wrapped := &identityRecordPublisher{JetStream: f.js}
				wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
					ack, err := f.js.PublishMsg(ctx, msg, opts...)
					if err == nil && armed && msg.Header.Get("KV-Operation") == phase {
						armed = false
						close(release)
						select {
						case staleErr = <-result:
						case <-ctx.Done():
							return nil, ctx.Err()
						}
					}
					return ack, err
				}
				revisions, err := f.replace(t, wrapped, ctx)
				if err != nil || armed {
					t.Fatalf("delayed CAS test failed to exercise the boundary: %v", err)
				}
				if !errors.Is(staleErr, jetstream.ErrKeyExists) {
					t.Fatalf("old CAS crossed %q boundary: %v", phase, staleErr)
				}
				f.assertReplaced(t, revisions)
			})
		}
	}
}

func TestReplaceIdentityRecordsRejectsWrongPinsRootAndTarget(t *testing.T) {
	for _, name := range []string{"replacement hash", "predecessor hash", "predecessor revision", "root", "target", "missing value", "v2"} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityRecordsFixture(t, 8)
			switch name {
			case "predecessor hash":
				f.reset.Records[0].PreviousSHA256 = strings.Repeat("0", 64)
			case "predecessor revision":
				f.reset.Records[0].PreviousRevision--
			}
			f.envelope = signIdentityResetForTest(t, f.reset, f.key)
			f.barrier(t)
			switch name {
			case "replacement hash":
				f.values[2] = []byte(`{"version":1,"unpinned":true}`)
			case "root":
				_, other, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				f.envelope = signIdentityResetForTest(t, f.reset, other)
			case "target":
				f.target.ClusterID = entityid.New()
			case "missing value":
				f.values = f.values[:2]
			case "v2":
				f.reset.Version = 2
				payload, err := trust.EncodePayload(f.reset)
				if err != nil {
					t.Fatal(err)
				}
				f.envelope, err = trust.Sign(payload, f.reset.trustScope(), f.envelope.IssuedAt, f.envelope.ExpiresAt, f.key)
				if err != nil {
					t.Fatal(err)
				}
			}
			before := make([]uint64, 3)
			for index := range before {
				before[index] = f.last(t, index).Sequence
			}
			if _, err := f.replace(t, f.js, t.Context()); err == nil {
				t.Fatal("invalid replacement was admitted")
			}
			for index, sequence := range before {
				if after := f.last(t, index); after.Sequence != sequence {
					t.Fatalf("rejected replacement changed record %d: %+v", index, after)
				}
			}
		})
	}
}

func TestReplaceIdentityRecordsRequiresExactReleasedBarrier(t *testing.T) {
	for _, name := range []string{"missing", "acquired", "deployment", "epoch", "operation", "floor", "pin", "plain released"} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityRecordsFixture(t, 8)
			if name != "missing" {
				f.barrier(t)
				stream, err := f.js.Stream(t.Context(), ControlStreamName)
				if err != nil {
					t.Fatal(err)
				}
				msg, err := stream.GetLastMsgForSubject(t.Context(), controlSubjectRoot+".gru.lease")
				if err != nil {
					t.Fatal(err)
				}
				lease, err := decodeLease(msg.Data)
				if err != nil {
					t.Fatal(err)
				}
				switch name {
				case "acquired":
					lease.Released = false
				case "deployment":
					lease.DeploymentID = entityid.New()
				case "epoch":
					lease.Epoch++
				case "operation":
					lease.TransitionID = entityid.New()
				case "pin":
					lease.IdentityResetSHA256 = strings.Repeat("0", 64)
				case "plain released":
					lease.IdentityResetSHA256 = ""
				case "floor":
					f.reset.PreviousSequence = msg.Sequence
					f.reset.LastSequence = msg.Sequence
					f.envelope = signIdentityResetForTest(t, f.reset, f.key)
				}
				if name != "floor" {
					wire, err := jsonMarshal(lease)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := f.js.Publish(t.Context(), msg.Subject, wire, jetstream.WithExpectLastSequence(msg.Sequence)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := f.replace(t, f.js, t.Context()); !errors.Is(err, ErrFenced) {
				t.Fatalf("%s barrier = %v, want fenced", name, err)
			}
			for index, record := range f.reset.Records {
				if msg := f.last(t, index); msg.Sequence != record.PreviousRevision || resetDigest(msg.Data) != record.PreviousSHA256 {
					t.Fatalf("invalid barrier permitted mutation of record %d", index)
				}
			}
		})
	}
}

func TestCompleteIdentityResetRefusesMissingOrUnpinnedRecords(t *testing.T) {
	for _, name := range []string{"obsolete", "missing", "wrong bytes", "wrong proof"} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityRecordsFixture(t, 8)
			barrier := f.barrier(t)
			if name == "missing" {
				stream, err := f.js.Stream(t.Context(), "KV_TS_TRUST_ROOTS")
				if err != nil {
					t.Fatal(err)
				}
				if err := stream.Purge(t.Context(), jetstream.WithPurgeSubject("$KV.TS_TRUST_ROOTS.material-generations")); err != nil {
					t.Fatal(err)
				}
			}
			if name == "wrong bytes" || name == "wrong proof" {
				if _, err := f.replace(t, f.js, t.Context()); err != nil {
					t.Fatal(err)
				}
				msg := nats.NewMsg("$KV.TS_TRUST_ROOTS.material-generations")
				msg.Data = f.values[2]
				msg.Header.Set(rekeyPinsHeader, resetDigest(f.envelope.Payload))
				if name == "wrong bytes" {
					msg.Data = []byte(`{"version":1,"wrong_material":true}`)
				} else {
					msg.Header.Set(rekeyPinsHeader, strings.Repeat("0", 64))
				}
				if _, err := f.js.PublishMsg(t.Context(), msg, jetstream.WithExpectLastSequencePerSubject(f.last(t, 2).Sequence)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err == nil {
				t.Fatal("completion released authority without three exact pinned records")
			}
			stream, err := f.js.Stream(t.Context(), ControlStreamName)
			if err != nil {
				t.Fatal(err)
			}
			info, err := stream.Info(t.Context())
			if err != nil || info.State.LastSeq != barrier {
				t.Fatalf("rejected completion changed immutable lease history: %+v, %v", info, err)
			}
		})
	}
}

func TestCompleteIdentityResetResolvesLostReplyAfterNormalAcquisition(t *testing.T) {
	f := newIdentityRecordsFixture(t, 8)
	barrier := f.barrier(t)
	if _, err := f.replace(t, f.js, t.Context()); err != nil {
		t.Fatal(err)
	}
	var acquired *Runtime
	wrapped := &identityRecordPublisher{JetStream: f.js}
	wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		ack, err := f.js.PublishMsg(ctx, msg, opts...)
		if err != nil {
			return ack, err
		}
		acquired, err = Start(t.Context(), f.js, Config{Scope: f.target.Scope, DeploymentID: f.target.DeploymentID,
			CandidateID: entityid.New(), Replicas: 1})
		if acquired != nil {
			acquired.cancel()
			<-acquired.done
		}
		return nil, errors.Join(jetstream.ErrNoStreamResponse, err)
	}
	t.Cleanup(func() {
		if acquired != nil {
			_ = acquired.Close()
		}
	})
	sequence, err := CompleteIdentityReset(t.Context(), wrapped, f.envelope, f.roots, f.target, time.Now())
	if err != nil || sequence != barrier+1 || acquired == nil || !acquired.Current().CanMutate() {
		t.Fatalf("lost completion reply after acquisition: sequence=%d, acquired=%v, error=%v", sequence, acquired, err)
	}
	// A crash after the readback must also recover the immutable outcome, even
	// after the new deployment has legitimately changed its current records.
	if _, err := f.buckets["TS_SERVICE_SET"].Put(t.Context(), "current", []byte("newer deployment state")); err != nil {
		t.Fatal(err)
	}
	retried, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now())
	if err != nil || retried != sequence {
		t.Fatalf("retry after committed completion: sequence=%d, want=%d, error=%v", retried, sequence, err)
	}
}

func TestCompleteIdentityResetRejectsBucketExpiryIntroducedAfterReplacement(t *testing.T) {
	f := newIdentityRecordsFixture(t, 8)
	barrier := f.barrier(t)
	if _, err := f.replace(t, f.js, t.Context()); err != nil {
		t.Fatal(err)
	}
	stream, err := f.js.Stream(t.Context(), "KV_TS_TRUST_ROOTS")
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	config := info.Config
	config.MaxAge = time.Hour
	if _, err := f.js.UpdateStream(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err == nil {
		t.Fatal("completion released normal authority with expiring identity records")
	}
	control, err := f.js.Stream(t.Context(), ControlStreamName)
	if err != nil {
		t.Fatal(err)
	}
	state, err := control.Info(t.Context())
	if err != nil || state.State.LastSeq != barrier {
		t.Fatalf("unsafe completion changed the immutable lease: %+v, %v", state, err)
	}
	msg, err := control.GetLastMsgForSubject(t.Context(), controlSubjectRoot+".gru.lease")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := decodeLease(msg.Data)
	if err != nil || !lease.Released || lease.IdentityResetSHA256 != resetDigest(f.envelope.Payload) || msg.Sequence != barrier {
		t.Fatalf("bucket policy failure removed the root reset hold: %+v, %v", lease, err)
	}
}

func TestIdentityResetCompletionRequiresItsCommittedBarrierAndCompletion(t *testing.T) {
	f := newIdentityRecordsFixture(t, 8)
	for _, phase := range []string{"before-barrier", "held", "records-replaced"} {
		t.Run(phase, func(t *testing.T) {
			if sequence, err := IdentityResetCompletion(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err != nil || sequence != 0 {
				t.Fatalf("uncommitted outcome: sequence=%d, error=%v", sequence, err)
			}
		})
		switch phase {
		case "before-barrier":
			f.barrier(t)
		case "held":
			if _, err := f.replace(t, f.js, t.Context()); err != nil {
				t.Fatal(err)
			}
		}
	}
	// An unrelated append cannot masquerade as this operation's completion.
	if _, err := f.js.Publish(t.Context(), controlSubjectRoot+".sfo.lease", []byte("another scope")); err != nil {
		t.Fatal(err)
	}
	wire, err := identityResetLease(f.reset, "")
	if err != nil {
		t.Fatal(err)
	}
	wire = bytes.Replace(wire, []byte(f.reset.DeploymentID), []byte(entityid.New()), 1)
	if _, err := f.js.Publish(t.Context(), controlSubjectRoot+".gru.lease", wire); err != nil {
		t.Fatal(err)
	}
	if _, err := IdentityResetCompletion(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign lease accepted as completion: %v", err)
	}
}

func TestReplaceIdentityRecordsInFlightCreateCannotOverwriteCompletedDeployment(t *testing.T) {
	f := newIdentityRecordsFixture(t, 1)
	f.barrier(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	paused := make(chan struct{})
	resume := make(chan struct{})
	result := make(chan error, 1)
	wrapped := &identityRecordPublisher{JetStream: f.js}
	wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		if msg.Subject == "$KV.TS_SERVICE_SET.current" && msg.Header.Get("KV-Operation") == "" {
			close(paused)
			select {
			case <-resume:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return f.js.PublishMsg(ctx, msg, opts...)
	}
	go func() {
		_, err := ReplaceIdentityRecords(ctx, wrapped, f.envelope, f.roots, f.target, f.values, time.Now())
		result <- err
	}()
	select {
	case <-paused:
	case err := <-result:
		t.Fatalf("delayed writer failed before its create boundary: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	revisions, err := f.replace(t, f.js, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompleteIdentityReset(ctx, f.js, f.envelope, f.roots, f.target, time.Now()); err != nil {
		t.Fatal(err)
	}
	runtime, err := Start(ctx, f.js, Config{Scope: f.target.Scope, DeploymentID: f.target.DeploymentID,
		CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	runtime.cancel()
	<-runtime.done
	t.Cleanup(func() { _ = runtime.Close() })
	if !runtime.Current().CanMutate() {
		t.Fatalf("normal deployment did not acquire after completion: %+v", runtime.Current())
	}
	current := []byte(`{"version":1,"normal_controller":"advanced"}`)
	advanced, err := f.buckets["TS_SERVICE_SET"].Update(ctx, "current", current, revisions[0])
	if err != nil {
		t.Fatal(err)
	}
	close(resume)
	select {
	case err := <-result:
		if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrFenced) {
			t.Fatalf("delayed rekey create after completion = %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := f.replace(t, f.js, ctx); !errors.Is(err, ErrFenced) {
		t.Fatalf("completed reset envelope could run again: %v", err)
	}
	for index, sequence := range []uint64{advanced, revisions[1], revisions[2]} {
		if stored := f.last(t, index); stored.Sequence != sequence || index == 0 && !bytes.Equal(stored.Data, current) {
			t.Fatalf("delayed rekey overwrote completed record %d: %+v", index, stored)
		}
	}
}

func TestReplaceIdentityRecordsUsesLeaderReadsWhenKVDirectReadsEnabled(t *testing.T) {
	f := newIdentityRecordsFixture(t, 8)
	f.barrier(t)
	leader, err := f.js.Conn().SubscribeSync("$JS.API.STREAM.MSG.GET.>")
	if err != nil {
		t.Fatal(err)
	}
	defer leader.Unsubscribe()
	direct, err := f.js.Conn().SubscribeSync("$JS.API.DIRECT.GET.>")
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Unsubscribe()
	if err := f.js.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.replace(t, f.js, t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := f.js.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	pending, _, err := leader.Pending()
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	for range pending {
		msg, err := leader.NextMsg(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(msg.Subject, "$JS.API.STREAM.MSG.GET.KV_") {
			reads++
		}
	}
	if pending, _, err := direct.Pending(); err != nil || pending != 0 || reads < 9 {
		t.Fatalf("replacement did not confirm each boundary through the leader: leader reads=%d, direct reads=%d, error=%v", reads, pending, err)
	}
}
