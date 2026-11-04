package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
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

func TestReplaceIdentityRecordsFencesDelayedOldCASWrites(t *testing.T) {
	for _, history := range []uint8{1} {
		for _, phase := range []string{"PURGE"} {
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
