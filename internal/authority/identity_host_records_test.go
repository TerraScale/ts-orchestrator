package authority

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type pinnedHostRecord struct {
	pin   IdentityResetRecord
	value []byte
}

func addIdentityHostRecords(t *testing.T, f *identityRecordsFixture) {
	t.Helper()
	for _, bucket := range []string{"TS_HOST_STATE", "TS_HOST_ENROLLMENT"} {
		kv, err := f.js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: bucket, History: 8, Replicas: f.target.Replicas, Storage: jetstream.FileStorage})
		if err != nil {
			t.Fatal(err)
		}
		f.buckets[bucket] = kv
	}
	var additions []pinnedHostRecord
	add := func(action IdentityResetAction, bucket, key string, value []byte, present bool) {
		pin := IdentityResetRecord{Action: action, Bucket: bucket, Key: key}
		if action != IdentityResetDeleteKV {
			pin.SHA256 = resetDigest(value)
		}
		if present {
			old := []byte("opaque obsolete host identity; not JSON")
			if bucket == ControlStreamName {
				ack, err := f.js.Publish(t.Context(), key, old)
				if err != nil {
					t.Fatal(err)
				}
				pin.PreviousRevision = ack.Sequence
				f.reset.LastSequence = ack.Sequence
			} else {
				revision, err := f.buckets[bucket].Put(t.Context(), key, old)
				if err != nil {
					t.Fatal(err)
				}
				pin.PreviousRevision = revision
			}
			pin.PreviousSHA256 = resetDigest(old)
		}
		additions = append(additions, pinnedHostRecord{pin, value})
	}
	for _, kind := range []HostMutationKind{MutationRegistration, MutationDesired, MutationRetirement} {
		key := "gru.ts-gru-2"
		if kind == MutationDesired {
			key += ".terrabase"
		}
		payload := []byte(`{"retired":false}`)
		if kind == MutationRegistration {
			payload = []byte(`{"node":"ts-gru-2"}`)
		}
		if kind == MutationDesired {
			payload = []byte(`{"withdrawn":true}`)
		}
		wire, err := jsonMarshal(controlRecord{Version: 1, Kind: kind, Scope: "gru", SubjectKey: key, OperationID: entityid.Derive("host-mutation", resetDigest(payload)), Epoch: f.reset.Epoch, Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		add(IdentityResetAppendHostHead, ControlStreamName, mutationSubject("gru", kind, key), wire, kind != MutationRetirement)
	}
	add(IdentityResetDeleteKV, "TS_HOST_STATE", "session.gru.ts-gru-2", nil, true)
	add(IdentityResetDeleteKV, "TS_HOST_STATE", "report.gru.ts-gru-2.terrabase", nil, false)
	add(IdentityResetDeleteKV, "TS_HOST_ENROLLMENT", resetDigest([]byte("instance")), nil, true)
	add(IdentityResetReplaceKV, "TS_HOST_ENROLLMENT", entityid.Derive("host-enrollment", "instance"), []byte(`{"schema_version":1}`), true)
	add(IdentityResetReplaceKV, "TS_HOST_STATE", entityid.Derive("terrabase-format", "gru", "ts-gru-2", "volume"), []byte(`{"uuid":"12345678-1234-1234-1234-000000000001"}`), false)
	slices.SortFunc(additions, func(a, b pinnedHostRecord) int {
		return strings.Compare(a.pin.Bucket+"/"+a.pin.Key, b.pin.Bucket+"/"+b.pin.Key)
	})
	for _, addition := range additions {
		f.reset.Records = append(f.reset.Records, addition.pin)
		f.values = append(f.values, addition.value)
	}
	f.envelope = signIdentityResetForTest(t, f.reset, f.key)
}

func newIdentityHostRecordsFixture(t *testing.T) *identityRecordsFixture {
	t.Helper()
	f := newIdentityRecordsFixture(t, 8)
	addIdentityHostRecords(t, f)
	return f
}

func assertIdentityHostRecords(t *testing.T, f *identityRecordsFixture, revisions []uint64) {
	t.Helper()
	if len(revisions) != len(f.reset.Records) {
		t.Fatalf("revisions: %v", revisions)
	}
	reader, err := identityRecordReader(f.js)
	if err != nil {
		t.Fatal(err)
	}
	for i, record := range f.reset.Records {
		msg, err := heldIdentityRecordReader(f.js, reader, f.reset, record, resetDigest(f.envelope.Payload), f.target.Replicas)(t.Context())
		if err != nil || !identityRecordComplete(record, msg, resetDigest(f.envelope.Payload)) || msg.Sequence != revisions[i] {
			t.Fatalf("record %s/%s: %+v, %v", record.Bucket, record.Key, msg, err)
		}
		if record.Action == IdentityResetAppendHostHead && record.PreviousRevision != 0 {
			stream, err := f.js.Stream(t.Context(), ControlStreamName)
			if err != nil {
				t.Fatal(err)
			}
			prior, err := stream.GetMsg(t.Context(), record.PreviousRevision)
			if err != nil || resetDigest(prior.Data) != record.PreviousSHA256 {
				t.Fatalf("host audit predecessor lost: %v", err)
			}
		}
	}
}

func TestIdentityHostRecordsHoldPartialHeadAndResolveLostReplies(t *testing.T) {
	f := newIdentityHostRecordsFixture(t)
	f.barrier(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	wrapped := &identityRecordPublisher{JetStream: f.js}
	stopped := false
	wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		ack, err := f.js.PublishMsg(ctx, msg, opts...)
		if err == nil && strings.HasPrefix(msg.Subject, "ts.control.gru.host.") && !stopped {
			stopped = true
			cancel()
		}
		return ack, err
	}
	if _, err := f.replace(t, wrapped, ctx); !errors.Is(err, context.Canceled) || !stopped {
		t.Fatalf("partial host head: %v", err)
	}
	if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err == nil {
		t.Fatal("partial host head released hold")
	}
	runtime, err := Start(t.Context(), f.js, Config{Scope: "gru", DeploymentID: f.reset.DeploymentID, CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	runtime.cancel()
	<-runtime.done
	t.Cleanup(func() { _ = runtime.Close() })
	if runtime.Current().CanMutate() || runtime.Current().Reason != "identity-reset-pending" {
		t.Fatalf("partial reset authority: %+v", runtime.Current())
	}
	wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		ack, err := f.js.PublishMsg(ctx, msg, opts...)
		if err != nil {
			return ack, err
		}
		return nil, jetstream.ErrNoStreamResponse
	}
	revisions, err := f.replace(t, wrapped, t.Context())
	if err != nil {
		t.Fatal(err)
	}
	assertIdentityHostRecords(t, f, revisions)
	// An unrelated same-cell control subject between barrier/completion is legitimate.
	if _, err := f.js.Publish(t.Context(), "ts.control.gru.audit.test", []byte("unrelated")); err != nil {
		t.Fatal(err)
	}
	completed, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.reconcile(t.Context()); err != nil || !runtime.Current().CanMutate() {
		t.Fatalf("complete reset did not acquire: %+v, %v", runtime.Current(), err)
	}
	retry, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now())
	if err != nil || retry != completed {
		t.Fatalf("immutable completion retry: %d, %v", retry, err)
	}
}

func TestIdentityHostRecordsResumeEveryCommittedBoundary(t *testing.T) {
	// 3 singleton purge/create pairs, 3 heads, 3 deletes, one grant purge/create, one closed proof create.
	for boundary := 1; boundary <= 15; boundary++ {
		t.Run(fmt.Sprint(boundary), func(t *testing.T) {
			f := newIdentityHostRecordsFixture(t)
			f.barrier(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			wrapped := &identityRecordPublisher{JetStream: f.js}
			wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
				ack, err := f.js.PublishMsg(ctx, msg, opts...)
				if err == nil {
					calls++
					if calls == boundary {
						cancel()
					}
				}
				return ack, err
			}
			if _, err := f.replace(t, wrapped, ctx); !errors.Is(err, context.Canceled) || calls != boundary {
				t.Fatalf("boundary %d calls %d: %v", boundary, calls, err)
			}
			revisions, err := f.replace(t, f.js, t.Context())
			if err != nil {
				t.Fatal(err)
			}
			assertIdentityHostRecords(t, f, revisions)
			retry, err := f.replace(t, f.js, t.Context())
			if err != nil || !slices.Equal(retry, revisions) {
				t.Fatalf("resume rewrote records: %v, %v", retry, err)
			}
			if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIdentityHostRecordsDeletionRequiresPositiveOwnTombstone(t *testing.T) {
	for _, mode := range []string{"absent", "foreign purge", "foreign delete", "purge with data"} {
		t.Run(mode, func(t *testing.T) {
			f := newIdentityHostRecordsFixture(t)
			f.barrier(t)
			revisions, err := f.replace(t, f.js, t.Context())
			if err != nil {
				t.Fatal(err)
			}
			index := slices.IndexFunc(f.reset.Records, func(r IdentityResetRecord) bool { return r.Key == "report.gru.ts-gru-2.terrabase" })
			record := f.reset.Records[index]
			if record.PreviousRevision != 0 || revisions[index] == 0 {
				t.Fatal("explicit absence did not produce positive tombstone")
			}
			if mode == "absent" {
				stream, err := f.js.Stream(t.Context(), "KV_"+record.Bucket)
				if err != nil {
					t.Fatal(err)
				}
				if err := stream.Purge(t.Context(), jetstream.WithPurgeSubject(identityRecordSubject(record))); err != nil {
					t.Fatal(err)
				}
			} else {
				msg := nats.NewMsg(identityRecordSubject(record))
				msg.Header.Set("KV-Operation", "PURGE")
				msg.Header.Set(nats.MsgRollup, nats.MsgRollupSubject)
				if mode == "foreign delete" {
					msg.Header.Set("KV-Operation", "DEL")
				}
				if mode == "purge with data" {
					msg.Header.Set(rekeyPinsHeader, resetDigest(f.envelope.Payload))
					msg.Data = []byte("not a tombstone")
				}
				if _, err := f.js.PublishMsg(t.Context(), msg); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err == nil {
				t.Fatal("false absence/tombstone completed reset")
			}
			if mode != "absent" {
				if _, err := f.replace(t, f.js, t.Context()); !errors.Is(err, ErrConflict) {
					t.Fatalf("foreign tombstone accepted for resume: %v", err)
				}
			}
		})
	}
}

func TestIdentityHostRecordsRejectMissingPlanActionAndUnknownDestinations(t *testing.T) {
	f := newIdentityHostRecordsFixture(t)
	for _, mutate := range []func(*IdentityReset){
		func(r *IdentityReset) { r.HostStatePlanSHA256 = "" },
		func(r *IdentityReset) { r.Records[0].Action = "" },
		func(r *IdentityReset) { r.Records[3].Action = "" },
		func(r *IdentityReset) { r.Records[3].Key = "ts.control.gru.placement.intent.a.b" },
		func(r *IdentityReset) { r.Records[3].Key = "ts.control.sfo.host.registration.gru.ts-gru-2" },
		func(r *IdentityReset) { r.Records[3].Key = "ts.control.gru.host.registration.sfo.ts-gru-2" },
		func(r *IdentityReset) { r.Records[3].Bucket = "ARBITRARY" },
		func(r *IdentityReset) {
			r.Records[3].Bucket = "TS_HOST_STATE"
			r.Records[3].Action = IdentityResetDeleteKV
			r.Records[3].SHA256 = ""
			r.Records[3].Key = "format.gru.ts-gru-2"
		},
		func(r *IdentityReset) { r.Records = append(r.Records, r.Records[3]) },
	} {
		reset := f.reset
		reset.Records = slices.Clone(reset.Records)
		mutate(&reset)
		if err := reset.Validate(); err == nil {
			t.Fatalf("invalid root contract admitted: %+v", reset)
		}
	}
	for _, pin := range []string{"", strings.Repeat("b", 64)} {
		target := f.target
		target.HostStatePlanSHA256 = pin
		if _, err := ResetIdentityLease(t.Context(), f.js, f.envelope, f.roots, target, time.Now()); !errors.Is(err, trust.ErrScopeMismatch) {
			t.Fatalf("wrong plan target: %v", err)
		}
	}
	f.barrier(t)
	values := slices.Clone(f.values)
	values[3] = []byte("wrong current head")
	if _, err := ReplaceIdentityRecords(t.Context(), &identityRecordPublisher{JetStream: f.js, publish: func(context.Context, *nats.Msg, ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		t.Fatal("wrong head caused effects")
		return nil, nil
	}}, f.envelope, f.roots, f.target, values, time.Now()); err == nil {
		t.Fatal("wrong head bytes admitted")
	}
}

func TestIdentityHostRecordInFlightAppendCannotOverwriteCompletion(t *testing.T) {
	f := newIdentityHostRecordsFixture(t)
	f.barrier(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	paused, resume := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	wrapped := &identityRecordPublisher{JetStream: f.js}
	wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		if msg.Subject == f.reset.Records[3].Key {
			close(paused)
			select {
			case <-resume:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return f.js.PublishMsg(ctx, msg, opts...)
	}
	go func() { _, err := f.replace(t, wrapped, ctx); result <- err }()
	select {
	case <-paused:
	case err := <-result:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := f.replace(t, f.js, ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := CompleteIdentityReset(ctx, f.js, f.envelope, f.roots, f.target, time.Now()); err != nil {
		t.Fatal(err)
	}
	runtime, err := Start(ctx, f.js, Config{Scope: "gru", DeploymentID: f.reset.DeploymentID, CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	runtime.cancel()
	<-runtime.done
	t.Cleanup(func() { _ = runtime.Close() })
	if !runtime.Current().CanMutate() {
		t.Fatal("ordinary authority failed after completion")
	}
	payload := []byte(`{"withdrawn":true,"generation":100}`)
	advanced, err := runtime.CommitHostMutation(ctx, runtime.Current().Epoch, MutationDesired, "gru.ts-gru-2.terrabase", entityid.New(), f.reset.LastSequence+2, payload)
	if err != nil {
		t.Fatal(err)
	}
	close(resume)
	select {
	case err := <-result:
		if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrFenced) {
			t.Fatalf("stale append: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	stream, err := f.js.Stream(ctx, ControlStreamName)
	if err != nil {
		t.Fatal(err)
	}
	head, err := stream.GetLastMsgForSubject(ctx, f.reset.Records[3].Key)
	if err != nil || head.Sequence != advanced {
		t.Fatalf("completed host head overwritten: %+v, %v", head, err)
	}
}

func newIdentityHostR3(t *testing.T) (jetstream.JetStream, []*server.Server) {
	t.Helper()
	var servers []*server.Server
	for index := range 3 {
		routeAddress := "nats-route://127.0.0.1:1"
		if index != 0 {
			routeAddress = "nats-route://" + servers[0].ClusterAddr().String()
		}
		route, err := url.Parse(routeAddress)
		if err != nil {
			t.Fatal(err)
		}
		routes := []*url.URL{route}
		for _, peer := range servers {
			if peer == servers[0] {
				continue
			}
			peerRoute, err := url.Parse("nats-route://" + peer.ClusterAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			routes = append(routes, peerRoute)
		}
		srv, err := server.NewServer(&server.Options{ServerName: fmt.Sprintf("identity-r3-%d", index), Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream"), Cluster: server.ClusterOpts{Name: "identity-r3", Host: "127.0.0.1", Port: -1}, Routes: routes})
		if err != nil {
			t.Fatal(err)
		}
		go srv.Start()
		if !srv.ReadyForConnections(5 * time.Second) {
			t.Fatal("routed NATS failed to start")
		}
		servers = append(servers, srv)
		t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		ready := false
		for _, srv := range servers {
			if srv.JetStreamIsLeader() && len(srv.JetStreamClusterPeers()) == 3 {
				ready = true
			}
		}
		for _, srv := range servers {
			routeInfo, err := srv.Routez(nil)
			if err != nil {
				t.Fatal(err)
			}
			remoteIDs := map[string]bool{}
			for _, route := range routeInfo.Routes {
				remoteIDs[route.RemoteID] = true
			}
			ready = ready && len(remoteIDs) == 2 && srv.JetStreamIsCurrent()
		}
		if ready && servers[0].JetStreamIsCurrent() {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("R3 metadata did not form: ", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	conn, err := nats.Connect(servers[0].ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return js, servers
}

func TestIdentityHostRecordsR3HeldResumeAfterLeaderLoss(t *testing.T) {
	js, servers := newIdentityHostR3(t)
	f := newIdentityRecordsFixtureWithJetStream(t, 8, js, 3)
	addIdentityHostRecords(t, f)
	f.barrier(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stopped := false
	wrapped := &identityRecordPublisher{JetStream: js}
	wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		ack, err := js.PublishMsg(ctx, msg, opts...)
		if err == nil && !stopped && msg.Subject == f.reset.Records[3].Key {
			stopped = true
			cancel()
		}
		return ack, err
	}
	if _, err := f.replace(t, wrapped, ctx); !errors.Is(err, context.Canceled) || !stopped {
		t.Fatalf("R3 partial boundary: %v", err)
	}
	stream, err := js.Stream(t.Context(), ControlStreamName)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(t.Context())
	if err != nil || info.Config.Replicas != 3 || info.Cluster == nil || len(info.Cluster.Replicas) != 2 {
		t.Fatalf("not real R3: %+v, %v", info, err)
	}
	lostLeader := info.Cluster.Leader
	names := []string{ControlStreamName, "KV_TS_SERVICE_SET", "KV_TS_TRUST_ROOTS", "KV_TS_HOST_STATE", "KV_TS_HOST_ENROLLMENT"}
	settled, settleCancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer settleCancel()
	for {
		ready := true
		for _, name := range names {
			attempt, attemptCancel := context.WithTimeout(settled, authorityAPITimeout)
			stream, err := js.Stream(attempt, name)
			var info *jetstream.StreamInfo
			if err == nil {
				info, err = stream.Info(attempt)
			}
			attemptCancel()
			if err != nil {
				ready = false
				break
			}
			if info.Cluster == nil || len(info.Cluster.Replicas) != 2 {
				ready = false
				break
			}
			for _, replica := range info.Cluster.Replicas {
				ready = ready && replica.Current && !replica.Offline && replica.Lag == 0
			}
		}
		if ready {
			break
		}
		select {
		case <-settled.Done():
			t.Fatal(settled.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	var survivor *server.Server
	for _, srv := range servers {
		if srv.Name() == lostLeader {
			srv.Shutdown()
			srv.WaitForShutdown()
		} else {
			survivor = srv
		}
	}
	conn, err := nats.Connect(survivor.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	recovered, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	f.js = recovered
	recovery, cancelRecovery := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancelRecovery()
	for {
		ready := true
		for _, name := range names {
			attempt, attemptCancel := context.WithTimeout(recovery, authorityAPITimeout)
			stream, err = recovered.Stream(attempt, name)
			if err == nil {
				info, err = stream.Info(attempt)
			}
			attemptCancel()
			if err != nil || info.Cluster == nil || info.Cluster.Leader == "" || info.Cluster.Leader == lostLeader {
				ready = false
				break
			}
		}
		if ready {
			break
		}
		select {
		case <-recovery.Done():
			t.Fatal(recovery.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}

	revisions, err := f.replace(t, recovered, recovery)
	if err != nil {
		t.Fatal(err)
	}
	assertIdentityHostRecords(t, f, revisions)
	if _, err := CompleteIdentityReset(recovery, recovered, f.envelope, f.roots, f.target, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, record := range f.reset.Records {
		if record.Action != IdentityResetAppendHostHead {
			stream, err := recovered.Stream(recovery, "KV_"+record.Bucket)
			if err != nil {
				t.Fatal(err)
			}
			info, err := stream.Info(recovery)
			if err != nil || info.Config.Replicas != 3 {
				t.Fatalf("KV lost R3: %+v, %v", info, err)
			}
		}
	}
}

func TestIdentityHostRecordsRejectInvalidCurrentHeadBeforeAnyEffects(t *testing.T) {
	for _, mode := range []string{"scope", "epoch", "subject", "kind", "operation", "version", "unknown field", "noncanonical"} {
		t.Run(mode, func(t *testing.T) {
			f := newIdentityHostRecordsFixture(t)
			head, err := decodeControlRecord(f.values[3])
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "scope":
				head.Scope = "sfo"
			case "epoch":
				head.Epoch++
			case "subject":
				head.SubjectKey = "gru.foreign.terrabase"
			case "kind":
				head.Kind = MutationPlacementIntent
			case "operation":
				head.OperationID = entityid.New()
			case "version":
				head.Version = 2
			}
			wire, err := jsonMarshal(head)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown field" {
				wire = append(wire[:len(wire)-1], []byte(`,"untrusted":true}`)...)
			}
			if mode == "noncanonical" {
				wire = append([]byte(" "), wire...)
			}
			f.values[3] = wire
			f.reset.Records[3].SHA256 = resetDigest(wire)
			f.envelope = signIdentityResetForTest(t, f.reset, f.key)
			f.barrier(t)
			wrapped := &identityRecordPublisher{JetStream: f.js, publish: func(context.Context, *nats.Msg, ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
				t.Fatal("invalid current head changed singleton/host state")
				return nil, nil
			}}
			if _, err := f.replace(t, wrapped, t.Context()); err == nil {
				t.Fatal("invalid canonical v1 head admitted")
			}
		})
	}
}

func TestIdentityHostRecordsRecheckPolicyAtMutationAndReadback(t *testing.T) {
	for _, mode := range []string{"before host mutation", "after KV mutation"} {
		t.Run(mode, func(t *testing.T) {
			f := newIdentityHostRecordsFixture(t)
			f.barrier(t)
			changed := false
			wrapped := &identityRecordPublisher{JetStream: f.js}
			changePolicy := func(ctx context.Context, name string) {
				stream, err := f.js.Stream(ctx, name)
				if err != nil {
					t.Fatal(err)
				}
				info, err := stream.Info(ctx)
				if err != nil {
					t.Fatal(err)
				}
				info.Config.MaxAge = time.Hour
				if _, err := f.js.UpdateStream(ctx, info.Config); err != nil {
					t.Fatal(err)
				}
				changed = true
			}
			wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
				ack, err := f.js.PublishMsg(ctx, msg, opts...)
				if err == nil && !changed {
					if mode == "after KV mutation" {
						changePolicy(ctx, "KV_TS_SERVICE_SET")
					} else if msg.Subject == "$KV.TS_TRUST_ROOTS.material-generations" && msg.Header.Get("KV-Operation") == "" {
						changePolicy(ctx, ControlStreamName)
					}
				}
				return ack, err
			}
			if _, err := f.replace(t, wrapped, t.Context()); err == nil || !changed {
				t.Fatalf("policy change escaped recheck: changed=%v error=%v", changed, err)
			}
			if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err == nil {
				t.Fatal("invalid durable policy completed")
			}
		})
	}
}

func TestIdentityHostCompletionChecksEveryRecord(t *testing.T) {
	for index := range 11 {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			f := newIdentityHostRecordsFixture(t)
			f.barrier(t)
			if _, err := f.replace(t, f.js, t.Context()); err != nil {
				t.Fatal(err)
			}
			record := f.reset.Records[index]
			msg := nats.NewMsg(identityRecordSubject(record))
			msg.Data = []byte("changed after executor readback")
			if _, err := f.js.PublishMsg(t.Context(), msg); err != nil {
				t.Fatal(err)
			}
			if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err == nil {
				t.Fatalf("record %s/%s escaped completion", record.Bucket, record.Key)
			}
			if sequence, err := IdentityResetCompletion(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err != nil || sequence != 0 {
				t.Fatalf("corrupt record released hold: sequence=%d err=%v", sequence, err)
			}
		})
	}
}

type identityHostInfoStream struct {
	jetstream.Stream
	inspect func(context.Context, ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error)
}

func (s *identityHostInfoStream) Info(ctx context.Context, opts ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error) {
	return s.inspect(ctx, opts...)
}

type identityHostInfoJetStream struct {
	jetstream.JetStream
	open func(context.Context, string) (jetstream.Stream, error)
}

func (js *identityHostInfoJetStream) Stream(ctx context.Context, name string) (jetstream.Stream, error) {
	return js.open(ctx, name)
}

func TestIdentityHostCompletionFencesHeadChangedAfterItsRead(t *testing.T) {
	f := newIdentityHostRecordsFixture(t)
	f.barrier(t)
	if _, err := f.replace(t, f.js, t.Context()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	changed := false
	wrapped := &identityHostInfoJetStream{JetStream: f.js}
	wrapped.open = func(ctx context.Context, name string) (jetstream.Stream, error) {
		stream, err := f.js.Stream(ctx, name)
		if err != nil || name != ControlStreamName {
			return stream, err
		}
		return &identityHostInfoStream{Stream: stream, inspect: func(ctx context.Context, opts ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error) {
			calls++
			// Completion outcome, initial hold, snapshot, three singleton holds,
			// first host head hold, then the next hold after the first head was read.
			if calls == 8 {
				if _, err := f.js.Publish(ctx, f.reset.Records[3].Key, []byte("concurrent changed host head")); err != nil {
					return nil, err
				}
				changed = true
			}
			return stream.Info(ctx, opts...)
		}}, nil
	}
	if _, err := CompleteIdentityReset(t.Context(), wrapped, f.envelope, f.roots, f.target, time.Now()); !errors.Is(err, ErrConflict) || !changed {
		t.Fatalf("completion crossed changed host head: changed=%v err=%v", changed, err)
	}
	if sequence, err := IdentityResetCompletion(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err != nil || sequence != 0 {
		t.Fatalf("changed head released hold: %d, %v", sequence, err)
	}
}

func TestIdentityHostRecordsOwnCopiesOfValidatedValues(t *testing.T) {
	f := newIdentityHostRecordsFixture(t)
	f.barrier(t)
	original := slices.Clone(f.values)
	wrapped := &identityRecordPublisher{JetStream: f.js}
	changed := false
	wrapped.publish = func(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
		if !changed {
			f.values[1][0] = '!'
			f.values[3] = []byte("changed host value")
			changed = true
		}
		return f.js.PublishMsg(ctx, msg, opts...)
	}
	if _, err := ReplaceIdentityRecords(t.Context(), wrapped, f.envelope, f.roots, f.target, original, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("caller mutation not exercised")
	}
	if _, err := CompleteIdentityReset(t.Context(), f.js, f.envelope, f.roots, f.target, time.Now()); err != nil {
		t.Fatalf("caller mutated root-pinned copy: %v", err)
	}
}
