package reaper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
)

func reaperTestState() State {
	return State{Version: 1, Cursor: "page-2", Entries: map[string]Entry{"db-1": {DatabaseID: "db-1", Plan: PlanFree, Phase: PhaseActive, LastRequest: time.Now().UTC().Add(-DefaultPauseAfter), Operations: map[string]Operation{}, Audits: map[string]bool{}}}}
}

func TestNATSReaperRefusesLegacyBackupJournalWithoutOverwriting(t *testing.T) {
	cluster := newReaperStateCluster(t)
	ctx := t.Context()
	nc := cluster.connect(t)
	kv := openReaperTestLeaseStore(t, ctx, nc, true)
	lease := reaperTestLease(1, "global-controller-gru-one")
	putReaperTestLease(t, ctx, kv, lease)
	session := newReaperTestSession(t, nc, lease)
	snapshot, err := session.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state := reaperTestState()
	// Even an old active entry with no stop operation cannot silently acquire
	// native-backup semantics just because its state otherwise looks valid.
	raw, err := json.Marshal(reaperEnvelope{SchemaVersion: 1, Lease: snapshot.lease, LeaseRevision: snapshot.leaseRevision, State: &state})
	if err != nil {
		t.Fatal(err)
	}
	ack, err := session.js.Publish(ctx, reaperStateSubject, raw, jetstream.WithExpectStream(reaperStream), jetstream.WithExpectLastSequence(snapshot.sequence))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Load(ctx); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("legacy journal admitted: %v", err)
	}
	if err := session.Save(ctx, state); !errors.Is(err, ErrStateNotLoaded) {
		t.Fatalf("refused state was overwritten: %v", err)
	}
	retained, found, err := session.rawGet(ctx, reaperStateSubject, 0)
	if err != nil || !found || retained.Sequence != ack.Sequence || !bytes.Equal(retained.Data, raw) {
		t.Fatal("legacy evidence changed", err)
	}
	// Relabeling a legacy operation inside a current envelope is also refused.
	for _, name := range []string{"pause/legacy", "pause/legacy/cycle-1"} {
		legacy := reaperTestState()
		entry := legacy.Entries["db-1"]
		entry.Cycle = 1
		entry.Operations[name] = Operation{Status: operationDone, Attempts: 1, StartedAt: time.Now().UTC(), CompletedAt: time.Now().UTC()}
		legacy.Entries["db-1"] = entry
		if _, err := reaperStateBytes(&legacy); !errors.Is(err, ErrStateUnavailable) {
			t.Fatalf("legacy operation %q accepted: %v", name, err)
		}
	}
}
func newReaperTestSession(t *testing.T, nc *nats.Conn, lease authority.RegionalAuthorityLeaseDocument) *NATSStateStore {
	t.Helper()
	session, err := NewNATSStateStore(NATSStateStoreConfig{Connection: nc, CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch), LeaseID: lease.LeaseId})
	if err != nil {
		t.Fatal(err)
	}
	return session
}
func TestNATSReaperRecoveryCASReceiptsAndQuorum(t *testing.T) {
	cluster := newReaperStateCluster(t)
	ctx := t.Context()
	nc := cluster.connect(t)
	kv := openReaperTestLeaseStore(t, ctx, nc, true)
	lease := reaperTestLease(1, "global-controller-gru-one")
	putReaperTestLease(t, ctx, kv, lease)
	one := newReaperTestSession(t, nc, lease)
	initial := reaperTestState()
	if err := one.Save(ctx, initial); !errors.Is(err, ErrStateNotLoaded) {
		t.Fatalf("save before load: %v", err)
	}
	if got, err := one.Load(ctx); err != nil || got.Version != 0 || len(got.Entries) != 0 {
		t.Fatalf("absent load: %+v %v", got, err)
	}
	if err := one.Save(ctx, initial); err != nil {
		t.Fatal(err)
	}
	two := newReaperTestSession(t, nc, lease)
	stale, err := two.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	current := cloneState(initial)
	entry := current.Entries["db-1"]
	now := time.Now().UTC()
	for _, name := range []string{"pause/snapshot", "pause/close", "pause/native-backup"} {
		entry.Operations[name] = Operation{Status: operationStarted, Attempts: 1, StartedAt: now}
		current.Version++
		if err := one.Save(ctx, current); err != nil {
			t.Fatal(err)
		}
		entry.Operations[name] = Operation{Status: operationDone, Attempts: 1, StartedAt: now, CompletedAt: now}
		entry.Audits[name+"/completed/db-1"] = true
		current.Version++
		if err := one.Save(ctx, current); err != nil {
			t.Fatal(err)
		}
	}
	entry.Phase = PhasePaused
	entry.PausedAt = now
	current.Entries["db-1"] = entry
	current.Version++
	if err := one.Save(ctx, current); err != nil {
		t.Fatal(err)
	}
	stale.Version++
	stale.Cursor = "stale"
	if err := two.Save(ctx, stale); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("stale overwrite: %v", err)
	}
	for _, change := range []func(*State){
		func(s *State) { delete(s.Entries, "db-1") },
		func(s *State) {
			e := s.Entries["db-1"]
			op := e.Operations["pause/snapshot"]
			op.Attempts++
			e.Operations["pause/snapshot"] = op
		},
		func(s *State) { delete(s.Entries["db-1"].Audits, "pause/snapshot/completed/db-1") },
	} {
		bad := cloneState(current)
		bad.Version++
		change(&bad)
		if err := one.Save(ctx, bad); err == nil {
			t.Fatal("receipt or entry regression admitted")
		}
	}
	nc.Close()
	cluster.restart(t)
	nc = cluster.connect(t)
	kv = openReaperTestLeaseStore(t, ctx, nc, false)
	lease.IssuedAt = time.Now().UTC()
	putReaperTestLease(t, ctx, kv, lease)
	recovered := newReaperTestSession(t, nc, lease)
	got, err := recovered.Load(ctx)
	if err != nil || !reflect.DeepEqual(got, current) {
		t.Fatalf("restart lost state: %+v %v", got, err)
	}
	proposed := cloneState(got)
	proposed.Version++
	proposed.Cursor = "page-3"
	snapshot, err := recovered.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(reaperEnvelope{SchemaVersion: reaperEnvelopeSchemaVersion, Lease: snapshot.lease, LeaseRevision: snapshot.leaseRevision, State: &proposed, PriorState: snapshot.state, PriorRevision: snapshot.revision})
	message := nats.NewMsg(reaperStateSubject)
	message.Data = payload
	message.Reply = nats.NewInbox()
	message.Header.Set(nats.ExpectedStreamHdr, reaperStream)
	message.Header.Set(nats.ExpectedLastSeqHdr, strconv.FormatUint(snapshot.sequence, 10))
	if err := nc.PublishMsg(message); err != nil {
		t.Fatal(err)
	}
	if err := nc.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	committed := uint64(0)
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		observed, found, err := recovered.rawGet(ctx, reaperStateSubject, 0)
		if err == nil && found && observed.Sequence == snapshot.sequence+1 {
			committed = observed.Sequence
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if committed == 0 || committed == recovered.revision {
		t.Fatal("lost-reply fixture failed")
	}
	if err := recovered.Save(ctx, proposed); err != nil {
		t.Fatalf("identical retry recovery: %v", err)
	}
	if recovered.revision != committed {
		t.Fatal("identical retry rewrote state")
	}
	lease.IssuedAt = time.Now().UTC()
	putReaperTestLease(t, ctx, kv, lease)
	if err := recovered.Save(ctx, proposed); err != nil {
		t.Fatalf("same lease renewal fenced: %v", err)
	}
	lease.LeaseId = "replacement-same-epoch"
	putReaperTestLease(t, ctx, kv, lease)
	if err := recovered.Save(ctx, proposed); !errors.Is(err, ErrStateFenced) {
		t.Fatalf("LeaseID replacement did not fence: %v", err)
	}
	if _, err := recovered.Load(ctx); !errors.Is(err, ErrStateFenced) {
		t.Fatalf("old identity loaded: %v", err)
	}
	successor := newReaperTestSession(t, nc, lease)
	if _, err := successor.Load(ctx); err != nil {
		t.Fatal(err)
	}
	cluster.servers[1].Shutdown()
	cluster.servers[2].Shutdown()
	cluster.servers[1].WaitForShutdown()
	cluster.servers[2].WaitForShutdown()
	minority, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := successor.Save(minority, proposed); err == nil {
		t.Fatal("minority identical save authorized")
	}
	minorityLoad, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if _, err := successor.Load(minorityLoad); err == nil {
		t.Fatal("minority load authorized")
	}
}
func TestNATSReaperLateCommitRecoversPriorIncludingAbsence(t *testing.T) {
	for _, initiallyAbsent := range []bool{false, true} {
		t.Run(strconv.FormatBool(initiallyAbsent), func(t *testing.T) {
			cluster := newReaperStateCluster(t)
			ctx := t.Context()
			nc := cluster.connect(t)
			kv := openReaperTestLeaseStore(t, ctx, nc, true)
			lease := reaperTestLease(7, "global-controller-gru-old")
			putReaperTestLease(t, ctx, kv, lease)
			old := newReaperTestSession(t, nc, lease)
			if _, err := old.Load(ctx); err != nil {
				t.Fatal(err)
			}
			valid := reaperTestState()
			if !initiallyAbsent {
				if err := old.Save(ctx, valid); err != nil {
					t.Fatal(err)
				}
			}
			lease.IssuedAt = time.Now().UTC()
			lease.DurationMilliseconds = 150
			putReaperTestLease(t, ctx, kv, lease)
			snapshot, err := old.snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			proposed := cloneState(valid)
			proposed.Version++
			proposed.Cursor = "late-page"
			raw, _ := json.Marshal(reaperEnvelope{SchemaVersion: reaperEnvelopeSchemaVersion, Lease: snapshot.lease, LeaseRevision: snapshot.leaseRevision, State: &proposed, PriorState: snapshot.state, PriorRevision: snapshot.revision})
			timer := time.NewTimer(time.Until(lease.IssuedAt.Add(220 * time.Millisecond)))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if _, err := old.js.Publish(ctx, reaperStateSubject, raw, jetstream.WithExpectStream(reaperStream), jetstream.WithExpectLastSequence(snapshot.sequence)); err != nil {
				t.Fatal(err)
			}
			if _, err := old.Load(ctx); !errors.Is(err, ErrStateFenced) {
				t.Fatalf("expired owner loaded: %v", err)
			}
			global, err := authority.RegionalAuthorityCoordinatorStartGlobalAsync(ctx, kv, "gru", "successor")
			if err != nil {
				t.Fatal(err)
			}
			defer global.Dispose()
			latest, err := kv.Get(ctx, "authority.global")
			if err != nil {
				t.Fatal(err)
			}
			var nextLease authority.RegionalAuthorityLeaseDocument
			if err := json.Unmarshal(latest.Value(), &nextLease); err != nil {
				t.Fatal(err)
			}
			if nextLease.Epoch <= lease.Epoch {
				t.Fatal("takeover epoch did not advance")
			}
			if _, err := old.js.Publish(ctx, reaperStateSubject, raw, jetstream.WithExpectStream(reaperStream), jetstream.WithExpectLastSequence(snapshot.sequence)); err == nil {
				t.Fatal("old stream CAS survived takeover")
			}
			next := newReaperTestSession(t, nc, nextLease)
			got, err := next.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if initiallyAbsent {
				if got.Version != 0 || len(got.Entries) != 0 {
					t.Fatalf("late first write survived: %+v", got)
				}
			} else if wantBytes, _ := reaperStateBytes(&valid); !bytes.Equal(wantBytes, func() []byte { b, _ := reaperStateBytes(&got); return b }()) {
				t.Fatalf("prior state lost: %+v", got)
			}
			repaired, err := next.snapshot(ctx)
			if err != nil || repaired.recovered || next.revision == 0 {
				t.Fatalf("recovery not durable: %+v %v", repaired, err)
			}
			if err := next.Save(ctx, valid); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestReaperStateBoundsAndTransitions(t *testing.T) {
	valid := reaperTestState()
	tests := map[string]func(*State){
		"version": func(s *State) { s.Version = 0 },
		"cursor":  func(s *State) { s.Cursor = strings.Repeat("x", 1025) },
		"entry count": func(s *State) {
			for i := 0; i < 129; i++ {
				id := "db-" + strconv.Itoa(i)
				e := s.Entries["db-1"]
				e.DatabaseID = id
				s.Entries[id] = e
			}
		},
		"raw provider error": func(s *State) {
			s.Entries["db-1"].Operations["pause/snapshot"] = Operation{Status: operationFailed, Attempts: 1, StartedAt: time.Now().UTC(), LastError: "token=secret value"}
		},
		"unknown operation": func(s *State) {
			s.Entries["db-1"].Operations["arbitrary"] = Operation{Status: operationStarted, Attempts: 1, StartedAt: time.Now().UTC()}
		},
		"unreceipted pause": func(s *State) {
			e := s.Entries["db-1"]
			e.Phase = PhasePaused
			e.PausedAt = time.Now().UTC()
			s.Entries["db-1"] = e
		},
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			s := cloneState(valid)
			edit(&s)
			if _, err := reaperStateBytes(&s); err == nil {
				t.Fatal("invalid state accepted")
			}
		})
	}
	huge := State{Version: 1, Entries: map[string]Entry{}}
	for i := 0; i < maximumReaperEntries; i++ {
		id := strings.Repeat("x", 240) + strconv.Itoa(i)
		huge.Entries[id] = Entry{DatabaseID: id, Plan: PlanFree, Phase: PhaseActive}
	}
	raw, _ := json.Marshal(huge)
	if len(raw) <= maximumReaperStateBytes {
		t.Fatal("oversize fixture too small")
	}
	if _, err := reaperStateBytes(&huge); err == nil {
		t.Fatal("oversize complete checkpoint accepted")
	}
	gap := cloneState(valid)
	gap.Version += 3
	gap.Cursor = "retry"
	if err := reaperIntentTransition(&valid, &gap); err != nil {
		t.Fatalf("failed save version gap rejected: %v", err)
	}
	sameVersion := cloneState(valid)
	sameVersion.Cursor = "changed"
	if err := reaperIntentTransition(&valid, &sameVersion); err == nil {
		t.Fatal("changed state reused version")
	}
	if strictReaperJSON([]byte(`{"version":1,"version":2}`), &State{}) == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestNATSReaperCapacityRefusesBeforeEffect(t *testing.T) {
	config := newProductionStateConfig(t)
	session, err := NewNATSStateStore(*config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	full := State{Version: 1, Entries: map[string]Entry{}}
	for i := 0; i < maximumReaperEntries; i++ {
		id := "retained-" + strconv.Itoa(i)
		full.Entries[id] = Entry{DatabaseID: id, Plan: PlanFree, Phase: PhaseActive}
	}
	if err := session.Save(t.Context(), full); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-DefaultPauseAfter)
	database := &productionDatabase{database: freeDatabase(base)}
	key := &productionKey{}
	production := productionConfig(database, key, ClockFunc(func() time.Time { return base.Add(DefaultPauseAfter) }), config)
	reconciler, err := NewProductionReconciler(production)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Run(t.Context()); err == nil {
		t.Fatal("capacity exhaustion accepted new database")
	}
	if len(database.calls) != 0 || len(key.calls) != 0 || len(production.Mail.(*testMailer).emails) != 0 || len(production.Audit.(*testAudit).events) != 0 {
		t.Fatal("effect ran after rejected intent")
	}
	got, err := session.Load(t.Context())
	if err != nil || len(got.Entries) != maximumReaperEntries || got.Version != 1 {
		t.Fatalf("capacity refusal changed durable obligations: %+v %v", got, err)
	}
}
