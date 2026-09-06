package reaper

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

func TestHostKeyDestructionRealCatalogAndNATS(t *testing.T) {
	cluster := newReaperStateCluster(t)
	nc := cluster.connect(t)
	ctx := t.Context()
	kv := openReaperTestLeaseStore(t, ctx, nc, true)
	lease := reaperTestLease(1, "global-controller-gru-one")
	putReaperTestLease(t, ctx, kv, lease)
	scope := keylease.DatabaseScope{Environment: "production", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAX"}
	host := "spiffe://terrascale.tech/production/terrabase-member/01ARZ3NDEKTSV4RRFFQ69G5FAY/01ARZ3NDEKTSV4RRFFQ69G5FAZ"
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".reaper-destruction-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "keys.json")
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := keylease.InitializeCatalog(path); err != nil {
		t.Fatal(err)
	}
	wrapped := keylease.Entry{Binding: keylease.Binding{Environment: scope.Environment, TenantID: scope.TenantID, ProjectID: scope.ProjectID, DatabaseID: scope.DatabaseID, KeyVersion: "01ARZ3NDEKTSV4RRFFQ69G5FAY", Region: "GRU", Purpose: "data"}, CryptoEndpoint: "https://fixture-crypto.kms.sa-saopaulo-1.oraclecloud.com", KEKID: "ocid1.key.oc1.sa-saopaulo-1.fixture", KEKVersionID: "ocid1.keyversion.oc1.sa-saopaulo-1.fixture", Ciphertext: "wrapped-only", LeaseSeconds: 30, NotAfter: time.Now().Add(time.Hour)}
	if err := keylease.MergeEntries(path, []keylease.Entry{wrapped}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	entry := Entry{DatabaseID: scope.DatabaseID, Plan: PlanFree, Phase: PhaseDeleting, LastRequest: now.Add(-100 * 24 * time.Hour), PausedAt: now, FirstNoticeAt: now, SecondNoticeAt: now, Operations: map[string]Operation{}}
	for _, name := range []string{"pause/snapshot", "pause/close", "pause/native-backup", "notice/second/" + scope.DatabaseID, "notice/final/" + scope.DatabaseID, "delete/cdn-purge"} {
		entry.Operations[name] = Operation{Status: operationDone, Attempts: 1, StartedAt: now, CompletedAt: now}
	}
	entry.Operations["delete/crypto-shred"] = Operation{Status: operationStarted, Attempts: 1, StartedAt: now}
	state := State{Version: 1, Entries: map[string]Entry{scope.DatabaseID: entry}}
	session := newReaperTestSession(t, nc, lease)
	snapshot, err := session.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	prior := state
	state.Version++
	raw, err := json.Marshal(reaperEnvelope{PriorState: &prior, PriorRevision: snapshot.sequence, SchemaVersion: reaperEnvelopeSchemaVersion, Lease: lease, LeaseRevision: snapshot.leaseRevision, State: &state})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.js.Publish(ctx, reaperStateSubject, raw, jetstream.WithExpectStream(reaperStream), jetstream.WithExpectLastSequence(snapshot.sequence)); err != nil {
		t.Fatal(err)
	}
	receiver, err := StartKeyDestructionHost(ctx, KeyDestructionHostConfig{Connection: nc, ServerIdentity: host, CatalogPath: path, Scopes: []keylease.DatabaseScope{scope}})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	config := HostKeyAdapterConfig{Connection: nc, Scope: scope, HostIdentities: []string{host}, Authority: NATSStateStoreConfig{CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch), LeaseID: lease.LeaseId}, CheckEffectAuthority: func(ctx context.Context) error { return ctx.Err() }}
	adapter, err := NewHostKeyAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	op := "delete/crypto-shred/" + scope.DatabaseID
	if err := adapter.DestroyDEK(ctx, scope.DatabaseID, "wrong"); err == nil {
		t.Fatal("wrong operation accepted")
	}
	catalog, _ := keylease.ReadCatalog(path)
	if len(catalog.Tombstones) != 0 {
		t.Fatal("invalid request mutated catalog")
	}
	for range 2 {
		if err := adapter.DestroyDEK(ctx, scope.DatabaseID, op); !errors.Is(err, ErrKeyLeasesPending) {
			t.Fatalf("lease barrier: %v", err)
		}
	}
	catalog, err = keylease.ReadCatalog(path)
	if err != nil || len(catalog.Tombstones) != 1 {
		t.Fatal("durable tombstone absent", err)
	}
	original := catalog.Tombstones[0]
	if original.Scope != scope || original.OperationKey != op || original.RemovedCopies != 1 || len(catalog.Entries) != 0 {
		t.Fatal("scope changed")
	}
	if err := receiver.Close(); err != nil {
		t.Fatal(err)
	}
	receiver, err = StartKeyDestructionHost(ctx, KeyDestructionHostConfig{Connection: nc, ServerIdentity: host, CatalogPath: path})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	if err := adapter.DestroyDEK(ctx, scope.DatabaseID, op); !errors.Is(err, ErrKeyLeasesPending) {
		t.Fatal("dynamic tombstone restart failed", err)
	}
	foreign := scope
	foreign.ProjectID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
	if destructionScopeAdmitted(KeyDestructionHostConfig{ServerIdentity: host, CatalogPath: path}, foreign) {
		t.Fatal("foreign scope admitted")
	}
	request := keyDestructionRequest{HostIdentity: host + "X", Scope: scope, OperationKey: op, CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch), LeaseID: lease.LeaseId}
	subject, _ := KeyDestructionSubject(host)
	payload, _ := json.Marshal(request)
	reply, err := nc.Request(subject, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var result keyDestructionReply
	if json.Unmarshal(reply.Data, &result) != nil || result.Error == "" || result.Receipt != nil {
		t.Fatal("wrong host request accepted")
	}
	config.Authority.AuthorityEpoch++
	stale, err := NewHostKeyAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := stale.DestroyDEK(ctx, scope.DatabaseID, op); err == nil || errors.Is(err, ErrKeyLeasesPending) {
		t.Fatal("wrong fence accepted", err)
	}
	config.Authority.AuthorityEpoch--
	config.HostIdentities = append(config.HostIdentities, host[:len(host)-1]+"Y")
	partial, err := NewHostKeyAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := partial.DestroyDEK(ctx, scope.DatabaseID, op); !errors.Is(err, ErrKeyDestructionUnavailable) {
		t.Fatal("missing host accepted", err)
	}
}
