package reaper

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
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
	entry := Entry{Cycle: 1, DatabaseID: scope.DatabaseID, Plan: PlanFree, Phase: PhaseDeleting, LastRequest: now.Add(-100 * 24 * time.Hour), PausedAt: now, FirstNoticeAt: now, SecondNoticeAt: now, Operations: map[string]Operation{}}
	for _, name := range []string{"pause/snapshot", "pause/close", "pause/native-backup", "notice/second/" + scope.DatabaseID, "notice/final/" + scope.DatabaseID, "delete/cdn-purge"} {
		if !strings.HasPrefix(name, "delete/") {
			name = reaperCycleName(entry, name)
		}
		entry.Operations[name] = Operation{Status: operationDone, Attempts: 1, StartedAt: now, CompletedAt: now}
	}
	entry.Operations[reaperCycleName(entry, "delete/crypto-shred")] = Operation{Status: operationStarted, Attempts: 1, StartedAt: now}
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
	config := HostKeyRevokerConfig{Connection: nc, Scope: scope, HostIdentities: []string{host}, Authority: NATSStateStoreConfig{CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch), LeaseID: lease.LeaseId}, CheckEffectAuthority: func(ctx context.Context) error { return ctx.Err() }}
	adapter, err := NewHostKeyRevoker(config)
	if err != nil {
		t.Fatal(err)
	}
	op := reaperCycleName(entry, "delete/crypto-shred") + "/" + scope.DatabaseID
	if _, err := adapter.RevokeWrappedCopies(ctx, scope.DatabaseID, "wrong"); err == nil {
		t.Fatal("wrong operation accepted")
	}
	catalog, _ := keylease.ReadCatalog(path)
	if len(catalog.Tombstones) != 0 {
		t.Fatal("invalid request mutated catalog")
	}
	for range 2 {
		result, err := adapter.RevokeWrappedCopies(ctx, scope.DatabaseID, op)
		if !errors.Is(err, ErrKeyLeasesPending) || result.Scope != scope || result.OperationKey != op || len(result.Receipts) != 1 || !result.LeasesExpireAt.Equal(result.Receipts[host].LeasesExpireAt) {
			t.Fatalf("lease barrier receipt: %+v %v", result, err)
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
	if _, err := adapter.RevokeWrappedCopies(ctx, scope.DatabaseID, op); !errors.Is(err, ErrKeyLeasesPending) {
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
	stale, err := NewHostKeyRevoker(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stale.RevokeWrappedCopies(ctx, scope.DatabaseID, op); err == nil || errors.Is(err, ErrKeyLeasesPending) {
		t.Fatal("wrong fence accepted", err)
	}
	config.Authority.AuthorityEpoch--
	config.HostIdentities = append(config.HostIdentities, host[:len(host)-1]+"Y")
	partial, err := NewHostKeyRevoker(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := partial.RevokeWrappedCopies(ctx, scope.DatabaseID, op); !errors.Is(err, ErrKeyDestructionUnavailable) {
		t.Fatal("missing host accepted", err)
	}
	if err := receiver.Close(); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"missing", "scope", "operation", "host", "future", "short-horizon"} {
		t.Run(kind, func(t *testing.T) {
			receipt := original
			response := keyDestructionReply{HostIdentity: host, Receipt: &receipt}
			switch kind {
			case "missing":
				response.Receipt = nil
			case "scope":
				receipt.Scope = foreign
			case "operation":
				receipt.OperationKey = "other"
			case "host":
				response.HostIdentity = host + "X"
			case "future":
				receipt.DestroyedAt = time.Now().Add(time.Hour)
				receipt.LeasesExpireAt = receipt.DestroyedAt.Add(1800 * time.Second)
			case "short-horizon":
				receipt.LeasesExpireAt = receipt.DestroyedAt
			}
			sub, err := nc.Subscribe(subject, func(msg *nats.Msg) { data, _ := json.Marshal(response); _ = msg.Respond(data) })
			if err != nil {
				t.Fatal(err)
			}
			defer sub.Unsubscribe()
			if err := nc.Flush(); err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.RevokeWrappedCopies(ctx, scope.DatabaseID, op); !errors.Is(err, ErrKeyDestructionUnavailable) {
				t.Fatal("malformed receipt accepted", err)
			}
		})
	}

}
