package app

import (
	"errors"
	"os"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	"github.com/nats-io/nats.go/jetstream"
)

func TestContainerChannelUnavailableNeverFallsBackToNative(t *testing.T) {
	ctx := t.Context()
	r, kv, bucket, _ := servicePinsSignedFixture(t)
	identity := cellspec.Identity{DeploymentID: entityid.New(), Cell: r.cell, Environment: "canary"}
	keys := newTestSpecTrust(t, t.TempDir(), identity)
	registry := &specRegistry{cell: identity.Cell, identity: identity, fixed: map[string]WorkloadProfile{}, signedArtifactStore: delivery.DefaultArtifactStoreMaxBytes}
	if err := registry.openRoots(keys.roots, trust.RootChain{Version: 1}, ""); err != nil {
		t.Fatal(err)
	}
	var err error
	registry.kv, err = r.js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: cellSpecBucket, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	service := cellspec.Service{Role: tsauth.Role, Profile: cellspec.Profile{Resources: placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 1 << 30}},
		Spec: &workload.ServiceSpec{Role: tsauth.Role, Environment: identity.Environment, Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 3}}}
	wire, err := os.ReadFile(keys.signRoot(t, t.TempDir(), cellspec.Spec{Schema: cellspec.Schema, Identity: identity, Generation: 1, RequiresBinary: cellspec.BinaryLevel, Services: []cellspec.Service{service}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.kv.Put(ctx, cellSpecKey, wire); err != nil {
		t.Fatal(err)
	}
	entry, err := registry.kv.Get(ctx, cellSpecKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.load(entry); err != nil {
		t.Fatal(err)
	}
	fencer, err := authority.Start(ctx, r.js, authority.Config{DeploymentID: identity.DeploymentID, Scope: identity.Cell, CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fencer.Close() })
	r.fencer, r.policy.services, r.environment = fencer, registry, identity.Environment
	// The native location exists, but a genuine root container connection does not.
	if err := r.pass(ctx, kv, tsauth.Role); !errors.Is(err, rootoci.ErrUnauthorized) {
		t.Fatal("unavailable container source reached the native channel", err)
	}
	if len(bucket.puts) != 0 {
		t.Fatal("unavailable container source published native status")
	}
	if _, revision, err := loadServiceRelease(ctx, kv, releasechannel.ServiceStatusKey("GRU", tsauth.Role)); err != nil || revision != 0 {
		t.Fatal("unavailable source changed persisted release state", revision, err)
	}
}
