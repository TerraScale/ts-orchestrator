package managedmaterial

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type floorReadObjectClient struct {
	ObjectClient
	duringRead func()
}

func (client *floorReadObjectClient) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	if hook := client.duringRead; hook != nil {
		client.duringRead = nil
		hook()
	}
	return client.ObjectClient.GetObject(ctx, request)
}

func TestCredentialFloorVerifiesPinnedAuthorityAndRejectsMidReadOverlay(t *testing.T) {
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	t.Cleanup(func() { ns.Shutdown(); ns.WaitForShutdown() })
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("floor fixture broker did not start")
	}
	conn, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := authority.Start(t.Context(), js, authority.Config{Scope: "gru", DeploymentID: entityid.New(), CandidateID: entityid.New(),
		Replicas: 1, LeaseDuration: 30 * time.Second, RenewInterval: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	mutations, err := authority.OpenReader(t.Context(), js, "gru")
	if err != nil {
		t.Fatal(err)
	}
	preparation, spec, objects, _ := preparationFixture(t)
	initial, err := preparation.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.EncodeJSON(initial)
	if err != nil {
		t.Fatal(err)
	}
	epoch := runtime.Current().Epoch
	if _, err := runtime.CommitMaterialReceipt(t.Context(), epoch, spec.PlacementDatabaseID, spec.PartitionID, entityid.New(), 0, payload); err != nil {
		t.Fatal(err)
	}
	client := &floorReadObjectClient{ObjectClient: objects}
	floor, err := NewCredentialFloorReader(preparation.Repository.config, client, mutations,
		preparation.ControllerKey.Public().(ed25519.PublicKey), preparation.AllowedSubnetCIDR)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if generation, err := floor.Current(ctx, spec.PlacementDatabaseID, spec.PartitionID); err != nil || generation != 1 {
		t.Fatal("verified initial material did not establish generation one", generation, err)
	}
	_, bundle, err := preparation.CurrentBundle(ctx, spec.PlacementDatabaseID, spec.PartitionID)
	if err != nil {
		t.Fatal(err)
	}
	initialSHA, err := initial.Digest()
	if err != nil {
		t.Fatal(err)
	}
	state, err := SignCredentialState(2, initialSHA, bundle.Members[0].Files["client-api-keys.json"].Contents, bundle.Retained.AuthoritySigner)
	if err != nil {
		t.Fatal(err)
	}
	receipt := CredentialReceipt{Version: 1, DatabaseID: spec.PlacementDatabaseID, PartitionID: spec.PartitionID,
		RequestSHA256: strings.Repeat("a", 64), PreviousSHA256: strings.Repeat("b", 64), State: state}
	if err := receipt.sign(preparation.ControllerKey); err != nil {
		t.Fatal(err)
	}
	var sequence uint64
	client.duringRead = func() {
		wire, err := protocol.EncodeJSON(receipt)
		if err != nil {
			t.Fatal(err)
		}
		sequence, err = runtime.CommitClientCredentials(ctx, epoch, spec.PlacementDatabaseID, spec.PartitionID, entityid.New(), 0, wire)
		if err != nil {
			t.Fatal(err)
		}
	}
	if generation, err := floor.Current(ctx, spec.PlacementDatabaseID, spec.PartitionID); err == nil || generation != 0 {
		t.Fatal("floor accepted an overlay created during the pinned object read", generation, err)
	}
	if generation, err := floor.Current(ctx, spec.PlacementDatabaseID, spec.PartitionID); err != nil || generation != 2 {
		t.Fatal("verified current overlay was rejected", generation, err)
	}
	receipt.State.Generation = 3
	if err := receipt.sign(preparation.ControllerKey); err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.CommitClientCredentials(ctx, epoch, spec.PlacementDatabaseID, spec.PartitionID, entityid.New(), sequence, wire); err != nil {
		t.Fatal(err)
	}
	if generation, err := floor.Current(ctx, spec.PlacementDatabaseID, spec.PartitionID); err == nil || generation != 0 {
		t.Fatal("valid outer controller signature hid an invalid database authority signature", generation, err)
	}
	if objects.putCount != 1 {
		t.Fatal("readonly floor created or rewrote material", objects.putCount)
	}
}
