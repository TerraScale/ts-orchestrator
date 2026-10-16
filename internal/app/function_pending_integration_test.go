package app

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/functionmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/controlapi"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestFunctionDemandRequiresWorkerQualifiedThroughFunctionExpiry(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	js := testRolloutJetStream(t)
	runtime, err := authority.Start(ctx, js, authority.Config{DeploymentID: entityid.New(), Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	artifacts, err := js.CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket})
	if err != nil {
		t.Fatal(err)
	}
	tasks := store.NewMemoryStore(nil)
	t.Cleanup(func() { _ = tasks.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	api.RegisterControlServer(server, controlapi.NewServer(tasks, nil, nil, nil, nil))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	connection, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	signer := newFunctionPublicationSigner(t)
	bundle, evidence := signer.worker(t, release.ContainerTarget{Cell: "GRU", Environment: "canary", Role: swarmruntime.FunctionWorkerRole, Architecture: "amd64"})
	config := functionControllerConfig{Authority: runtime, Client: api.NewControlClient(connection), Cell: "gru", Environment: "canary",
		Material: functionmaterial.Controller{Reader: functionmaterial.Reader{Artifacts: artifacts, Roots: func() trust.Keyring { return signer.roots }}},
		Worker: func(context.Context, release.VerifiedFunction) (functionWorkerRelease, error) {
			return functionWorkerRelease{Architecture: "amd64", Bundle: bundle}, nil
		}, Evidence: evidence}
	observe := functionDemandSource(config)
	if demand, err := observe(ctx); err != nil || len(demand) != 0 {
		t.Fatalf("empty authoritative inventory: %+v, %v", demand, err)
	}
	proof := signer.proof(t, 42, "first")
	if _, err := artifacts.Put(ctx, jetstream.ObjectMeta{Name: "sha256-" + proof.Claim().Digest}, bytes.NewReader(proof.Module())); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.CommitFunctionIntent(ctx, runtime.Current().Epoch, entityid.New(), 0, proof); err != nil {
		t.Fatal(err)
	}
	if demand, err := observe(ctx); err == nil || demand != nil {
		t.Fatalf("short-lived qualified worker produced capacity: %+v, %v", demand, err)
	}
	wrongScope := config
	wrongScope.Cell = "fra"
	if demand, err := functionDemandSource(wrongScope)(ctx); err == nil || demand != nil {
		t.Fatalf("foreign regional intent produced capacity: %+v, %v", demand, err)
	}
}
