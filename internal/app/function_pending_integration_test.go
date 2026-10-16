package app

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
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
	deploymentID := entityid.New()
	runtime, err := authority.Start(ctx, js, authority.Config{DeploymentID: deploymentID, Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
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
	identity := trust.ChainIdentity{DeploymentID: deploymentID, Cell: "gru", Environment: "canary"}
	roots, err := newRootRegistry(signer.roots, identity, trust.RootChain{Version: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	target := release.ContainerTarget{Cell: "GRU", Environment: "canary", Role: swarmruntime.FunctionWorkerRole, Architecture: "amd64"}
	bundle, evidence := signer.worker(t, target)
	config := functionControllerConfig{Authority: runtime, Client: api.NewControlClient(connection), Roots: roots, Factory: signer.factory, Cell: "gru", Environment: "canary",
		Material: functionmaterial.Controller{Reader: functionmaterial.Reader{Artifacts: artifacts, Roots: roots.current}},
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
	if demand, err := observe(ctx); !errors.Is(err, trust.ErrExpired) || demand != nil {
		t.Fatalf("short-lived qualified worker produced capacity: %+v, %v", demand, err)
	}
	wrongScope := config
	wrongScope.Cell = "fra"
	if demand, err := functionDemandSource(wrongScope)(ctx); err == nil || demand != nil {
		t.Fatalf("foreign regional intent produced capacity: %+v, %v", demand, err)
	}
	envelope, err := trust.DecodeEnvelope(bundle.Claim)
	if err != nil {
		t.Fatal(err)
	}
	extended, err := trust.Sign(envelope.Payload, envelope.Scope, envelope.IssuedAt, envelope.IssuedAt.Add(90*time.Minute), signer.leaf)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Claim, err = trust.EncodeEnvelope(extended)
	if err != nil {
		t.Fatal(err)
	}
	allocations, err := currentContainerAllocations(ctx, signer.factory, bundle, roots.current(), target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyContainerCurrent(ctx, bundle, roots.current(), target, time.Now(), proof.ExpiresAt(), evidence, allocations); err != nil {
		t.Fatalf("independent worker qualification through function expiry: %v", err)
	}
	addedRoot := newRootKey(t)
	rotation := trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{
		signTestRotation(t, identity, roots.verified, rootKeys(signer.root, addedRoot), signer.root, addedRoot),
	}}
	config.Worker = func(context.Context, release.VerifiedFunction) (functionWorkerRelease, error) {
		if err := roots.adopt(rotation); err != nil {
			t.Fatal(err)
		}
		return functionWorkerRelease{Architecture: "amd64", Bundle: bundle}, nil
	}
	if demand, err := functionDemandSource(config)(ctx); err == nil || !strings.Contains(err.Error(), "function roots changed") || demand != nil {
		t.Fatalf("root rotation during worker lookup produced capacity: %+v, %v", demand, err)
	}
}
