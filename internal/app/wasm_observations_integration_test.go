package app

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/functionmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/controlapi"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// The real authority, object store and upstream TCP ControlAPI establish
// desired-but-unplaced state; manager failure cannot establish an empty fleet.
func TestFunctionObservationInventoryUsesCurrentAuthorityAndManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	js := testRolloutJetStream(t)
	control, err := authority.Start(ctx, js, authority.Config{DeploymentID: entityid.New(), Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	artifacts, err := js.CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket})
	if err != nil {
		t.Fatal(err)
	}
	signer := newFunctionPublicationSigner(t)
	proof := signer.proof(t, 42, "current")
	if _, err := artifacts.Put(ctx, jetstream.ObjectMeta{Name: "sha256-" + proof.Claim().Digest}, bytes.NewReader(proof.Module())); err != nil {
		t.Fatal(err)
	}
	if _, err := control.CommitFunctionIntent(ctx, control.Current().Epoch, entityid.New(), 0, proof); err != nil {
		t.Fatal(err)
	}
	material := generationtest.New(t, time.Now().UTC())
	generation := material.Generation(bootstrap.MaterialGenerationExpectation{DeploymentID: entityid.New(), Environment: "canary", ClusterID: entityid.New(), Cell: "GRU", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}}, 1, "")
	issuer, err := bootstrapmaterial.LoadControllerIssuer(generation, material.Files["controller-tls-issuer-cert.pem"], material.Files["controller-tls-issuer-key.pem"], material.Files["controller-account-signer.seed"])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuer.Wipe)
	state := store.NewMemoryStore(nil)
	t.Cleanup(func() { _ = state.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	api.RegisterControlServer(server, controlapi.NewServer(state, nil, nil, nil, nil))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	connection, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	controller := functionController{config: functionControllerConfig{Authority: control, Client: api.NewControlClient(connection), Cell: "gru", Environment: "canary",
		Material: functionmaterial.Controller{Issuer: issuer, Reader: functionmaterial.Reader{Authority: control, Artifacts: artifacts, Roots: func() trust.Keyring { return signer.roots }}}}}
	hosts := func(context.Context) ([]host.HostStatus, error) { return nil, nil }
	addresses := 0
	address := func(context.Context, string) (string, error) { addresses++; return "", nil }
	observed, err := controller.observeFunctions(ctx, hosts, address)
	if err != nil || len(observed) != 1 || observed[0].State != "unplaced" || observed[0].Snapshot != nil || observed[0].FunctionID != proof.Claim().FunctionID || addresses != 0 {
		t.Fatalf("current unplaced function lost or invented a worker: %+v %v", observed, err)
	}
	if _, err := artifacts.Put(ctx, jetstream.ObjectMeta{Name: "sha256-" + proof.Claim().Digest}, bytes.NewReader([]byte("tampered"))); err != nil {
		t.Fatal(err)
	}
	observed, err = controller.observeFunctions(ctx, hosts, address)
	if err != nil || len(observed) != 1 || observed[0].State != "unavailable" || observed[0].Snapshot != nil || addresses != 0 {
		t.Fatalf("invalid current artifact authorized observation: %+v %v", observed, err)
	}
	server.Stop()
	failed, cancelFailed := context.WithTimeout(ctx, time.Second)
	defer cancelFailed()
	if observed, err := controller.observeFunctions(failed, hosts, address); err == nil || len(observed) != 0 {
		t.Fatal("manager outage became an empty observed function fleet")
	}
}
