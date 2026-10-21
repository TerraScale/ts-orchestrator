package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
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
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/controlapi"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
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
	hostController := newObservationHostController(t, ctx, js, control, artifacts)
	hosts := hostController.ListHosts
	membershipReads := 0
	membership := func(context.Context, string) (swarmruntime.VerifiedWorkerMembership, error) {
		membershipReads++
		return swarmruntime.VerifiedWorkerMembership{}, errors.New("current worker membership unavailable")
	}
	observed, err := controller.observeFunctions(ctx, hosts, membership)
	if err != nil || len(observed) != 1 || observed[0].State != "unplaced" || observed[0].Snapshot != nil || observed[0].FunctionID != proof.Claim().FunctionID || membershipReads != 0 {
		t.Fatalf("current unplaced function lost or invented a worker: %+v %v", observed, err)
	}
	claim := proof.Claim()
	hostID, nodeID, serviceID, taskID := entityid.Derive("host", "gru", "observation-host"), entityid.New(), entityid.New(), entityid.New()
	registerObservationHost(t, ctx, hostController, "observation-host", claim.Environment)
	instance := "ocid1.instance.oc1.sa-saopaulo-1.function"
	if err := state.Update(func(tx store.Tx) error {
		if err := store.CreateService(tx, &api.Service{ID: serviceID, Spec: api.ServiceSpec{Annotations: api.Annotations{Labels: map[string]string{
			swarmruntime.LabelRole: swarmruntime.FunctionWorkerRole, swarmruntime.LabelFunctionTenant: claim.TenantID,
			swarmruntime.LabelFunctionID: claim.FunctionID, swarmruntime.LabelRegion: "sa-saopaulo-1", swarmruntime.LabelEnvironment: claim.Environment,
		}}}}); err != nil {
			return err
		}
		if err := store.CreateNode(tx, &api.Node{ID: nodeID, Spec: api.NodeSpec{Annotations: api.Annotations{Name: hostID,
			Labels: map[string]string{swarmruntime.LabelInstanceID: instance}}}, Status: api.NodeStatus{Addr: "10.0.0.99"}}); err != nil {
			return err
		}
		return store.CreateTask(tx, &api.Task{ID: taskID, ServiceID: serviceID, NodeID: nodeID,
			DesiredState: api.TaskStateRunning, Status: api.TaskStatus{State: api.TaskStateRunning}})
	}); err != nil {
		t.Fatal(err)
	}
	observed, err = controller.observeFunctions(ctx, hosts, membership)
	if err != nil || len(observed) != 1 || observed[0].State != "unavailable" || observed[0].Snapshot != nil || observed[0].TaskID != taskID || observed[0].NodeID != nodeID || membershipReads != 1 {
		t.Fatalf("missing independent membership used a node label or invented counters: %+v %v", observed, err)
	}
	if retired, err := hostController.RetireIdle(ctx, "observation-host"); err != nil || !retired {
		t.Fatalf("retire registered host: %v %v", retired, err)
	}
	observed, err = controller.observeFunctions(ctx, hosts, membership)
	if err != nil || len(observed) != 1 || observed[0].State != "unavailable" || observed[0].Snapshot != nil || membershipReads != 1 {
		t.Fatalf("retired host triggered collection or retained counters: %+v %v", observed, err)
	}
	if _, err := artifacts.Put(ctx, jetstream.ObjectMeta{Name: "sha256-" + proof.Claim().Digest}, bytes.NewReader([]byte("tampered"))); err != nil {
		t.Fatal(err)
	}
	observed, err = controller.observeFunctions(ctx, hosts, membership)
	if err != nil || len(observed) != 1 || observed[0].State != "unavailable" || observed[0].Snapshot != nil || membershipReads != 1 {
		t.Fatalf("invalid current artifact authorized observation: %+v %v", observed, err)
	}
	server.Stop()
	failed, cancelFailed := context.WithTimeout(ctx, time.Second)
	defer cancelFailed()
	if observed, err := controller.observeFunctions(failed, hosts, membership); err == nil || len(observed) != 0 {
		t.Fatal("manager outage became an empty observed function fleet")
	}
}

func newObservationHostController(t *testing.T, ctx context.Context, js jetstream.JetStream, control *authority.Runtime, artifacts host.ArtifactStore) *host.Controller {
	t.Helper()
	_, responseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := host.NewController(ctx, host.ControllerConfig{Cell: "gru", Conn: js.Conn(), JS: js, Artifacts: artifacts,
		ResponseKey: responseKey, StateReplicas: 1, HostMutations: control,
		AuthorityEpoch: func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func registerObservationHost(t *testing.T, ctx context.Context, controller *host.Controller, node, environment string) host.Registration {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	userID, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	registration := host.Registration{ID: entityid.Derive("host", "gru", node), Cell: "gru", Node: node, Environment: environment,
		Roles: []string{swarmruntime.FunctionWorkerRole}, Generation: 1, PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: userID}
	if _, err := controller.Register(ctx, registration); err != nil {
		t.Fatal(err)
	}
	return registration
}
