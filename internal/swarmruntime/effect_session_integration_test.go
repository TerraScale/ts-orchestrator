package swarmruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

// This recovery scenario seeds an actual possible-writer journal, then crosses
// R3 authority and real manager certificate/Raft boundaries. It does not qualify
// DATA issuance or a containerd stopped observation.
func TestEffectSessionsRecoverHeldR3AfterLeaderChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 70*time.Second)
	defer cancel()
	js := effectSessionR3(t)
	config := authority.Config{Scope: "gru", DeploymentID: entityid.New(), CandidateID: entityid.New(), Replicas: 3}
	old, err := authority.Start(ctx, js, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = old.Close() })
	founderCfg := nodeFixtureConfig(t, "founder", "manager")
	founder := nodeFixtureStart(t, ctx, founderCfg)
	control, err := founder.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clusters, err := control.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		t.Fatalf("actual cluster: %v", err)
	}
	hostID := entityid.New()
	workerCfg := nodeFixtureConfig(t, hostID, "container")
	workerCfg.Admission.Region = "sa-saopaulo-1"
	workerCfg.Admission.InstanceID = "ocid1.instance.oc1.sa-saopaulo-1.held-worker"
	workerCfg.Admission.ManagerAddress, err = founder.RemoteAddress()
	if err != nil {
		t.Fatal(err)
	}
	workerCfg.Admission.JoinToken = clusters.Clusters[0].RootCA.JoinTokens.Worker
	worker := nodeFixtureStart(t, ctx, workerCfg)
	admitted, err := AdmitNode(ctx, control, worker.ID(), workerCfg.Admission)
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	public, err := user.PublicKey()
	user.Wipe()
	if err != nil {
		t.Fatal(err)
	}
	scope := authority.WorkloadScope{DatabaseID: entityid.New(), PartitionID: entityid.New()}
	registration := host.Registration{ID: hostID, Cell: "gru", Node: "worker", PublicKey: base64.StdEncoding.EncodeToString(key), NATSUserPublicKey: public, Generation: 1,
		ManagedPlacement: &host.ManagedPlacementBinding{DatabaseID: scope.DatabaseID, PartitionID: scope.PartitionID},
		ManagedOCI:       &host.ManagedOCIBinding{Region: "sa-saopaulo-1", InstanceID: workerCfg.Admission.InstanceID}}
	registrationBytes, err := json.Marshal(registration, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	material := executionwire.WorkerGrantMaterial{Registration: registrationBytes}
	materialBytes, err := json.Marshal(material, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	effect := authority.RuntimeEffect{EffectID: entityid.New(), Scope: scope, RegistrationID: registration.ID, HostSessionID: entityid.New(), WorkerPublicKey: registration.PublicKey,
		NATSUserPublicKey: public, RegistrationGeneration: 1, InstanceID: workerCfg.Admission.InstanceID, NodeID: worker.ID(), TaskID: strings.Repeat("b", 25), ServiceID: strings.Repeat("c", 25),
		TaskSHA256: strings.Repeat("d", 64), Material: materialBytes, MaterialSHA256: fmt.Sprintf("%x", sha256.Sum256(materialBytes)), Epoch: old.Current().Epoch, IssuedAt: now,
		ExpiresAt: now.Add(2 * time.Second), Phase: authority.RuntimeEffectHeld}
	identity := executionwire.WorkerIdentity{Cell: "gru", HostNode: "worker", NATSUserPublicKey: public, HostPublicKey: registration.PublicKey, InstanceID: effect.InstanceID,
		NodeID: effect.NodeID, HostSessionID: effect.HostSessionID, RegistrationGeneration: 1}
	effect.AdmissionSHA256, err = executionwire.WorkerAdmissionSHA256(executionwire.WorkerGrantPayload{Identity: identity, TaskID: effect.TaskID, ServiceID: effect.ServiceID,
		TaskSHA256: effect.TaskSHA256, EffectID: effect.EffectID, Epoch: effect.Epoch, Material: material})
	if err != nil {
		t.Fatal(err)
	}
	effect.Sequence, err = old.BeginRuntimeEffect(ctx, effect.Epoch, effect)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	config.CandidateID = entityid.New()
	current, err := authority.Start(ctx, js, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = current.Close() })
	if current.Current().Epoch <= effect.Epoch {
		t.Fatal("successor did not advance authority epoch")
	}
	sessions := &EffectSessions{control: control, authority: current, scopes: make(map[authority.WorkloadScope]*runtimeEffectScope)}
	if err := sessions.recover(ctx, current.Current().Epoch); err != nil {
		t.Fatal(err)
	}
	held := sessions.scope(scope)
	t.Cleanup(func() {
		held.mu.Lock()
		defer held.mu.Unlock()
		if held.release != nil {
			held.release()
			held.release = nil
		}
	})
	if held.release == nil {
		t.Fatal("successor did not restore retained read gate")
	}
	if _, err := sessions.admittedNode(ctx, registration, worker.ID()); err != nil {
		t.Fatalf("actual manager admission: %v", err)
	}
	wrong := registration
	wrong.ManagedOCI = &host.ManagedOCIBinding{Region: "sa-saopaulo-1", InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.foreign"}
	if _, err := sessions.admittedNode(ctx, wrong, worker.ID()); err == nil {
		t.Fatal("manager admitted foreign worker instance")
	}
	if _, err := sessions.currentTask(ctx, registration, &api.Task{ID: effect.TaskID}, effect.TaskSHA256); err == nil {
		t.Fatal("missing actual task became an assignment")
	}
	timer := time.NewTimer(time.Until(effect.ExpiresAt) + time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	query := executionwire.RuntimeEffectQuery{Action: "close", EffectID: effect.EffectID, Nonce: strings.Repeat("a", 32), Identity: identity,
		Task: &api.Task{ID: effect.TaskID, ServiceID: effect.ServiceID, NodeID: effect.NodeID}}
	held.mu.Lock()
	closing, err := sessions.close(ctx, current.Current().Epoch, held, effect, query)
	held.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if closing.Phase != authority.RuntimeEffectClosing || closing.Epoch != effect.Epoch || closing.StopChallenge == "" || held.release == nil {
		t.Fatal("close after leader change released authority or lost original grant")
	}
	pending, err := current.ListUnresolvedRuntimeEffects(ctx, scope)
	if err != nil || len(pending) != 1 || pending[0].Phase != authority.RuntimeEffectClosing {
		t.Fatalf("durable closing: %v", err)
	}
	effect = pending[0]
	challenge := held.challenges[effect.EffectID]
	certificate, _ := pem.Decode(admitted.Certificate.Certificate)
	if certificate == nil {
		t.Fatal("manager did not retain worker certificate")
	}
	proof := executionwire.SignedRuntimeStop{Payload: executionwire.RuntimeStopPayload{EffectID: effect.EffectID, TaskSHA256: effect.TaskSHA256, InstanceID: effect.InstanceID,
		NodeID: effect.NodeID, ContainerID: "ts-" + effect.TaskID, KernelStart: "123", Cgroup: "0::/terrascale/ts-" + effect.TaskID + "\n", Challenge: challenge.nonce,
		Epoch: effect.Epoch, Revision: effect.Sequence, PIDNamespace: 2, MountNamespace: 3, HostPID: 4, Deadline: effect.ExpiresAt, ObservedAt: time.Now().UTC()},
		CertificateChain: [][]byte{certificate.Bytes}, Signature: []byte("invalid-signature")}
	if err := sessions.verifyRuntimeStop(ctx, current.Current().Epoch, effect, challenge, proof); err == nil || !strings.Contains(err.Error(), "signature is invalid") {
		t.Fatalf("actual worker certificate did not reach independent signature rejection: %v", err)
	}
	query.StopProof = &proof
	held.mu.Lock()
	_, err = sessions.close(ctx, current.Current().Epoch, held, effect, query)
	held.mu.Unlock()
	if err == nil || held.release == nil {
		t.Fatal("forged stop proof released held execution")
	}
	pending, err = current.ListUnresolvedRuntimeEffects(ctx, scope)
	if err != nil || len(pending) != 1 || pending[0].Sequence != effect.Sequence {
		t.Fatal("forged stop proof changed durable hold")
	}
	challenge.epoch--
	if err := sessions.verifyRuntimeStop(ctx, current.Current().Epoch, effect, challenge, proof); err == nil {
		t.Fatal("prior leader challenge remained current")
	}
}

func effectSessionR3(t *testing.T) jetstream.JetStream {
	t.Helper()
	var brokers []*server.Server
	for index := range 3 {
		var routes []*url.URL
		if index == 0 {
			route, err := url.Parse("nats-route://127.0.0.1:1")
			if err != nil {
				t.Fatal(err)
			}
			routes = append(routes, route)
		}
		for _, broker := range brokers {
			route, err := url.Parse("nats-route://" + broker.ClusterAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			routes = append(routes, route)
		}
		broker, err := server.NewServer(&server.Options{ServerName: fmt.Sprintf("effect-r3-%d", index), Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream"),
			Cluster: server.ClusterOpts{Name: "effect-r3", Host: "127.0.0.1", Port: -1}, Routes: routes})
		if err != nil {
			t.Fatal(err)
		}
		go broker.Start()
		if !broker.ReadyForConnections(5 * time.Second) {
			t.Fatal("effect R3 broker did not start")
		}
		brokers = append(brokers, broker)
		t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for {
		ready := false
		for _, broker := range brokers {
			if broker.JetStreamIsLeader() && len(broker.JetStreamClusterPeers()) == 3 {
				ready = true
			}
		}
		for _, broker := range brokers {
			ready = ready && broker.JetStreamIsCurrent()
		}
		if ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("effect R3 metadata unavailable: ", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	connection, err := nats.Connect(brokers[0].ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	return js
}
