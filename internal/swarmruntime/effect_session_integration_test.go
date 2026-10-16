package swarmruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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
	js, connection := effectSessionR3(t)
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
	hostID := entityid.Derive("host", "gru", "worker")
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
	key, originalKey, err := ed25519.GenerateKey(rand.Reader)
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
	registration := host.Registration{ID: hostID, Cell: "gru", Node: "worker", Environment: "production", Roles: []string{"terrabase"}, FailureDomain: "FAULT-DOMAIN-1",
		Capacity: host.Capacity{CPU: 2, MemoryBytes: 8 << 30, DiskBytes: 50 << 30}, SystemReserveBytes: 1 << 30, PublicKey: base64.StdEncoding.EncodeToString(key), NATSUserPublicKey: public, Generation: 1,
		ManagedPlacement: &host.ManagedPlacementBinding{DatabaseID: scope.DatabaseID, PartitionID: scope.PartitionID, SeatID: entityid.New(), IntentGeneration: 1, IntentPayloadDigest: strings.Repeat("a", 64), CanonicalRosterDigest: strings.Repeat("b", 64), ManagedHostProfileDigest: strings.Repeat("c", 64)},
		ManagedMember:    &host.ManagedMemberBinding{Scope: host.MemberScope{ClusterID: strings.Repeat("a", 32), TenantID: entityid.New(), DatabaseID: scope.DatabaseID, ShardID: 1, MemberID: entityid.New(), Incarnation: strings.Repeat("b", 32)}, HostAttempt: 1},
		ManagedOCI:       &host.ManagedOCIBinding{Region: "GRU", InstanceID: workerCfg.Admission.InstanceID, Owner: "orchestrator", FleetGeneration: 1, CreateKey: entityid.New()}}
	registrationBytes, err := json.Marshal(registration, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	registrationSequence, err := old.CommitHostMutation(ctx, old.Current().Epoch, authority.MutationRegistration, "gru.worker", entityid.New(), 0, registrationBytes)
	if err != nil {
		t.Fatal(err)
	}
	material := executionwire.WorkerGrantMaterial{Registration: registrationBytes}
	materialBytes, err := json.Marshal(material, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: strings.Repeat("b", 25), ServiceID: strings.Repeat("c", 25), NodeID: worker.ID()}
	taskHash, err := executionwire.TaskSHA256(task)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	effect := authority.RuntimeEffect{EffectID: entityid.New(), Scope: scope, RegistrationID: registration.ID, HostSessionID: entityid.New(), WorkerPublicKey: registration.PublicKey,
		NATSUserPublicKey: public, RegistrationGeneration: 1, InstanceID: workerCfg.Admission.InstanceID, NodeID: worker.ID(), TaskID: strings.Repeat("b", 25), ServiceID: strings.Repeat("c", 25),
		TaskSHA256: taskHash, Material: materialBytes, MaterialSHA256: fmt.Sprintf("%x", sha256.Sum256(materialBytes)), Epoch: old.Current().Epoch, IssuedAt: now,
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
	wrong.ManagedOCI = &host.ManagedOCIBinding{Region: "GRU", InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.foreign"}
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
		Task: task}
	freshPublic, freshKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	freshUser, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	freshNATS, err := freshUser.PublicKey()
	freshUser.Wipe()
	if err != nil {
		t.Fatal(err)
	}
	fresh := registration
	fresh.PublicKey, fresh.NATSUserPublicKey, fresh.Generation = base64.StdEncoding.EncodeToString(freshPublic), freshNATS, 2
	freshBytes, err := json.Marshal(fresh, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := current.CommitHostMutation(ctx, current.Current().Epoch, authority.MutationRegistration, "gru.worker", entityid.New(), registrationSequence, freshBytes); err != nil {
		t.Fatal(err)
	}
	state, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "TS_HOST_STATE", History: 2, Replicas: 3, Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := json.Marshal(map[string]any{"registration_generation": 1, "session_id": entityid.New(), "epoch": 40, "expires_at": time.Now().UTC().Add(-time.Minute), "last_nonce": strings.Repeat("f", 32), "last_issued_at": time.Now().UTC().Add(-2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Put(ctx, "session.gru.worker", expired); err != nil {
		t.Fatal(err)
	}
	artifacts, err := js.CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: "EFFECT_ARTIFACTS", Replicas: 3, Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic, controllerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := host.NewController(ctx, host.ControllerConfig{Cell: "gru", Conn: connection, JS: js, State: state, StateReplicas: 3, Artifacts: artifacts, ResponseKey: controllerKey,
		HostMutations: current, AuthorityEpoch: func() uint64 { return current.Current().Epoch }, AuthorityGuard: current.Guard, RuntimeEffects: sessions})
	if err != nil {
		t.Fatal(err)
	}
	controllerContext, stopController := context.WithCancel(ctx)
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- controller.Run(controllerContext) }()
	t.Cleanup(func() {
		stopController()
		select {
		case <-controllerDone:
		case <-time.After(5 * time.Second):
			t.Error("host controller did not stop")
		}
	})
	select {
	case <-controller.Ready():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	currentSession := entityid.New()
	_, sessionBytes, err := effectHostExchange(ctx, connection, fresh, freshKey, controllerPublic, currentSession, 0, "session", map[string]string{"kind": "acquire"})
	if err != nil {
		t.Fatal(err)
	}
	var session struct {
		RegistrationGeneration uint64    `json:"registration_generation"`
		SessionID              string    `json:"session_id"`
		Epoch                  uint64    `json:"epoch"`
		ExpiresAt              time.Time `json:"expires_at"`
		LastNonce              string    `json:"last_nonce"`
		LastIssuedAt           time.Time `json:"last_issued_at"`
	}
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		t.Fatal(err)
	}
	if session.Epoch != 41 || session.Epoch == current.Current().Epoch {
		t.Fatal("test did not separate host session and leader counters")
	}
	_, grantBytes, err := effectHostExchange(ctx, connection, fresh, freshKey, controllerPublic, currentSession, session.Epoch, "runtime-effect", query)
	if err != nil {
		t.Fatal(err)
	}
	var closing executionwire.WorkerGrantPayload
	if err := json.Unmarshal(grantBytes, &closing, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if closing.Identity != identity {
		t.Fatal("refreshed registration replaced original immutable grant identity")
	}
	if _, _, err := effectHostExchange(ctx, connection, fresh, originalKey, controllerPublic, currentSession, session.Epoch, "runtime-effect", query); err == nil {
		t.Fatal("old host key authorized the refreshed registration")
	}
	renew := query
	renew.Action = "renew"
	if _, _, err := effectHostExchange(ctx, connection, fresh, freshKey, controllerPublic, currentSession, session.Epoch, "runtime-effect", renew); err == nil {
		t.Fatal("refreshed registration renewed original old-key execution")
	}

	if closing.Phase != authority.RuntimeEffectClosing || closing.Epoch != effect.Epoch || closing.LeaderEpoch != current.Current().Epoch || closing.StopChallenge == "" || held.release == nil {
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

func effectSessionR3(t *testing.T) (jetstream.JetStream, *nats.Conn) {
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
	return js, connection
}

func effectHostExchange(ctx context.Context, connection *nats.Conn, registration host.Registration, key ed25519.PrivateKey, controller ed25519.PublicKey, sessionID string, epoch uint64, operation string, payload any) (protocol.Envelope, jsontext.Value, error) {
	var empty protocol.Envelope
	data, err := json.Marshal(payload)
	if err != nil {
		return empty, nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return empty, nil, err
	}
	nonceHex := hex.EncodeToString(nonce[:])
	issued := time.Now().UTC()
	request := struct {
		Version           int            `json:"version"`
		Node              string         `json:"node"`
		NATSUserPublicKey string         `json:"nats_user_public_key"`
		Operation         string         `json:"operation"`
		SessionID         string         `json:"session_id"`
		Epoch             uint64         `json:"epoch"`
		Nonce             string         `json:"nonce"`
		IssuedAt          time.Time      `json:"issued_at"`
		Payload           jsontext.Value `json:"payload"`
	}{1, registration.Node, registration.NATSUserPublicKey, operation, sessionID, epoch, nonceHex, issued, data}
	wire, err := json.Marshal(request)
	if err != nil {
		return empty, nil, err
	}
	envelope, err := protocol.SignEnvelope(wire, protocol.EnvelopeScope{Region: registration.Cell, Kind: "host." + operation, Actor: registration.Node, OperationID: entityid.Derive("host-request", nonceHex), Epoch: epoch}, issued, issued.Add(10*time.Second), key)
	if err != nil {
		return empty, nil, err
	}
	wire, err = protocol.EncodeJSON(envelope)
	if err != nil {
		return empty, nil, err
	}
	subject, err := protocol.AgentObservationSubject(registration.Cell, registration.NATSUserPublicKey, operation)
	if err != nil {
		return empty, nil, err
	}
	reply, err := connection.RequestWithContext(ctx, subject, wire)
	if err != nil {
		return empty, nil, err
	}
	if err := protocol.DecodeStrict(reply.Data, &envelope, 512<<10); err != nil {
		return empty, nil, err
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{Region: registration.Cell, Kind: "host.response." + operation, Actor: "controller", OperationID: entityid.Derive("host-request", nonceHex), Epoch: epoch}, controller, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: 10 * time.Second, ClockSkew: 2 * time.Second}); err != nil {
		return empty, nil, err
	}
	var response struct {
		Nonce     string         `json:"nonce"`
		Node      string         `json:"node"`
		SessionID string         `json:"session_id"`
		Epoch     uint64         `json:"epoch"`
		Operation string         `json:"operation"`
		Error     string         `json:"error,omitempty"`
		Retryable bool           `json:"retryable,omitzero"`
		Payload   jsontext.Value `json:"payload,omitempty"`
	}
	if err := protocol.DecodeStrict(envelope.Payload, &response, 512<<10); err != nil {
		return empty, nil, err
	}
	if response.Nonce != nonceHex || response.Node != registration.Node || response.SessionID != sessionID || response.Epoch != epoch || response.Operation != operation {
		return empty, nil, errors.New("signed host response mismatch")
	}
	if response.Error != "" {
		return empty, nil, errors.New(response.Error)
	}
	return envelope, response.Payload, nil
}
