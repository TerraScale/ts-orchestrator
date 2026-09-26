package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"github.com/nats-io/nkeys"
)

type inMemoryRunner struct {
	mu       sync.Mutex
	observed host.Observation
}

func testHostWorkloadIdentity() host.WorkloadIdentity {
	if os.Geteuid() == 0 {
		return host.WorkloadIdentity{UID: 65534, GID: 65534}
	}
	return host.WorkloadIdentity{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
}

func testHostInstallRoot(t *testing.T) string {
	t.Helper()
	parent, err := os.MkdirTemp("/tmp", "ts-host-install-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove test install parent: %v", err)
		}
	})
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "install")
}

func testHostStateRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		return filepath.Join(t.TempDir(), "state")
	}
	parent, err := os.MkdirTemp("/var/lib", "ts-host-state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove test state parent: %v", err)
		}
	})
	return filepath.Join(parent, "state")
}

func (*inMemoryRunner) Recover(context.Context) error { return nil }
func (r *inMemoryRunner) Apply(_ context.Context, workload host.Workload) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observed = host.Observation{Role: workload.Role, Digest: workload.Digest, Fingerprint: workload.Fingerprint, Running: true, PID: 1}
	return nil
}
func (r *inMemoryRunner) Stop(_ context.Context, role string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observed = host.Observation{Role: role}
	return nil
}
func (r *inMemoryRunner) Observe(_ context.Context, _ string) (host.Observation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.observed, nil
}
func (*inMemoryRunner) Close(context.Context) error { return nil }

type readyWriter struct {
	mu     sync.Mutex
	ready  chan struct{}
	once   sync.Once
	buffer bytes.Buffer
}

func (w *readyWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buffer.Write(data)
	if strings.Contains(w.buffer.String(), " ready in cell ") {
		w.once.Do(func() { close(w.ready) })
	}
	return n, err
}

func TestAuthenticatedOperatorToHostDelivery(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	root := t.TempDir()
	portListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portListener.Addr().(*net.TCPAddr).Port
	portListener.Close()
	controllerNKey, controllerSeed := testNKey(t)
	operatorNKey, operatorSeed := testNKey(t)
	hostNKey, hostSeed := testNKey(t)
	controllerPublic, _ := testEd25519(t, root, "controller.key")
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	hostPublic, hostPrivate := testEd25519(t, root, "host.key")
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"test"}, CanRegisterHosts: true, CanPlaceTerraBase: true}
	controllerConfig := Config{
		NATS: natscell.Config{Cell: "gru", Instance: "one", Replicas: 1, Lab: true, NKeySeedFile: controllerSeed,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: port, StoreDir: filepath.Join(root, "nats"), StoreMaxBytes: 2 << 30,
				Users: []natscell.NKeyGrant{{PublicKey: controllerNKey, Role: "controller"}, {PublicKey: operatorNKey, Role: "operator"}, {PublicKey: hostNKey, Role: "host", Node: "node-a"}}}},
		Controller: ControllerConfig{CandidateID: "one", ResponseKeyFile: filepath.Join(root, "controller.key"), ArtifactStoreMaxBytes: 64 << 20, TrustedSigners: []TrustedSignerConfig{grant},
			Workloads: map[string]WorkloadProfile{"terrabase": {Resources: placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20}}}},
	}
	controllerConfigPath := testJSONFile(t, root, "controller.json", controllerConfig)
	controllerOutput := &readyWriter{ready: make(chan struct{})}
	controllerDone := make(chan error, 1)
	go func() {
		controllerDone <- Run(ctx, []string{"run", "--config", controllerConfigPath}, controllerOutput)
	}()
	select {
	case <-controllerOutput.ready:
	case err := <-controllerDone:
		t.Fatalf("controller exited before ready: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	operatorConfig := Config{NATS: natscell.Config{Cell: "gru", Instance: "operator", Replicas: 1, Lab: true,
		URL: fmt.Sprintf("nats://127.0.0.1:%d", port), NKeySeedFile: operatorSeed},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "operator.key")}}
	operatorConfigPath := testJSONFile(t, root, "operator.json", operatorConfig)
	registration := host.Registration{Cell: "gru", Node: "node-a", Environment: "test", Roles: []string{"terrabase"},
		PublicKey: base64.StdEncoding.EncodeToString(hostPublic), Generation: 1,
		Capacity: host.Capacity{CPU: 2, MemoryBytes: 256 << 20, DiskBytes: 512 << 20}}
	registrationPath := testJSONFile(t, root, "registration.json", registration)
	var output bytes.Buffer
	if err := Run(ctx, []string{"operator", "host-register", "--config", operatorConfigPath, "--registration", registrationPath}, &output); err != nil {
		t.Fatalf("signed host registration: %v", err)
	}
	var registrationReceipt host.Receipt
	if err := json.Unmarshal(output.Bytes(), &registrationReceipt); err != nil || registrationReceipt.Generation != 1 {
		t.Fatalf("registration receipt: %v: %s", err, output.String())
	}
	hostRuntime, err := natscell.Start(ctx, natscell.Config{Cell: "gru", Instance: "host-a", Replicas: 1, Lab: true,
		URL: operatorConfig.NATS.URL, NKeySeedFile: hostSeed, ClientRole: "host"})
	if err != nil {
		t.Fatal(err)
	}
	defer hostRuntime.Close()
	runner := &inMemoryRunner{}
	clock := &testBrokerClock{}
	clock.healthy.Store(true)
	agent, err := host.NewAgent(host.AgentConfig{WorkloadIdentity: testHostWorkloadIdentity(), Cell: "gru", Node: "node-a", Environment: "test", Roles: []string{"terrabase"},
		Conn: hostRuntime.Conn(), Identity: hostPrivate, ControllerPublicKey: controllerPublic, Runner: runner,
		InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t), PollInterval: 100 * time.Millisecond,
		ClockCheck: controllerClockCheck(clock)})
	if err != nil {
		t.Fatal(err)
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx) }()
	for {
		output.Reset()
		if err := Run(ctx, []string{"operator", "hosts", "--config", operatorConfigPath}, &output); err == nil {
			var statuses []host.HostStatus
			if json.Unmarshal(output.Bytes(), &statuses) == nil && len(statuses) == 1 && !statuses[0].SessionExpiresAt.IsZero() {
				break
			}
		}
		select {
		case err := <-agentDone:
			t.Fatalf("host agent exited before session: %v", err)
		case <-ctx.Done():
			t.Fatal("host did not establish a session: ", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	artifactPath := filepath.Join(root, "guest")
	if err := os.WriteFile(artifactPath, []byte("#!/bin/sh\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := delivery.ArtifactSource{Repository: "https://example.com/terrascale/terrabase", Commit: strings.Repeat("a", 40), TreeDigest: strings.Repeat("b", 64)}
	output.Reset()
	if err := Run(ctx, []string{"operator", "artifact-push", "--config", operatorConfigPath, "--file", artifactPath,
		"--repository", source.Repository, "--commit", source.Commit, "--tree-digest", source.TreeDigest,
		"--role", "terrabase", "--environment", "test"}, &output); err != nil {
		t.Fatalf("signed artifact admission: %v", err)
	}
	var record delivery.ArtifactRecord
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("artifact reply: %v: %s", err, output.String())
	}
	intent := delivery.Intent{Source: source, ArtifactDigest: record.Digest, ManifestDigest: record.ManifestDigest,
		Role: "terrabase", Environment: "test", Generation: 1, DesiredReplicas: 1, ConfigDigest: delivery.ConfigDigestOf(nil, nil)}
	intentPath := testJSONFile(t, root, "intent.json", intent)
	output.Reset()
	if err := Run(ctx, []string{"operator", "deploy", "--config", operatorConfigPath, "--intent", intentPath}, &output); err != nil {
		t.Fatalf("signed delivery submit: %v", err)
	}
	var submitted struct {
		OperationID string `json:"operationId"`
		Fingerprint string `json:"fingerprint"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(output.Bytes(), &submitted); err != nil || submitted.OperationID == "" || submitted.Fingerprint == "" {
		t.Fatalf("submit receipt: %v: %s", err, output.String())
	}
	for {
		output.Reset()
		err := Run(ctx, []string{"operator", "status", "--config", operatorConfigPath,
			"--operation-id", submitted.OperationID, "--fingerprint", submitted.Fingerprint}, &output)
		if err == nil {
			var receipt delivery.Receipt
			if json.Unmarshal(output.Bytes(), &receipt) == nil && receipt.Status == "accepted" {
				break
			}
		}
		select {
		case err := <-agentDone:
			t.Fatalf("host agent exited before delivery acceptance: %v", err)
		case <-ctx.Done():
			t.Fatalf("delivery did not reach accepted: %v, last output %s, error %v", ctx.Err(), output.String(), err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	for {
		observed, _ := runner.Observe(ctx, "terrabase")
		if observed.Running && observed.Digest == record.Digest {
			break
		}
		select {
		case err := <-agentDone:
			t.Fatalf("host agent exited before applying desired: %v", err)
		case <-ctx.Done():
			t.Fatal("host did not apply desired: ", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	output.Reset()
	if err := Run(ctx, []string{"operator", "status", "--config", operatorConfigPath,
		"--operation-id", submitted.OperationID, "--fingerprint", strings.Repeat("0", 64)}, &output); !errors.Is(err, delivery.ErrConflict) {
		t.Fatalf("status accepted wrong fingerprint: %v", err)
	}
	placeIntent := testManagedPlacementIntent()
	placeIntent.DatabaseID = "db-a"
	placeIntent.Generation = 1
	placePath := testJSONFile(t, root, "placement.json", placeIntent)
	output.Reset()
	if err := Run(ctx, []string{"operator", "placement-apply", "--config", operatorConfigPath, "--intent", placePath}, &output); err != nil {
		t.Fatalf("signed placement apply: %v", err)
	}
	var placeReceipt placementApplyResponse
	if err := json.Unmarshal(output.Bytes(), &placeReceipt); err != nil || placeReceipt.DatabaseID != placeIntent.DatabaseID || placeReceipt.PartitionID != placeIntent.PartitionID || placeReceipt.Sequence == 0 {
		t.Fatalf("placement receipt: %v: %s", err, output.String())
	}
	operatorConnection := operatorConfig.NATS
	operatorConnection.ClientRole = "operator"
	operatorRuntime, err := natscell.Start(ctx, operatorConnection)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := authority.OpenReader(ctx, operatorRuntime.JetStream(), "gru")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := reader.ReadPlacementIntent(ctx, placeIntent.DatabaseID, placeIntent.PartitionID)
	operatorRuntime.Close()
	if err != nil || stored.Sequence != placeReceipt.Sequence {
		t.Fatalf("ordered placement readback: sequence %d, err %v", stored.Sequence, err)
	}
	var committed placement.Intent
	if err := json.Unmarshal(stored.Payload, &committed); err != nil || committed.DatabaseID != placeIntent.DatabaseID ||
		committed.Generation != placeIntent.Generation || committed.CanonicalRoster.DatabaseID != placeIntent.CanonicalRoster.DatabaseID ||
		committed.CanonicalRoster.DatabaseID == committed.DatabaseID {
		t.Fatalf("committed placement intent: %v, %+v", err, committed)
	}
	secondIntent := placeIntent
	secondIntent.PartitionID = "partition-b"
	secondIntent.CanonicalRoster.ShardID = 2
	secondPath := testJSONFile(t, root, "placement-b.json", secondIntent)
	output.Reset()
	if err := Run(ctx, []string{"operator", "placement-apply", "--config", operatorConfigPath, "--intent", secondPath}, &output); err != nil {
		t.Fatalf("second partition placement apply: %v", err)
	}
	var secondReceipt placementApplyResponse
	if err := json.Unmarshal(output.Bytes(), &secondReceipt); err != nil || secondReceipt.Sequence == placeReceipt.Sequence || secondReceipt.PartitionID != secondIntent.PartitionID {
		t.Fatalf("second partition receipt: %v: %s", err, output.String())
	}
	operatorRuntime, err = natscell.Start(ctx, operatorConnection)
	if err != nil {
		t.Fatal(err)
	}
	reader, err = authority.OpenReader(ctx, operatorRuntime.JetStream(), "gru")
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := (admittedPlacementReader{cell: "gru", store: reader}).ListPlacementIntents(ctx, "gru")
	operatorRuntime.Close()
	if err != nil || len(admitted) != 2 {
		t.Fatalf("independent partition admissions: %d, %v", len(admitted), err)
	}
	cancel()
	if err := <-controllerDone; err != nil {
		t.Fatalf("controller shutdown: %v", err)
	}
	if err := <-agentDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("agent shutdown: %v", err)
	}
}

func testNKey(t *testing.T) (string, string) {
	t.Helper()
	pair, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := pair.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	path := filepath.Join(t.TempDir(), "user.nk")
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	return public, path
}

func testEd25519(t *testing.T, dir, name string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(base64.StdEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	return public, private
}

func testJSONFile(t *testing.T, dir, name string, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
