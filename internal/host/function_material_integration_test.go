//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"maps"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestFunctionMaterialSignedHostSessionDeliversExactDurableTaskGrant(t *testing.T) {
	f := newFunctionMaterialTransport(t)
	var calls atomic.Int64
	f.controller.functionMaterial = func(ctx context.Context, registration Registration, binding FunctionMaterialBinding) (FunctionMaterialFiles, error) {
		calls.Add(1)
		return f.current(ctx, registration, binding)
	}
	agent := f.start(t)
	observed := make(chan functionMaterialReply, 64)
	responses, err := f.conn.Subscribe("_INBOX.>", func(message *nats.Msg) {
		var envelope protocol.Envelope
		if protocol.DecodeStrict(message.Data, &envelope, 512<<10) != nil {
			return
		}
		var result response
		if decodeStrict([]byte(envelope.Payload), &result) != nil || result.Operation != "function-material" || result.Error != "" {
			return
		}
		var chunk functionMaterialReply
		if decodeStrict(result.Payload, &chunk) == nil {
			observed <- chunk
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = responses.Unsubscribe() })
	if err := f.conn.FlushWithContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	material, err := agent.CurrentFunctionMaterial(t.Context(), f.binding)
	if err != nil {
		t.Fatal(err)
	}
	files := material.Files
	if !material.ExpiresAt.Equal(f.expires) || !material.CredentialExpiresAt.Equal(f.credentialExpires) || material.ExpiresAt.Equal(material.CredentialExpiresAt) || len(files) != len(f.files) {
		t.Fatal("transport changed the material expiry or inventory")
	}
	for name, expected := range f.files {
		if !bytes.Equal(files[name], expected) {
			t.Fatalf("transport changed %s", name)
		}
	}
	if want := int64(len(functionMaterialNames) + 2); calls.Load() != want {
		t.Fatalf("inventory used %d provider reads, want %d with three module chunks", calls.Load(), want)
	}
	largeModuleChunk, encryptedCredentials := false, false
	for range calls.Load() {
		select {
		case chunk := <-observed:
			if !chunk.CredentialExpiresAt.Equal(f.credentialExpires) {
				t.Fatal("credential expiry changed in signed chunk")
			}
			if len(chunk.Ciphertext) > functionMaterialChunkSize(chunk.File)+16 {
				t.Fatal("encrypted NATS chunk exceeded its file-specific bound")
			}
			if chunk.File == "module.wasm" && len(chunk.Ciphertext) > materialChunkBytes {
				largeModuleChunk = true
			}
			if chunk.File == "broker.creds" {
				encryptedCredentials = len(chunk.Ciphertext) > 0 && !bytes.Contains(chunk.Ciphertext, f.files["broker.creds"])
			}
		case <-time.After(3 * time.Second):
			t.Fatal("signed NATS material reply was not observed")
		}
	}
	if !largeModuleChunk || !encryptedCredentials {
		t.Fatal("actual NATS replies did not carry a large module chunk and confidential credentials")
	}
	if err := responses.Unsubscribe(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*FunctionMaterialBinding){
		"task":        func(b *FunctionMaterialBinding) { b.TaskID = strings.Repeat("z", 25) },
		"service":     func(b *FunctionMaterialBinding) { b.ServiceID = strings.Repeat("z", 25) },
		"node":        func(b *FunctionMaterialBinding) { b.NodeID = strings.Repeat("z", 25) },
		"instance":    func(b *FunctionMaterialBinding) { b.InstanceID += "other" },
		"region":      func(b *FunctionMaterialBinding) { b.Region = "eu-frankfurt-1" },
		"host":        func(b *FunctionMaterialBinding) { b.HostID = entityid.New() },
		"fingerprint": func(b *FunctionMaterialBinding) { b.Fingerprint = strings.Repeat("f", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			binding := f.binding
			change(&binding)
			if _, _, err := agent.CurrentFunctionFiles(t.Context(), binding); err == nil {
				t.Fatal("another recipient received material")
			}
		})
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	query := functionMaterialQuery{Binding: f.binding, RegistrationGeneration: 1, File: "module.wasm",
		Length: materialChunkBytes, EphemeralPublicKey: private.PublicKey().Bytes()}
	for name, change := range map[string]func(*functionMaterialQuery){
		"unknown-file":       func(q *functionMaterialQuery) { q.File = "../controller.creds" },
		"large-chunk":        func(q *functionMaterialQuery) { q.Length = artifactChunkBytes + 1 },
		"large-normal-chunk": func(q *functionMaterialQuery) { q.File = "broker.creds"; q.Length = materialChunkBytes + 1 },
		"negative-offset":    func(q *functionMaterialQuery) { q.Offset = -1 },
		"past-module-limit":  func(q *functionMaterialQuery) { q.Offset = release.MaxFunctionModuleBytes },
		"stale-generation":   func(q *functionMaterialQuery) { q.RegistrationGeneration++ },
	} {
		t.Run(name, func(t *testing.T) {
			malformed := query
			change(&malformed)
			before := calls.Load()
			var reply functionMaterialReply
			if _, err := agent.sendToLeader(t.Context(), "function-material", malformed, &reply, nil, nil); err == nil || calls.Load() != before {
				t.Fatalf("malformed selector reached provider: %v", err)
			}
		})
	}
	before := calls.Load()
	agent.mu.Lock()
	agent.session.Epoch++
	agent.mu.Unlock()
	if _, _, err := agent.CurrentFunctionFiles(t.Context(), f.binding); err == nil || calls.Load() != before {
		t.Fatalf("stale signed session reached provider: %v", err)
	}
}

func TestFunctionMaterialRechecksRegistrationAfterProvider(t *testing.T) {
	f := newFunctionMaterialTransport(t)
	var rotate atomic.Bool
	f.controller.functionMaterial = func(ctx context.Context, registration Registration, binding FunctionMaterialBinding) (FunctionMaterialFiles, error) {
		material, err := f.current(ctx, registration, binding)
		if err == nil && rotate.Swap(false) {
			registration.Generation++
			_, err = f.controller.Register(ctx, registration)
		}
		return material, err
	}
	agent := f.start(t)
	rotate.Store(true)
	if files, _, err := agent.CurrentFunctionFiles(t.Context(), f.binding); err == nil || len(files) != 0 {
		t.Fatalf("rotated host received material: %v", err)
	}
}

func TestFunctionMaterialRejectsInventoryChangeBetweenChunks(t *testing.T) {
	f := newFunctionMaterialTransport(t)
	var calls atomic.Int64
	f.controller.functionMaterial = func(ctx context.Context, registration Registration, binding FunctionMaterialBinding) (FunctionMaterialFiles, error) {
		material, err := f.current(ctx, registration, binding)
		if err == nil && calls.Add(1) > 2 {
			material.Files["broker.creds"] = []byte("different credential inventory")
		}
		return material, err
	}
	agent := f.start(t)
	if files, _, err := agent.CurrentFunctionFiles(t.Context(), f.binding); err == nil || len(files) != 0 {
		t.Fatalf("mixed function material inventory accepted: %v", err)
	}
}

func TestFunctionMaterialRejectsCredentialExpiryChangeBetweenChunks(t *testing.T) {
	f := newFunctionMaterialTransport(t)
	var calls atomic.Int64
	f.controller.functionMaterial = func(ctx context.Context, registration Registration, binding FunctionMaterialBinding) (FunctionMaterialFiles, error) {
		material, err := f.current(ctx, registration, binding)
		if err == nil && calls.Add(1) > 2 {
			material.CredentialExpiresAt = material.CredentialExpiresAt.Add(time.Second)
		}
		return material, err
	}
	agent := f.start(t)
	if material, err := agent.CurrentFunctionMaterial(t.Context(), f.binding); err == nil || len(material.Files) != 0 {
		t.Fatalf("mixed credential lifetimes accepted: %v", err)
	}
}

func TestFunctionMaterialProviderIsRequired(t *testing.T) {
	f := newFunctionMaterialTransport(t)
	agent := f.start(t)
	if files, _, err := agent.CurrentFunctionFiles(t.Context(), f.binding); err == nil || len(files) != 0 {
		t.Fatalf("missing provider served files: %v", err)
	}
}

type functionMaterialTransport struct {
	controller        *Controller
	conn              *nats.Conn
	authority         *authority.Runtime
	proof             release.VerifiedFunction
	binding           FunctionMaterialBinding
	grant             authority.FunctionBinding
	files             map[string][]byte
	expires           time.Time
	credentialExpires time.Time
	hostKey           ed25519.PrivateKey
	responseKey       ed25519.PrivateKey
}

func (f *functionMaterialTransport) current(ctx context.Context, registration Registration, binding FunctionMaterialBinding) (FunctionMaterialFiles, error) {
	// This fixture resolves the authenticated registration before consulting the
	// real durable grant. Query fields alone cannot select another recipient.
	if registration.Node != "function-host" || registration.ID != f.binding.HostID ||
		binding != f.binding {
		return FunctionMaterialFiles{}, errors.New("recipient differs from admitted host task")
	}
	if err := f.authority.VerifyFunctionGrant(ctx, f.proof, f.grant); err != nil {
		return FunctionMaterialFiles{}, err
	}
	files := maps.Clone(f.files)
	for name, content := range files {
		files[name] = bytes.Clone(content)
	}
	return FunctionMaterialFiles{Files: files, ExpiresAt: f.expires, CredentialExpiresAt: f.credentialExpires}, nil
}

func (f *functionMaterialTransport) start(t *testing.T) *Agent {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- f.controller.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-f.controller.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("host controller did not subscribe")
	}
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("function-host"),
		ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(),
		Cell: "gru", Node: "function-host", Environment: "production", Roles: []string{"function-worker"},
		Conn: f.conn, Identity: f.hostKey, ControllerPublicKey: f.responseKey.Public().(ed25519.PublicKey),
		Runner: &memoryRunner{observed: make(map[string]Observation)}, InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	return agent
}

func newFunctionMaterialTransport(t *testing.T) *functionMaterialTransport {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("embedded NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := authority.Start(t.Context(), js, authority.Config{Scope: "gru", DeploymentID: entityid.New(), CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	artifacts, err := js.CreateObjectStore(t.Context(), jetstream.ObjectStoreConfig{Bucket: "FUNCTION_TRANSPORT_ARTIFACTS", Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	_, responseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewController(t.Context(), ControllerConfig{Cell: "gru", Conn: conn, JS: js, Artifacts: artifacts,
		ResponseKey: responseKey, StateReplicas: 1, HostMutations: runtime,
		AuthorityEpoch: func() uint64 { return runtime.Current().Epoch }, AuthorityGuard: runtime.Guard})
	if err != nil {
		t.Fatal(err)
	}
	public, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registration := Registration{Cell: "gru", Node: "function-host", Environment: "production", Roles: []string{"function-worker"},
		PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: testNATSUserKey("function-host"), Generation: 1}
	if _, err := controller.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	proof, rootPublic := functionTransportProof(t)
	if _, err := runtime.CommitFunctionIntent(t.Context(), runtime.Current().Epoch, entityid.New(), 0, proof); err != nil {
		t.Fatal(err)
	}
	binding := FunctionMaterialBinding{TaskID: strings.Repeat("a", 25), ServiceID: strings.Repeat("b", 25), NodeID: strings.Repeat("c", 25),
		InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.function", Region: "sa-saopaulo-1",
		HostID: entityid.Derive("host", "gru", "function-host"), Fingerprint: strings.Repeat("d", 64)}
	files := make(map[string][]byte, len(functionMaterialNames))
	for _, name := range functionMaterialNames {
		files[name] = []byte("transport fixture for " + name)
	}
	files["root.pub"], files["module.wasm"], files["receipt.json"], files["delegation.json"] = rootPublic, proof.Module(), proof.Envelope(), proof.Delegation()
	expires := proof.ExpiresAt()
	credentialExpires := expires.Add(30 * time.Minute)
	manifest, err := functionMaterialDigest(files, expires, credentialExpires)
	if err != nil {
		t.Fatal(err)
	}
	grant := authority.FunctionBinding{TaskID: binding.TaskID, ServiceID: binding.ServiceID, NodeID: binding.NodeID,
		InstanceID: binding.InstanceID, Region: binding.Region, HostID: binding.HostID,
		Fingerprint: binding.Fingerprint, MaterialManifestSHA256: manifest}
	if _, err := runtime.CommitFunctionGrant(t.Context(), runtime.Current().Epoch, entityid.New(), 0, proof, grant); err != nil {
		t.Fatal(err)
	}
	return &functionMaterialTransport{controller: controller, conn: conn, authority: runtime, proof: proof,
		binding: binding, grant: grant, files: files, expires: expires, credentialExpires: credentialExpires, hostKey: hostKey, responseKey: responseKey}
}

func functionTransportProof(t *testing.T) (release.VerifiedFunction, ed25519.PublicKey) {
	t.Helper()
	module, err := hex.DecodeString("0061736d0100000001040160000003020100070a01065f737461727400000a040102000b")
	if err != nil {
		t.Fatal(err)
	}
	section := append([]byte{0}, bytes.Repeat([]byte{'x'}, 2*artifactChunkBytes)...)
	module = append(module, 0)
	module = binary.AppendUvarint(module, uint64(len(section)))
	module = append(module, section...)
	digest := sha256.Sum256(module)
	claim := release.FunctionClaim{Schema: release.FunctionSchema, ABI: release.FunctionABI, TenantID: entityid.New(),
		FunctionID: "echo", Revision: "first", Digest: hex.EncodeToString(digest[:]), Bytes: int64(len(module)),
		Environment: "production", Cell: "GRU", Sequence: 42}
	root, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leaf, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	scope := release.FunctionScope(claim)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: keyID, SubjectPublicKey: encodedPublic,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
			Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}},
	}, now.Add(-time.Minute), now.Add(2*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := release.SignFunctionClaim(claim, module, delegation, roots, leaf, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := release.VerifyFunctionCurrent(wire, grant, module, roots, release.FunctionExpectation{
		Environment: claim.Environment, Cell: claim.Cell, TenantID: claim.TenantID, FunctionID: claim.FunctionID,
		Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: claim.Sequence}, now)
	if err != nil {
		t.Fatal(err)
	}
	return proof, root
}
