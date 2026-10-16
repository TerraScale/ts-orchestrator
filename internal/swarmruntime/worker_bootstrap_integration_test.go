package swarmruntime

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nkeys"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// Starts after current registration authority: the pinned enrollment signature,
// OCI Secrets SDK, TLS join, dual-key proof and durable floor are real.
func TestWorkerBootstrapIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	managerConfig := nodeFixtureConfig(t, "founder", "manager")
	manager := nodeFixtureStart(t, ctx, managerConfig)
	client, err := manager.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		t.Fatal("actual regional cluster unavailable", err)
	}
	cluster := clusters.Clusters[0]
	address, err := manager.RemoteAddress()
	if err != nil {
		t.Fatal(err)
	}
	fixture, vault, bundles := bootstrapVaultServer(t)
	responsePublic, responseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPublic, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := hostboot.Static("gru", "GRU", "ts-gru-4")
	descriptorWire, err := protocol.EncodeJSON(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	natsKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	natsPublic, err := natsKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := hostenroll.Request{SchemaVersion: 1, Operation: "enroll", InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.worker",
		Descriptor: string(descriptorWire), IdentityPublicKey: base64.StdEncoding.EncodeToString(hostPublic), NATSUserPublicKey: natsPublic,
		CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), Nonce: base64.StdEncoding.EncodeToString(nonce), IssuedAt: now}
	if err := request.Sign(hostKey); err != nil {
		t.Fatal(err)
	}
	requestWire, err := protocol.EncodeJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	material := workerJoinMaterial{Version: 1, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", ClusterID: "0000000000RMSAJ9B0JFV7ESHN", Environment: "production",
		Region: "sa-saopaulo-1", FounderID: "founder", RegistrationID: entityid.Derive("host", descriptor.Cell, descriptor.Node), InstanceID: request.InstanceID,
		Role: "container", Architecture: runtime.GOARCH, SwarmID: cluster.ID, CAPEM: string(cluster.RootCA.CACert), ManagerAddress: address, WorkerToken: cluster.RootCA.JoinTokens.Worker}
	materialWire, err := json.Marshal(material)
	if err != nil {
		t.Fatal(err)
	}
	name := "integration-recipient-worker"
	target := vaultsecret.Target{CompartmentID: "ocid1.compartment.oc1..control", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.control", KeyID: "ocid1.key.oc1.sa-saopaulo-1.control"}
	stored, err := vaultsecret.Ensure(ctx, vault, target, name, "integration worker-only material", func(context.Context) (string, error) { return string(materialWire), nil })
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(materialWire)
	signed := hostenroll.SwarmWorker{Version: 1, DeploymentID: material.DeploymentID, ClusterID: material.ClusterID, Environment: material.Environment, Cell: descriptor.Cell,
		Region: material.Region, OCIRegion: material.Region, FounderID: material.FounderID, RegistrationID: material.RegistrationID, Generation: 1, Revision: 1,
		InstanceID: material.InstanceID, PrivateIP: "127.0.0.2", Architecture: material.Architecture, Role: material.Role, ManagerAddress: address, SwarmID: material.SwarmID, CAPEM: material.CAPEM,
		SecretID: stored.ID, SecretVersion: 1, SecretSHA256: hex.EncodeToString(digest[:]), IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	metadata := hostenroll.InstanceMetadata{InstanceID: request.InstanceID, Descriptor: descriptor}
	transport := func(worker hostenroll.SwarmWorker) []byte {
		t.Helper()
		descriptorDigest, err := descriptor.Digest()
		if err != nil {
			t.Fatal(err)
		}
		response := hostenroll.Response{SchemaVersion: 1, Operation: request.Operation, InstanceID: request.InstanceID, Node: descriptor.Node,
			DescriptorSHA256: descriptorDigest, RequestSHA256: hostenroll.RequestSHA256(requestWire), Nonce: request.Nonce,
			RegistrationReceipt: host.Receipt{Generation: worker.Generation, Revision: worker.Revision}, Swarm: &worker,
			NATSUserJWT: "signed-enrollment-projection-fixture", TLSCertificatePEM: "separate-enrollment-chain", ExpiresAt: now.Add(10 * time.Minute)}
		if err := response.Sign(responseKey); err != nil {
			t.Fatal(err)
		}
		responseWire, err := protocol.EncodeJSON(response)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := protocol.EncodeJSON(hostenroll.WorkerTransport{Request: requestWire, Response: responseWire})
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	verify := func(worker hostenroll.SwarmWorker) hostenroll.VerifiedSwarmWorker {
		t.Helper()
		accepted, err := hostenroll.VerifyWorkerTransport(transport(worker), responsePublic, metadata, runtime.GOARCH, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		return accepted
	}
	accepted := verify(signed)
	for _, scenario := range []struct {
		name   string
		mutate func(*hostenroll.SwarmWorker)
	}{
		{"wrong-instance", func(worker *hostenroll.SwarmWorker) { worker.InstanceID += "-other" }},
		{"wrong-architecture", func(worker *hostenroll.SwarmWorker) {
			worker.Architecture = "arm64"
			if runtime.GOARCH == "arm64" {
				worker.Architecture = "amd64"
			}
		}},
		{"manager-role", func(worker *hostenroll.SwarmWorker) { worker.Role = "manager" }},
		{"expired", func(worker *hostenroll.SwarmWorker) { worker.ExpiresAt = now.Add(-time.Second) }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			changed := signed
			scenario.mutate(&changed)
			if _, err := hostenroll.VerifyWorkerTransport(transport(changed), responsePublic, metadata, runtime.GOARCH, time.Now().UTC()); err == nil {
				t.Fatal("accepted mismatched signed projection")
			}
		})
	}
	directory := t.TempDir()
	worker, err := startAcceptedWorkerAt(ctx, directory, accepted, bundles, nodeIdleExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nodeFixtureStop(t, worker) })
	if _, err := worker.ControlClient(ctx); err == nil {
		t.Fatal("recipient worker acquired manager control")
	}
	certificate, err := os.ReadFile(filepath.Join(directory, "node", "certificates", "swarm-node.crt"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := worker.WorkerBinding(accepted, hostKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := hostenroll.VerifyWorkerBinding(binding, accepted, hostPublic, certificate, time.Now().UTC()); err != nil {
		t.Fatal("real joined certificate did not verify both identity keys", err)
	}
	_, wrongHost, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongBinding, err := worker.WorkerBinding(accepted, wrongHost)
	if err != nil {
		t.Fatal(err)
	}
	if err := hostenroll.VerifyWorkerBinding(wrongBinding, accepted, hostPublic, certificate, time.Now().UTC()); err == nil {
		t.Fatal("accepted a different enrolled host key")
	}
	wrongBinding, err = hostenroll.SignWorkerBinding(accepted, worker.ID(), hostKey, csrKey, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := hostenroll.VerifyWorkerBinding(wrongBinding, accepted, hostPublic, certificate, time.Now().UTC()); err == nil {
		t.Fatal("accepted possession of host key without actual Swarm key")
	}
	if err := hostenroll.VerifyWorkerBinding(binding, accepted, hostPublic, certificate, binding.ExpiresAt); err == nil {
		t.Fatal("accepted expired post-join binding")
	}
	if _, err := AdmitNode(ctx, client, worker.ID(), Admission{Region: signed.Region, HostID: signed.RegistrationID, InstanceID: signed.InstanceID, FounderID: signed.FounderID, Role: signed.Role}); err != nil {
		t.Fatal(err)
	}
	registered, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: worker.ID()})
	if err != nil || registered.Node.Spec.Annotations.Name != signed.RegistrationID || registered.Node.Spec.Annotations.Labels[LabelRegion] != signed.Region {
		t.Fatal("verified worker did not acquire canonical placement", err)
	}
	nodeFixtureStop(t, worker)
	workerID := worker.ID()
	restarted, err := startAcceptedWorkerAt(ctx, directory, accepted, bundles, nodeIdleExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	worker = restarted
	if worker.ID() != workerID {
		t.Fatal("worker restart changed its actual certificate", err)
	}
	nodeFixtureStop(t, worker)
	advanced := signed
	advanced.Generation, advanced.Revision = 2, 3
	if err := persistWorkerEnrollment(directory, verify(advanced)); err != nil {
		t.Fatal(err)
	}
	if _, err := startAcceptedWorkerAt(ctx, directory, accepted, bundles, nodeIdleExecutor{}); err == nil {
		t.Fatal("worker restart accepted rollback below its durable enrollment floor")
	}
	changedRole := advanced
	changedRole.Role = "wasm"
	if _, err := startAcceptedWorkerAt(ctx, directory, verify(changedRole), bundles, nodeIdleExecutor{}); err == nil {
		t.Fatal("worker restart accepted a changed execution role")
	}
	fixture.mu.Lock()
	fixture.values[name] = base64.StdEncoding.EncodeToString([]byte(cluster.RootCA.JoinTokens.Manager))
	fixture.mu.Unlock()
	if _, err := startAcceptedWorkerAt(ctx, t.TempDir(), accepted, bundles, nodeIdleExecutor{}); err == nil {
		t.Fatal("recipient read accepted substituted manager material")
	}
}
