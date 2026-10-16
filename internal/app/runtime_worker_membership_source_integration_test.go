package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

// This qualifies the shared concrete source over real JetStream. Swarm TLS join,
// live OCI/Vault verification and the fixed child are separate boundaries.
func TestWorkerMembershipSourceReadsOrderedAdmissionAndRevocation(t *testing.T) {
	ctx := t.Context()
	js, observer := testRolloutJetStreamWithObserver(t, hostenroll.GrantBucket)
	control, err := authority.Start(ctx, js, authority.Config{DeploymentID: entityid.New(), Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	artifacts, err := js.CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket})
	if err != nil {
		t.Fatal(err)
	}
	responsePublic, responseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := host.NewController(ctx, host.ControllerConfig{Cell: "gru", Conn: js.Conn(), JS: js, Artifacts: artifacts,
		ResponseKey: responseKey, StateReplicas: 1, HostMutations: control, AuthorityEpoch: func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard})
	if err != nil {
		t.Fatal(err)
	}
	hostPublic, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	natsKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer natsKey.Wipe()
	natsPublic, err := natsKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	descriptor := hostboot.Static("gru", "GRU", "ts-gru-4")
	descriptorWire, err := protocol.EncodeJSON(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	registration := host.Registration{Cell: "gru", Node: descriptor.Node, Environment: "canary", Roles: []string{"function-worker"}, Generation: 1,
		PublicKey: base64.StdEncoding.EncodeToString(hostPublic), NATSUserPublicKey: natsPublic}
	receipt, err := hosts.Register(ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	registration.ID = entityid.Derive("host", registration.Cell, registration.Node)
	now := time.Now().UTC()
	ca, caPEM, _ := generationtest.Certificate(t, generationtest.CA("actual membership signature chain", now, now.Add(time.Hour)), nil)
	nodeID, swarmID := entityid.New(), entityid.New()
	node, certificate, _ := generationtest.Certificate(t, &x509.Certificate{Subject: pkix.Name{CommonName: nodeID, Organization: []string{swarmID}, OrganizationalUnit: []string{"swarm-worker"}},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, &ca)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, node.Key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	request := hostenroll.Request{SchemaVersion: 1, Operation: "enroll", InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.membership",
		Descriptor: string(descriptorWire), IdentityPublicKey: registration.PublicKey, NATSUserPublicKey: natsPublic,
		CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), Nonce: base64.StdEncoding.EncodeToString(nonce), IssuedAt: now}
	if err := request.Sign(hostKey); err != nil {
		t.Fatal(err)
	}
	requestWire, err := protocol.EncodeJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	worker := hostenroll.SwarmWorker{Version: 1, DeploymentID: entityid.New(), ClusterID: entityid.New(), Environment: registration.Environment, Cell: "gru", Region: "sa-saopaulo-1", OCIRegion: "sa-saopaulo-1",
		FounderID: "controller-a", RegistrationID: registration.ID, Generation: receipt.Generation, Revision: receipt.Revision, InstanceID: request.InstanceID,
		PrivateIP: "10.0.0.2", Architecture: runtime.GOARCH, Role: "wasm", ManagerAddress: "10.0.0.1:2377", SwarmID: swarmID, CAPEM: string(caPEM),
		SecretID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.membership", SecretVersion: 1, SecretSHA256: strings.Repeat("a", 64), IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	descriptorDigest, err := descriptor.Digest()
	if err != nil {
		t.Fatal(err)
	}
	// Two real completed enrollment responses make the persisted grant exceed the
	// old 64 KiB source limit while each signed response stays below 32 KiB.
	response := hostenroll.Response{SchemaVersion: 1, Operation: request.Operation, InstanceID: request.InstanceID, Node: descriptor.Node,
		DescriptorSHA256: descriptorDigest, RequestSHA256: hostenroll.RequestSHA256(requestWire), Nonce: request.Nonce, RegistrationReceipt: receipt,
		Swarm: &worker, NATSUserJWT: "separate-host-delivery-jwt", TLSCertificatePEM: string(certificate) + strings.Repeat(" ", 22000), ExpiresAt: now.Add(10 * time.Minute)}
	if err := response.Sign(responseKey); err != nil {
		t.Fatal(err)
	}
	responseWire, err := protocol.EncodeJSON(response)
	if err != nil {
		t.Fatal(err)
	}
	// The durable enrollment response precedes the separately signed worker
	// projection and therefore contains no Swarm join material.
	baseResponse := response
	baseResponse.Swarm = nil
	if err := baseResponse.Sign(responseKey); err != nil {
		t.Fatal(err)
	}
	baseResponseWire, err := protocol.EncodeJSON(baseResponse)
	if err != nil {
		t.Fatal(err)
	}
	transport := hostenroll.WorkerTransport{Request: requestWire, Response: responseWire}
	wire, err := protocol.EncodeJSON(transport)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := hostenroll.VerifyWorkerTransport(wire, responsePublic, hostenroll.InstanceMetadata{InstanceID: request.InstanceID, Descriptor: descriptor}, runtime.GOARCH, now)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := hostenroll.SignWorkerBinding(accepted, nodeID, hostKey, node.Key, now)
	if err != nil {
		t.Fatal(err)
	}
	record := hostenroll.SwarmMembership{Transport: transport, Binding: binding, Certificate: certificate}
	grants, err := hostenroll.OpenGrantStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	grant, revision, err := grants.Claim(ctx, hostenroll.Grant{SchemaVersion: 1, InstanceID: request.InstanceID, CreateKey: entityid.New(), DescriptorSHA256: descriptorDigest, Request: requestWire})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grants.Finish(ctx, grant, revision, baseResponseWire); err != nil {
		t.Fatal(err)
	}
	grant, revision, err = grants.ClaimRenew(ctx, request.InstanceID, requestWire, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := grants.FinishRenew(ctx, grant, revision, baseResponseWire, now); err != nil {
		t.Fatal(err)
	}
	mutations, err := authority.OpenReader(ctx, js, "gru")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := host.NewReader(ctx, host.ReaderConfig{Cell: "gru", Conn: js.Conn(), JS: js, StateReplicas: 1, HostMutations: mutations})
	if err != nil {
		t.Fatal(err)
	}
	source, err := hostenroll.NewWorkerMembershipSource(ctx, mutations, reader, grants, js, "gru", responsePublic)
	if err != nil {
		t.Fatal(err)
	}
	read := func(query hostenroll.WorkerMembershipQuery) (hostenroll.WorkerMembershipSnapshot, error) {
		finish := assertGrantReadsUseLeader(t, observer)
		defer finish()
		return source.Read(ctx, query)
	}
	query := hostenroll.WorkerMembershipQuery{NodeID: nodeID, RegistrationID: registration.ID, InstanceID: request.InstanceID}
	if _, err := read(query); err == nil {
		t.Fatal("an enrollment grant without durable dual-key membership became current")
	}
	query.Admission = &record
	published, err := read(query)
	if err != nil || published.Admission == nil || published.Sequence != receipt.Revision || published.Retired || published.Disabled {
		t.Fatalf("actual membership CAS/readback: %+v %v", published, err)
	}
	held, _, err := hostenroll.ReadCurrentGrant(ctx, js, request.InstanceID)
	if err != nil || held.SwarmMembership == nil {
		t.Fatal("successful source reply preceded durable membership", err)
	}
	heldWire, err := protocol.EncodeJSON(held)
	if err != nil || len(heldWire) <= 64<<10 || len(heldWire) > hostenroll.MaxGrantBytes {
		t.Fatalf("grant bound was not exercised: bytes=%d err=%v", len(heldWire), err)
	}
	query.Admission = nil
	source, err = hostenroll.NewWorkerMembershipSource(ctx, mutations, reader, grants, js, "gru", responsePublic)
	if err != nil {
		t.Fatal(err)
	}
	current, err := read(query)
	if err != nil || current.GrantRevision != published.GrantRevision || !bytes.Equal(current.Admission.Transport.Response, responseWire) {
		t.Fatal("fresh reader lost retained signed admission", err)
	}
	foreign := query
	foreign.NodeID = entityid.New()
	if _, err := read(foreign); err == nil {
		t.Fatal("another node inherited retained membership")
	}
	if retired, err := hosts.RetireIdle(ctx, registration.Node); err != nil || !retired {
		t.Fatal("actual host retirement failed", err)
	}
	retired, err := read(query)
	if err != nil || !retired.Retired {
		t.Fatal("ordered retirement became unavailable instead of verified revocation", err)
	}
	query.Admission = &record
	if _, err := read(query); err == nil {
		t.Fatal("retired host republished placement admission")
	}
	query.Admission = nil
	if _, err := grants.Disable(ctx, request.InstanceID); err != nil {
		t.Fatal(err)
	}
	disabled, err := read(query)
	if err != nil || !disabled.Disabled {
		t.Fatal("leader grant read lost verified disable", err)
	}
	if err := grants.Forget(ctx, request.InstanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := read(query); err == nil {
		t.Fatal("deleted enrollment grant remained current")
	}
}
