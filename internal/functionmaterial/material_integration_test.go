package functionmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/functions"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

func TestControllerRecoversVaultPublicationBeforeImmutableRecipientGrant(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22 (Q-MAIN-GREEN), owner ts-orch consolidation thread: flaky on main and M1 PRs since the 2026-10-21 integration-line merge")
	now := time.Now().UTC().Truncate(time.Second)
	root, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		t.Fatal(err)
	}
	proof := materialProof(t, roots, private, 1)
	brokers := materialBrokerCluster(t)
	conn, err := nats.Connect(brokers[0].ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	control, err := authority.Start(t.Context(), js, authority.Config{DeploymentID: entityid.New(), Scope: "gru", CandidateID: entityid.New(), Replicas: 3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if _, err := control.CommitFunctionIntent(t.Context(), control.Current().Epoch, entityid.New(), 0, proof); err != nil {
		t.Fatal(err)
	}
	artifacts, err := js.CreateObjectStore(t.Context(), jetstream.ObjectStoreConfig{Bucket: "FUNCTION_INTEGRATION", Replicas: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifacts.PutBytes(t.Context(), "sha256-"+proof.Claim().Digest, proof.Module()); err != nil {
		t.Fatal(err)
	}
	material := generationtest.New(t, now)
	expected := bootstrap.MaterialGenerationExpectation{DeploymentID: entityid.New(), ClusterID: entityid.New(), Environment: "production", Cell: oci.RegionGRU, ControllerSlots: []string{"a"}}
	generation := material.Generation(expected, 1, "")
	sealed, err := bootstrap.SignMaterialGeneration(generation, now.Add(-time.Minute), now.Add(2*time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := bootstrap.VerifyMaterialGenerationChain([]trust.Envelope{sealed}, roots, expected, now)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := bootstrapmaterial.LoadControllerIssuer(generation, material.Files["controller-tls-issuer-cert.pem"], material.Files["controller-tls-issuer-key.pem"], material.Files["controller-account-signer.seed"])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuer.Wipe)
	accounts, err := brokerauth.OpenStore(t.Context(), js, "gru", control)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.Commit(t.Context(), control.Current().Epoch, material.CellID, strings.TrimSpace(string(material.Files["cell.jwt"])), 0); err != nil {
		t.Fatal(err)
	}
	public, err := NewPublicTrust(verified[0], material.Files["operator.jwt"], material.Files["ca.pem"], "tls://localhost:4222")
	if err != nil {
		t.Fatal(err)
	}
	wrongOperator := generationtest.New(t, now)
	if _, err := NewPublicTrust(verified[0], wrongOperator.Files["operator.jwt"], material.Files["ca.pem"], "tls://localhost:4222"); err == nil {
		t.Fatal("foreign operator was accepted")
	}
	vault, bundles, backend, target := materialVault(t)
	binding := Binding{TaskID: strings.Repeat("a", 25), ServiceID: strings.Repeat("b", 25), NodeID: strings.Repeat("c", 25), InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.worker", Region: "sa-saopaulo-1", HostID: entityid.New(), Fingerprint: strings.Repeat("a", 64)}
	reader := Reader{Authority: control, Artifacts: artifacts, Roots: func() trust.Keyring { return roots }, Accounts: accounts, Bundles: bundles, VaultID: target.VaultID, Trust: public, Recipient: Recipient{NodeID: binding.NodeID, InstanceID: binding.InstanceID, Region: binding.Region, HostID: binding.HostID}}
	checks := 0
	interrupted := errors.New("recipient disappeared after publication")
	controller := Controller{Reader: reader, Authority: control, Conn: conn, Issuer: issuer, Vault: vault, Versions: vault, Target: target, AuthorizeRecipient: func(_ context.Context, candidate Binding) error {
		if candidate != binding {
			return ErrMaterial
		}
		checks++
		if checks == 2 {
			return interrupted
		}
		return nil
	}}
	reader.AuthorizeRecipient = func(_ context.Context, candidate Binding) error {
		if candidate != binding {
			return ErrMaterial
		}
		return nil
	}
	if _, err := controller.Prepare(t.Context(), proof.Claim().TenantID, proof.Claim().FunctionID, binding); !errors.Is(err, interrupted) {
		t.Fatalf("publication interruption: %v", err)
	}
	if _, err := control.ReadFunctionGrant(t.Context(), binding.TaskID); !errors.Is(err, authority.ErrNotFound) {
		t.Fatalf("grant published before recipient recheck: %v", err)
	}
	backend.mu.Lock()
	original, err := decodeMaterial(backend.value)
	if err != nil {
		backend.mu.Unlock()
		t.Fatal(err)
	}
	previousKey := bytes.Clone(original.Files["broker.creds"])
	// Expire only the ungranted delivery to exercise conditional renewal.
	original.ExpiresAt = now.Add(-time.Minute)
	backend.value, err = json.Marshal(original)
	backend.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := controller.Prepare(t.Context(), proof.Claim().TenantID, proof.Claim().FunctionID, binding)
	if err != nil || !delivery.Valid() {
		t.Fatalf("recover durable publication: %v", err)
	}
	if delivery.Binding() != binding || delivery.MinimumSequence() != 1 || len(delivery.Files()) != 10 {
		t.Fatal("sealed delivery lost admitted scope")
	}
	oldSeed, err := jwt.ParseDecoratedUserNKey(previousKey)
	if err != nil {
		t.Fatal(err)
	}
	defer oldSeed.Wipe()
	newSeed, err := jwt.ParseDecoratedUserNKey(delivery.Files()["broker.creds"])
	if err != nil {
		t.Fatal(err)
	}
	defer newSeed.Wipe()
	oldPublic, _ := oldSeed.PublicKey()
	newPublic, _ := newSeed.PublicKey()
	if oldPublic != newPublic {
		t.Fatal("conditional recovery replaced the worker key")
	}
	backend.mu.Lock()
	creates, updates := backend.creates, backend.updates
	backend.mu.Unlock()
	if creates != 1 || updates != 1 {
		t.Fatalf("Vault creation/conditional update = %d/%d", creates, updates)
	}
	clone := delivery.Files()
	clone["broker.creds"][0] = 0
	if bytes.Equal(clone["broker.creds"], delivery.Files()["broker.creds"]) {
		t.Fatal("mutable delivery files")
	}
	queueScope, err := functions.QueueIdentity(functions.Manifest{ABI: proof.Claim().ABI, TenantID: proof.Claim().TenantID, FunctionID: proof.Claim().FunctionID, Revision: proof.Claim().Revision, Digest: proof.Claim().Digest})
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := js.KeyValue(t.Context(), queueScope.ReceiptBucket)
	if err != nil {
		t.Fatal(err)
	}
	receiptDigest := bytes.Repeat([]byte{1}, 32)
	receiptRevision, err := receipts.Create(t.Context(), "retained", receiptDigest)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{queueScope.Stream, "KV_" + queueScope.ReceiptBucket} {
		stream, err := js.Stream(t.Context(), name)
		if err != nil {
			t.Fatal(err)
		}
		config := stream.CachedInfo().Config
		config.Replicas = 1
		if _, err := js.UpdateStream(t.Context(), config); err != nil {
			t.Fatal(err)
		}
	}
	consumer, err := js.Consumer(t.Context(), queueScope.Stream, "worker")
	if err != nil {
		t.Fatal(err)
	}
	consumerConfig := consumer.CachedInfo().Config
	consumerConfig.Replicas = 1
	if _, err := js.UpdateConsumer(t.Context(), queueScope.Stream, consumerConfig); err != nil {
		t.Fatal(err)
	}
	grantBefore, err := control.ReadFunctionGrant(t.Context(), binding.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	assertLegacy := func() {
		t.Helper()
		for _, name := range []string{queueScope.Stream, "KV_" + queueScope.ReceiptBucket} {
			stream, err := js.Stream(t.Context(), name)
			if err != nil || stream.CachedInfo().Config.Replicas != 1 {
				t.Fatalf("denied migration changed %s: %v", name, err)
			}
		}
		consumer, err := js.Consumer(t.Context(), queueScope.Stream, "worker")
		if err != nil || consumer.CachedInfo().Config.Replicas != 1 {
			t.Fatalf("denied migration changed durable consumer: %v", err)
		}
	}
	authorize := controller.AuthorizeRecipient
	controller.AuthorizeRecipient = func(context.Context, Binding) error { return ErrMaterial }
	if _, err := controller.Prepare(t.Context(), proof.Claim().TenantID, proof.Claim().FunctionID, binding); err == nil {
		t.Fatal("unauthorized recipient migrated queue")
	}
	assertLegacy()
	controller.AuthorizeRecipient = func(context.Context, Binding) error { return nil }
	foreign := binding
	foreign.NodeID = strings.Repeat("d", 25)
	if _, err := controller.Prepare(t.Context(), proof.Claim().TenantID, proof.Claim().FunctionID, foreign); err == nil {
		t.Fatal("mismatched grant binding migrated queue")
	}
	assertLegacy()
	controller.AuthorizeRecipient = authorize
	trustExpiry := controller.Reader.Trust.expiresAt
	controller.Reader.Trust.expiresAt = now.Add(-time.Minute)
	if _, err := controller.Prepare(t.Context(), proof.Claim().TenantID, proof.Claim().FunctionID, binding); err == nil {
		t.Fatal("expired delivery trust migrated queue")
	}
	assertLegacy()
	controller.Reader.Trust.expiresAt = trustExpiry
	retried, err := controller.Prepare(t.Context(), proof.Claim().TenantID, proof.Claim().FunctionID, binding)
	if err != nil || !bytes.Equal(retried.Files()["broker.creds"], delivery.Files()["broker.creds"]) {
		t.Fatalf("immutable grant retry: %v", err)
	}
	for _, name := range []string{queueScope.Stream, "KV_" + queueScope.ReceiptBucket} {
		stream, err := js.Stream(t.Context(), name)
		if err != nil || stream.CachedInfo().Config.Replicas != 3 {
			t.Fatalf("existing grant did not migrate %s to R3: %v", name, err)
		}
	}
	consumer, err = js.Consumer(t.Context(), queueScope.Stream, "worker")
	if err != nil || consumer.CachedInfo().Config.Replicas != 0 || consumer.CachedInfo().Config.MemoryStorage {
		t.Fatalf("existing R1 durable consumer did not inherit R3 file storage: %v", err)
	}
	retained, err := receipts.Get(t.Context(), "retained")
	if err != nil || retained.Revision() != receiptRevision || !bytes.Equal(retained.Value(), receiptDigest) {
		t.Fatalf("migration changed retained receipt: %v", err)
	}
	grantAfter, err := control.ReadFunctionGrant(t.Context(), binding.TaskID)
	if err != nil || grantBefore.Sequence != grantAfter.Sequence || !bytes.Equal(grantBefore.Payload, grantAfter.Payload) {
		t.Fatalf("queue migration changed immutable grant: %v", err)
	}
	other := binding
	other.NodeID = strings.Repeat("d", 25)
	if _, err := reader.Current(t.Context(), other); err == nil {
		t.Fatal("foreign recipient read material")
	}
	credential, err := functions.VerifyWorkerCredentials(proof, material.CellID, strings.TrimSpace(string(material.Files["cell.jwt"])), delivery.Files()["broker.creds"])
	if err != nil {
		t.Fatal(err)
	}
	tlsExpiry, err := verifyTLS(delivery.Files(), proof)
	if err != nil {
		t.Fatal(err)
	}
	if !delivery.CredentialExpiresAt().Equal(minTime(credential.ExpiresAt, tlsExpiry)) {
		t.Fatal("delivery credential expiry differs from verified broker and TLS credentials")
	}
	verifyMaterialTLSConnection(t, delivery.Files(), proof)
	backend.mu.Lock()
	backend.value = append(backend.value, ' ')
	backend.mu.Unlock()
	if _, err := reader.Current(t.Context(), binding); err == nil {
		t.Fatal("modified Vault material passed immutable manifest")
	}
}

func materialProof(t *testing.T, roots trust.Keyring, root ed25519.PrivateKey, sequence uint64) release.VerifiedFunction {
	t.Helper()
	module := []byte("\x00asm\x01\x00\x00\x00")
	claim := release.FunctionClaim{Schema: release.FunctionSchema, ABI: release.FunctionABI, TenantID: entityid.New(), FunctionID: "echo", Revision: "v1", Digest: sum(module), Bytes: int64(len(module)), Environment: "production", Cell: "GRU", Sequence: sequence}
	public, leaf, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	scope := release.FunctionScope(claim)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded, Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), now.Add(2*time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := release.SignFunctionClaim(claim, module, delegation, roots, leaf, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(receipt)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := release.VerifyFunctionCurrent(wire, grant, module, roots, release.FunctionExpectation{Environment: claim.Environment, Cell: claim.Cell, TenantID: claim.TenantID, FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: sequence}, now)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

type vaultBackend struct {
	mu               sync.Mutex
	value            []byte
	name             string
	version          int64
	creates, updates int
	target           vaultsecret.Target
}

const materialSecretID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.function"

func materialVault(t *testing.T) (*ocivault.VaultsClient, *ocisecrets.SecretsClient, *vaultBackend, vaultsecret.Target) {
	t.Helper()
	backend := &vaultBackend{target: vaultsecret.Target{CompartmentID: "ocid1.compartment.oc1..function", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.function", KeyID: "ocid1.key.oc1.sa-saopaulo-1.function"}}
	endpoint := httptest.NewServer(http.HandlerFunc(backend.serve))
	t.Cleanup(endpoint.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..function", "ocid1.user.oc1..function", "sa-saopaulo-1", "fp", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	vault, err := ocivault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := ocisecrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	vault.Host, bundles.Host = endpoint.URL, endpoint.URL
	return &vault, &bundles, backend, backend.target
}

func (backend *vaultBackend) serve(w http.ResponseWriter, r *http.Request) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	write := func(value any) {
		wire, err := json.Marshal(value)
		if err != nil {
			http.Error(w, "encode", 500)
			return
		}
		_, _ = w.Write(wire)
	}
	metadata := func() map[string]any {
		return map[string]any{"id": materialSecretID, "vaultId": backend.target.VaultID, "secretName": backend.name, "lifecycleState": "ACTIVE", "currentVersionNumber": backend.version}
	}
	switch {
	case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/secrets"):
		if backend.name == "" {
			write([]any{})
			return
		}
		write([]any{metadata()})
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/secrets"):
		var input struct {
			SecretName    string `json:"secretName"`
			SecretContent struct {
				Content string `json:"content"`
			} `json:"secretContent"`
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if json.Unmarshal(body, &input) != nil || backend.name != "" {
			http.Error(w, "conflict", 409)
			return
		}
		value, err := base64.StdEncoding.DecodeString(input.SecretContent.Content)
		if err != nil {
			http.Error(w, "content", 400)
			return
		}
		backend.name, backend.value, backend.version = input.SecretName, value, 1
		backend.creates++
		w.WriteHeader(200)
		write(metadata())
	case r.Method == "GET" && strings.Contains(r.URL.Path, "/secrets/"):
		w.Header().Set("ETag", fmt.Sprint(backend.version))
		write(metadata())
	case r.Method == "PUT" && strings.Contains(r.URL.Path, "/secrets/"):
		if r.Header.Get("If-Match") != fmt.Sprint(backend.version) {
			http.Error(w, "changed", 412)
			return
		}
		var input struct {
			SecretContent struct {
				Content string `json:"content"`
			} `json:"secretContent"`
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if json.Unmarshal(body, &input) != nil {
			http.Error(w, "content", 400)
			return
		}
		value, err := base64.StdEncoding.DecodeString(input.SecretContent.Content)
		if err != nil {
			http.Error(w, "content", 400)
			return
		}
		backend.value = value
		backend.version++
		backend.updates++
		write(metadata())
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/secretbundles/actions/getByName"):
		write(map[string]any{"secretId": materialSecretID, "versionNumber": backend.version, "secretBundleContent": map[string]any{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString(backend.value)}})
	default:
		http.Error(w, "unknown route", 404)
	}
}

func verifyMaterialTLSConnection(t *testing.T, files map[string][]byte, proof release.VerifiedFunction) {
	t.Helper()
	cert, err := tls.X509KeyPair(files["ingress-cert.pem"], files["ingress-key.pem"])
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	endpoint.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	endpoint.StartTLS()
	defer endpoint.Close()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(files["ingress-ca.pem"])
	claim := proof.Claim()
	name := claim.FunctionID + "." + strings.ToLower(claim.TenantID) + ".functions.gru.terrascale.internal"
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: name}}}
	defer client.CloseIdleConnections()
	response, err := client.Get(endpoint.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("function TLS endpoint unavailable")
	}
}

func materialBrokerCluster(t *testing.T) []*server.Server {
	t.Helper()
	var brokers []*server.Server
	for index := range 3 {
		routeAddress := "nats-route://127.0.0.1:1"
		if index != 0 {
			routeAddress = "nats-route://" + brokers[0].ClusterAddr().String()
		}
		route, err := url.Parse(routeAddress)
		if err != nil {
			t.Fatal(err)
		}
		broker, err := server.NewServer(&server.Options{ServerName: fmt.Sprintf("material-r3-%d", index), Host: "127.0.0.1", Port: -1,
			JetStream: true, StoreDir: t.TempDir(), Cluster: server.ClusterOpts{Name: "material-r3", Host: "127.0.0.1", Port: -1}, Routes: []*url.URL{route}})
		if err != nil {
			t.Fatal(err)
		}
		go broker.Start()
		if !broker.ReadyForConnections(5 * time.Second) {
			t.Fatal("material R3 broker did not start")
		}
		brokers = append(brokers, broker)
		t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		ready := false
		for _, broker := range brokers {
			ready = ready || (broker.JetStreamIsLeader() && len(broker.JetStreamClusterPeers()) == 3)
		}
		for _, broker := range brokers {
			ready = ready && broker.JetStreamIsCurrent()
		}
		if ready {
			return brokers
		}
		select {
		case <-ctx.Done():
			t.Fatal("material R3 metadata unavailable: ", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}
