package materialsource

import (
	"bytes"
	"context"
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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
	"golang.org/x/sys/unix"
)

// This fixture exercises public DATA and persistence mechanics, not a sealed
// actor. The fixed production actor constructor is tested in region; these
// helper scenarios do not qualify the composed constructor-to-archive path.
func originalMechanicalInputs(t *testing.T) originalSourceInputs {
	t.Helper()
	digest := strings.Repeat("a", 64)
	cfg := bootstrapmaterial.Config{Environment: "production", Region: "sa-saopaulo-1", Cell: "gru",
		DeploymentID: "0000000000F9PR1WNVDTEXS31Z", ClusterID: "0000000000RMSAJ9B0JFV7ESHN", SubnetCIDR: "10.251.0.0/24", ValidityHours: 48,
		Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.11"}, {Name: "controller-b", PrivateIP: "10.251.0.12"}, {Name: "controller-c", PrivateIP: "10.251.0.13"}}}
	wire, err := json.Marshal(cfg, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	installation := "0000000000YTR4D9RJ6W8NG1HC"
	home := bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "gru-1-head", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", LedgerBucket: "gru-1-ledger", LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", Prefix: "bootstrap"}
	authorization := release.AdmissionAttestorAuthorization{Schema: release.AdmissionAttestorAuthorizationSchema, Domain: "terrascale.release.container-admission", Action: "reserve", SourceBinding: "original-source-inventory.v1",
		TenancyID: "ocid1.tenancy.oc1..test", InstallationID: installation, DeploymentID: cfg.DeploymentID, ClusterID: cfg.ClusterID, Cell: "GRU", Environment: cfg.Environment, Generation: 1,
		ControllerSlots: [3]string{"controller-a", "controller-b", "controller-c"}, Roles: [3]string{"function-worker", "terrabase", "ts-auth"}, PlanSHA256: digestWire(wire), WorkloadGenesisSHA256: digest, SourceRegistrationSHA256: digest,
		SourceNamespace: "ns", SourceBucket: "gru-1-head", SourceObject: "bootstrap/bootstrap/v2/material-source/original-test.json"}
	authSHA, err := authorization.Digest()
	if err != nil {
		t.Fatal(err)
	}
	intent := region.OriginalSourceProducerIntent{Purpose: originalSourceKind, TenancyID: authorization.TenancyID, InstallationID: installation, Cell: "GRU", OCIRegion: cfg.Region, Generation: 1,
		PlanSHA256: authorization.PlanSHA256, AdmissionAuthorizationSHA256: authSHA, Home: home, SourceObject: authorization.SourceObject, SourceSecretName: "ts-bootstrap-source-originaltest",
		Escrow: bootstrapmaterial.VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..control", VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.vault", KMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head"}}
	intentWire, err := json.Marshal(intent, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	scope := region.OriginalSourceActorScope{SHA256: digest, InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.original", Cell: "GRU", InstallationID: installation, Generation: 1, GrantSHA256: digest,
		BundleSHA256: digest, BirthSHA256: digest, ActorRequestSHA256: digest, ActorReadbackSHA256: digest, SourceIAMSHA256: digest, AdmissionReadsSHA256: digest, PublicationSHA256: digest,
		PlanSHA256: authorization.PlanSHA256, TemplateSHA256: digest, Deadline: time.Now().UTC().Add(time.Hour)}
	return originalSourceInputs{scope: scope, intent: intent, config: cfg, admission: authorization, intentSHA: digestWire(intentWire), admissionSHA: authSHA}
}

type originalMechanicalSDK struct {
	mu               sync.Mutex
	t                *testing.T
	in               originalSourceInputs
	state            []byte
	secret           []byte
	secretID         string
	fault            string
	faulted          bool
	creates          int
	byName, metadata int
	material         *originalMaterialSDK
}

func (f *originalMechanicalSDK) fail(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
	io.WriteString(w, `{"code":"NotAuthorizedOrNotFound","message":"mechanical fixture response"}`)
}

func (f *originalMechanicalSDK) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
		f.t.Error("mechanical request lacks actual OCI SDK signing")
	}
	q := f.in.intent
	if f.material != nil && f.serveMaterial(w, r) {
		return
	}
	if r.URL.Path == "/n/ns/b/gru-1-head/o/"+q.SourceObject {
		if r.Host != "objectstorage.sa-saopaulo-1.oraclecloud.com" {
			f.t.Error("source object escaped fixed HOME host")
		}
		if r.Method == http.MethodGet {
			if f.state == nil {
				f.fail(w, 404)
				return
			}
			w.Header().Set("etag", digestWire(f.state))
			w.Write(f.state)
			return
		}
		if r.Method != http.MethodPut {
			f.t.Error("unexpected source object operation")
			f.fail(w, 400)
			return
		}
		if r.Header.Get("opc-sse-kms-key-id") != q.Home.HeadKMSKeyOCID {
			f.t.Error("source CAS omitted exact signed KMS key")
		}
		if f.state == nil && r.Header.Get("If-None-Match") != "*" || f.state != nil && r.Header.Get("If-Match") != digestWire(f.state) {
			f.fail(w, 412)
			return
		}
		wire, err := io.ReadAll(io.LimitReader(r.Body, originalSourceStateLimit+1))
		var next originalSourceState
		if err != nil || json.Unmarshal(wire, &next) != nil || next.SchemaVersion != 3 || next.Kind != "original-source-archive/v1" || next.Scope.InstanceID != f.in.scope.InstanceID {
			f.t.Error("invalid original source reservation DATA")
		}
		if f.fault == "reservation refused" && !f.faulted {
			f.faulted = true
			f.fail(w, 503)
			return
		}
		if f.material != nil {
			var previous originalSourceState
			if json.Unmarshal(f.state, &previous) != nil || !validOriginalState(next, f.in) || !immutableOriginalState(previous, next) {
				f.t.Error("material checkpoint escaped monotone protected state")
				f.fail(w, 400)
				return
			}
			if f.material.fault == "journal refused" && next.Publication != nil && len(next.Publication.Journal) > 0 && !bytes.Equal(previous.Publication.Journal, next.Publication.Journal) {
				f.fail(w, 503)
				return
			}
		}
		f.state = bytes.Clone(wire)
		if f.fault == "lost CAS response" && !f.faulted {
			f.faulted = true
			f.fail(w, 503)
			return
		}
		w.Header().Set("etag", digestWire(wire))
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/20180608/secrets" {
		if r.Host != "vaults.sa-saopaulo-1.oci.oraclecloud.com" {
			f.t.Error("Vault create escaped fixed HOME host")
		}
		var saved originalSourceState
		if json.Unmarshal(f.state, &saved) != nil || saved.Candidate.SHA256 == "" || saved.Candidate.CreateSHA256 == "" {
			f.t.Error("Vault effect preceded durable candidate CAS")
		}
		wire, err := io.ReadAll(io.LimitReader(r.Body, 128<<10))
		var details struct {
			CompartmentID string `json:"compartmentId"`
			VaultID       string `json:"vaultId"`
			KeyID         string `json:"keyId"`
			SecretName    string `json:"secretName"`
			SecretContent struct {
				Content string `json:"content"`
				Stage   string `json:"stage"`
			} `json:"secretContent"`
		}
		if err != nil || json.Unmarshal(wire, &details) != nil || details.CompartmentID != q.Escrow.CompartmentOCID || details.VaultID != q.Escrow.VaultOCID || details.KeyID != q.Escrow.KMSKeyOCID || details.SecretName != q.SourceSecretName || details.SecretContent.Stage != "CURRENT" || r.Header.Get("opc-retry-token") != saved.RetryToken {
			f.t.Error("Vault request escaped exact pinned original scope")
		}
		body, err := base64.StdEncoding.Strict().DecodeString(details.SecretContent.Content)
		if err != nil || digestWire(body) != saved.Candidate.SHA256 || int64(len(body)) != saved.Candidate.MaxBytes {
			f.t.Error("Vault request replaced pinned candidate bytes")
		}
		var request map[string]any
		if err := json.Unmarshal(wire, &request); err != nil {
			f.t.Error(err)
		}
		canonical, err := json.Marshal(request, json.Deterministic(true))
		if err != nil || digestWire(append([]byte(r.Header.Get("opc-retry-token")+"\x00"), canonical...)) != saved.Candidate.CreateSHA256 {
			f.t.Error("actual SDK body/token differs from durable request digest")
		}
		f.creates++
		if f.secret != nil && !bytes.Equal(body, f.secret) {
			f.t.Error("same original secret name was rekeyed")
		}
		f.secret = bytes.Clone(body)
		if f.fault == "lost create response" && !f.faulted {
			f.faulted = true
			f.fail(w, 503)
			return
		}
		json.MarshalWrite(w, ocivault.Secret{Id: new(f.secretID)})
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/20190301/secretbundles/actions/getByName" {
		if r.Host != "secrets.vaults.sa-saopaulo-1.oci.oraclecloud.com" || r.URL.Query().Get("secretName") != q.SourceSecretName || r.URL.Query().Get("vaultId") != q.Escrow.VaultOCID || r.URL.Query().Get("versionNumber") != "1" || r.URL.Query().Get("stage") != "" {
			f.t.Error("source lookup escaped exact named Vault version1")
		}
		f.byName++
		if f.secret == nil || f.fault == "bundle absent" {
			f.fail(w, 404)
			return
		}
		version := int64(1)
		if f.fault == "bundle version2" {
			version = 2
		}
		body := f.secret
		if f.fault == "bundle conflict" {
			body = []byte("different original archive")
		}
		json.MarshalWrite(w, ocisecrets.SecretBundle{SecretId: new(f.secretID), VersionNumber: new(version), SecretBundleContent: ocisecrets.Base64SecretBundleContentDetails{Content: new(base64.StdEncoding.EncodeToString(body))}})
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/20180608/secrets/"+f.secretID {
		if r.Host != "vaults.sa-saopaulo-1.oci.oraclecloud.com" {
			f.t.Error("secret metadata escaped fixed HOME host")
		}
		f.metadata++
		secret := ocivault.Secret{Id: new(f.secretID), CompartmentId: new(q.Escrow.CompartmentOCID), VaultId: new(q.Escrow.VaultOCID), KeyId: new(q.Escrow.KMSKeyOCID), SecretName: new(q.SourceSecretName), CurrentVersionNumber: new(int64(1)), LifecycleState: ocivault.SecretLifecycleStateActive}
		if f.fault == "metadata wrong key" {
			secret.KeyId = new("ocid1.key.oc1.sa-saopaulo-1.foreign")
		}
		if f.fault == "metadata version2" {
			secret.CurrentVersionNumber = new(int64(2))
		}
		if f.fault == "metadata pending deletion" {
			secret.LifecycleState = ocivault.SecretLifecycleStatePendingDeletion
		}
		json.MarshalWrite(w, secret)
		return
	}
	f.t.Errorf("unexpected mechanical SDK operation %s %s%s", r.Method, r.Host, r.URL.RequestURI())
	f.fail(w, 400)
}

func newOriginalMechanicalSDK(t *testing.T, in originalSourceInputs, fault string) (*originalMechanicalSDK, originalSourceClients) {
	t.Helper()
	f := &originalMechanicalSDK{t: t, in: in, fault: fault, secretID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.original"}
	server := httptest.NewTLSServer(f)
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() {
		t.Fatal("mechanical SDK fixture requires literal loopbackTLS")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("mechanical fixture denies plaintext and proxies")
	}
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("unexpected network %q", network)
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..mechanical", "sa-saopaulo-1", "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	objects, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := ocisecrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []*common.BaseClient{&objects.BaseClient, &management.BaseClient, &bundles.BaseClient} {
		client.HTTPClient = &http.Client{Transport: transport}
		policy := common.NoRetryPolicy()
		client.Configuration.RetryPolicy = &policy
		ociclient.ConfigureRequestCancellation(client)
	}
	return f, originalSourceClients{&objects, &management, &bundles}
}

func pinMechanicalCandidate(t *testing.T, in originalSourceInputs, clients originalSourceClients, directory string) (originalSourceState, string, []byte) {
	t.Helper()
	state := originalState(in, time.Now().UTC())
	etag, err := writeOriginalState(t.Context(), t.Context(), clients.objects, in, state, "")
	if err != nil {
		t.Fatal(err)
	}
	dir, unlock, err := lockOriginalDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	body, err := generateOriginalCandidate(directory, in, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistOriginalCandidate(directory, dir, body); err != nil {
		t.Fatal(err)
	}
	requestSHA, err := originalCreateSHA(state, body)
	if err != nil {
		t.Fatal(err)
	}
	state.Candidate = originalSourceCandidate{SHA256: digestWire(body), MaxBytes: int64(len(body)), CreateSHA256: requestSHA}
	etag, err = writeOriginalState(t.Context(), t.Context(), clients.objects, in, state, etag)
	if err != nil {
		t.Fatal(err)
	}
	return state, etag, body
}

func TestOriginalSourceArchiveRefusesUnsealedActor(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "original")
	if archive, err := ResolveOriginalSourceArchive(t.Context(), region.VerifiedOriginalSourceActor{}, directory, time.Now()); err == nil || archive.IsVerified() {
		t.Fatal("zero original proof acquired archive authority")
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("zero proof performed local candidate effects")
	}
	if (VerifiedOriginalSourceArchive{}).VerifyCurrent(t.Context()) == nil {
		t.Fatal("zero archive proof passed currentness")
	}
}

func TestOriginalSourceArchiveSDKMechanicalRecovery(t *testing.T) {
	in := originalMechanicalInputs(t)
	f, clients := newOriginalMechanicalSDK(t, in, "lost CAS response")
	directory := filepath.Join(t.TempDir(), "original")
	state, etag, candidate := pinMechanicalCandidate(t, in, clients, directory)
	defer clear(candidate)
	if !f.faulted || f.creates != 0 {
		t.Fatal("candidate pin failed exact recovery or created Vault material early")
	}
	f.mu.Lock()
	f.fault = "lost create response"
	f.faulted = false
	f.mu.Unlock()
	request := originalCreateRequest(state, candidate)
	if _, err := clients.management.CreateSecret(ociclient.RequestContext(t.Context()), request); err == nil {
		t.Fatal("lost create response did not exercise uncertainty")
	}
	body, id, err := readOriginalVault(t.Context(), clients, state)
	if err != nil || !bytes.Equal(body, candidate) || f.creates != 1 || f.byName == 0 || f.metadata == 0 {
		t.Fatal("exact named Vault-v1 recovery changed bytes or repeated a create", err)
	}
	defer clear(body)
	archive, record, err := decodeOriginalCandidate(directory, in, state, body)
	if err != nil {
		t.Fatal(err)
	}
	defer clearArchive(archive)
	state.Reference = materialSourceReference{SecretOCID: id, SHA256: digestWire(body), MaxBytes: int64(len(body))}
	etag, err = writeOriginalState(t.Context(), t.Context(), clients.objects, in, state, etag)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := originalInventory(in, state, archive, record)
	if err != nil {
		t.Fatal(err)
	}
	state.OriginalAdmissionInventory = inventory
	etag, err = writeOriginalState(t.Context(), t.Context(), clients.objects, in, state, etag)
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(f.state)
	read, observed, err := readOriginalState(t.Context(), clients.objects, in)
	if err != nil || observed != etag || !sameOriginalState(read, state) {
		t.Fatal("selected original state was not durable", err)
	}
	if selected, err := originalInventory(in, read, archive, record); err != nil || !bytes.Equal(selected, inventory) {
		t.Fatal("original inventory was re-signed or changed", err)
	}
	// Local loss after exact Vault selection recovers the same archive and key.
	if err := os.Remove(filepath.Join(directory, originalCandidateName)); err != nil {
		t.Fatal(err)
	}
	recovered, _, err := readOriginalVault(t.Context(), clients, read)
	if err != nil || !bytes.Equal(recovered, candidate) {
		t.Fatal("Vault-v1 recovery depended on a new local key", err)
	}
	clear(recovered)
	if !bytes.Equal(before, f.state) || f.creates != 1 {
		t.Fatal("read-only recovery replaced selected source history")
	}
	for _, mutate := range []func(*originalSourceState){
		func(s *originalSourceState) { s.Scope.BirthSHA256 = strings.Repeat("b", 64) },
		func(s *originalSourceState) { s.RetryToken = "replacement" },
		func(s *originalSourceState) { s.Candidate.SHA256 = strings.Repeat("b", 64) },
		func(s *originalSourceState) { s.Reference = materialSourceReference{} },
		func(s *originalSourceState) { s.OriginalAdmissionInventory = nil },
	} {
		changed := state
		mutate(&changed)
		if _, err := writeOriginalState(t.Context(), t.Context(), clients.objects, in, changed, etag); err == nil || !bytes.Equal(before, f.state) {
			t.Fatal("mechanical CAS replaced immutable original selection")
		}
	}
}

func TestOriginalSourceArchiveSDKMechanicalHolds(t *testing.T) {
	t.Run("refused reservation has no candidate or Vault effect", func(t *testing.T) {
		in := originalMechanicalInputs(t)
		f, clients := newOriginalMechanicalSDK(t, in, "reservation refused")
		state := originalState(in, time.Now().UTC())
		if _, err := writeOriginalState(t.Context(), t.Context(), clients.objects, in, state, ""); err == nil || f.state != nil || f.creates != 0 {
			t.Fatal("unacknowledged reservation acquired an effect")
		}
	})
	in := originalMechanicalInputs(t)
	f, clients := newOriginalMechanicalSDK(t, in, "")
	directory := filepath.Join(t.TempDir(), "original")
	state, _, candidate := pinMechanicalCandidate(t, in, clients, directory)
	defer clear(candidate)
	if _, err := clients.management.CreateSecret(ociclient.RequestContext(t.Context()), originalCreateRequest(state, candidate)); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"bundle absent", "bundle version2", "bundle conflict", "metadata wrong key", "metadata version2", "metadata pending deletion"} {
		t.Run(fault, func(t *testing.T) {
			f.mu.Lock()
			f.fault = fault
			f.mu.Unlock()
			if body, _, err := readOriginalVault(t.Context(), clients, state); err == nil {
				clear(body)
				t.Fatal("uncertain or different Vault data passed exact version1 recovery")
			}
			if f.creates != 1 {
				t.Fatal("failed recovery created a new source key")
			}
		})
	}
	f.mu.Lock()
	f.fault = ""
	f.mu.Unlock()
	if _, err := writeOriginalState(t.Context(), t.Context(), clients.objects, in, originalState(in, time.Now().UTC()), ""); err == nil {
		t.Fatal("existing source reservation was replaced by another birth")
	}
	// No combined candidate/reference or reference/inventory CAS is allowed.
	reserved := originalState(in, time.Now().UTC())
	selected := reserved
	selected.Candidate = state.Candidate
	selected.Reference = materialSourceReference{SecretOCID: f.secretID, SHA256: state.Candidate.SHA256, MaxBytes: state.Candidate.MaxBytes}
	if immutableOriginalState(reserved, selected) {
		t.Fatal("Vault reference skipped the separately acknowledged candidate")
	}
	pinned := reserved
	pinned.Candidate = state.Candidate
	selected.OriginalAdmissionInventory = []byte("unselected-data")
	if immutableOriginalState(pinned, selected) {
		t.Fatal("inventory skipped the separately acknowledged Vault reference")
	}
}

func TestOriginalSourceArchiveLocalCandidateMechanics(t *testing.T) {
	in := originalMechanicalInputs(t)
	directory := filepath.Join(t.TempDir(), "original")
	dir, unlock, err := lockOriginalDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, other, err := lockOriginalDirectory(directory); err == nil {
		other()
		t.Fatal("two local writers acquired the same candidate lock")
	}
	state := originalState(in, time.Now().UTC())
	body, err := generateOriginalCandidate(directory, in, state)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	if err := persistOriginalCandidate(directory, dir, body); err != nil {
		t.Fatal(err)
	}
	if err := persistOriginalCandidate(directory, dir, []byte("replacement")); err == nil {
		t.Fatal("existing durable candidate was overwritten")
	}
	read, err := readOriginalCandidate(dir)
	if err != nil || !bytes.Equal(read, body) {
		t.Fatal("durable candidate differs from generated bytes", err)
	}
	clear(read)
	repeated, err := generateOriginalCandidate(directory, in, state)
	if err != nil || !bytes.Equal(repeated, body) {
		t.Fatal("same original reservation regenerated different source bytes", err)
	}
	clear(repeated)
	other := in
	other.scope.SHA256 = strings.Repeat("b", 64)
	otherState := state
	otherState.Scope = other.scope
	if archive, _, err := decodeOriginalCandidate(directory, other, otherState, body); err == nil {
		clearArchive(archive)
		t.Fatal("local candidate from another original scope was accepted")
	}
	otherReservation := originalState(in, state.StartedAt)
	if archive, _, err := decodeOriginalCandidate(directory, in, otherReservation, body); err == nil {
		clearArchive(archive)
		t.Fatal("same actor's candidate was adopted by a different reservation")
	}
	if err := os.Remove(filepath.Join(directory, originalCandidateName)); err != nil {
		t.Fatal(err)
	}
	if _, err := readOriginalCandidate(dir); !errors.Is(err, unix.ENOENT) {
		t.Fatal("missing pinned candidate did not remain unavailable")
	}
	if err := os.Symlink("candidate/material.json", filepath.Join(directory, originalCandidateName)); err != nil {
		t.Fatal(err)
	}
	if read, err := readOriginalCandidate(dir); err == nil {
		clear(read)
		t.Fatal("candidate symlink was followed")
	}
	if err := os.Remove(filepath.Join(directory, originalCandidateName)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, originalCandidateName), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if read, err := readOriginalCandidate(dir); err == nil {
		clear(read)
		t.Fatal("public-readable source candidate was accepted")
	}
}
