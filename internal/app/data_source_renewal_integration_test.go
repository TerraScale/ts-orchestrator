//go:build linux

package app

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/elf"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/firecracker/production"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"golang.org/x/sys/unix"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"uuid"
)

const (
	renewalFixtureChild    = "TS_SOURCE_RENEWAL_CHILD"
	renewalFixtureParent   = "TS_SOURCE_RENEWAL_PARENT_NETNS"
	renewalFixtureInstance = "ocid1.instance.oc1.sa-saopaulo-1.sourcerenewal"
	renewalFixtureTenancy  = "ocid1.tenancy.oc1..sourcerenewal"
	renewalFixtureAuth     = "auth.sa-saopaulo-1.oraclecloud.com"
	renewalFixtureSecrets  = "secrets.vaults.sa-saopaulo-1.oci.oraclecloud.com"
	renewalFixtureStorage  = "objectstorage.sa-saopaulo-1.oraclecloud.com"
	renewalFixtureCompute  = "iaas.sa-saopaulo-1.oraclecloud.com"
)

// This prerequisite crosses production IMDS, federation, Vault and SDK CAS.
// Source admission, lease renewal and writer withdrawal require the full runtime scenario.
func TestSourceRenewalSDKFixtureIntegration(t *testing.T) {
	if !renewalIsolatedChild(t) {
		return
	}
	fixture := newRenewalCloud(t)
	instance, err := bootstrapstart.NewIMDSClient().FetchInstanceID(t.Context())
	if err != nil || instance != renewalFixtureInstance {
		t.Fatalf("production fixed-address IMDS: instance=%q error=%v", instance, err)
	}
	credential := oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.sourcerenewal", VersionNumber: 1}
	credentialPath := "/20190301/secretbundles/" + credential.SecretOCID + "?versionNumber=1"
	fixture.putJSON(t, renewalFixtureSecrets, credentialPath, map[string]any{
		"secretId": credential.SecretOCID, "versionNumber": credential.VersionNumber,
		"secretBundleContent": map[string]string{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString([]byte(`{"version":1,"access_key_id":"fixture-access","secret_access_key":"fixture-secret"}`))},
	})
	resolver, err := host.NewOCIS3CredentialResolver(oci.RegionGRU)
	if err != nil {
		t.Fatalf("production instance-principal Vault constructor: %v", err)
	}
	resolved, err := resolver.Resolve(t.Context(), credential)
	if err != nil || resolved.AccessKeyID != "fixture-access" || resolved.SecretAccessKey != "fixture-secret" {
		t.Fatalf("production exact Vault resolution: %v", err)
	}
	storage := renewalStorageClient(t)
	const allocationPath = "/n/fixture/b/gru-1-head/o/source-renewal-cas"
	fixture.allowCAS(renewalFixtureStorage, allocationPath)
	wire := []byte("first retained fixture allocation")
	_, err = storage.PutObject(t.Context(), objectstorage.PutObjectRequest{NamespaceName: new("fixture"), BucketName: new("gru-1-head"), ObjectName: new("source-renewal-cas"),
		IfNoneMatch: new("*"), ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire))})
	if err != nil {
		t.Fatalf("signed SDK conditional creation: %v", err)
	}
	read, err := storage.GetObject(t.Context(), objectstorage.GetObjectRequest{NamespaceName: new("fixture"), BucketName: new("gru-1-head"), ObjectName: new("source-renewal-cas")})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(read.Content)
	closeErr := read.Content.Close()
	if err != nil || closeErr != nil || !bytes.Equal(actual, wire) || read.ETag == nil {
		t.Fatalf("signed SDK conditional read: read=%v close=%v", err, closeErr)
	}
	_, err = storage.PutObject(t.Context(), objectstorage.PutObjectRequest{NamespaceName: new("fixture"), BucketName: new("gru-1-head"), ObjectName: new("source-renewal-cas"),
		IfNoneMatch: new("*"), ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire))})
	serviceErr, ok := common.IsServiceError(err)
	if !ok || serviceErr.GetHTTPStatusCode() != http.StatusPreconditionFailed {
		t.Fatal("occupied SDK allocation did not reject a second creator")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.rejected != 0 || fixture.federations < 2 || fixture.reads != 2 || fixture.writes != 1 || fixture.conflicts != 1 {
		t.Fatalf("unexpected fixture boundary counts: federation=%d reads=%d writes=%d conflicts=%d rejected=%d", fixture.federations, fixture.reads, fixture.writes, fixture.conflicts, fixture.rejected)
	}
}

// This prerequisite starts with retained fixture material. It does not qualify
// TerraBase's native material producer or invoke PrepareInitial/NativeValidator.
func TestSourceRenewalRetainedMaterialIntegration(t *testing.T) {
	if !renewalIsolatedChild(t) {
		return
	}
	cloud := newRenewalCloud(t)
	control, err := authority.Start(t.Context(), testRolloutJetStream(t), authority.Config{
		DeploymentID: entityid.New(), Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if !control.Current().CanMutate() {
		t.Fatal("retained-material fixture did not acquire genuine R3 authority")
	}
	material := renewalRetainMaterial(t, cloud, renewalStorageClient(t), control, "/srv/source-renewal")
	if material.receipt.Spec.Scope.DatabaseID == material.receipt.Spec.PlacementDatabaseID ||
		material.receipt.Spec.Backup == nil || !bytes.Equal(material.bundle.Authority.TrustedKey, material.bundle.Retained.AuthoritySigner.Public().(ed25519.PublicKey)) {
		t.Fatal("retained fixture lacks distinct business scope, backup or authority continuity")
	}
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	if cloud.rejected != 0 || cloud.writes != 1 || cloud.reads != 2 {
		t.Fatalf("retained material SDK boundary: reads=%d writes=%d rejected=%d", cloud.reads, cloud.writes, cloud.rejected)
	}
}

func renewalStorageClient(t *testing.T) objectstorage.ObjectStorageClient {
	t.Helper()
	provider, err := ociclient.InstancePrincipalProvider(common.Region("sa-saopaulo-1"), bootstrap.BoundInstancePrincipalDispatcher)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	storage.HTTPClient, err = bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	noRetry := common.NoRetryPolicy()
	storage.SetCustomClientConfiguration(common.CustomClientConfiguration{RetryPolicy: &noRetry})
	return storage
}

type renewalMaterial struct {
	deployment managedmaterial.InitialDeployment
	service    managedmaterial.PreparationService
	receipt    managedmaterial.PreparationReceipt
	bundle     managedmaterial.InitialBundle
}

func renewalRetainMaterial(t *testing.T, cloud *renewalCloud, storage objectstorage.ObjectStorageClient,
	control *authority.Runtime, root string,
) renewalMaterial {
	t.Helper()
	now := time.Now().UTC()
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, controller, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seats, err := placement.RegionSeatIDs(oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	live := oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.sourcerenewallive", VersionNumber: 1}
	deployment, err := managedmaterial.NewDeploymentIdentity(managedmaterial.InitialDeployment{
		Region: oci.RegionGRU, PlacementDatabaseID: entityid.New(), PartitionID: entityid.New(),
		LiveS3: managedmaterial.LiveS3Target{Bucket: "source-renewal-live", Region: "sa-saopaulo-1",
			Endpoint:   "https://fixture.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
			Credential: live, NativeOCIRoot: &managedmaterial.NativeOCIRoot{Namespace: "fixture"}},
		Members: [2]managedmaterial.DeploymentMember{
			{SeatID: seats[0], ServerName: "owner.source-renewal.test", FailureDomain: "FAULT-DOMAIN-1", PrivateIP: "10.44.0.11"},
			{SeatID: seats[1], ServerName: "peer.source-renewal.test", FailureDomain: "FAULT-DOMAIN-2", PrivateIP: "10.44.0.12"}},
		ReplicationPort: 9443, ClientPort: 9465, ManagedRuntimeRoot: root}, 1)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := deployment.DraftSpec()
	if err != nil {
		t.Fatal(err)
	}
	backup := managedmaterial.BackupS3Target{Bucket: "source-renewal-backup", Region: "sa-saopaulo-1",
		Endpoint:         "https://fixture.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
		Credential:       oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.sourcerenewalbackup", VersionNumber: 1},
		CredentialSHA256: strings.Repeat("0", 64)}
	target, err := backup.Digest()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := protocol.EncodeJSON(struct {
		Version         uint64 `json:"version"`
		TargetDigest    string `json:"target_digest"`
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	}{1, target, "fixture-backup-access", "fixture-backup-secret"})
	if err != nil {
		t.Fatal(err)
	}
	backup.CredentialSHA256 = fmt.Sprintf("%x", sha256.Sum256(credential))
	dataKey := bytes.Repeat([]byte{0x42}, 32)
	draft.Backup = &managedmaterial.InitialBackupSpec{Target: backup,
		OwnerMemberID: deployment.Members[0].MemberID,
		DataKey:       oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.sourcerenewalkey", VersionNumber: 1},
		DataKeyID:     entityid.New(), DataKeySHA256: fmt.Sprintf("%x", sha256.Sum256(dataKey)),
		RetentionPolicyID: "retention-30d", RetentionUntilUnixMS: uint64(now.Add(30 * 24 * time.Hour).UnixMilli()), MaxPointCadenceMS: 60_000}
	spec, err := managedmaterial.SignRecipientGrant(draft, recipient, signer, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	putSecret := func(reference oci.SecretVersionReference, wire []byte) {
		cloud.putJSON(t, renewalFixtureSecrets, "/20190301/secretbundles/"+reference.SecretOCID+"?versionNumber=1", map[string]any{
			"secretId": reference.SecretOCID, "versionNumber": reference.VersionNumber,
			"secretBundleContent": map[string]string{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString(wire)}})
	}
	putSecret(live, []byte(`{"version":1,"access_key_id":"fixture-live-access","secret_access_key":"fixture-live-secret"}`))
	putSecret(backup.Credential, credential)
	putSecret(spec.Backup.DataKey, dataKey)
	const kms = "ocid1.key.oc1.sa-saopaulo-1.sourcerenewal"
	repository, err := managedmaterial.NewRepository(managedmaterial.RepositoryConfig{
		Region: oci.RegionGRU, Cell: "gru", Namespace: "fixture", Bucket: "gru-1-head", KMSKeyID: kms}, storage, control)
	if err != nil {
		t.Fatal(err)
	}
	specWire, err := protocol.EncodeJSON(spec)
	if err != nil {
		t.Fatal(err)
	}
	specSHA := fmt.Sprintf("%x", sha256.Sum256(specWire))
	name := "material/v2/gru/" + spec.PlacementDatabaseID + "/" + spec.PartitionID + "/g1-" + specSHA + ".json"
	cloud.mu.Lock()
	cloud.routes[renewalFixtureStorage+"/n/fixture/b/gru-1-head/o/"+name] = renewalCloudRoute{cas: true, kmsKey: kms}
	cloud.mu.Unlock()
	epoch := control.Current().Epoch
	if err := control.Guard(t.Context(), epoch); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.LookupInitial(t.Context(), spec.PartitionID, spec, controller.Public().(ed25519.PublicKey)); !errors.Is(err, managedmaterial.ErrMaterialNotFound) {
		t.Fatalf("exact retained fixture object must initially be absent: %v", err)
	}
	// Signed starting-state records exercise retention and readback only;
	// native material generation/validation is outside this fixture's claim.
	bundle, err := managedmaterial.GenerateInitial(spec, public, now)
	if err != nil {
		t.Fatal(err)
	}
	object, err := repository.CreateInitial(t.Context(), epoch, spec.PartitionID, spec, bundle, controller)
	if err != nil || object.VersionID == "" || object.ETag == "" || object.SpecSHA256 != specSHA || object.Name != name {
		t.Fatalf("real SDK immutable material CAS: %v", err)
	}
	receipt, err := managedmaterial.SignPreparationReceipt("gru", spec.PartitionID, spec, bundle, object, controller, now)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := control.CommitMaterialReceipt(t.Context(), epoch, spec.PlacementDatabaseID, spec.PartitionID,
		entityid.Derive("material-preparation", specSHA), 0, wire)
	if err != nil || sequence == 0 {
		t.Fatalf("real R3 retained material commit: sequence=%d error=%v", sequence, err)
	}
	entry, err := control.ReadMaterialReceipt(t.Context(), spec.PlacementDatabaseID, spec.PartitionID)
	if err != nil || entry.Sequence != sequence || entry.Kind != authority.MutationMaterialReceipt || !bytes.Equal(entry.Payload, wire) {
		t.Fatalf("retained material R3 readback: %v", err)
	}
	service := managedmaterial.PreparationService{Cell: "gru", Repository: repository, Receipts: control,
		Fencer: control, ControllerKey: controller, RecipientSigner: public, AllowedSubnetCIDR: "10.44.0.0/24"}
	confirmed, actual, err := service.CurrentBundle(t.Context(), spec.PlacementDatabaseID, spec.PartitionID)
	if err != nil || confirmed.Signature != receipt.Signature || confirmed.Object != object {
		t.Fatalf("authenticated retained material CurrentBundle: %v", err)
	}
	if err := managedmaterial.VerifyPreparationReceipt(confirmed, controller.Public().(ed25519.PublicKey), "gru", spec.PartitionID, actual); err != nil {
		t.Fatalf("retained material signature and file hashes: %v", err)
	}
	t.Logf("signed retained-material fixture: R3 sequence=%d, immutable version=%s; native producer validation outside claim", sequence, object.VersionID)
	return renewalMaterial{deployment: deployment, service: service, receipt: confirmed, bundle: actual}
}

func renewalIsolatedChild(t *testing.T) bool {
	t.Helper()
	if os.Getenv(renewalFixtureChild) == t.Name() {
		if os.Geteuid() != 0 {
			t.Fatal("renewal fixture child requires root")
		}
		namespace, err := os.Readlink("/proc/self/ns/net")
		if err != nil || os.Getenv(renewalFixtureParent) == "" || namespace == os.Getenv(renewalFixtureParent) {
			t.Fatal("renewal fixture must have its own network namespace")
		}
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"link", "set", "lo", "up"}, {"address", "add", "169.254.169.254/32", "dev", "lo"}} {
			command := exec.CommandContext(t.Context(), "ip", args...)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("isolated IMDS address: %v: %s", err, output)
			}
		}
		return true
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "sudo", "-n", "env", renewalFixtureChild+"="+t.Name(), renewalFixtureParent+"="+namespace, "GOMAXPROCS=2", "nice", "-n", "19", "unshare", "--mount", "--net", executable,
		"-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.timeout=90s", "-test.v")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated renewal fixture: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
	return false
}

type renewalCloudRoute struct {
	body            []byte
	etag            string
	cas             bool
	version, kmsKey string
}

type renewalCloud struct {
	simulator                                       *production.Simulator
	mu                                              sync.Mutex
	sessions                                        map[string]*rsa.PublicKey
	routes                                          map[string]renewalCloudRoute
	federations, reads, writes, conflicts, rejected int
}

func newRenewalCloud(t *testing.T) *renewalCloud {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Source renewal fixture CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Source renewal fixture instance",
		ExtraNames: []pkix.AttributeTypeAndValue{{Type: []int{2, 5, 4, 13}, Value: "opc-tenant:" + renewalFixtureTenancy}}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{renewalFixtureAuth, renewalFixtureSecrets, renewalFixtureStorage, renewalFixtureCompute}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	simulator, err := production.NewSimulator(production.Config{Region: "sa-saopaulo-1", InstanceID: renewalFixtureInstance,
		DescriptorSlot: "source-renewal", PrimaryPrivateIP: "10.44.0.11", TenancyID: renewalFixtureTenancy,
		LeafCertificate: certificate, LeafPrivateKey: privateKey, Intermediate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &renewalCloud{simulator: simulator, sessions: make(map[string]*rsa.PublicKey), routes: make(map[string]renewalCloudRoute)}
	server := httptest.NewUnstartedServer(fixture)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	listener, err := net.Listen("tcp4", "169.254.169.254:80")
	if err != nil {
		t.Fatal(err)
	}
	imds := &http.Server{Handler: fixture, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := imds.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("isolated IMDS server: %v", err)
		}
	}()
	t.Cleanup(func() { _ = imds.Close() })
	trusted := x509.NewCertPool()
	trusted.AddCert(root)
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "169.254.169.254:80" {
				return nil, errors.New("renewal fixture refuses non-IMDS plain HTTP")
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
		// OCI's default transport replaces DialContext and TLSClientConfig.
		// DialTLSContext survives its clone and still validates the original hostname.
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			hostname, port, err := net.SplitHostPort(address)
			if err != nil || network != "tcp" || port != "443" || hostname != renewalFixtureAuth && hostname != renewalFixtureSecrets && hostname != renewalFixtureStorage && hostname != renewalFixtureCompute {
				return nil, errors.New("renewal fixture refuses unlisted TLS destination")
			}
			dialer := &tls.Dialer{Config: &tls.Config{RootCAs: trusted, ServerName: hostname, MinVersion: tls.VersionTLS12}}
			return dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
		}}
	original := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	return fixture
}

func (fixture *renewalCloud) putJSON(t *testing.T, hostname, path string, value any) {
	t.Helper()
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	fixture.putBytes(hostname, path, wire)
}

func (fixture *renewalCloud) putBytes(hostname, path string, wire []byte) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.routes[hostname+path] = renewalCloudRoute{body: bytes.Clone(wire), etag: fmt.Sprintf(`"%x"`, sha256.Sum256(wire))}
}

func (fixture *renewalCloud) allowCAS(hostname, path string) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.routes[hostname+path] = renewalCloudRoute{cas: true}
}

var renewalSignature = regexp.MustCompile(`^Signature version="1",headers="([a-z0-9() -]+)",keyId="ST\$([^"]+)",algorithm="rsa-sha256",signature="([A-Za-z0-9+/=]+)"$`)

func (fixture *renewalCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host == "169.254.169.254" {
		fixture.simulator.ServeHTTP(w, r)
		return
	}
	if r.Host == renewalFixtureAuth && r.Method == http.MethodPost && r.URL.RequestURI() == "/v1/x509" {
		body, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
		if err != nil || len(body) > 64<<10 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		fixture.simulator.ServeHTTP(recorder, r)
		if recorder.Code == http.StatusOK {
			var submitted struct {
				PublicKey string `json:"publicKey"`
			}
			var response struct {
				Token string `json:"token"`
			}
			if json.Unmarshal(body, &submitted) != nil || json.Unmarshal(recorder.Body.Bytes(), &response) != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			der, err := base64.StdEncoding.DecodeString(submitted.PublicKey)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			parsed, err := x509.ParsePKIXPublicKey(der)
			public, ok := parsed.(*rsa.PublicKey)
			if err != nil || !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fixture.mu.Lock()
			fixture.sessions[response.Token] = public
			fixture.federations++
			fixture.mu.Unlock()
		}
		for name, values := range recorder.Header() {
			w.Header()[name] = values
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
		return
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	route, exists := fixture.routes[r.Host+r.URL.RequestURI()]
	if !exists || r.Method != http.MethodGet && !(r.Method == http.MethodPut && route.cas) {
		fixture.rejected++
		w.WriteHeader(http.StatusMisdirectedRequest)
		return
	}
	limit := 64 << 10
	if route.kmsKey != "" {
		limit = 8 << 20 // Production retained-material repository bound.
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil || len(body) > limit || fixture.verify(r) != nil || r.Method == http.MethodPut && r.ContentLength != int64(len(body)) {
		fixture.rejected++
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPut {
		if route.kmsKey != "" {
			checksum := sha256.Sum256(body)
			if r.Header.Get("If-None-Match") != "*" || r.Header.Get("opc-sse-kms-key-id") != route.kmsKey ||
				r.Header.Get("opc-checksum-algorithm") != "SHA256" || r.Header.Get("opc-content-sha256") != base64.StdEncoding.EncodeToString(checksum[:]) {
				fixture.rejected++
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		if r.Header.Get("If-None-Match") == "*" && route.body != nil || r.Header.Get("If-Match") != "" && (route.body == nil || r.Header.Get("If-Match") != route.etag) {
			fixture.conflicts++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = io.WriteString(w, `{"code":"PreconditionFailed","message":"fixture CAS conflict"}`)
			return
		}
		if r.Header.Get("If-None-Match") != "*" && r.Header.Get("If-Match") == "" {
			fixture.rejected++
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		route.body, route.etag = bytes.Clone(body), fmt.Sprintf(`"%x"`, sha256.Sum256(body))
		if route.kmsKey != "" {
			route.version = fmt.Sprintf("fixture-%x", sha256.Sum256(body))
			pinned := route
			pinned.cas = false
			fixture.routes[r.Host+r.URL.RequestURI()+"?versionId="+route.version] = pinned
			w.Header().Set("version-id", route.version)
		}
		fixture.routes[r.Host+r.URL.RequestURI()] = route
		fixture.writes++
		w.Header().Set("ETag", route.etag)
		w.WriteHeader(http.StatusOK)
		return
	}
	if route.body == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"code":"ObjectNotFound","message":"fixture CAS object absent"}`)
		return
	}
	if r.Header.Get("If-Match") != "" && r.Header.Get("If-Match") != route.etag ||
		r.URL.Query().Get("versionId") != "" && (r.URL.Query().Get("versionId") != route.version || r.Header.Get("If-Match") != route.etag) {
		fixture.conflicts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPreconditionFailed)
		_, _ = io.WriteString(w, `{"code":"PreconditionFailed","message":"fixture immutable version conflict"}`)
		return
	}
	fixture.reads++
	if route.version != "" {
		w.Header().Set("version-id", route.version)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(route.body)))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", route.etag)
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	_, _ = w.Write(route.body)
}

func (fixture *renewalCloud) verify(r *http.Request) error {
	match := renewalSignature.FindStringSubmatch(r.Header.Get("Authorization"))
	if match == nil || fixture.sessions[match[2]] == nil {
		return errors.New("unknown fixture federation session")
	}
	date, err := http.ParseTime(r.Header.Get("Date"))
	if err != nil || time.Since(date).Abs() > 5*time.Minute {
		return errors.New("stale fixture request")
	}
	headers := "date (request-target) host"
	lines := []string{"date: " + r.Header.Get("Date"), "(request-target): " + strings.ToLower(r.Method) + " " + r.URL.RequestURI(), "host: " + r.Host}
	// The OCI SDK deliberately excludes PutObject bodies from HTTP signatures.
	if match[1] != headers {
		return errors.New("fixture request signed header set differs")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(match[3])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return rsa.VerifyPKCS1v15(fixture.sessions[match[2]], crypto.SHA256, digest[:], signature)
}

const renewalMemberExecutable = "/source-renewal-member"

// The same disposable test binary supplies the workload, including when cgo
// needs the host's ELF loader. No TerraBase binary is fetched or executed.
func init() {
	if os.Args[0] != renewalMemberExecutable {
		return
	}
	if os.Getpid() != 1 || os.Geteuid() == 0 {
		os.Exit(70)
	}
	if err := renewalMemberMain(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(71)
	}
	os.Exit(0)
}

func newRenewalContainerd(t *testing.T, directory string) *containerd.Client {
	t.Helper()
	for _, name := range []string{"containerd", "containerd-shim-runc-v2", "runc"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("renewal runtime prerequisite %s: %v", name, err)
		}
	}
	log, err := os.OpenFile(filepath.Join(directory, "containerd.log"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	socket := filepath.Join(directory, "daemon.sock")
	command := exec.Command("nice", "-n", "19", "containerd", "--config", "/dev/null", "--root", filepath.Join(directory, "root"),
		"--state", filepath.Join(directory, "state"), "--address", socket, "--log-level", "error")
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
	})
	client, err := containerd.New(socket, containerd.WithTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for {
		if _, err := client.Version(ctx); err == nil {
			return client
		}
		select {
		case err := <-done:
			done <- err
			t.Fatalf("owned renewal containerd exited: %v", err)
		case <-ctx.Done():
			t.Fatal("owned renewal containerd did not become ready")
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func renewalLoopVolume(t *testing.T, directory, mount string) hostvolume.MountPins {
	t.Helper()
	image := filepath.Join(directory, "retained.ext4")
	file, err := os.OpenFile(image, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(32 << 20); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	device := strings.TrimSpace(renewalCommand(t, t.Context(), "losetup", "--find", "--show", "--nooverlap", image))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		renewalCommand(t, ctx, "losetup", "--detach", device)
	})
	id := uuid.New().String()
	tool, args, err := hostvolume.FormatCommand("ext4", id)
	if err != nil {
		t.Fatal(err)
	}
	renewalCommand(t, t.Context(), tool, append(args, device)...)
	if actual := strings.TrimSpace(renewalCommand(t, t.Context(), "blkid", "-p", "-s", "UUID", "-o", "value", device)); actual != id {
		t.Fatalf("fixture UUID readback = %q, want %q", actual, id)
	}
	alias := filepath.Join("/dev/disk/by-uuid", id)
	if err := os.Symlink(device, alias); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(alias); err != nil {
			t.Error(err)
		}
	})
	if err := os.MkdirAll(mount, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(device, mount, "ext4", hostvolume.MountFlags, hostvolume.FilesystemData("ext4")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(mount, 0); err != nil {
			t.Error(err)
		}
	})
	for _, path := range []string{mount, filepath.Join(mount, "data"), filepath.Join(mount, "replication")} {
		mode, uid := os.FileMode(0o700), 65532
		if path == mount {
			mode, uid = 0o750, 0
		} else if err := os.Mkdir(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, uid, 65532); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	pins := hostvolume.MountPins{DevicePath: device, MountPath: mount, FileSystemUUID: id, FileSystemType: "ext4", UID: 65532, GID: 65532}
	witness, err := hostvolume.ObserveMount(pins)
	if err != nil {
		t.Fatal(err)
	}
	witness.Close()
	return pins
}

func renewalCommand(t *testing.T, ctx context.Context, name string, args ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "nice", append([]string{"-n", "19", name}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("disposable fixture command %s: %v: %s", name, err, output)
	}
	return string(output)
}

// renewalMemberImage retains the exact local workload bytes in containerd's
// content store and unpacks them with the same native snapshotter as production.
func renewalMemberImage(t *testing.T, client *containerd.Client, environment []string) (containerd.Image, map[string][]byte) {
	t.Helper()
	ctx := namespaces.WithNamespace(t.Context(), "terrascale")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{renewalMemberExecutable: executable}
	var addELF func(string)
	addELF = func(path string) {
		image, err := elf.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer image.Close()
		for _, program := range image.Progs {
			if program.Type != elf.PT_INTERP {
				continue
			}
			wire, err := io.ReadAll(program.Open())
			if err != nil {
				t.Fatal(err)
			}
			loader := strings.TrimRight(string(wire), "\x00")
			if _, exists := files[loader]; !exists {
				files[loader] = loader
				addELF(loader)
			}
		}
		libraries, err := image.ImportedLibraries()
		if err != nil {
			t.Fatal(err)
		}
		for _, library := range libraries {
			found := false
			for _, directory := range []string{"/lib", "/lib64", "/usr/lib", "/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu"} {
				path := filepath.Join(directory, library)
				if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
					continue
				}
				found = true
				if _, exists := files[path]; !exists {
					files[path] = path
					addELF(path)
				}
				break
			}
			if !found {
				t.Fatalf("fixture ELF library %s is unavailable", library)
			}
		}
	}
	addELF(executable)
	var layer bytes.Buffer
	archive := tar.NewWriter(&layer)
	for _, destination := range slices.Sorted(maps.Keys(files)) {
		wire, err := os.ReadFile(files[destination])
		if err != nil {
			t.Fatal(err)
		}
		if err := archive.WriteHeader(&tar.Header{Name: strings.TrimPrefix(destination, "/"), Mode: 0o755, Size: int64(len(wire)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(wire); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	put := func(mediaType string, wire []byte) ocispec.Descriptor {
		t.Helper()
		descriptor := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(wire), Size: int64(len(wire))}
		if err := content.WriteBlob(ctx, client.ContentStore(), "source-renewal-"+descriptor.Digest.Encoded(), bytes.NewReader(wire), descriptor); err != nil {
			t.Fatal(err)
		}
		return descriptor
	}
	layerDescriptor := put(ocispec.MediaTypeImageLayer, layer.Bytes())
	config := ocispec.Image{Platform: ocispec.Platform{Architecture: runtime.GOARCH, OS: "linux"},
		Config: ocispec.ImageConfig{User: "65532:65532", Entrypoint: []string{renewalMemberExecutable}, Env: environment},
		RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{layerDescriptor.Digest}}}
	configWire, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	manifest := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, Config: put(ocispec.MediaTypeImageConfig, configWire), Layers: []ocispec.Descriptor{layerDescriptor}}
	manifest.SchemaVersion = 2
	manifestWire, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDescriptor := put(ocispec.MediaTypeImageManifest, manifestWire)
	record, err := client.ImageService().Create(ctx, images.Image{Name: "fixture.invalid/terrabase@" + manifestDescriptor.Digest.String(), Target: manifestDescriptor})
	if err != nil {
		t.Fatal(err)
	}
	image := containerd.NewImage(client, record)
	if err := image.Unpack(ctx, "native"); err != nil {
		t.Fatal(err)
	}
	return image, map[string][]byte{manifestDescriptor.Digest.Encoded(): manifestWire, manifest.Config.Digest.Encoded(): configWire}
}

func renewalStartMember(t *testing.T, client *containerd.Client, image containerd.Image, pins execution.RuntimePins) containerd.Task {
	t.Helper()
	ctx := namespaces.WithNamespace(t.Context(), "terrascale")
	id := "ts-" + pins.Task.ID
	spec := &runtimespec.Spec{Version: runtimespec.Version, Process: &pins.Process, Root: &runtimespec.Root{Path: "rootfs", Readonly: true}, Mounts: pins.Mounts,
		Linux: &runtimespec.Linux{Namespaces: pins.Namespaces, Resources: &pins.Resources, CgroupsPath: "/terrascale/" + id}}
	container, err := client.NewContainer(ctx, id, containerd.WithImage(image), containerd.WithSnapshotter("native"), containerd.WithNewSnapshot(id, image),
		containerd.WithRuntime("io.containerd.runc.v2", nil), containerd.WithSpec(spec), containerd.WithContainerLabels(map[string]string{
			"terrascale.task": pins.Task.ID, "terrascale.service": pins.Task.ServiceID, "terrascale.spec": pins.ContainerSpecSHA256, "terrascale.task-binding": pins.ContainerSpecSHA256}))
	if err != nil {
		t.Fatal(err)
	}
	var process containerd.Task
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(namespaces.WithNamespace(context.Background(), "terrascale"), 10*time.Second)
		defer cancel()
		if process != nil {
			if _, err := process.Delete(cleanup, containerd.WithProcessKill); err != nil {
				t.Error(err)
			}
		}
		if err := container.Delete(cleanup, containerd.WithSnapshotCleanup); err != nil {
			t.Error(err)
		}
	})
	process, err = container.NewTask(ctx, cio.NullIO)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return process
}

func renewalMemberMain() error {
	arguments := make(map[string]string)
	for i := 1; i+1 < len(os.Args); i += 2 {
		arguments[os.Args[i]] = os.Args[i+1]
	}
	var authority memberstatus.Authority
	if err := json.Unmarshal([]byte(os.Getenv("TS_SOURCE_RENEWAL_AUTHORITY")), &authority); err != nil {
		return err
	}
	shard, err := strconv.ParseUint(arguments["--shard-id"], 10, 64)
	if err != nil {
		return err
	}
	scope := memberstatus.Scope{ClusterID: arguments["--cluster-id"], TenantID: arguments["--tenant-id"], DatabaseID: arguments["--database-id"], ShardID: shard,
		MemberID: arguments["--member-id"], Incarnation: arguments["--member-incarnation"]}
	listener, err := net.Listen("unix", arguments["--member-control-socket"])
	if err != nil {
		return err
	}
	if err := os.Chmod(listener.Addr().String(), 0o602); err != nil {
		_ = listener.Close()
		return err
	}
	process := memberstatus.Process{PID: 1, StartNonce: strings.Repeat("1", 32)}
	marker := func(name string) error {
		return os.WriteFile(filepath.Join(arguments["--data-dir"], "fixture-"+name), []byte(time.Now().UTC().Format(time.RFC3339Nano)), 0o600)
	}
	if err := marker("started"); err != nil {
		return err
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/backup/prepare" && r.Method == http.MethodPost {
			if _, err := io.Copy(io.Discard, io.LimitReader(r.Body, 64<<10)); err != nil {
				return
			}
			if err := marker("prepare-started"); err != nil {
				w.WriteHeader(500)
				return
			}
			for {
				select {
				case <-r.Context().Done():
					_ = marker("prepare-canceled")
					return
				case <-time.After(20 * time.Millisecond):
					if _, err := os.Stat(filepath.Join(arguments["--data-dir"], "fixture-prepare-release")); err == nil {
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, `{"version":1,"payload":"fixture-cut","signature":"fixture-signature"}`)
						return
					}
				}
			}
		}
		if r.URL.Path != "/v1/member/status" || r.Method != http.MethodGet {
			w.WriteHeader(404)
			return
		}
		reply := memberstatus.Status{SchemaVersion: 2, Nonce: r.URL.Query().Get("nonce"), Process: process, Scope: scope, Authority: authority,
			Local: memberstatus.Local{StorageRecovered: true, ReplicationListenerReady: true}, Capabilities: memberstatus.Capabilities{ServingProof: true, DurableDrain: true}, CredentialGeneration: 1}
		wire, err := json.Marshal(reply)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(wire)))
		_, _ = w.Write(wire)
	})}
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type renewalSignedRelease struct {
	bundle       release.ContainerBundle
	roots        trust.Keyring
	root, signer ed25519.PrivateKey
	allocations  release.SequenceLocation
	evidence     releasechannel.Location
}

// This signs only fixture evidence for the local test workload. It exercises
// production verifiers without qualifying a TerraBase release.
func renewalQualifyImage(t *testing.T, cloud *renewalCloud, storage objectstorage.ObjectStorageClient,
	image containerd.Image, objects map[string][]byte, data execution.RetainedData, native []byte,
) renewalSignedRelease {
	t.Helper()
	rootPublic, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	qualifierPublic, qualifier, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootID, err := trust.KeyID(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	qualifierID, err := trust.KeyID(qualifierPublic)
	if err != nil {
		t.Fatal(err)
	}
	signerID, err := trust.KeyID(signerPublic)
	if err != nil {
		t.Fatal(err)
	}
	roots := trust.Keyring{rootID: rootPublic, qualifierID: qualifierPublic}
	now := time.Now().UTC().Truncate(time.Second)
	target := release.ContainerTarget{Cell: "GRU", Environment: "production", Role: "terrabase", Architecture: runtime.GOARCH}
	evidence := releasechannel.Location{Client: storage, Namespace: "fixture", Bucket: "gru-1-head"}
	allocations := release.SequenceLocation{Client: storage, Namespace: evidence.Namespace, Bucket: evidence.Bucket}
	objectPath := func(name string) string { return "/n/fixture/b/gru-1-head/o/" + name }
	put := func(wire []byte) string {
		sha := fmt.Sprintf("%x", sha256.Sum256(wire))
		cloud.putBytes(renewalFixtureStorage, objectPath(releasechannel.ContainerEvidenceObject("terrabase", sha)), wire)
		return sha
	}
	for expected, wire := range objects {
		if put(wire) != expected {
			t.Fatal("local OCI image evidence digest changed")
		}
	}
	if put(native) != data.SourceArtifactSHA256 {
		t.Fatal("native retained artifact differs from placement")
	}
	cpu, err := execution.HostCPUProfile()
	if err != nil {
		t.Fatal(err)
	}
	sign := func(value any, scope trust.Scope, key ed25519.PrivateKey) []byte {
		t.Helper()
		payload, err := trust.EncodePayload(value)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, scope, now, now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: evidence.Namespace,
		Bucket: evidence.Bucket, Region: target.Cell, SignerKeyID: signerID,
		SignerPublicKey: base64.RawURLEncoding.EncodeToString(signerPublic), Role: target.Role,
		Environment: target.Environment, SequenceFloor: 100}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 100,
			EvidenceSHA256: strings.Repeat("1", 64)})
	}
	migrationEnvelope, err := release.SignSequenceMigration(migration, now, root)
	if err != nil {
		t.Fatal(err)
	}
	migrationWire, err := trust.EncodeEnvelope(migrationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	migrationSHA, err := trust.Fingerprint(migrationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	cloud.allowCAS(renewalFixtureStorage, objectPath(release.SequenceObject(target.Role, target.Environment)))
	cloud.allowCAS(renewalFixtureStorage, objectPath(release.SequenceReservationObject(target.Role, target.Environment, migrationSHA, 101)))
	if err := allocations.ImportMigration(t.Context(), migrationEnvelope, roots, target.Role, target.Environment, now); err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: signerID, SubjectPublicKey: base64.RawURLEncoding.EncodeToString(signerPublic),
		Capabilities: []trust.Capability{{Domain: release.ContainerClaimDomain,
			DeploymentID: release.ContainerScope(target).DeploymentID, Cell: target.Cell, Environment: target.Environment,
			Role: target.Role, Slots: []string{"linux-" + runtime.GOARCH}, Actions: []string{"sign"}}}}, now, now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	manifestDescriptor := image.Target()
	manifestWire := objects[manifestDescriptor.Digest.Encoded()]
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestWire, &manifest); err != nil {
		t.Fatal(err)
	}
	configWire := objects[manifest.Config.Digest.Encoded()]
	child := manifestDescriptor
	child.Platform = &ocispec.Platform{OS: "linux", Architecture: runtime.GOARCH}
	index := ocispec.Index{MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{child}}
	index.SchemaVersion = 2
	indexWire, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	indexSHA := put(indexWire)
	proof := execution.StatefulQualification{Schema: execution.StatefulQualificationSchema,
		CandidateSourceTreeSHA256: strings.Repeat("b", 64), Data: data, ResultData: data,
		SourceCPU: cpu, TargetCPU: cpu, DiskFormatSHA256: data.DiskFormatSHA256,
		SourceArtifact: &release.ProductionGateEvidence{Gate: "native-source-artifact", SHA256: data.SourceArtifactSHA256,
			Bytes: int64(len(native)), CompletedAt: now},
		ImageManifest: release.ProductionGateEvidence{Gate: "image-manifest", SHA256: manifestDescriptor.Digest.Encoded(),
			Bytes: int64(len(manifestWire)), CompletedAt: now},
		ImageConfig: release.ProductionGateEvidence{Gate: "image-config", SHA256: manifest.Config.Digest.Encoded(),
			Bytes: int64(len(configWire)), CompletedAt: now}}
	proof.ResultData.SourceArtifactSHA256 = manifestDescriptor.Digest.Encoded()
	proof.ResultData.SourceTreeSHA256 = proof.CandidateSourceTreeSHA256
	proof.ResultData.SourceArchitecture = runtime.GOARCH
	for _, gate := range []string{"retained-restart", "restore", "replication-catchup", "durable-drain", "sigterm", "cpu-format-transition"} {
		wire := []byte("test workload fixture " + gate)
		proof.Scenarios = append(proof.Scenarios, release.ProductionGateEvidence{Gate: gate, SHA256: put(wire),
			Bytes: int64(len(wire)), CompletedAt: now})
	}
	proofWire, err := trust.EncodePayload(proof)
	if err != nil {
		t.Fatal(err)
	}
	claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: image.Name(),
		SourceRepository: "https://github.com/TerraScale/terrascale", SourceRevision: strings.Repeat("a", 40),
		SourceTreeSHA256: proof.CandidateSourceTreeSHA256, Cell: target.Cell, Environment: target.Environment,
		Role: target.Role, Architecture: target.Architecture, ReleaseSequence: 101,
		SequenceMigrationSHA256: migrationSHA, QualificationSHA256: indexSHA}
	expected := release.ProductionExpectation{SourceRevision: claim.SourceRevision,
		ArtifactSHA256: manifestDescriptor.Digest.Encoded(), QualificationSHA256: indexSHA, Cell: target.Cell,
		Environment: target.Environment, Role: target.Role, Architecture: target.Architecture, Runtime: release.ProductionRuntime}
	ha := []byte("test workload runtime fixture")
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: expected,
		Evidence: []release.ProductionGateEvidence{{Gate: "runtime-ha", SHA256: put(ha), Bytes: int64(len(ha)), CompletedAt: now},
			{Gate: "workload-safety", SHA256: put(proofWire), Bytes: int64(len(proofWire)), CompletedAt: now}}}
	claim.Production.Qualification = sign(qualification, release.ProductionQualificationScope(expected), qualifier)
	family, err := claim.WorkerFamilyDigest()
	if err != nil {
		t.Fatal(err)
	}
	sequence, sequenceWire, err := allocations.AllocateWithEvidence(t.Context(), release.SequenceIdentity{
		Role: target.Role, Environment: target.Environment, SourceRevision: claim.SourceRevision, ManifestSHA256: family}, roots, signer)
	if err != nil {
		t.Fatal(err)
	}
	if sequence != 101 {
		t.Fatalf("fixture allocated sequence %d, want 101", sequence)
	}
	bundle := release.ContainerBundle{Index: indexWire, Sequence: sequenceWire,
		Claim: sign(claim, release.ContainerScope(target), signer), Migration: migrationWire, Delegation: delegationWire}
	open := func(ctx context.Context, sha string) (io.ReadCloser, error) {
		return releasechannel.ReadContainerEvidence(ctx, evidence, "terrabase", sha)
	}
	verified, err := execution.VerifyStatefulCurrent(t.Context(), bundle, roots, target, data, cpu, now,
		now.Add(time.Minute), open, allocations)
	if err != nil || verified.Data() != data || verified.CPU() != cpu {
		t.Fatalf("signed local image qualification: %v", err)
	}
	return renewalSignedRelease{bundle: bundle, roots: roots, root: root, signer: signer,
		allocations: allocations, evidence: evidence}
}
