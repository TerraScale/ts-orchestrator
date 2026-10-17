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
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionleader"
	"github.com/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/firecracker/production"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		"-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.timeout=180s", "-test.v")
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
	reads           uint64
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
	route.reads++
	fixture.routes[r.Host+r.URL.RequestURI()] = route
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
	if len(os.Args) == 3 && os.Args[1] == "--runtime-logger" {
		swarmruntime.RunRuntimeLogger(os.Args[2])
		os.Exit(0)
	}
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

// renewalOwnedFleet uses retained launch records plus exact signed SDK reads;
// neither OCI tags alone nor an accepting image/registration callback suffice.
func renewalOwnedFleet(t *testing.T, cloud *renewalCloud, js jetstream.JetStream,
	state *placement.MemberState,
) (oci.RegionConfig, *oci.VolumeMountObserver, oci.FleetObserver) {
	t.Helper()
	images, now := managedImageVerifierFixture(t, runtime.GOARCH)
	config := images.region
	config.Generation, config.Endpoint, config.Owner = 1, "https://"+renewalFixtureCompute, "source-renewal"
	config.Shape = state.ManagedHostProfile.Compute.Shape
	config.FaultDomains = []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"}
	config.SubnetID = "ocid1.subnet.oc1.sa-saopaulo-1.sourcerenewal"
	config.NetworkSecurityGroupIDs = []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.sourcerenewal"}
	config.BootVolumeGB, config.BootVolumeVPUsPerGB, config.DataVolumeVPUsPerGB, config.MaxDataVolumeGB = 50, 10, 10, 32768
	images.region = config
	proof, err := independentManagedImageProof(config, oci.RegionGRU, "production", images.roots, images.receiptWire, images.delegationWire, now)
	if err != nil {
		t.Fatal(err)
	}
	proof.images, err = newManagedImageReadback(config)
	if err != nil {
		t.Fatal(err)
	}
	proof.now = time.Now
	intent := oci.RegionIntent{SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU,
		Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}}
	if err := config.Validate(intent); err != nil {
		t.Fatal(err)
	}
	hasher := sha256.New()
	for _, value := range []string{config.Owner, string(config.Region), "1", state.CreateKey} {
		_, _ = hasher.Write([]byte{0})
		_, _ = hasher.Write([]byte(value))
	}
	state.HostNode = fmt.Sprintf("host-%x", hasher.Sum(nil)[:12])
	descriptor := hostboot.Descriptor{SchemaVersion: 1, Cell: "gru", Region: "GRU", Node: state.HostNode,
		Owner: config.Owner, FleetGeneration: 1, CreateKey: state.CreateKey, ImageID: config.ImageID,
		DatabaseID: state.DatabaseID, PartitionID: state.PartitionID, SeatID: state.MemberID, HostAttempt: state.HostAttempt,
		IntentGeneration: state.IntentGeneration, IntentPayloadDigest: state.IntentPayloadDigest,
		CanonicalRosterDigest: state.CanonicalRosterDigest, ManagedHostProfileDigest: state.ManagedHostProfileDigest,
		RuntimeManifestDigest: state.RuntimeManifestDigest}
	wire, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	descriptorSHA, err := descriptor.Digest()
	if err != nil {
		t.Fatal(err)
	}
	journal, err := oci.OpenJournal(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	record := func(operation oci.OperationIntent, id, etag string) {
		t.Helper()
		if err := journal.RecordIntent(t.Context(), operation); err != nil {
			t.Fatal(err)
		}
		if err := journal.RecordResult(t.Context(), oci.OperationResult{Intent: operation, ResourceID: id, ETag: etag, RecordedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	hostIP, _, err := net.SplitHostPort(state.RuntimeManifest.ReplicationListenAddress)
	if err != nil {
		t.Fatal(err)
	}
	compute := state.ManagedHostProfile.Compute
	record(oci.OperationIntent{Action: "launch", Key: state.CreateKey, CreateKey: state.CreateKey,
		Region: config.Region, Generation: 1, Owner: config.Owner, CreatedAt: now, FaultDomain: state.FailureDomain,
		PrivateIP: hostIP, Shape: config.Shape, WholeOCPUs: compute.WholeOCPUs, MemoryInGBs: compute.MemoryInGBs,
		PlacementProfileDigest: state.ManagedHostProfileDigest, PlacementGeneration: state.IntentGeneration,
		ImageID: config.ImageID, BootDescriptor: string(wire), BootDescriptorSHA256: descriptorSHA}, state.InstanceID, state.InstanceETag)
	volumeKey := entityid.New()
	record(oci.OperationIntent{Action: "volume-create", Key: volumeKey, CreateKey: volumeKey, Region: config.Region,
		Generation: 1, Owner: config.Owner, CreatedAt: now, AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50}, state.VolumeID, "volume-v1")
	record(oci.OperationIntent{Action: "volume-attach", Key: entityid.New(), CreateKey: state.CreateKey, ResourceID: state.InstanceID,
		VolumeID: state.VolumeID, Region: config.Region, Generation: 1, Owner: config.Owner, CreatedAt: now,
		Device: state.AttachmentDevice, IsPvEncryptionInTransitEnabled: true}, state.AttachmentID, state.AttachmentETag)
	put := func(path, etag string, body any) {
		cloud.putJSON(t, renewalFixtureCompute, path, body)
		if etag != "" {
			cloud.mu.Lock()
			route := cloud.routes[renewalFixtureCompute+path]
			route.etag = etag
			cloud.routes[renewalFixtureCompute+path] = route
			cloud.mu.Unlock()
		}
	}
	query := func(path string, fields ...string) string {
		values := url.Values{}
		for index := 0; index < len(fields); index += 2 {
			values.Set(fields[index], fields[index+1])
		}
		return "/20160918/" + path + "?" + values.Encode()
	}
	tags := map[string]string{"terrascale-managed-by": "ts-orchestrator", "terrascale-owner": config.Owner,
		"terrascale-region": "GRU", "terrascale-component": "terrabase", "terrascale-generation": "1",
		"terrascale-resource": "member-host", "terrascale-create-key": state.CreateKey, "terrascale-host-node": state.HostNode,
		"terrascale-placement-profile-digest": state.ManagedHostProfileDigest, "terrascale-placement-generation": fmt.Sprint(state.IntentGeneration)}
	instance := map[string]any{"id": state.InstanceID, "compartmentId": config.CompartmentID,
		"availabilityDomain": config.AvailabilityDomain, "faultDomain": state.FailureDomain, "lifecycleState": "RUNNING",
		"shape": config.Shape, "shapeConfig": map[string]any{"ocpus": compute.WholeOCPUs, "memoryInGBs": compute.MemoryInGBs},
		"imageId": config.ImageID, "metadata": map[string]string{hostboot.MetadataKey: string(wire)}, "freeformTags": tags}
	put("/20160918/instances/"+state.InstanceID, state.InstanceETag, instance)
	put(query("instances", "compartmentId", config.CompartmentID, "limit", "100"), "", []any{instance})
	boot, vnic := "ocid1.bootvolume.oc1.sa-saopaulo-1.sourcerenewal", "ocid1.vnic.oc1.sa-saopaulo-1.sourcerenewal"
	put(query("bootVolumeAttachments", "compartmentId", config.CompartmentID, "availabilityDomain", config.AvailabilityDomain, "instanceId", state.InstanceID), "",
		[]any{map[string]any{"instanceId": state.InstanceID, "bootVolumeId": boot, "lifecycleState": "ATTACHED"}})
	put("/20160918/bootVolumes/"+boot, "boot-v1", map[string]any{"id": boot, "compartmentId": config.CompartmentID,
		"availabilityDomain": config.AvailabilityDomain, "imageId": config.ImageID, "sizeInGBs": 50, "vpusPerGB": 10, "lifecycleState": "AVAILABLE"})
	put(query("vnicAttachments", "compartmentId", config.CompartmentID, "instanceId", state.InstanceID), "",
		[]any{map[string]any{"instanceId": state.InstanceID, "vnicId": vnic, "lifecycleState": "ATTACHED"}})
	put("/20160918/vnics/"+vnic, "", map[string]any{"id": vnic, "subnetId": config.SubnetID, "privateIp": hostIP,
		"lifecycleState": "AVAILABLE", "nsgIds": config.NetworkSecurityGroupIDs})
	volumeTags := maps.Clone(tags)
	delete(volumeTags, "terrascale-host-node")
	delete(volumeTags, "terrascale-placement-profile-digest")
	delete(volumeTags, "terrascale-placement-generation")
	volumeTags["terrascale-resource"], volumeTags["terrascale-create-key"], volumeTags["terrascale-volume-size-gib"] = "member-data", volumeKey, "50"
	put("/20160918/volumes/"+state.VolumeID, "volume-v1", map[string]any{"id": state.VolumeID, "compartmentId": config.CompartmentID,
		"availabilityDomain": config.AvailabilityDomain, "lifecycleState": "AVAILABLE", "sizeInGBs": 50, "vpusPerGB": 10, "freeformTags": volumeTags})
	attachment := map[string]any{"id": state.AttachmentID, "instanceId": state.InstanceID, "volumeId": state.VolumeID,
		"device": state.AttachmentDevice, "lifecycleState": "ATTACHED", "attachmentType": "paravirtualized",
		"isReadOnly": false, "isShareable": false, "isPvEncryptionInTransitEnabled": true}
	put("/20160918/volumeAttachments/"+state.AttachmentID, state.AttachmentETag, attachment)
	put(query("volumeAttachments", "compartmentId", config.CompartmentID, "instanceId", state.InstanceID, "limit", "100"), "", []any{attachment})
	put(query("volumeAttachments", "compartmentId", config.CompartmentID, "availabilityDomain", config.AvailabilityDomain, "volumeId", state.VolumeID, "limit", "100"), "", []any{attachment})
	put("/20160918/images/"+config.ImageID, "", map[string]any{"id": config.ImageID, "compartmentId": config.ImageCompartmentID, "lifecycleState": "AVAILABLE"})
	put("/20160918/images/"+config.ImageID+"/shapes/"+config.Shape, "", map[string]any{"imageId": config.ImageID, "shape": config.Shape})
	processor := "AMD EPYC"
	if runtime.GOARCH == "arm64" {
		processor = "AmpereOne ARM"
	}
	put(query("shapes", "compartmentId", config.CompartmentID, "availabilityDomain", config.AvailabilityDomain, "imageId", config.ImageID, "shape", config.Shape), "",
		[]any{map[string]any{"shape": config.Shape, "processorDescription": processor}})
	if err := proof.VerifyImageQualified(t.Context(), config.Region, config.ImageID); err != nil {
		t.Fatalf("genuine signed image and instance-principal readback: %v", err)
	}
	factory, err := ociclient.InstancePrincipal("sa-saopaulo-1")
	if err != nil {
		t.Fatal(err)
	}
	volumes, err := oci.NewVolumeMountObserver(factory, config, intent, journal)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := oci.OpenJournalReader(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	fleet, err := oci.NewFleetObserver(config, intent, factory, reader, proof)
	if err != nil {
		t.Fatal(err)
	}
	pins := oci.VolumeInitializationPins{DatabaseID: state.DatabaseID, PartitionID: state.PartitionID,
		InstanceID: state.InstanceID, HostCreateKey: state.CreateKey, VolumeID: state.VolumeID, AttachmentID: state.AttachmentID,
		AttachmentETag: state.AttachmentETag, Device: state.AttachmentDevice,
		FileSystemUUID: state.RuntimeManifest.FileSystemUUID, FileSystemType: state.RuntimeManifest.FileSystemType}
	observation, err := volumes.InspectVolumeMount(t.Context(), pins, "")
	if err != nil || !observation.IsVerified() || observation.Pins() != pins || observation.BootDescriptorSHA256() != descriptorSHA {
		t.Fatalf("actual volume observer and retained ownership: %v", err)
	}
	observed, err := fleet.Observe(t.Context())
	if err != nil || len(observed) != 1 || observed[0].BootDescriptorSHA256 != descriptorSHA || observed[0].Node != state.HostNode {
		t.Fatalf("actual fleet observer and signed image: %v", err)
	}
	return config, volumes, fleet
}

func renewalPlacement(t *testing.T, material renewalMaterial, artifact, source string) placement.Intent {
	t.Helper()
	baseline := testManagedPlacementIntent()
	baseline.DatabaseID, baseline.PartitionID = material.deployment.PlacementDatabaseID, material.deployment.PartitionID
	for index := range baseline.RuntimeManifests {
		manifest := &baseline.RuntimeManifests[index]
		manifest.ArtifactDigest, manifest.SourceDigest = artifact, source
		manifest.ManagedRuntimeRoot = material.deployment.ManagedRuntimeRoot
		for _, member := range material.deployment.Members {
			if member.SeatID == manifest.SeatID {
				manifest.FileSystemUUID = member.FileSystemUUID
			}
		}
	}
	return backupAdmissionIntent(t, baseline, material.receipt)
}

func renewalMemberState(t *testing.T, intent placement.Intent, index int) placement.MemberState {
	t.Helper()
	row, manifest := intent.CanonicalRoster.Rows[index], intent.RuntimeManifests[index]
	if row.SeatID != manifest.SeatID {
		t.Fatal("renewal fixture roster and runtime seat order differs")
	}
	manifestSHA, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := intent.ManagedHostProfile(oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	profileSHA, err := profile.ProfileDigest()
	if err != nil {
		t.Fatal(err)
	}
	rosterSHA, err := intent.CanonicalRosterDigest()
	if err != nil {
		t.Fatal(err)
	}
	kind := placement.MemberPermanent
	if index == 1 {
		kind = placement.MemberElastic
	}
	state := placement.MemberState{SchemaVersion: 5, DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
		MemberID: row.SeatID, Region: row.Region, FailureDomain: row.FailureDomain, Kind: kind, Stage: placement.StageServing,
		CreateKey: entityid.New(), HostNode: "fixture-host", InstanceID: renewalFixtureInstance,
		InstanceETag: "instance-v1", VolumeID: fmt.Sprintf("ocid1.volume.oc1.sa-saopaulo-1.sourcerenewal%d", index),
		AttachmentID:     fmt.Sprintf("ocid1.volumeattachment.oc1.sa-saopaulo-1.sourcerenewal%d", index),
		AttachmentDevice: "/dev/loop0", AttachmentETag: "attachment-v1", HostAttempt: 1,
		IntentGeneration: intent.Generation, IntentPayloadDigest: intent.PayloadDigest(), ManagedHostProfile: profile,
		ManagedHostProfileDigest: profileSHA, CanonicalRosterRow: row, CanonicalRosterDigest: rosterSHA,
		AuthorityReference: intent.CanonicalRoster.Authority, RuntimeManifest: manifest, RuntimeManifestDigest: manifestSHA,
		DesiredGeneration: 1, HostGeneration: 1, OperationID: entityid.New(), UpdatedAt: time.Now().UTC()}
	if err := state.Validate(); err != nil {
		t.Fatalf("retained initial member state: %v", err)
	}
	return state
}

func TestSourceRenewalOwnershipSDKFixtureIntegration(t *testing.T) {
	if !renewalIsolatedChild(t) {
		return
	}
	cloud := newRenewalCloud(t)
	js := testRolloutJetStream(t)
	control, err := authority.Start(t.Context(), js, authority.Config{DeploymentID: entityid.New(), Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	material := renewalRetainMaterial(t, cloud, renewalStorageClient(t), control, "/srv/source-renewal")
	intent := renewalPlacement(t, material, strings.Repeat("a", 64), strings.Repeat("b", 64))
	state := renewalMemberState(t, intent, 0)
	_, _, _ = renewalOwnedFleet(t, cloud, js, &state)
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	if cloud.rejected != 0 {
		t.Fatalf("ownership fixture rejected %d unexpected or unsigned SDK calls", cloud.rejected)
	}
}

func renewalDesired(epoch uint64, state placement.MemberState, registration host.Registration) (host.Desired, error) {
	manifest := state.EffectiveRuntimeManifest()
	binding := *registration.ManagedMember
	mountPath, err := host.ManagedMountPath(manifest.ManagedRuntimeRoot, binding)
	if err != nil {
		return host.Desired{}, err
	}
	return host.Desired{
		Cell: registration.Cell, Node: state.HostNode, Environment: registration.Environment,
		Role: "terrabase", Digest: manifest.ArtifactDigest,
		Generation: state.DesiredGeneration, AuthorityEpoch: epoch,
		ManagedMember: &host.ManagedMemberLaunch{
			OCI: host.ManagedOCIBinding{
				Region: registration.ManagedOCI.Region, InstanceID: state.InstanceID, Owner: registration.ManagedOCI.Owner,
				FleetGeneration: registration.ManagedOCI.FleetGeneration, CreateKey: state.CreateKey,
			},
			Member: binding,
			Authority: host.MemberAuthority{
				Epoch: state.AuthorityReference.Epoch, ConfigurationID: state.AuthorityReference.ConfigurationID,
				CertificateSHA256: state.AuthorityReference.CertificateSHA256,
				TLSLeafSHA256:     state.CanonicalRosterRow.TLSLeafSHA256,
			},
			SourceDigest: manifest.SourceDigest, VolumeID: state.VolumeID,
			AttachmentID: state.AttachmentID, AttachmentETag: state.AttachmentETag,
			ProcessMemoryBytes:   state.ManagedHostProfile.ProcessMemoryBytes,
			MemoryHeadroomBytes:  state.ManagedHostProfile.MemoryHeadroomBytes,
			CgroupMemoryMaxBytes: state.ManagedHostProfile.CgroupMemoryMaxBytes,
			SystemReserveBytes:   state.ManagedHostProfile.SystemReserveBytes,
			Runtime: &host.ManagedRuntimePins{
				DevicePath: state.AttachmentDevice, MountPath: mountPath,
				FileSystemUUID: manifest.FileSystemUUID, FileSystemType: manifest.FileSystemType,
				TrustedKeySHA256:                    manifest.TrustedKeySHA256,
				ServerCertificateSHA256:             manifest.ServerCertificateSHA256,
				ServerPrivateKeySHA256:              manifest.ServerPrivateKeySHA256,
				ClientCARootsSHA256:                 manifest.ClientCARootsSHA256,
				ClientManagedMaterialManifestSHA256: manifest.ClientManagedMaterialManifestSHA256,
				SQLSchemaBundleSHA256:               manifest.SQLSchemaBundleSHA256,
				LiveS3ConfigSHA256:                  manifest.LiveS3ConfigSHA256,
				LiveS3TargetSHA256:                  manifest.LiveS3TargetSHA256,
				LiveS3Credential:                    manifest.LiveS3Credential,
				BackupManifestSHA256:                manifest.BackupManifestSHA256,
				BackupS3ConfigSHA256:                manifest.BackupS3ConfigSHA256,
				BackupS3TargetSHA256:                manifest.BackupS3TargetSHA256,
				BackupS3CredentialSHA256:            manifest.BackupS3CredentialSHA256,
				BackupDataKeySHA256:                 manifest.BackupDataKeySHA256,
				BackupOwner:                         manifest.BackupOwner,
				BackupS3Credential:                  manifest.BackupS3Credential,
				BackupDataKey:                       manifest.BackupDataKey,
				ReplicationListenAddress:            manifest.ReplicationListenAddress,
				ReplicationPeerMemberID:             manifest.ReplicationPeerMemberID,
				ReplicationPeerAddress:              manifest.ReplicationPeerAddress,
				ReplicationServerCASHA256:           manifest.ReplicationServerCASHA256,
			},
		},
	}, nil
}

// The actual concrete authorizer guards each actual manager mutation. Socket
// peer identity is qualified separately by the management integration fixture.
type renewalCanonicalManager struct {
	api.ControlClient
	authorizer *executionleader.ServiceAuthorizer
}

func (manager renewalCanonicalManager) CreateService(ctx context.Context, request *api.CreateServiceRequest, options ...grpc.CallOption) (*api.CreateServiceResponse, error) {
	var response *api.CreateServiceResponse
	err := manager.authorizer.WithStatefulService(ctx, request.Spec, func(effect context.Context) error {
		var err error
		response, err = manager.ControlClient.CreateService(effect, request, options...)
		return err
	})
	return response, err
}

func (manager renewalCanonicalManager) UpdateService(ctx context.Context, request *api.UpdateServiceRequest, options ...grpc.CallOption) (*api.UpdateServiceResponse, error) {
	var response *api.UpdateServiceResponse
	err := manager.authorizer.WithStatefulService(ctx, request.Spec, func(effect context.Context) error {
		var err error
		response, err = manager.ControlClient.UpdateService(effect, request, options...)
		return err
	})
	return response, err
}

func renewalNode(t *testing.T, directory, id, role, instance string, executor *swarmruntime.Executor,
	managerAddress, token string,
) *swarmruntime.Node {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	node, err := swarmruntime.StartNode(t.Context(), swarmruntime.NodeConfig{
		StateDir: directory, ListenAddress: address, AdvertiseAddress: address,
		Admission: swarmruntime.Admission{Region: "sa-saopaulo-1", HostID: id, InstanceID: instance,
			FounderID: "renewal-founder", Role: role, ManagerAddress: managerAddress, JoinToken: token}}, executor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := node.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
	return node
}

func renewalInstallMaterial(t *testing.T, material renewalMaterial) {
	t.Helper()
	root := material.deployment.ManagedRuntimeRoot
	for _, member := range material.receipt.Spec.Members {
		for _, path := range []string{root, filepath.Dir(member.MaterialDirectory), member.MaterialDirectory,
			filepath.Join(filepath.Dir(member.MaterialDirectory), "control")} {
			if err := os.MkdirAll(path, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, 0, 65532); err != nil {
				t.Fatal(err)
			}
			mode := os.FileMode(0o750)
			if filepath.Base(path) == "control" {
				mode = 0o730
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
		}
		for _, bundle := range material.bundle.Members {
			if bundle.MemberID != member.MemberID {
				continue
			}
			for name, file := range bundle.Files {
				path := filepath.Join(member.MaterialDirectory, name)
				if err := os.WriteFile(path, file.Contents, 0o440); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(path, 0, 65532); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func renewalWait(t *testing.T, label string, until time.Time, ready func() bool) {
	t.Helper()
	for !ready() {
		if !time.Now().Before(until) {
			t.Fatal("timed out: " + label)
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func renewalDelivery(t *testing.T, js jetstream.JetStream, control *authority.Runtime, members placement.Store,
	upstream api.ControlClient, volumes *oci.VolumeMountObserver, signed renewalSignedRelease,
) (*delivery.Service, *executionleader.Producer, delivery.Intent) {
	t.Helper()
	identity := cellspec.Identity{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Cell: "gru", Environment: "production"}
	profile := cellspec.Spec{Schema: cellspec.Schema, Identity: identity, Generation: 1, RequiresBinary: 1,
		Services: []cellspec.Service{{Role: "terrabase", Profile: cellspec.Profile{Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 32 << 30}}}}}
	wire, err := cellspec.Sign(profile, nil, signed.roots, time.Now(), time.Hour, signed.root)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "RENEWAL_SIGNED_PROFILE", Storage: jetstream.FileStorage, History: 2, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := profiles.Create(t.Context(), "current", wire)
	if err != nil {
		t.Fatal(err)
	}
	verifyProfile := func(ctx context.Context, intent delivery.Intent) error {
		entry, err := profiles.Get(ctx, "current")
		if err != nil {
			return err
		}
		verified, err := cellspec.VerifyHistorical(entry.Value(), signed.roots, identity)
		if err != nil {
			return err
		}
		if !verified.RootSigned || entry.Revision() != revision || verified.Spec.Generation != 1 ||
			intent.Cell != identity.Cell || intent.Environment != identity.Environment {
			return execution.ErrUnsafe
		}
		for _, service := range verified.Spec.Services {
			if service.Role == intent.Role && intent.ConfigDigest == delivery.ConfigDigestOf(service.Profile.Args, service.Profile.Env, service.Profile.Secrets) {
				return nil
			}
		}
		return execution.ErrUnsafe
	}
	key := signed.signer.Public().(ed25519.PublicKey)
	keyID, err := protocol.KeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	codec := delivery.Ed25519Codec{Cell: "gru", Actor: "release", PrivateKey: signed.signer,
		Trusted: map[string]delivery.TrustedSigner{keyID: {Actor: "release", PublicKey: key}}, Lifetime: time.Minute, MaxLifetime: time.Minute}
	authorize := func(ctx context.Context, actor string, intent delivery.Intent) error {
		if actor != "release" {
			return delivery.ErrUnauthorized
		}
		return verifyProfile(ctx, intent)
	}
	var producer *executionleader.Producer
	releases, err := delivery.Open(t.Context(), delivery.Config{Conn: js.Conn(), JS: js, Cell: "gru", Replicas: 1,
		Signer: codec, Verifier: codec, Fencer: control, Authorize: authorize,
		ContainerApply: func(ctx context.Context, intent delivery.Intent) error { return producer.Apply(ctx, intent) }})
	if err != nil {
		t.Fatal(err)
	}
	rootDelivery, err := delivery.ConnectClient(t.Context(), delivery.Config{Conn: js.Conn(), JS: js, Cell: "gru", Verifier: codec, Authorize: authorize})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.DecodeEnvelope(signed.bundle.Claim)
	if err != nil {
		t.Fatal(err)
	}
	var claim release.ContainerClaim
	if err := protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
		t.Fatal(err)
	}
	intent := delivery.Intent{SchemaVersion: delivery.SchemaVersion, OperationID: entityid.New(),
		Source: delivery.ArtifactSource{Repository: claim.SourceRepository, Commit: claim.SourceRevision, TreeDigest: claim.SourceTreeSHA256},
		Cell:   "gru", Role: "terrabase", Environment: "production", Generation: 1, DesiredReplicas: 1,
		ConfigDigest: delivery.ConfigDigestOf(nil, nil, nil), AuthorityEpoch: control.Current().Epoch, Container: &signed.bundle}
	allocations := func(_ context.Context, operation string, bundle release.ContainerBundle, _ trust.Keyring, target release.ContainerTarget) (release.SequenceLocation, error) {
		if operation != intent.OperationID || !bytes.Equal(bundle.Claim, signed.bundle.Claim) || target.Cell != claim.Cell ||
			target.Environment != claim.Environment || target.Role != claim.Role || target.Architecture != claim.Architecture {
			return release.SequenceLocation{}, execution.ErrUnsafe
		}
		return signed.allocations, nil
	}
	evidence := func(ctx context.Context, operation, sha string) (io.ReadCloser, error) {
		if operation != intent.OperationID {
			return nil, execution.ErrUnsafe
		}
		return releasechannel.ReadContainerEvidence(ctx, signed.evidence, "terrabase", sha)
	}
	reader, err := authority.OpenReader(t.Context(), js, "gru")
	if err != nil {
		t.Fatal(err)
	}
	pinReader, err := placement.OpenMemberPinReader(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := executionleader.NewServiceAuthorizer(executionleader.ServiceAuthorizerConfig{Client: upstream,
		Authority: reader, Members: pinReader, Delivery: rootDelivery, Roots: signed.roots, Evidence: evidence,
		Allocations: allocations, Profile: verifyProfile, Guard: control.Guard, Cell: "gru", Environment: "production"})
	if err != nil {
		t.Fatal(err)
	}
	producer, err = executionleader.NewProducer(renewalCanonicalManager{ControlClient: upstream, authorizer: gate}, control,
		members, releases, volumes, signed.roots, evidence, "gru", "production", allocations, evidence, allocations, signed.roots)
	if err != nil {
		t.Fatal(err)
	}
	return releases, producer, intent
}

// This exercises Source renewal from retained starting-state records. Native
// producer validation, initial OCI provisioning and root socket peer admission
// remain separate required qualification; this fixture never executes TerraBase.
func TestSourceBackupRenewalIntegration(t *testing.T) {
	if !renewalIsolatedChild(t) {
		return
	}
	directory, err := os.MkdirTemp("/tmp", "ts-renewal-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	cloud := newRenewalCloud(t)
	auth := newAuthenticatedNATS(t, "gru")
	broker, err := auth.start(t, t.Context(), natscell.Config{Cell: "gru", Instance: "source-renewal", Replicas: 1, Embedded: &natscell.Embedded{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	js := broker.JetStream()
	control, err := authority.Start(t.Context(), js, authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	epoch := control.Current().Epoch
	storage := renewalStorageClient(t)
	material := renewalRetainMaterial(t, cloud, storage, control, filepath.Join(directory, "managed"))
	renewalInstallMaterial(t, material)
	owner := material.deployment.Members[0]
	binding := host.ManagedMemberBinding{Scope: host.MemberScope{ClusterID: material.deployment.Scope.ClusterID,
		TenantID: material.deployment.Scope.TenantID, DatabaseID: material.deployment.Scope.DatabaseID,
		ShardID: material.deployment.Scope.ShardID, MemberID: owner.MemberID, Incarnation: owner.Incarnation}, HostAttempt: 1}
	mount, err := host.ManagedMountPath(material.deployment.ManagedRuntimeRoot, binding)
	if err != nil {
		t.Fatal(err)
	}
	volume := renewalLoopVolume(t, directory, mount)
	material.deployment.Members[0].FileSystemUUID = volume.FileSystemUUID
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	native, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	intent := renewalPlacement(t, material, fmt.Sprintf("%x", sha256.Sum256(native)), strings.Repeat("e", 64))
	state := renewalMemberState(t, intent, 0)
	state.AttachmentDevice = volume.DevicePath
	config, volumes, fleet := renewalOwnedFleet(t, cloud, js, &state)
	wire, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.CommitPlacementIntent(t.Context(), epoch, intent.DatabaseID, intent.PartitionID, intent.OperationID(), 0, wire); err != nil {
		t.Fatal(err)
	}
	intents, err := placement.NewAuthorityIntentReader(control, "gru", oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	members, err := placement.NewJetStreamStore(t.Context(), js, "gru", 1, intents)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := members.CompareAndSwap(t.Context(), 0, state); err != nil {
		t.Fatal(err)
	}
	peer := renewalMemberState(t, intent, 1)
	peer.InstanceID, peer.HostNode = "ocid1.instance.oc1.sa-saopaulo-1.sourcerenewalpeer", "retained-source-renewal-peer"
	if _, err := members.CompareAndSwap(t.Context(), 0, peer); err != nil {
		t.Fatal(err)
	}
	client := newRenewalContainerd(t, directory)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(namespaces.WithNamespace(context.Background(), "terrascale"), 10*time.Second)
		defer cancel()
		containers, err := client.Containers(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		for _, container := range containers {
			if task, err := container.Task(ctx, nil); err == nil {
				_, _ = task.Delete(ctx, containerd.WithProcessKill)
			}
			if err := container.Delete(ctx, containerd.WithSnapshotCleanup); err != nil {
				t.Error(err)
			}
		}
	})
	memberIndex := slices.IndexFunc(material.receipt.Spec.Members[:], func(member managedmaterial.InitialMember) bool { return member.MemberID == owner.MemberID })
	memberAuthority := memberstatus.Authority{Epoch: material.receipt.Spec.Scope.Epoch, ConfigurationID: material.receipt.AuthorityConfigurationID,
		CertificateSHA256: material.receipt.AuthoritySHA256, TLSLeafSHA256: material.receipt.Members[memberIndex].TLSLeafSHA256}
	authorityWire, err := protocol.EncodeJSON(memberAuthority)
	if err != nil {
		t.Fatal(err)
	}
	image, objects := renewalMemberImage(t, client, []string{"TS_SOURCE_RENEWAL_AUTHORITY=" + string(authorityWire)})
	signed := renewalQualifyImage(t, cloud, storage, image, objects, execution.RetainedData{
		DatabaseID: state.DatabaseID, PartitionID: state.PartitionID, VolumeID: state.VolumeID,
		FileSystemUUID: volume.FileSystemUUID, FileSystemType: "ext4", DiskFormatSHA256: strings.Repeat("d", 64),
		SourceArtifactSHA256: state.RuntimeManifest.ArtifactDigest, SourceTreeSHA256: state.RuntimeManifest.SourceDigest, SourceArchitecture: runtime.GOARCH}, native)
	executor, err := swarmruntime.NewExecutor(filepath.Join(directory, "daemon.sock"), filepath.Join(directory, "manager-executor"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = executor.Close() })
	founder := renewalNode(t, filepath.Join(directory, "manager-node"), "renewal-founder", "manager", "ocid1.instance.oc1.sa-saopaulo-1.renewalfounder", executor, "", "")
	upstream, err := founder.ControlClient(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	releases, producer, deployment := renewalDelivery(t, js, control, members, upstream, volumes, signed)
	effects, err := swarmruntime.NewEffectSessions(upstream, control, producer, volumes)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	responsePublic, response, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nkey, seed := testNKey(t)
	registration := host.Registration{ID: entityid.Derive("host", "gru", state.HostNode), Cell: "gru", Node: state.HostNode,
		Environment: "production", Roles: []string{"terrabase"}, Generation: 1, FailureDomain: state.FailureDomain,
		PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: nkey,
		Capacity:           host.Capacity{CPU: runtime.NumCPU(), MemoryBytes: int64(state.ManagedHostProfile.AllocatableMemoryBytes), DiskBytes: 32 << 30},
		SystemReserveBytes: int64(state.ManagedHostProfile.SystemReserveBytes),
		ManagedOCI:         &host.ManagedOCIBinding{Region: "GRU", InstanceID: state.InstanceID, Owner: config.Owner, FleetGeneration: 1, CreateKey: state.CreateKey},
		ManagedPlacement: &host.ManagedPlacementBinding{DatabaseID: state.DatabaseID, PartitionID: state.PartitionID, SeatID: state.MemberID,
			IntentGeneration: state.IntentGeneration, IntentPayloadDigest: state.IntentPayloadDigest, CanonicalRosterDigest: state.CanonicalRosterDigest, ManagedHostProfileDigest: state.ManagedHostProfileDigest},
		ManagedMember: &binding}
	verifier, err := newManagedRegistrationVerifier("gru", oci.RegionGRU, config.Owner, 1, control, members, fleet)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := js.ObjectStore(t.Context(), delivery.ArtifactBucket)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := host.NewController(t.Context(), host.ControllerConfig{Cell: "gru", Conn: broker.Conn(), JS: js,
		Artifacts: artifacts, ResponseKey: response, StateReplicas: 1, HostMutations: control,
		AuthorityEpoch: func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard,
		ManagedRegistrationVerifier: verifier, RuntimeEffects: effects})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hosts.Register(t.Context(), registration); err != nil {
		t.Fatalf("actual registration against current material/placement/SDK host: %v", err)
	}
	desired, err := renewalDesired(epoch, state, registration)
	if err != nil {
		t.Fatal(err)
	}
	if err := host.ValidateContainerDesired(desired, registration); err != nil {
		t.Fatal(err)
	}
	if _, _, err := material.service.CurrentBundle(t.Context(), intent.DatabaseID, intent.PartitionID); err != nil {
		t.Fatal(err)
	}
	desiredWire, err := protocol.EncodeJSON(desired)
	if err != nil {
		t.Fatal(err)
	}
	subject := "gru." + state.HostNode + ".terrabase"
	sequence, err := control.CommitHostMutation(t.Context(), epoch, authority.MutationDesired, subject, entityid.New(), 0, desiredWire)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := control.ReadHostMutation(t.Context(), authority.MutationDesired, subject)
	if err != nil || retained.Sequence != sequence || !bytes.Equal(retained.Payload, desiredWire) {
		t.Fatalf("retained canonical desired R3 sequence/bytes: %v", err)
	}
	hostCtx, stopHosts := context.WithCancel(t.Context())
	hostDone := make(chan error, 1)
	go func() { hostDone <- hosts.Run(hostCtx) }()
	t.Cleanup(func() { stopHosts(); <-hostDone })
	select {
	case <-hosts.Ready():
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	transport, err := auth.start(t, t.Context(), natscell.Config{Cell: "gru", Instance: state.HostNode,
		URL: broker.Conn().ConnectedUrl(), ClientRole: "host", NKeySeedFile: seed})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	ready := make(chan struct{})
	agent, err := host.NewAgent(host.AgentConfig{Cell: "gru", Node: state.HostNode, Environment: "production", Roles: registration.Roles,
		Conn: transport.Conn(), Identity: private, NATSUserPublicKey: nkey, ControllerPublicKey: responsePublic,
		InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t), ManagedRuntimeRoot: material.deployment.ManagedRuntimeRoot,
		WorkloadIdentity: host.WorkloadIdentity{UID: 65532, GID: 65532}, BakedSystemReserveBytes: state.ManagedHostProfile.SystemReserveBytes,
		ClockCheck: controllerClockCheck(hostClockProbe()), Initialized: func() { close(ready) }})
	if err != nil {
		t.Fatal(err)
	}
	agentCtx, stopAgent := context.WithCancel(t.Context())
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.RunSession(agentCtx) }()
	t.Cleanup(func() { stopAgent(); <-agentDone })
	select {
	case <-ready:
	case err := <-agentDone:
		agentDone <- err
		t.Fatalf("real signed Agent session: %v", err)
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	workerExecutor, err := swarmruntime.NewExecutor(filepath.Join(directory, "daemon.sock"), filepath.Join(directory, "worker-executor"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = workerExecutor.Close() })
	clusters, err := upstream.ListClusters(t.Context(), &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		t.Fatalf("actual manager join material: %v", err)
	}
	address, err := founder.RemoteAddress()
	if err != nil {
		t.Fatal(err)
	}
	worker := renewalNode(t, filepath.Join(directory, "worker-node"), registration.ID, "container", state.InstanceID,
		workerExecutor, address, clusters.Clusters[0].RootCA.JoinTokens.Worker)
	session, err := execution.NewWorkerSessionFromAgent(agent, state.InstanceID, worker.ID(), client)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.BindRuntimeStopSigner(worker); err != nil {
		t.Fatal(err)
	}
	sourceDirectory := filepath.Join(directory, "source")
	if err := os.Mkdir(sourceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := execution.NewSource(session, execution.RuntimeObserver{Client: client}, signed.roots, signed.evidence, sourceDirectory,
		func(_ context.Context, bundle release.ContainerBundle, _ trust.Keyring, target release.ContainerTarget) (release.SequenceLocation, error) {
			if !bytes.Equal(bundle.Claim, signed.bundle.Claim) || target.Cell != "GRU" || target.Role != "terrabase" || target.Environment != "production" || target.Architecture != runtime.GOARCH {
				return release.SequenceLocation{}, execution.ErrUnsafe
			}
			return signed.allocations, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := workerExecutor.BindStateful(source); err != nil {
		t.Fatal(err)
	}
	node, err := upstream.GetNode(t.Context(), &api.GetNodeRequest{NodeID: worker.ID()})
	if err != nil {
		t.Fatal(err)
	}
	active := node.Node.Spec.Copy()
	active.Availability = api.NodeAvailabilityActive
	active.Annotations.Labels = map[string]string{swarmruntime.LabelRegion: "sa-saopaulo-1", swarmruntime.LabelExecutionScope: "platform",
		"terrascale.instance-id": state.InstanceID, "terrascale.host-role": "container"}
	if _, err := upstream.UpdateNode(t.Context(), &api.UpdateNodeRequest{NodeID: worker.ID(), NodeVersion: &node.Node.Meta.Version, Spec: active}); err != nil {
		t.Fatal(err)
	}
	deliveryCtx, stopDelivery := context.WithCancel(t.Context())
	deliveryDone := make(chan error, 1)
	go func() { deliveryDone <- releases.Run(deliveryCtx) }()
	t.Cleanup(func() { stopDelivery(); <-deliveryDone })
	if err := releases.Submit(t.Context(), deployment); err != nil {
		t.Fatal(err)
	}
	renewalAssertBackupLifecycle(t, cloud, control, members, hosts, agent, session, source, client, upstream, material, state, desired, response)
}

func renewalAssertBackupLifecycle(t *testing.T, cloud *renewalCloud, control *authority.Runtime, members placement.Store,
	hosts *host.Controller, agent *host.Agent, session *execution.WorkerSession, source *execution.Source,
	client *containerd.Client, manager api.ControlClient, material renewalMaterial, state placement.MemberState,
	desired host.Desired, response ed25519.PrivateKey,
) {
	t.Helper()
	scope := authority.WorkloadScope{DatabaseID: state.DatabaseID, PartitionID: state.PartitionID}
	var first authority.RuntimeEffect
	renewalWait(t, "first real R3 worker effect", time.Now().Add(45*time.Second), func() bool {
		history, err := control.ListRuntimeEffectHistory(t.Context(), scope)
		if err != nil {
			t.Fatal(err)
		}
		if len(history) == 0 {
			return false
		}
		if len(history) != 1 || history[0].Phase != authority.RuntimeEffectHeld {
			t.Fatalf("unexpected initial real effects: %+v", history)
		}
		first = history[0]
		if time.Since(first.IssuedAt) >= 3*time.Second {
			t.Fatal("first effect was not observed before the worker's first renewal interval")
		}
		return true
	})
	var task *api.Task
	renewalWait(t, "actual manager task assignment", time.Now().Add(20*time.Second), func() bool {
		tasks, err := manager.ListTasks(t.Context(), &api.ListTasksRequest{})
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range tasks.Tasks {
			if candidate.ID == first.TaskID && execution.Stateful(candidate) {
				task = candidate.Copy()
				return true
			}
		}
		return false
	})
	mount, _, publication, err := host.ContainerMemberPaths(material.deployment.ManagedRuntimeRoot, *desired.ManagedMember)
	if err != nil {
		t.Fatal(err)
	}
	marker := func(name string) string { return filepath.Join(mount, "data", "fixture-"+name) }
	renewalWait(t, "native/runc workload start and actual Source report", time.Now().Add(30*time.Second), func() bool {
		if _, err := os.Stat(marker("started")); err != nil {
			return false
		}
		statuses, err := hosts.ListHosts(t.Context())
		if err != nil {
			return false
		}
		for _, current := range statuses {
			for _, report := range current.Reports {
				if report.Managed != nil && report.Managed.Container != nil && report.Managed.Container.EffectID == first.EffectID {
					return true
				}
			}
		}
		return false
	})
	pins, err := source.ResolveRuntime(t.Context(), task)
	if err != nil {
		t.Fatal(err)
	}
	observer := execution.RuntimeObserver{Client: client}
	before, err := observer.Observe(t.Context(), pins)
	if err != nil || before.State != containerd.Running || before.Process.PID < 2 || before.Process.ProtocolPID() != 1 {
		t.Fatalf("exact initial native/runc writer: %+v error=%v", before, err)
	}
	if _, err := agent.RuntimeWorkerIdentity(state.InstanceID, task.NodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(publication); err != nil {
		t.Fatalf("Source did not publish its actual Unix root socket: %v", err)
	}
	operator, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := buildSignerPolicy(Config{NATS: natscell.Config{Cell: "gru"}, Controller: ControllerConfig{
		TrustedSigners: []TrustedSignerConfig{{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operator),
			Roles: []string{"terrabase"}, Environments: []string{"production"}, CanOperateBackup: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := backupOperationRuntime{cell: "gru", memberRole: "terrabase", control: control, placements: members, hosts: hosts,
		producer: managedmaterial.BackupOperationProducer{Preparation: material.service, Store: control}, policy: policy, responseKey: response}
	request, err := protocol.EncodeJSON(backupOperationRequest{Action: "start", DatabaseID: state.DatabaseID, PartitionID: state.PartitionID})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(request, protocol.EnvelopeScope{Region: "gru", Kind: "backup.operation", Actor: "ops",
		OperationID: entityid.New(), Generation: 1, Epoch: control.Current().Epoch}, now, now.Add(time.Minute), signer)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := runtime.admit(t.Context(), envelope)
	if err != nil || reply.OperationID == "" || reply.Sequence == 0 {
		t.Fatalf("actual signed backup admission and final current roster: %+v error=%v", reply, err)
	}
	if err := hosts.RequestManagedBackupOperation(t.Context(), control.Current().Epoch, state.DatabaseID, state.PartitionID,
		desired.ManagedMember.Member.Scope.MemberID, "prepare"); err != nil {
		t.Fatalf("actual signed Prepare relay to Source: %v", err)
	}
	renewalWait(t, "blocked real Unix Prepare request", time.Now().Add(8*time.Second), func() bool {
		_, err := os.Stat(marker("prepare-started"))
		return err == nil
	})
	startedWire, err := os.ReadFile(marker("prepare-started"))
	if err != nil {
		t.Fatal(err)
	}
	started, err := time.Parse(time.RFC3339Nano, string(startedWire))
	if err != nil || !started.Before(first.ExpiresAt) {
		t.Fatalf("Prepare must block before the first grant deadline: started=%s first=%s error=%v", started, first.ExpiresAt, err)
	}
	var renewed authority.RuntimeEffect
	renewalWait(t, "blocked Prepare crosses initial deadline using actual R3 renewal", first.ExpiresAt.Add(10*time.Second), func() bool {
		history, err := control.ListRuntimeEffectHistory(t.Context(), scope)
		if err != nil || len(history) != 1 {
			t.Fatalf("real renewal history: %+v error=%v", history, err)
		}
		renewed = history[0]
		if renewed.EffectID != first.EffectID || renewed.TaskID != task.ID || renewed.Phase != authority.RuntimeEffectHeld ||
			renewed.MaterialSHA256 != first.MaterialSHA256 {
			t.Fatalf("renewal changed retained admission identity: %+v", renewed)
		}
		actual, err := observer.Observe(t.Context(), pins)
		if err != nil || actual != before {
			t.Fatalf("blocked Prepare lost exact writer during renewal: %v", err)
		}
		if _, err := os.Lstat(publication); err != nil {
			t.Fatalf("publication withdrawn during valid renewal: %v", err)
		}
		if _, err := os.Stat(marker("prepare-canceled")); err == nil {
			t.Fatal("Prepare canceled while renewed authority remained current")
		}
		return time.Now().After(first.ExpiresAt.Add(time.Second)) && renewed.Sequence > first.Sequence && renewed.ExpiresAt.After(first.ExpiresAt)
	})
	current, err := session.Resolve(t.Context(), task)
	if err != nil || current.EffectID() != first.EffectID || !current.Deadline().After(first.ExpiresAt) {
		t.Fatalf("actual WorkerSession did not adopt renewed deadline: %v", err)
	}
	// Change one exact provider ETag. The genuine producer's next independent
	// volume read must refuse renewal, while the host session remains valid.
	cloud.mu.Lock()
	path := renewalFixtureCompute + "/20160918/volumeAttachments/" + state.AttachmentID
	route := cloud.routes[path]
	readsBeforeFailure := route.reads
	route.etag = "changed-attachment-after-renewal"
	cloud.routes[path] = route
	cloud.mu.Unlock()
	failedAt := time.Now()
	renewalWait(t, "expiry withdraws actual publication and stops exact writer", renewed.ExpiresAt.Add(15*time.Second), func() bool {
		_, socketErr := os.Lstat(publication)
		stopped, err := renewalOriginalProcessStopped(before.Process.PID, before.Process.KernelStart)
		if err != nil {
			t.Fatalf("read exact original writer identity: %v", err)
		}
		return errors.Is(socketErr, os.ErrNotExist) && stopped
	})
	if connection, err := net.DialTimeout("unix", publication, time.Second); err == nil {
		connection.Close()
		t.Fatal("withdrawn publication still accepts Unix connections")
	}
	if _, err := session.Resolve(t.Context(), task); err == nil {
		t.Fatal("expired exact writer retained a usable WorkerSession grant")
	}
	var last authority.RuntimeEffect
	renewalWait(t, "real close or stopped-proof settlement retained in R3", renewed.ExpiresAt.Add(15*time.Second), func() bool {
		history, err := control.ListRuntimeEffectHistory(t.Context(), scope)
		if err != nil || len(history) != 1 || history[0].EffectID != first.EffectID {
			t.Fatalf("expiry discarded retained effect: %+v error=%v", history, err)
		}
		last = history[0]
		return (last.Phase == authority.RuntimeEffectClosing || last.Phase == authority.RuntimeEffectSettled) && !time.Now().Before(last.ExpiresAt)
	})
	if last.MaterialSHA256 != first.MaterialSHA256 || !bytes.Equal(last.Material, first.Material) ||
		last.TaskSHA256 != first.TaskSHA256 || last.AdmissionSHA256 != first.AdmissionSHA256 ||
		last.InstanceID != first.InstanceID || last.NodeID != first.NodeID {
		t.Fatal("closed effect changed its retained exact-writer admission")
	}
	if last.ExpiresAt.After(renewed.ExpiresAt.Add(3 * time.Second)) {
		t.Fatal("changed provider attachment continued renewing execution authority")
	}
	cloud.mu.Lock()
	readsAfterFailure, rejected := cloud.routes[path].reads, cloud.rejected
	cloud.mu.Unlock()
	if readsAfterFailure <= readsBeforeFailure || rejected != 0 {
		t.Fatalf("genuine signed attachment read after ETag change: before=%d after=%d rejected=%d", readsBeforeFailure, readsAfterFailure, rejected)
	}
	if _, err := agent.RuntimeWorkerIdentity(state.InstanceID, task.NodeID); err != nil {
		t.Fatalf("host session expired instead of failed volume renewal: %v", err)
	}
	pending, err := control.ListUnresolvedRuntimeEffects(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if last.Phase != authority.RuntimeEffectSettled && (len(pending) != 1 || pending[0].EffectID != first.EffectID) {
		t.Fatal("unsettled exact writer disappeared from the durable unresolved set")
	}
	if last.Phase == authority.RuntimeEffectSettled && len(pending) != 0 {
		t.Fatal("genuine stopped proof settled the effect but left it unresolved")
	}
	operation, _, err := control.ReadBackupOperation(t.Context(), state.DatabaseID, state.PartitionID)
	if err != nil || operation.OperationID != reply.OperationID {
		t.Fatalf("blocked backup operation was lost during execution expiry: %v", err)
	}
	for _, member := range operation.Roster {
		if len(member.CutEnvelope) != 0 {
			t.Fatal("blocked Prepare produced a cut after authority withdrawal")
		}
	}
	t.Logf("real Source: Prepare blocked at %s, first deadline %s, renewed deadline %s; provider refusal at %s withdrew publication and stopped task=%s hostPID=%d start=%s; retained effect=%s",
		started.Format(time.RFC3339Nano), first.ExpiresAt.Format(time.RFC3339Nano), renewed.ExpiresAt.Format(time.RFC3339Nano), failedAt.Format(time.RFC3339Nano),
		task.ID, before.Process.PID, before.Process.KernelStart, last.Phase)
}

// Match the original kernel start time; an inspection error is never a stop.
func renewalOriginalProcessStopped(pid int, start string) (bool, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	_, rest, ok := strings.CutLast(string(data), ") ")
	fields := strings.Fields(rest)
	if !ok || len(fields) < 20 {
		return false, execution.ErrUnsafe
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return false, err
	}
	return fields[19] != start || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x", nil
}
