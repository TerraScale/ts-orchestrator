//go:build fixturetest

package bootstrapstart

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"golang.org/x/sys/unix"
)

// ControllerManagerStartupTemplate supplies data before signing. The app fixture
// must prepare a disposable root mount namespace and the real service account.
type ControllerManagerStartupTemplate struct {
	Manifests         map[string]bootstrap.Manifest
	MaterialDirectory string
	ServiceUID        uint32
	ServiceGID        uint32
}

// NewInstalledControllerManagerStartupFixture admits rendered config and actual
// generated Vault material at production paths. The app test executable must
// dispatch the production bootstrap-credential-check command in TestMain.
func NewInstalledControllerManagerStartupFixture(t *testing.T, enrollment []byte, broker identityrekey.BrokerIdentity,
	root ed25519.PrivateKey, foundation bootstrap.FoundationScope, template ControllerManagerStartupTemplate,
) *ControllerManagerStartupFixture {
	t.Helper()
	if os.Geteuid() != 0 || template.ServiceUID == 0 || template.ServiceGID == 0 || len(template.Manifests) != 3 {
		t.Fatal("installed manager fixture requires root, a real service account and three rendered manifests")
	}
	currentNamespace, err := os.Readlink("/proc/self/ns/mnt")
	initialNamespace, initialErr := os.Readlink("/proc/1/ns/mnt")
	if err != nil || initialErr != nil || currentNamespace == initialNamespace {
		t.Fatal("installed manager fixture requires a disposable mount namespace", err, initialErr)
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for path, source := range map[string]string{
		"/etc": "ts-installed-controller-etc", "/var/lib": "ts-installed-controller-state", "/run": "ts-installed-controller-run",
	} {
		found := false
		for line := range strings.SplitSeq(string(mounts), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 6 && fields[4] == path && strings.Contains(line, " - tmpfs "+source+" ") {
				found = true
			}
		}
		var stat unix.Statfs_t
		if !found || unix.Statfs(path, &stat) != nil || stat.Type != unix.TMPFS_MAGIC {
			t.Fatalf("installed fixture requires its private tmpfs at %s", path)
		}
	}
	binary := measuredControllerManagerFixtureBinary(t)
	fixture := newControllerManagerStartupFixture(t, enrollment, broker, root, foundation,
		binary, executableBinaryChecker{}, &template)
	measured, err := VerifyAcceptedRunningBinary(fixture.Accepted.Binary)
	if err != nil || measured != binary {
		t.Fatal("installed fixture lost its actual executable measurement", err)
	}
	return fixture
}

func cloneConfigFiles(files []bootstrap.ControllerConfigFile) []bootstrap.ControllerConfigFile {
	result := make([]bootstrap.ControllerConfigFile, len(files))
	for index, file := range files {
		result[index] = file
		result[index].Bytes = bytes.Clone(file.Bytes)
	}
	return result
}

func installedManagerTLSMaterial(t *testing.T, manifest bootstrap.Manifest) bootstrap.FounderTLSMaterialDigests {
	t.Helper()
	digest := func(name string) string {
		t.Helper()
		for _, ref := range manifest.Secrets {
			if ref.TargetFile == name {
				return ref.SHA256
			}
		}
		t.Fatalf("installed manager fixture lacks TLS reference %s", name)
		return ""
	}
	return bootstrap.FounderTLSMaterialDigests{ClientCA: digest("ca.pem"), RouteCA: digest("ca.pem"),
		ClientCertificate: digest(manifest.Slot + "-tls-cert.pem"), RouteCertificate: digest(manifest.Slot + "-tls-cert.pem"),
		ClientPrivateKey: digest(manifest.Slot + "-tls-key.pem"), RoutePrivateKey: digest(manifest.Slot + "-tls-key.pem")}
}

func configureInstalledManagerFixtureGate(t *testing.T, gate *Gate, template *ControllerManagerStartupTemplate, manifest bootstrap.Manifest) {
	t.Helper()
	var cfg struct {
		NATS       natscell.Config `json:"nats"`
		Controller struct {
			ResponseKeyFile        string `json:"response_key_file"`
			BrokerTicketKeyFile    string `json:"broker_ticket_key_file"`
			HostNATSIssuerSeedFile string `json:"host_nats_issuer_seed_file"`
			HostTLSIssuerKeyFile   string `json:"host_tls_issuer_key_file"`
			HostTLSIssuerCertFile  string `json:"host_tls_issuer_cert_file"`
			TerraBaseCACertFile    string `json:"terrabase_ca_cert_file"`
			TerraBaseCAKeyFile     string `json:"terrabase_ca_key_file"`
		} `json:"controller"`
	}
	if err := json.Unmarshal(manifest.ControllerConfig, &cfg); err != nil || cfg.NATS.Embedded == nil ||
		cfg.NATS.Embedded.StoreDir != FounderSelectionFloorDirectory+"/nats" ||
		cfg.NATS.Cell != "gru" || cfg.NATS.Instance != manifest.Slot {
		t.Fatal("installed manager fixture requires its rendered fixed-path NATS config", err)
	}
	client := installedManagerVaultSDK(t, template)
	vault, err := bootstrap.NewVaultFromSDKFixture(client)
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewMaterialStore(vault, template.ServiceUID, template.ServiceGID)
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Controller
	// Root must use the real service-account child for controller key validation.
	credentials, err := NewLiveCredentialChecker(cfg.NATS, template.ServiceUID, template.ServiceGID,
		c.ResponseKeyFile, c.BrokerTicketKeyFile, c.HostNATSIssuerSeedFile, c.HostTLSIssuerKeyFile, c.HostTLSIssuerCertFile,
		func() error { return ErrLiveCredentials })
	if err != nil {
		t.Fatal(err)
	}
	credentials.TerraBaseCACertFile, credentials.TerraBaseCAKeyFile = c.TerraBaseCACertFile, c.TerraBaseCAKeyFile
	credentials.ControllerConfig = bytes.Clone(manifest.ControllerConfig)
	gate.Material, gate.Credentials = material, credentials
	gate.Markers = NewMarkerStore()
	gate.trustStore = &bakedStore{directory: BakedDirectory, chainFile: RootChainFile}
	identity := func(observed natscell.InstallationIdentity, err error) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
		return identityrekey.BrokerIdentity{Operator: observed.Operator, SystemAccount: observed.SystemAccount,
				CellAccount: observed.CellAccount, HostSigner: observed.HostSigner, RoleSigner: observed.RoleSigner,
				AccountSigner: observed.AccountSigner, InterRegionAccount: observed.InterRegionAccount},
			identityrekey.StoreIdentity{Directory: observed.Directory, ServerName: observed.ServerName, RaftNodeID: observed.RaftNodeID,
				ServerNameSHA256: observed.ServerNameSHA256, NodeIdentitySHA256: observed.NodeIdentitySHA256}, err
	}
	gate.InitialIdentity = func(bootstrap.Manifest) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
		return identity(natscell.PrepareInitialInstallationIdentity(cfg.NATS, template.ServiceUID, template.ServiceGID))
	}
	gate.ObserveIdentity = func(AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
		return identity(natscell.ObserveInstalledIdentity(cfg.NATS))
	}
}

func installedManagerVaultSDK(t *testing.T, template *ControllerManagerStartupTemplate) *secrets.SecretsClient {
	t.Helper()
	record, err := bootstrapmaterial.Load(template.MaterialDirectory)
	if err != nil || !time.Now().Before(record.ExpiresAt) {
		t.Fatal("installed fixture requires an intact production-generated material source", err)
	}
	refs := make(map[string]bootstrap.SecretReference)
	for _, manifest := range template.Manifests {
		for _, ref := range manifest.Secrets {
			if prior, exists := refs[ref.SecretOCID]; exists && prior != ref {
				t.Fatal("installed fixture repeats a Vault identity with different material")
			}
			refs[ref.SecretOCID] = ref
			matched := false
			for _, file := range record.Files {
				if ref.TargetFile == file.Name && ref.Purpose == file.Purpose && ref.Slot == file.Slot &&
					ref.SHA256 == file.SHA256 && ref.MaxBytes == file.MaxBytes {
					matched = true
				}
			}
			if !matched {
				t.Fatal("installed fixture reference differs from generated inventory")
			}
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := `Signature version="1",headers="date (request-target) host",keyId="ocid1.tenancy.oc1..test/ocid1.user.oc1..test/test-fingerprint",algorithm="rsa-sha256",signature="`
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), prefix)
		raw, suffix := strings.CutSuffix(raw, `"`)
		signature, err := base64.StdEncoding.Strict().DecodeString(raw)
		message := "date: " + r.Header.Get("Date") + "\n(request-target): " + strings.ToLower(r.Method) + " " + r.URL.RequestURI() + "\nhost: " + r.Host
		digest := sha256.Sum256([]byte(message))
		if !ok || !suffix || err != nil || rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature) != nil {
			http.Error(w, "signed SDK read required", http.StatusUnauthorized)
			return
		}
		id, pathOK := strings.CutPrefix(r.URL.Path, "/20190301/secretbundles/")
		ref, exists := refs[id]
		if r.Method != http.MethodGet || !pathOK || !exists || r.URL.Query().Get("versionNumber") != fmt.Sprint(ref.VersionNumber) || r.URL.Query().Get("stage") != "" {
			http.Error(w, "exact published secret version required", http.StatusBadRequest)
			return
		}
		body, err := os.ReadFile(filepath.Join(template.MaterialDirectory, ref.TargetFile))
		if err != nil || digestWire(body) != ref.SHA256 || int64(len(body)) > ref.MaxBytes {
			clear(body)
			http.Error(w, "generated source changed", http.StatusConflict)
			return
		}
		defer clear(body)
		wire, err := protocol.EncodeJSON(map[string]any{"secretId": ref.SecretOCID, "versionNumber": ref.VersionNumber,
			"timeOfExpiry": record.ExpiresAt.Format(time.RFC3339Nano), "secretBundleContent": map[string]string{
				"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString(body)}})
		if err != nil {
			http.Error(w, "encode bundle", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wire)
	}))
	t.Cleanup(server.Close)
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test-fingerprint", string(private), nil)
	client, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
	clear(private)
	if err != nil {
		t.Fatal(err)
	}
	client.Host, client.HTTPClient = server.URL, server.Client()
	return &client
}
