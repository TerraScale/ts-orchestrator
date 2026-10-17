//go:build fixturetest

package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/jwt/v2"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"golang.org/x/sys/unix"
)

// Consumers call runInstalledControllerNamespace before building any fixtures.
// This value carries installed inputs; socket Calls still require real children.
type installedControllerFixture struct {
	Config           Config
	Bootstrap        *bootstrapstart.ControllerManagerStartupFixture
	MaterialPins     bootstrapstart.MaterialPins
	Record           bootstrapmaterial.Record
	Publication      bootstrapmaterial.Publication
	Vault            *vault.VaultsClient
	Bundles          *secrets.SecretsClient
	SourceDirectory  string
	ConfigPath       string
	Executable       string
	ServiceUID       uint32
	ServiceGID       uint32
	FoundationGrant  []byte
	FoundationIntent region.FoundationIntent
}

const installedControllerParentMount = "TS_INSTALLED_CONTROLLER_PARENT_MOUNT"

// runInstalledControllerNamespace returns true only in the parent after its
// disposable child has finished. Namespace failures fail the test, never skip.
func runInstalledControllerNamespace(t *testing.T) bool {
	t.Helper()
	if os.Getenv(installedControllerParentMount) != "" {
		requireInstalledControllerNamespace(t)
		return false
	}
	parentMount, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(name string) string {
		t.Helper()
		for _, directory := range filepath.SplitList(os.Getenv("PATH")) {
			path, err := exec.LookPath(filepath.Join(directory, name))
			if err != nil {
				continue
			}
			path, err = filepath.EvalSymlinks(path)
			if err != nil {
				continue
			}
			// sudo executes before /run is replaced; root helpers need no wrapper.
			if name != "sudo" && (strings.HasPrefix(path, "/run/") || strings.HasPrefix(path, "/etc/") || strings.HasPrefix(path, "/var/lib/") || strings.HasPrefix(path, "/tmp/")) {
				continue
			}
			return path
		}
		t.Fatalf("no persistent executable path for namespace helper %s", name)
		return ""
	}
	unshare, mount, ip := lookup("unshare"), lookup("mount"), lookup("ip")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		t.Fatal(err)
	}
	const script = `set -eu
mount_command="$1"
ip_command="$2"
executable="$3"
test_pattern="$4"
parent_mount="$5"
copy_command="$6"
mkdir_command="$7"
chmod_command="$8"
"$mount_command" --make-rprivate /
"$mount_command" -t tmpfs -o size=16m,mode=0755 ts-installed-controller-etc /etc
"$mount_command" -t tmpfs -o size=512m,mode=0755 ts-installed-controller-state /var/lib
"$mount_command" -t tmpfs -o size=16m,mode=0755 ts-installed-controller-run /run
printf 'root:x:0:0:root:/root:/sbin/nologin\nterrascale-orchestrator:x:1000:1000:service:/nonexistent:/sbin/nologin\n' > /etc/passwd
printf 'root:x:0:\nterrascale-orchestrator:x:1000:\n' > /etc/group
printf 'passwd: files\ngroup: files\n' > /etc/nsswitch.conf
"$chmod_command" 0644 /etc/passwd /etc/group /etc/nsswitch.conf
"$mkdir_command" -m 0755 /var/lib/installed-controller-bin
"$copy_command" "$executable" /var/lib/installed-controller-bin/app.test
"$chmod_command" 0755 /var/lib/installed-controller-bin/app.test
"$mount_command" -t tmpfs -o size=512m,mode=1777 ts-installed-controller-tmp /tmp
"$ip_command" link set lo up
"$ip_command" addr add 10.44.0.10/32 dev lo
TS_INSTALLED_CONTROLLER_PARENT_MOUNT="$parent_mount" TMPDIR=/tmp GOMAXPROCS=2 exec /var/lib/installed-controller-bin/app.test -test.v -test.run="$test_pattern" -test.timeout=110s
`
	args := []string{unshare, "--mount", "--net", "--fork", "--kill-child=SIGKILL", "--",
		lookup("sh"), "-c", script, "ts-installed-controller", mount, ip, self, "^" + regexp.QuoteMeta(t.Name()) + "$", parentMount,
		lookup("cp"), lookup("mkdir"), lookup("chmod")}
	if os.Geteuid() != 0 {
		args = append([]string{lookup("sudo"), "-n"}, args...)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		return nil
	}
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("installed-controller namespace child: %v\n%s", err, output)
	}
	t.Log(string(output))
	return true
}

func requireInstalledControllerNamespace(t *testing.T) {
	t.Helper()
	parent := os.Getenv(installedControllerParentMount)
	current, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil || parent == "" || current == parent || os.Geteuid() != 0 {
		t.Fatal("installed controller requires its disposable root mount namespace", err)
	}
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for path, source := range map[string]string{
		"/etc": "ts-installed-controller-etc", "/var/lib": "ts-installed-controller-state", "/run": "ts-installed-controller-run",
		"/tmp": "ts-installed-controller-tmp",
	} {
		found := false
		for line := range strings.SplitSeq(string(info), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 6 && fields[4] == path && strings.Contains(line, " - tmpfs "+source+" ") {
				found = true
			}
		}
		var stat unix.Statfs_t
		if !found || unix.Statfs(path, &stat) != nil || stat.Type != unix.TMPFS_MAGIC {
			t.Fatalf("installed controller requires its private tmpfs at %s", path)
		}
	}
	uid, gid, err := controllerServiceIdentity()
	if err != nil || uid != 1000 || gid != 1000 {
		t.Fatal("installed controller requires its dedicated namespace account", err)
	}
}

func newInstalledControllerFixture(t *testing.T) *installedControllerFixture {
	t.Helper()
	requireInstalledControllerNamespace(t)
	uid, gid, err := controllerServiceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{controllerConfigDirectory, bootstrapstart.BakedDirectory,
		bootstrapstart.MarkerDirectory, bootstrapstart.FounderSelectionFloorDirectory,
		filepath.Dir(bootstrapstart.RootChainFile)} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{bootstrapstart.MaterialDirectory, bootstrapstart.StagingDirectory} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(bootstrapstart.MaterialDirectory, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(bootstrapstart.FounderSelectionFloorDirectory, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bootstrapstart.FounderSelectionFloorDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	chainWire, err := trust.EncodeRootChain(trust.RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bootstrapstart.RootChainFile, chainWire, 0o444); err != nil {
		t.Fatal(err)
	}
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(root) })
	foundation, grantWire, intent := managerStartupFoundation(t, root)
	now := time.Now().UTC().Truncate(time.Second)
	source := "/run/installed-controller-source"
	record, err := bootstrapmaterial.Generate(source, bootstrapmaterial.Config{
		Environment: "production", Cell: "gru", Region: "sa-saopaulo-1",
		DeploymentID: bootstrapstart.ControllerManagerStartupDeployment, ClusterID: bootstrapstart.ControllerManagerStartupCluster,
		SubnetCIDR: "10.44.0.0/24", ValidityHours: 48,
		Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.44.0.11"},
			{Name: "controller-b", PrivateIP: "10.44.0.12"}, {Name: "controller-c", PrivateIP: "10.44.0.10"}},
	}, now.Add(-2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	readSource := func(name string) []byte {
		t.Helper()
		wire, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	broker := identityrekey.BrokerIdentity{Operator: record.Public.OperatorNKey, SystemAccount: record.Public.SystemAccountNKey,
		CellAccount: record.Public.CellAccountNKey, HostSigner: record.Public.HostNATSIssuerNKey, AccountSigner: record.Public.ControllerAccountSignerNKey}
	cell, err := jwt.DecodeAccountClaims(string(readSource("cell.jwt")))
	if err != nil {
		t.Fatal(err)
	}
	for key, scope := range cell.SigningKeys {
		if user, ok := scope.(*jwt.UserScope); ok && user.Role == "role" {
			broker.RoleSigner = key
		}
	}
	enrollment, err := json.Marshal(hostenroll.PublicBundle{SchemaVersion: 1, Cell: "gru", Region: "GRU", Environment: "production",
		ControllerEndpoints: []string{"10.44.0.11:8443", "10.44.0.12:8443", "10.44.0.10:8443"},
		NATSURLs:            []string{"tls://10.44.0.11:4222", "tls://10.44.0.12:4222", "tls://10.44.0.10:4222"},
		CAPEM:               string(readSource("ca.pem")), ControllerResponsePublicKey: record.Public.ControllerResponsePublicKey,
		CellAccountNKey: record.Public.CellAccountNKey, InstallRoot: hostenroll.ImageInstallRoot,
		StateRoot: hostenroll.ImageStateRoot, ManagedRuntimeRoot: hostenroll.ImageManagedRuntimeRoot,
		WorkloadUID: hostenroll.ImageWorkloadUID, WorkloadGID: hostenroll.ImageWorkloadGID})
	if err != nil {
		t.Fatal(err)
	}
	publication, management, bundles := installedControllerPublication(t, source, now)
	templates := installedControllerTemplates(t, record, publication, now)
	fixture := bootstrapstart.NewInstalledControllerManagerStartupFixture(t, enrollment, broker, root, foundation,
		bootstrapstart.ControllerManagerStartupTemplate{Manifests: templates, MaterialDirectory: source, ServiceUID: uid, ServiceGID: gid})
	if err := installSignedControllerFiles(controllerConfigDirectory, fixture.ManifestWire, fixture.Manifest); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(controllerConfigDirectory, controllerConfigFilename)
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cfg.signedWire()
	if err != nil || !bytes.Equal(wire, templates["controller-c"].ControllerConfig) {
		t.Fatal("installed controller changed its pre-signing config bytes", err)
	}
	if _, err := loadManagedControllerConfig(cfg); err != nil {
		t.Fatal("load genuine signed installed controller config", err)
	}
	inputs, err := bootstrapstart.LoadTrustInputs(fixture.Accepted)
	if err != nil {
		t.Fatal(err)
	}
	material, err := bootstrapstart.NewMaterialStore(nil, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := material.RestartPins(fixture.Accepted, inputs.Roots.Historical)
	if err != nil {
		t.Fatal(err)
	}
	if err := material.VerifyRestart(t.Context(), fixture.Accepted, pins); err != nil {
		t.Fatal("verify installed controller restart material", err)
	}
	if _, err := bootstrapstart.LoadAcceptedHostLaunchMaterial(fixture.Accepted); err != nil {
		t.Fatal("verify installed controller accepted launch material", err)
	}
	if _, _, err := bootstrapstart.LoadAcceptedManagedImageMaterial(fixture.Accepted); err != nil {
		t.Fatal("verify installed controller accepted image material", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return &installedControllerFixture{Config: cfg, Bootstrap: fixture, MaterialPins: pins, Record: record, SourceDirectory: source,
		Publication: publication, Vault: management, Bundles: bundles,
		ConfigPath: configPath, Executable: executable, ServiceUID: uid, ServiceGID: gid,
		FoundationGrant: grantWire, FoundationIntent: intent}
}

func installedControllerTemplates(t *testing.T, record bootstrapmaterial.Record, publication bootstrapmaterial.Publication, now time.Time) map[string]bootstrap.Manifest {
	t.Helper()
	intent := oci.RegionIntent{SchemaVersion: 1, Generation: 4, BootstrapRegion: oci.RegionGRU,
		Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: record.Config.Region}}}
	regionConfig := oci.RegionConfig{Region: oci.RegionGRU, Generation: intent.Generation,
		Endpoint: "https://iaas.sa-saopaulo-1.oraclecloud.com", CompartmentID: "ocid1.compartment.oc1..compartment",
		ImageCompartmentID: "ocid1.compartment.oc1..images", AvailabilityDomain: "SA-SAOPAULO-1-AD-1",
		FaultDomains:            []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"},
		SubnetID:                "ocid1.subnet.oc1.sa-saopaulo-1.controller-c",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.controller-c"},
		ImageID:                 bootstrapstart.ControllerManagerStartupImage, Shape: "VM.Standard.E5.Flex", Owner: "controller",
		BootVolumeGB: 50, BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 50}
	settings := managedPlacementSettings{Environment: "production", MemberRole: "terrabase",
		Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}}
	var files []bootstrap.ControllerConfigFile
	for index, value := range []any{intent, regionConfig, settings} {
		wire, err := protocol.EncodeJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, bootstrap.ControllerConfigFile{Name: bootstrap.ControllerConfigFileNames[index], Bytes: wire, SHA256: controllerSHA256(wire)})
	}
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: record.Public.ControllerResponsePublicKey,
		Roles: []string{"terrabase"}, Environments: []string{"production"}}
	manifests := make(map[string]bootstrap.Manifest, 3)
	for _, slot := range record.Config.Slots {
		manifest := bootstrap.Manifest{DeploymentID: record.Config.DeploymentID, ClusterID: record.Config.ClusterID,
			Environment: record.Config.Environment, Cell: oci.RegionGRU, OCIRegion: record.Config.Region,
			Slot: slot.Name, SeedSlot: "controller-c", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"},
			IntentGeneration: intent.Generation, IntentSHA256: files[0].SHA256, ControllerFiles: files}
		for _, published := range publication.References {
			reference := published.Reference
			if reference.Purpose != bootstrap.SecretRegionalShared && reference.Purpose != bootstrap.SecretHostIssuer &&
				reference.Purpose != bootstrap.SecretControllerIssuer && (reference.Purpose != bootstrap.SecretController || reference.Slot != slot.Name) {
				continue
			}
			manifest.Secrets = append(manifest.Secrets, reference)
		}
		cfg, err := ControllerConfigFromRecord(manifest, record, grant, now)
		if err != nil {
			t.Fatal(err)
		}
		manifest.ControllerConfig, err = cfg.signedWire()
		if err != nil {
			t.Fatal(err)
		}
		manifest.ControllerConfigSHA256 = controllerSHA256(manifest.ControllerConfig)
		if _, err := ValidateSignedControllerConfig(manifest, slot.PrivateIP); err != nil {
			t.Fatal("validate controller template before signing", err)
		}
		manifests[slot.Name] = manifest
	}
	return manifests
}

// Production Generate -> Provision -> exact SDK readback supplies every signed
// reference. The local HTTP endpoint implements only this finite Vault scope.
func installedControllerPublication(t *testing.T, directory string, now time.Time) (bootstrapmaterial.Publication, *vault.VaultsClient, *secrets.SecretsClient) {
	t.Helper()
	target := bootstrapmaterial.VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..control",
		VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.control", KMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.control"}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	type storedSecret struct {
		ID, Name, Content string
	}
	stored := make(map[string]storedSecret)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		headers := "date (request-target) host"
		message := "date: " + r.Header.Get("Date") + "\n(request-target): " + strings.ToLower(r.Method) + " " + r.URL.RequestURI() + "\nhost: " + r.Host
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(io.LimitReader(r.Body, 2*bootstrap.MaxSecretBytes+1))
			if err != nil || int64(len(body)) != r.ContentLength || int64(len(body)) > 2*bootstrap.MaxSecretBytes {
				http.Error(w, "bounded signed Vault body required", http.StatusBadRequest)
				return
			}
			digest := sha256.Sum256(body)
			if r.Header.Get("x-content-sha256") != base64.StdEncoding.EncodeToString(digest[:]) {
				http.Error(w, "Vault body differs from signed digest", http.StatusUnauthorized)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			headers += " content-length content-type x-content-sha256"
			message += "\ncontent-length: " + strconv.FormatInt(r.ContentLength, 10) + "\ncontent-type: " + r.Header.Get("Content-Type") + "\nx-content-sha256: " + r.Header.Get("x-content-sha256")
		}
		prefix := `Signature version="1",headers="` + headers + `",keyId="ocid1.tenancy.oc1..test/ocid1.user.oc1..test/fixture-fingerprint",algorithm="rsa-sha256",signature="`
		raw, prefixOK := strings.CutPrefix(r.Header.Get("Authorization"), prefix)
		raw, suffixOK := strings.CutSuffix(raw, `"`)
		signature, err := base64.StdEncoding.Strict().DecodeString(raw)
		digest := sha256.Sum256([]byte(message))
		if !prefixOK || !suffixOK || err != nil || rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature) != nil {
			http.Error(w, "unsigned Vault SDK request", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		write := func(value any) {
			if err := json.MarshalWrite(w, value); err != nil {
				t.Error(err)
			}
		}
		metadata := func(secret storedSecret) map[string]any {
			return map[string]any{"id": secret.ID, "secretName": secret.Name, "compartmentId": target.CompartmentOCID,
				"vaultId": target.VaultOCID, "keyId": target.KMSKeyOCID, "lifecycleState": "ACTIVE", "currentVersionNumber": 1}
		}
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets"):
			query := r.URL.Query()
			if query.Get("compartmentId") != target.CompartmentOCID || query.Get("vaultId") != target.VaultOCID || query.Get("name") == "" || query.Get("page") != "" {
				http.Error(w, "outside fixture Vault scope", http.StatusBadRequest)
				return
			}
			items := []any{}
			for _, secret := range stored {
				if secret.Name == query.Get("name") {
					items = append(items, metadata(secret))
				}
			}
			write(items)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/secrets"):
			var body struct {
				Name          string `json:"secretName"`
				CompartmentID string `json:"compartmentId"`
				VaultID       string `json:"vaultId"`
				KeyID         string `json:"keyId"`
				Content       struct {
					Type    string `json:"contentType"`
					Content string `json:"content"`
					Stage   string `json:"stage"`
				} `json:"secretContent"`
			}
			if err := json.UnmarshalRead(io.LimitReader(r.Body, 2*bootstrap.MaxSecretBytes), &body); err != nil || body.Name == "" ||
				body.CompartmentID != target.CompartmentOCID || body.VaultID != target.VaultOCID || body.KeyID != target.KMSKeyOCID ||
				body.Content.Type != "BASE64" || body.Content.Stage != "CURRENT" || body.Content.Content == "" || r.Header.Get("opc-retry-token") == "" {
				http.Error(w, "invalid scoped Vault create", http.StatusBadRequest)
				return
			}
			digest := sha256.Sum256([]byte(body.Name))
			id := "ocid1.vaultsecret.oc1.sa-saopaulo-1." + hex.EncodeToString(digest[:])
			if _, exists := stored[id]; exists {
				http.Error(w, `{"code":"Conflict","message":"already exists"}`, http.StatusConflict)
				return
			}
			secret := storedSecret{ID: id, Name: body.Name, Content: body.Content.Content}
			stored[id] = secret
			write(metadata(secret))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/secretbundles/"):
			_, id, _ := strings.Cut(r.URL.Path, "/secretbundles/")
			secret, exists := stored[id]
			if !exists || r.URL.Query().Get("versionNumber") != "1" {
				http.Error(w, `{"code":"NotFound","message":"absent version"}`, http.StatusNotFound)
				return
			}
			write(map[string]any{"secretId": id, "versionNumber": 1,
				"secretBundleContent": map[string]string{"contentType": "BASE64", "content": secret.Content}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/secrets/"):
			_, id, _ := strings.Cut(r.URL.Path, "/secrets/")
			secret, exists := stored[id]
			if !exists {
				http.Error(w, `{"code":"NotFound","message":"absent secret"}`, http.StatusNotFound)
				return
			}
			write(metadata(secret))
		default:
			http.Error(w, "unexpected Vault SDK operation", http.StatusNotFound)
		}
	}))
	t.Cleanup(func() {
		server.Close()
		clear(stored)
	})
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	defer clear(private)
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "fixture-fingerprint", string(private), nil)
	management, err := vault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []*common.BaseClient{&management.BaseClient, &bundles.BaseClient} {
		client.Host, client.HTTPClient = server.URL, server.Client()
		retry := common.NoRetryPolicy()
		client.Configuration.RetryPolicy = &retry
	}
	publication, err := bootstrapmaterial.Provision(t.Context(), directory, target, &management, &bundles, now)
	if err != nil {
		t.Fatal("publish generated material through Vault SDK", err)
	}
	journal, err := os.ReadFile(filepath.Join(directory, "publication.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrapmaterial.ValidatePublication(directory, publication, journal); err != nil {
		t.Fatal("validate exact generated publication readback", err)
	}
	return publication, &management, &bundles
}

func TestInstalledControllerFixture(t *testing.T) {
	if runInstalledControllerNamespace(t) {
		return
	}
	fixture := newInstalledControllerFixture(t)
	if _, err := fixture.Bootstrap.Reader.ReadRuntimeAuthority(t.Context(), fixture.Bootstrap.Accepted, time.Now().UTC()); err != nil {
		t.Fatal("installed controller lost current genuine founder authority", err)
	}
}
