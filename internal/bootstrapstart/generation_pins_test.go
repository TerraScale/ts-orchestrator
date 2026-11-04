package bootstrapstart

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

const pinnedIP = "10.0.1.10"

// generationInstall is one controller's credential directory, first holding
// manifest-era material, and the generation that renews it.
type generationInstall struct {
	t          *testing.T
	dir        string
	manifest   bootstrap.Manifest
	accepted   AcceptedIdentity
	configPath string
	credential LiveCredentials
	material   generationtest.Material
	roots      trust.Keyring
	rootKey    ed25519.PrivateKey
	expected   bootstrap.MaterialGenerationExpectation
	// loaded, when set, is the loaded controller config, which verify
	// checks as restart admission does against acceptedManifest.
	loaded []byte
}

func newGenerationInstall(t *testing.T) *generationInstall {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	install := &generationInstall{t: t, dir: dir}
	install.material = generationtest.New(t, time.Now())
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	install.roots, _ = trust.ParseKeyring(public)
	install.rootKey = private
	install.expected = bootstrap.MaterialGenerationExpectation{DeploymentID: "0000000000YY15F5R431V5JPJ9", Environment: "production",
		ClusterID: "00000000006GRRF84JEVN9TX7M", Cell: "GRU", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}}
	install.manifest = bootstrap.Manifest{DeploymentID: "0000000000YY15F5R431V5JPJ9", Environment: "production", ClusterID: "00000000006GRRF84JEVN9TX7M",
		Cell: "GRU", Slot: "controller-a", SeedSlot: "controller-b", ControllerSlots: install.expected.ControllerSlots}
	// Manifest-era material: placeholder bytes, except the controller
	// credentials, which renewal re-signs.
	user, _ := nkeys.CreateUser()
	userID, _ := user.PublicKey()
	userSeed, _ := user.Seed()
	claims := jwt.NewUserClaims(userID)
	claims.Expires = time.Now().Add(time.Hour).Unix()
	encoded, _ := claims.Encode(install.material.Cell)
	creds, _ := jwt.FormatUserConfig(encoded, userSeed)
	files := map[string]bootstrap.SecretPurpose{
		"ca.pem": bootstrap.SecretRegionalShared, "operator.jwt": bootstrap.SecretRegionalShared,
		"system.jwt": bootstrap.SecretRegionalShared, "cell.jwt": bootstrap.SecretRegionalShared,
		"system.creds": bootstrap.SecretRegionalShared, "ticket.pub": bootstrap.SecretRegionalShared,
		"ticket.key": bootstrap.SecretRegionalShared, "route-password": bootstrap.SecretRegionalShared, "host-nats-issuer.seed": bootstrap.SecretHostIssuer,
		"host-tls-issuer-key.pem": bootstrap.SecretHostIssuer, "host-tls-issuer-cert.pem": bootstrap.SecretHostIssuer,
		"controller-a.creds": bootstrap.SecretController, "controller-a-tls-cert.pem": bootstrap.SecretController,
		"controller-a-tls-key.pem": bootstrap.SecretController, "controller-a-response.key": bootstrap.SecretController,
	}
	for name, purpose := range files {
		content := []byte("manifest-era " + name)
		if name == "controller-a.creds" {
			content = creds
		}
		install.write(name, content)
		reference := bootstrap.SecretReference{Purpose: purpose, TargetFile: name, SHA256: digest(content), SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.baseline-" + strings.ReplaceAll(name, ".", "-"), VersionNumber: 1, MaxBytes: bootstrap.MaxSecretBytes}
		if purpose == bootstrap.SecretController {
			reference.Slot = "controller-a"
		}
		install.manifest.Secrets = append(install.manifest.Secrets, reference)
	}
	path := func(name string) string { return filepath.Join(dir, name) }
	tlsFiles := natscell.TLSFiles{CAFile: path("ca.pem"), CertFile: path("controller-a-tls-cert.pem"),
		KeyFile: path("controller-a-tls-key.pem")}
	install.credential = LiveCredentials{Config: natscell.Config{Cell: "gru", Instance: "controller-a", Replicas: 1,
		CredentialsFile: path("controller-a.creds"), TLS: tlsFiles,
		Embedded: &natscell.Embedded{TLS: tlsFiles, RouteTLS: tlsFiles,
			OperatorJWTFile: path("operator.jwt"), SystemJWTFile: path("system.jwt"), CellJWTFile: path("cell.jwt"),
			SystemCredentialsFile: path("system.creds"), TicketPublicKeyFile: path("ticket.pub")}},
		ServiceUID: uint32(os.Getuid()), ServiceGID: uint32(os.Getgid()),
		ResponseKeyFile: path("controller-a-response.key"), BrokerTicketKeyFile: path("ticket.key"),
		HostNATSIssuerSeedFile: path("host-nats-issuer.seed"), HostTLSIssuerKeyFile: path("host-tls-issuer-key.pem"),
		HostTLSIssuerCertFile: path("host-tls-issuer-cert.pem"), ValidateControllerKeys: func() error { return nil },
		directory: dir, allowUnsafeAncestors: true, ControllerConfig: []byte(oldConfig)}
	install.accepted = acceptedIdentityFixture(t)
	install.accepted.DeploymentID = install.expected.DeploymentID
	install.accepted.ClusterID = install.expected.ClusterID
	install.accepted.Environment = install.expected.Environment
	install.accepted.PrimaryPrivateIP = pinnedIP
	install.accepted.MaterialReferences = install.manifest.Secrets
	install.accepted.Broker = identityrekey.BrokerIdentity{Operator: install.material.OperatorID,
		SystemAccount: install.material.SystemID, CellAccount: install.material.CellID,
		HostSigner: install.material.HostSignerID, RoleSigner: install.material.RoleSignerID}
	install.accepted.ConfigSHA256["controller.json"] = digest([]byte(oldConfig))
	install.accepted.ControllerBindings = []ControllerBinding{install.accepted.localBinding()}
	if err := install.accepted.Validate(); err != nil {
		t.Fatal(err)
	}
	install.configPath = filepath.Join(t.TempDir(), "controller.json")
	if err := os.WriteFile(install.configPath, []byte(oldConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	install.credential.Config.Embedded.RoutePasswordFile = path("route-password")
	return install
}

func (install *generationInstall) write(name string, content []byte) {
	install.t.Helper()
	temporary := filepath.Join(install.dir, "."+name)
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		install.t.Fatal(err)
	}
	if err := os.Rename(temporary, filepath.Join(install.dir, name)); err != nil {
		install.t.Fatal(err)
	}
}

func (install *generationInstall) read(name string) []byte {
	install.t.Helper()
	content, err := os.ReadFile(filepath.Join(install.dir, name))
	if err != nil {
		install.t.Fatal(err)
	}
	return content
}

func (install *generationInstall) acceptance() string {
	install.t.Helper()
	value, err := install.accepted.AcceptanceSHA256()
	if err != nil {
		install.t.Fatal(err)
	}
	return value
}

func (install *generationInstall) target() GenerationTarget {
	install.t.Helper()
	target, err := generationTarget(install.accepted)
	if err != nil {
		install.t.Fatal(err)
	}
	return target
}

// adopt installs the generation's files and its chain, signed by key.
func (install *generationInstall) adopt(material generationtest.Material, expected bootstrap.MaterialGenerationExpectation,
	key ed25519.PrivateKey,
) {
	install.t.Helper()
	for name := range bootstrap.MaterialGenerationFiles() {
		install.write(name, material.Files[name])
	}
	envelope, err := bootstrap.SignMaterialGeneration(material.Generation(expected, 1, ""), time.Now().Add(-time.Minute),
		time.Now().AddDate(0, 6, 0), key)
	if err != nil {
		install.t.Fatal(err)
	}
	wire, err := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{envelope})
	if err != nil {
		install.t.Fatal(err)
	}
	install.write(MaterialGenerationsFile, wire)
}

// verify runs what restart admission checks of the directory.
func (install *generationInstall) verify(privateIP string) error {
	dir, err := openMaterialDirectory(install.dir, uint32(os.Getuid()), uint32(os.Getgid()), 0o700, true)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	accepted := install.accepted.Clone()
	accepted.PrimaryPrivateIP = privateIP
	accepted.ControllerBindings = []ControllerBinding{accepted.localBinding()}
	pins, err := restartPins(dir, uint32(os.Getuid()), uint32(os.Getgid()), accepted, install.roots)
	if err != nil {
		return err
	}
	if install.loaded != nil {
		want, err := pins.controllerConfigSHA256(accepted)
		if err != nil || want != digest(install.loaded) {
			return fmt.Errorf("loaded controller config differs from acceptance: %v", err)
		}
		pins.config = install.loaded
	}
	store := MaterialStore{installedDirectory: install.dir, serviceUID: uint32(os.Getuid()),
		serviceGID: uint32(os.Getgid()), allowUnsafeAncestors: true}
	if err := store.verifyInstalled(install.t.Context(), dir, pins.Digests); err != nil {
		return err
	}
	if err := pins.verifyGeneration(dir, uint32(os.Getuid()), uint32(os.Getgid()), time.Now()); err != nil {
		return err
	}
	if err := install.credential.verifyPaths(pins, accepted.Slot, accepted.SeedSlot, accepted.MaterialReferences); err != nil {
		return err
	}
	return install.credential.verifyInventory(pins)
}

func (install *generationInstall) renew(identity bootstrapmaterial.LeafIdentity) {
	install.t.Helper()
	issuer, err := bootstrapmaterial.LoadControllerIssuer(install.material.Generation(install.expected, 1, ""),
		install.material.Files["controller-tls-issuer-cert.pem"], install.material.Files["controller-tls-issuer-key.pem"],
		install.material.Files["controller-account-signer.seed"])
	if err != nil {
		install.t.Fatal(err)
	}
	defer issuer.Wipe()
	cert, key, err := issuer.RenewTLS(identity, time.Now())
	if err != nil {
		install.t.Fatal(err)
	}
	creds, err := issuer.RenewCredentials(install.read("controller-a.creds"))
	if err != nil {
		install.t.Fatal(err)
	}
	install.write("controller-a-tls-key.pem", key)
	install.write("controller-a-tls-cert.pem", cert)
	install.write("controller-a.creds", creds)
}

// adoptInterRegion installs gru-1's v1 shape for controller-a: no
// controller issuers, the role signer and the interregion files, every
// slot's new controller config bound to manifestSHA256. It holds only
// controller-a's leaf TLS, gives the live credential check that slot's
// interregion block, and returns the material and controller-a's config.
func (install *generationInstall) adoptInterRegion(manifestSHA256 string) (generationtest.Material, []byte) {
	t := install.t
	t.Helper()
	material := install.material.WithoutIssuers(t).InterRegion(t, time.Now(), install.expected.ControllerSlots)
	config := install.adoptMaterial(material, manifestSHA256)
	install.credential.Config.Embedded.InterRegion = embeddedBlock(t, config, install.dir).InterRegion
	return material, config
}

// adoptMaterial installs material's generation 1 for controller-a, every
// slot's config bound to manifestSHA256 or else the acceptance, and returns
// controller-a's config.
func (install *generationInstall) adoptMaterial(material generationtest.Material, manifestSHA256 string) []byte {
	t := install.t
	t.Helper()
	generation := material.Generation(install.expected, 1, "")
	for index := range generation.ControllerConfigs {
		generation.ControllerConfigs[index].AcceptanceSHA256 = install.acceptance()
		if manifestSHA256 != "" {
			generation.ControllerConfigs[index].AcceptanceSHA256 = manifestSHA256
		}
	}
	for _, secret := range generation.Secrets {
		if secret.Slot == "" || secret.Slot == "controller-a" {
			install.write(secret.TargetFile, material.Files[secret.TargetFile])
		}
	}
	envelope, err := bootstrap.SignMaterialGeneration(generation, time.Now().Add(-time.Minute), time.Now().AddDate(0, 6, 0),
		install.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{envelope})
	if err != nil {
		t.Fatal(err)
	}
	install.write(MaterialGenerationsFile, wire)
	return material.Files["controller-controller-a.json"]
}

// embeddedBlock is config's embedded broker block with its files in dir.
func embeddedBlock(t *testing.T, config []byte, dir string) *natscell.Embedded {
	t.Helper()
	var loaded struct {
		NATS natscell.Config `json:"nats"`
	}
	local := strings.ReplaceAll(string(config), MaterialDirectory+"/", dir+"/")
	if err := protocol.DecodeTolerant([]byte(local), &loaded, bootstrap.MaxControllerConfigBytes); err != nil {
		t.Fatal(err)
	}
	return loaded.NATS.Embedded
}
