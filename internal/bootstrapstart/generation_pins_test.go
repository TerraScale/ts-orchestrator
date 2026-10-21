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

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
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

func TestAcceptedMaterialBaselineSurvivesSubsequentRenewal(t *testing.T) {
	install := newGenerationInstall(t)
	first, files := install.signedGeneration()
	chain, err := bootstrap.DecodeMaterialGenerationChain(first)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := trust.Fingerprint(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	generation, err := bootstrap.MaterialGenerationPayload(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	install.accepted.Broker.AccountSigner = generation.AccountSigner
	refs := materialReferences(install.accepted, nil)
	for _, ref := range generation.Secrets {
		refs[ref.TargetFile] = ref
	}
	install.accepted.MaterialReferences = nil
	for _, ref := range refs {
		install.accepted.MaterialReferences = append(install.accepted.MaterialReferences, ref)
	}
	install.accepted.MaterialGenerationSHA256 = baseline
	if err := install.accepted.Validate(); err != nil {
		t.Fatal(err)
	}
	store := install.store()
	if err := store.AdoptGeneration(install.target(), install.roots, first, files, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := install.verify(pinnedIP); err != nil {
		t.Fatal(err)
	}
	next, err := bootstrap.SignMaterialGeneration(install.material.Generation(install.expected, 2, baseline), time.Now().Add(-30*time.Second), time.Now().AddDate(0, 6, 0), install.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	both, err := bootstrap.EncodeMaterialGenerationChain(append(chain, next))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdoptGeneration(install.target(), install.roots, both, files, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	install.renew(bootstrapmaterial.ControllerLeafIdentity("gru", "controller-a", pinnedIP))
	if err := install.verify(pinnedIP); err != nil {
		t.Fatalf("legitimate subsequent renewal: %v", err)
	}
	if install.accepted.MaterialGenerationSHA256 != baseline {
		t.Fatal("renewal changed accepted baseline")
	}
	if _, err := store.RestartPins(install.accepted, install.roots); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"missing", "foreign baseline"} {
		accepted := install.accepted.Clone()
		if bad == "missing" {
			if err := os.Remove(filepath.Join(install.dir, MaterialGenerationsFile)); err != nil {
				t.Fatal(err)
			}
		} else {
			install.write(MaterialGenerationsFile, both)
			accepted.MaterialGenerationSHA256 = digest([]byte("another baseline"))
		}
		if _, err := store.RestartPins(accepted, install.roots); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestMaterialPinsCannotBeReusedWithChangedAcceptedBaseline(t *testing.T) {
	install := newGenerationInstall(t)
	install.adopt(install.material, install.expected, install.rootKey)
	pins, err := install.store().RestartPins(install.accepted, install.roots)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"references", "config", "generation"} {
		accepted := install.accepted.Clone()
		switch field {
		case "references":
			for i := range accepted.MaterialReferences {
				if accepted.MaterialReferences[i].TargetFile == "ticket.key" {
					accepted.MaterialReferences[i].SHA256 = digest([]byte("new ticket"))
				}
			}
		case "config":
			accepted.ConfigSHA256["controller.json"] = digest([]byte("new baseline config"))
		case "generation":
			accepted.MaterialGenerationSHA256 = digest([]byte("new baseline generation"))
		}
		if acceptance, err := accepted.AcceptanceSHA256(); err != nil || acceptance != pins.acceptance {
			t.Fatalf("acyclic binding changed for %s: %v", field, err)
		}
		if err := install.store().VerifyRestart(t.Context(), accepted, pins); err == nil {
			t.Fatalf("reused material pins after %s changed", field)
		}
		if err := install.credential.VerifyLiveCredentials(t.Context(), pins, accepted); err == nil {
			t.Fatalf("reused live pins after %s changed", field)
		}
	}
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

func TestRestartPinsFollowTheAdoptedGeneration(t *testing.T) {
	install := newGenerationInstall(t)
	if err := install.verify(pinnedIP); err != nil {
		t.Fatalf("manifest-era material before any generation: %v", err)
	}
	install.adopt(install.material, install.expected, install.rootKey)
	if err := install.verify(pinnedIP); err != nil {
		t.Fatalf("an adopted generation before the slot's first renewal: %v", err)
	}
	identity := bootstrapmaterial.ControllerLeafIdentity("gru", "controller-a", pinnedIP)
	install.renew(identity)
	if err := install.verify(pinnedIP); err != nil {
		t.Fatalf("leaf and credentials renewed under the generation: %v", err)
	}
	if err := install.verify("10.0.1.99"); err == nil {
		t.Fatal("a leaf for another address was accepted")
	}
	install.renew(bootstrapmaterial.ControllerLeafIdentity("gru", "controller-b", pinnedIP))
	if err := install.verify(pinnedIP); err == nil {
		t.Fatal("another slot's leaf was accepted")
	}
}

func TestRestartPinsRefuseUntrustedOrStaleMaterial(t *testing.T) {
	identity := bootstrapmaterial.ControllerLeafIdentity("gru", "controller-a", pinnedIP)
	for name, change := range map[string]func(*generationInstall){
		"a chain signed by an untrusted root": func(install *generationInstall) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			install.adopt(install.material, install.expected, other)
		},
		"another deployment's chain": func(install *generationInstall) {
			other := install.expected
			other.DeploymentID = "00000000000ZGTG9F4ZD9XG0T1"
			install.adopt(install.material, other, install.rootKey)
		},
		"a renewable file the generation did not pin": func(install *generationInstall) {
			install.adopt(install.material, install.expected, install.rootKey)
			install.write("ca.pem", []byte("manifest-era ca.pem"))
		},
		"credentials signed by another generation's signer": func(install *generationInstall) {
			install.adopt(install.material, install.expected, install.rootKey)
			install.renew(identity)
			other := generationtest.New(t, time.Now())
			issuer, _ := bootstrapmaterial.LoadControllerIssuer(other.Generation(install.expected, 1, ""),
				other.Files["controller-tls-issuer-cert.pem"], other.Files["controller-tls-issuer-key.pem"],
				other.Files["controller-account-signer.seed"])
			creds, _ := issuer.RenewCredentials(install.read("controller-a.creds"))
			install.write("controller-a.creds", creds)
		},
		"an adopted generation whose issuer has since expired": func(install *generationInstall) {
			template := generationtest.ControllerIssuer(time.Now().Add(-time.Hour), time.Now().Add(-time.Minute))
			_, cert, key := generationtest.Certificate(t, template, &install.material.CA)
			install.adopt(install.material.With(map[string][]byte{"controller-tls-issuer-cert.pem": cert,
				"controller-tls-issuer-key.pem": key}), install.expected, install.rootKey)
		},
		"an adopted generation past its signed expiry": func(install *generationInstall) {
			for name := range bootstrap.MaterialGenerationFiles() {
				install.write(name, install.material.Files[name])
			}
			envelope, err := bootstrap.SignMaterialGeneration(install.material.Generation(install.expected, 1, ""),
				time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), install.rootKey)
			if err != nil {
				t.Fatal(err)
			}
			wire, _ := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{envelope})
			install.write(MaterialGenerationsFile, wire)
		},
		"an extra file": func(install *generationInstall) {
			install.adopt(install.material, install.expected, install.rootKey)
			install.write("stranger.pem", []byte("not pinned"))
		},
		"a chain others can read": func(install *generationInstall) {
			install.adopt(install.material, install.expected, install.rootKey)
			if err := os.Chmod(filepath.Join(install.dir, MaterialGenerationsFile), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		install := newGenerationInstall(t)
		change(install)
		if err := install.verify(pinnedIP); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
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

// The v1 contract as gru-1 and sjc-1 adopt it (TS-668). Without controller issuers
// nothing is issued: the slot's manifest-era leaf (placeholder bytes no
// issuance rule accepts) keeps its manifest pin, and no issuer file is read,
// since none is installed. The interregion files have their role in the
// loaded config, which must be the generation's config for the slot, bound
// to the accepted manifest. A controller holds only its own leaf TLS.
func TestRestartPinsAdoptWithRoleSignerInterRegion(t *testing.T) {
	old := []byte(`{"nats":{},"controller":{}}`)
	newInstall := func(manifestSHA256 string) (*generationInstall, generationtest.Material, []byte) {
		install := newGenerationInstall(t)
		install.manifest.ControllerConfigSHA256 = digest(old)
		material, config := install.adoptInterRegion(manifestSHA256)
		install.loaded = config
		return install, material, config
	}
	install, _, config := newInstall("")
	if err := install.verify(pinnedIP); err != nil {
		t.Fatalf("the generation's config and files: %v", err)
	}
	store := MaterialStore{installedDirectory: install.dir, serviceUID: uint32(os.Getuid()),
		serviceGID: uint32(os.Getgid()), allowUnsafeAncestors: true}
	if want, err := store.ControllerConfigSHA256(install.accepted, install.roots); err != nil ||
		want != digest(config) {
		t.Fatalf("expected config digest = %s, %v; want the generation's", want, err)
	}
	otherAcceptance := install.accepted.Clone()
	otherAcceptance.OperationID = "00000000000ZGTG9F4ZD9XG0T1"
	if _, err := store.ControllerConfigSHA256(otherAcceptance, install.roots); err == nil {
		t.Fatal("a config bound to another manifest was expected")
	}

	certA, keyA := bootstrap.InterRegionTLSFiles("controller-a")
	certB, keyB := bootstrap.InterRegionTLSFiles("controller-b")
	for name, change := range map[string]func(*generationInstall, generationtest.Material){
		"the manifest's old config": func(install *generationInstall, _ generationtest.Material) { install.loaded = old },
		"another slot's config": func(install *generationInstall, material generationtest.Material) {
			install.loaded = material.Files["controller-controller-b.json"]
		},
		"another slot's leaf TLS": func(install *generationInstall, material generationtest.Material) {
			install.write(certB, material.Files[certB])
		},
		"no leaf TLS key": func(install *generationInstall, _ generationtest.Material) {
			if err := os.Remove(filepath.Join(install.dir, keyA)); err != nil {
				t.Fatal(err)
			}
		},
		"another slot's leaf TLS in the slot's place": func(install *generationInstall, material generationtest.Material) {
			install.write(certA, material.Files[certB])
			install.write(keyA, material.Files[keyB])
		},
		"an altered issued file": func(install *generationInstall, _ generationtest.Material) {
			install.write("controller-a-tls-cert.pem", []byte("altered"))
		},
		"an interregion file the generation does not pin": func(install *generationInstall, _ generationtest.Material) {
			install.credential.Config.Embedded.InterRegion.Remotes[0].CredentialsFile = filepath.Join(install.dir, "leaf-fra.creds")
		},
		"a regional file as an interregion file": func(install *generationInstall, _ generationtest.Material) {
			install.credential.Config.Embedded.InterRegion.AccountJWTFile = filepath.Join(install.dir, "cell.jwt")
		},
		"an interregion file outside the credential directory": func(install *generationInstall, _ generationtest.Material) {
			install.credential.Config.Embedded.InterRegion.AccountJWTFile = filepath.Join(t.TempDir(), "interregion.jwt")
		},
	} {
		install, material, _ := newInstall("")
		change(install, material)
		if err := install.verify(pinnedIP); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	if other, _, _ := newInstall(digest([]byte("another manifest"))); other.verify(pinnedIP) == nil {
		t.Error("accepted a config bound to another manifest")
	}
	plain := newGenerationInstall(t)
	plain.credential.Config.Embedded.InterRegion = embeddedBlock(t, config, plain.dir).InterRegion
	if err := plain.verify(pinnedIP); err == nil {
		t.Error("accepted interregion files without an adopted generation")
	}
}

// The home's link (TS-803) pins the interregion CA and the slot's leaf TLS;
// the loaded config's link block gives them their role, and only them.
func TestRestartPinsAdoptLink(t *testing.T) {
	newInstall := func() *generationInstall {
		install := newGenerationInstall(t)
		install.manifest.ControllerConfigSHA256 = digest([]byte(oldConfig))
		material := install.material.WithoutIssuers(t).Link(t, time.Now(), install.expected.ControllerSlots)
		install.loaded = install.adoptMaterial(material, "")
		install.credential.Config.Embedded.Link = embeddedBlock(t, install.loaded, install.dir).Link
		return install
	}
	if err := newInstall().verify(pinnedIP); err != nil {
		t.Fatalf("the link's files: %v", err)
	}
	for name, change := range map[string]func(*natscell.Link, string){
		"a regional file as the link CA":   func(link *natscell.Link, dir string) { link.TLS.CAFile = filepath.Join(dir, "ca.pem") },
		"link credentials it does not pin": func(link *natscell.Link, dir string) { link.CredentialsFile = filepath.Join(dir, "link.creds") },
	} {
		install := newInstall()
		change(install.credential.Config.Embedded.Link, install.dir)
		if err := install.verify(pinnedIP); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}
