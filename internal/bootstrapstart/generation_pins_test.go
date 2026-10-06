package bootstrapstart

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const pinnedIP = "10.0.1.10"

// generationInstall is one controller's credential directory, first holding
// manifest-era material, and the generation that renews it.
type generationInstall struct {
	t          *testing.T
	dir        string
	manifest   bootstrap.Manifest
	credential LiveCredentials
	material   generationtest.Material
	roots      trust.Keyring
	rootKey    ed25519.PrivateKey
	expected   bootstrap.MaterialGenerationExpectation
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
	install.expected = bootstrap.MaterialGenerationExpectation{DeploymentID: "gru-1-deployment", Environment: "production",
		ClusterID: "gru-1", Cell: "GRU", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}}
	install.manifest = bootstrap.Manifest{DeploymentID: "gru-1-deployment", Environment: "production", ClusterID: "gru-1",
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
		"ticket.key": bootstrap.SecretRegionalShared, "host-nats-issuer.seed": bootstrap.SecretHostIssuer,
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
		reference := bootstrap.SecretReference{Purpose: purpose, TargetFile: name, SHA256: digest(content)}
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
		directory: dir, allowUnsafeAncestors: true}
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
	pins, err := restartPins(dir, uint32(os.Getuid()), uint32(os.Getgid()), install.manifest, install.roots, privateIP)
	if err != nil {
		return err
	}
	store := MaterialStore{installedDirectory: install.dir, serviceUID: uint32(os.Getuid()),
		serviceGID: uint32(os.Getgid()), allowUnsafeAncestors: true}
	if err := store.verifyInstalled(install.t.Context(), dir, pins.Digests); err != nil {
		return err
	}
	if err := pins.verifyGeneration(dir, uint32(os.Getuid()), uint32(os.Getgid()), time.Now()); err != nil {
		return err
	}
	if err := install.credential.verifyPaths(pins, install.manifest); err != nil {
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
			other.DeploymentID = "another-deployment"
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

// Install continuity binds the adopted generation, not the slot's issued
// files: renewal keeps the bound, an expired generation or a foreign leaf
// has none.
func TestCredentialBoundFollowsTheAdoptedGeneration(t *testing.T) {
	install := newGenerationInstall(t)
	install.adopt(install.material, install.expected, install.rootKey)
	materials := expectedMaterials(install.manifest, install.manifest.Slot)
	bound, err := install.credential.CurrentCredentialBound(materials, install.manifest, install.roots, pinnedIP)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := os.ReadFile(filepath.Join(install.dir, MaterialGenerationsFile))
	chain, _ := bootstrap.DecodeMaterialGenerationChain(wire)
	fingerprint, _ := trust.Fingerprint(chain[0])
	want, _ := bootstrap.InstallContinuityGenerationDigest(fingerprint)
	if bound.SHA256 != want || bound.Generation != fingerprint || !bound.ValidUntil.Equal(chain[0].ExpiresAt) {
		t.Fatalf("bound = %+v, want the generation %s until %s", bound, fingerprint, chain[0].ExpiresAt)
	}
	install.renew(bootstrapmaterial.ControllerLeafIdentity("gru", "controller-a", pinnedIP))
	if renewed, err := install.credential.CurrentCredentialBound(materials, install.manifest, install.roots,
		pinnedIP); err != nil || renewed != bound {
		t.Fatalf("renewal changed the bound: %+v, %v", renewed, err)
	}
	install.renew(bootstrapmaterial.ControllerLeafIdentity("gru", "controller-b", pinnedIP))
	if _, err := install.credential.CurrentCredentialBound(materials, install.manifest, install.roots, pinnedIP); err == nil {
		t.Fatal("another slot's leaf was bound")
	}

	expired := newGenerationInstall(t)
	for name := range bootstrap.MaterialGenerationFiles() {
		expired.write(name, expired.material.Files[name])
	}
	envelope, err := bootstrap.SignMaterialGeneration(expired.material.Generation(expired.expected, 1, ""),
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), expired.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ = bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{envelope})
	expired.write(MaterialGenerationsFile, wire)
	if _, err := expired.credential.CurrentCredentialBound(expectedMaterials(expired.manifest, "controller-a"),
		expired.manifest, expired.roots, pinnedIP); err == nil {
		t.Fatal("an expired generation was bound")
	}
}
