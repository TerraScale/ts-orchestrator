package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nkeys"
)

// launchMaterialFixture returns an image directory holding only trust roots,
// plus launch material whose anchor those roots sign.
func launchMaterialFixture(t *testing.T) (bakedStore, LaunchMaterial) {
	t.Helper()
	fixture := newAdmissionFlowFixture(t)
	roots, anchorWire := fixture.gate.Roots, fixture.gate.AnchorWire
	envelope, err := trust.DecodeEnvelope(fixture.ledger.state.ManifestRecord.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := bootstrap.ManifestPayload(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "bootstrap")
	rootsDirectory := filepath.Join(directory, "trust-roots")
	if err := os.MkdirAll(rootsDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{directory, rootsDirectory} {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range roots {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		writeBakedFixture(t, filepath.Join(rootsDirectory, "001.pem"),
			pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	identity, err := protocol.EncodeJSON(BakedIdentity{
		SchemaVersion: 1, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Environment: "production", Cell: oci.RegionGRU,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := bakedStore{directory: directory, ownerUID: uint32(os.Getuid()),
		ownerGID: uint32(os.Getgid()), allowUnsafeAncestors: true}
	return store, LaunchMaterial{Identity: identity, Anchor: anchorWire, HostEnrollment: hostEnrollmentFixture(t),
		OperatorSSHKey: []byte(testOperatorSSHKey), ManagedHostImageReceipt: manifest.ReleaseImageReceiptWire,
		ManagedHostImageDelegation: manifest.ReleaseDelegationWire}
}

func hostEnrollmentFixture(t *testing.T) []byte {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "launch material CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	responsePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(account.Wipe)
	accountPublic, err := account.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := hostenroll.PublicBundle{SchemaVersion: 1, Cell: "gru", Region: "GRU",
		ControllerEndpoints:         []string{"10.251.0.11:8443", "10.251.0.12:8443", "10.251.0.13:8443"},
		NATSURLs:                    []string{"tls://10.251.0.11:4222", "tls://10.251.0.12:4222", "tls://10.251.0.13:4222"},
		CAPEM:                       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		ControllerResponsePublicKey: base64.StdEncoding.EncodeToString(responsePublic),
		CellAccountNKey:             accountPublic, Environment: "production",
		InstallRoot: hostenroll.ImageInstallRoot, StateRoot: hostenroll.ImageStateRoot,
		ManagedRuntimeRoot: hostenroll.ImageManagedRuntimeRoot,
		WorkloadUID:        hostenroll.ImageWorkloadUID, WorkloadGID: hostenroll.ImageWorkloadGID}
	if err := bundle.Validate(); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func fetchOnce(t *testing.T, material LaunchMaterial) func(context.Context) (LaunchMaterial, error) {
	calls := 0
	t.Cleanup(func() {
		if calls > 1 {
			t.Fatalf("launch metadata fetched %d times", calls)
		}
	})
	return func(context.Context) (LaunchMaterial, error) {
		calls++
		return material, nil
	}
}

func TestInstallLaunchMaterialWritesVerifiedWriteOnceFiles(t *testing.T) {
	store, material := launchMaterialFixture(t)
	now := time.Now().UTC()
	if err := store.installLaunchMaterial(t.Context(), fetchOnce(t, material), now); err != nil {
		t.Fatalf("install verified launch material: %v", err)
	}
	loaded, err := store.loadLaunchMaterial()
	if err != nil || string(loaded.Identity) != string(material.Identity) ||
		string(loaded.Anchor) != string(material.Anchor) || string(loaded.HostEnrollment) != string(material.HostEnrollment) ||
		string(loaded.OperatorSSHKey) != testOperatorSSHKey ||
		!bytes.Equal(loaded.ManagedHostImageReceipt, material.ManagedHostImageReceipt) ||
		!bytes.Equal(loaded.ManagedHostImageDelegation, material.ManagedHostImageDelegation) {
		t.Fatalf("installed launch material differs: %v", err)
	}
	baked, err := store.load()
	if err != nil || baked.Identity.DeploymentID != "0000000000F9PR1WNVDTEXS31Z" || string(baked.AnchorWire) != string(material.Anchor) {
		t.Fatalf("baked loader rejected installed launch material: %v", err)
	}
	unexpected := func(context.Context) (LaunchMaterial, error) {
		t.Fatal("installed launch material was fetched again")
		return LaunchMaterial{}, nil
	}
	if err := store.installLaunchMaterial(t.Context(), unexpected, now); err != nil {
		t.Fatalf("reinstall over complete material: %v", err)
	}
}

func TestInstallLaunchMaterialRejectsMissingForeignAndExpiredManagedImage(t *testing.T) {
	for _, fault := range []string{"missing receipt", "missing delegation", "foreign signer", "expired"} {
		t.Run(fault, func(t *testing.T) {
			store, material := launchMaterialFixture(t)
			now := time.Now().UTC()
			switch fault {
			case "missing receipt":
				material.ManagedHostImageReceipt = nil
			case "missing delegation":
				material.ManagedHostImageDelegation = nil
			case "foreign signer":
				_, foreign := launchMaterialFixture(t)
				material.ManagedHostImageReceipt, material.ManagedHostImageDelegation = foreign.ManagedHostImageReceipt, foreign.ManagedHostImageDelegation
			case "expired":
				now = now.Add(2 * time.Hour)
			}
			if err := store.installLaunchMaterial(t.Context(), fetchOnce(t, material), now); !errors.Is(err, ErrLaunchMaterial) {
				t.Fatalf("invalid managed image installed: %v", err)
			}
			for _, name := range launchMaterialNames {
				if _, err := os.Lstat(filepath.Join(store.directory, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("rejected launch installed %s: %v", name, err)
				}
			}
		})
	}
}

func TestInstallLaunchMaterialRecoversBeforeManagedImagePublication(t *testing.T) {
	store, material := launchMaterialFixture(t)
	for index, wire := range material.wires() {
		if index < 4 {
			writeBakedFixture(t, filepath.Join(store.directory, launchMaterialNames[index]), wire)
		}
	}
	if err := store.installLaunchMaterial(t.Context(), fetchOnce(t, material), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.loadLaunchMaterial()
	if err != nil || !bytes.Equal(loaded.ManagedHostImageReceipt, material.ManagedHostImageReceipt) {
		t.Fatalf("partial publication did not recover: %v", err)
	}
}

func TestInstallLaunchMaterialRejectsForeignAnchorAndRedirection(t *testing.T) {
	store, material := launchMaterialFixture(t)
	_, _, _, _, foreignAnchor := verifiedAnchorFixture(t)
	foreign := material
	foreign.Anchor = foreignAnchor
	now := time.Now().UTC()
	if err := store.installLaunchMaterial(t.Context(), fetchOnce(t, foreign), now); !errors.Is(err, ErrLaunchMaterial) {
		t.Fatalf("anchor signed outside the image roots was accepted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(store.directory, anchorFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected launch material left an installed anchor: %v", err)
	}

	writeBakedFixture(t, filepath.Join(store.directory, identityFilename), []byte(`{"schemaVersion":1}`))
	if err := store.installLaunchMaterial(t.Context(), fetchOnce(t, material), now); !errors.Is(err, ErrLaunchMaterial) {
		t.Fatalf("launch material replaced a different installed identity: %v", err)
	}
}

func TestInstallLaunchMaterialRejectsBundleOutsideImageLayout(t *testing.T) {
	store, material := launchMaterialFixture(t)
	var bundle hostenroll.PublicBundle
	if err := json.Unmarshal(material.HostEnrollment, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle.ManagedRuntimeRoot = "/srv/elsewhere"
	wire, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	material.HostEnrollment = wire
	if err := store.installLaunchMaterial(t.Context(), fetchOnce(t, material), time.Now().UTC()); !errors.Is(err, ErrLaunchMaterial) {
		t.Fatalf("host bundle with a foreign managed root was accepted: %v", err)
	}
}

func TestInstallLaunchMaterialRejectsNonCanonicalOperatorSSHKey(t *testing.T) {
	_, blob, _ := strings.Cut(testOperatorSSHKey, " ")
	blob, _, _ = strings.Cut(blob, " ")
	rsa := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 operator"
	for _, key := range []string{"", testOperatorSSHKey + "\n", "ssh-ed25519  " + blob, "ssh-ed25519 " + blob + " a b",
		"ssh-ed25519 " + blob + " bad;comment", "ssh-ed25519 " + blob[:len(blob)-4], rsa,
		"ssh-ed25519 " + base64.StdEncoding.EncodeToString(append([]byte("\x00\x00\x00\x07ssh-rsa"), make([]byte, 36)...))} {
		store, material := launchMaterialFixture(t)
		material.OperatorSSHKey = []byte(key)
		if err := store.installLaunchMaterial(t.Context(), fetchOnce(t, material), time.Now().UTC()); !errors.Is(err, ErrLaunchMaterial) {
			t.Fatalf("operator SSH key %q was accepted: %v", key, err)
		}
	}
	store, material := launchMaterialFixture(t)
	material.OperatorSSHKey = []byte("ssh-ed25519 " + blob)
	if err := store.installLaunchMaterial(t.Context(), fetchOnce(t, material), time.Now().UTC()); err != nil {
		t.Fatalf("operator SSH key without a comment was rejected: %v", err)
	}
}

func TestLaunchMetadataForwardsOperatorSSHKey(t *testing.T) {
	for name, metadata := range map[string]map[string]string{
		"controller": testLaunchMaterial.ControllerMetadata(), "host": testLaunchMaterial.HostMetadata(),
	} {
		if metadata[OperatorSSHKeyMetadataKey] != testOperatorSSHKey {
			t.Fatalf("%s launch metadata omits the operator SSH key: %v", name, metadata)
		}
	}
}
