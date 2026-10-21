package managedmaterial

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func testDeployment(t *testing.T) InitialDeployment {
	t.Helper()
	deployment, err := NewDeploymentIdentity(InitialDeployment{
		Region: oci.RegionGRU, PlacementDatabaseID: "0000000000HX30KC7N7WJ1ZFC8", PartitionID: "00000000003ZJEV7X3HYJENEYG",
		LiveS3: LiveS3Target{Bucket: "alpha-live", Region: "sa-saopaulo-1",
			Endpoint:      "https://alpha.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
			Credential:    oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 1},
			NativeOCIRoot: &NativeOCIRoot{Namespace: "alpha"}},
		Members: [2]DeploymentMember{
			{SeatID: "000000000082AXF7GZQT1D126Y", ServerName: "permanent-a.terrabase.internal", FailureDomain: "FAULT-DOMAIN-1", PrivateIP: "10.0.0.21"},
			{SeatID: "0000000000XG8SBD7XGE97V28G", ServerName: "elastic-gru.terrabase.internal", FailureDomain: "FAULT-DOMAIN-2", PrivateIP: "10.0.0.22"},
		},
		ReplicationPort: 7422, ClientPort: 8080, ManagedRuntimeRoot: "/srv/ts-managed",
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return deployment
}

func testHostProfile() placement.ManagedHostProfile {
	return placement.ManagedHostProfile{Region: oci.RegionGRU,
		Compute:            placement.ComputeTuple{Shape: "VM.Standard.A1.Flex", WholeOCPUs: 1, MemoryInGBs: 6},
		ProcessMemoryBytes: 4 << 30, MemoryHeadroomBytes: 1 << 30, CgroupMemoryMaxBytes: 4 << 30,
		SystemReserveBytes: 1 << 30, AllocatableMemoryBytes: 4 << 30}
}

func TestInitialDeploymentRendersAdmittedPlacementFromReceipt(t *testing.T) {
	service, _, _, _ := preparationFixture(t)
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service.RecipientSigner = public
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deployment := testDeployment(t)
	draft, err := deployment.DraftSpec()
	if err != nil {
		t.Fatal(err)
	}
	if draft.Members[0].MemberID >= draft.Members[1].MemberID || len(draft.Catalogs) != 1 {
		t.Fatalf("draft is not in authority order: %+v", draft.Members)
	}
	now := time.Now().UTC()
	spec, err := SignRecipientGrant(draft, recipient, signer, now.Add(24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRecipientGrant(spec, public); err != nil {
		t.Fatal(err)
	}
	again, err := SignRecipientGrant(draft, recipient, signer, spec.Recipient.ExpiresAt, now)
	if err != nil || !bytes.Equal(again.Recipient.Signature, spec.Recipient.Signature) {
		t.Fatal("recipient grant signing is not deterministic for a retained expiry")
	}
	receipt, err := service.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, now)
	if err != nil {
		t.Fatal(err)
	}
	artifact := RuntimeArtifact{Digest: strings.Repeat("a", 64), SourceDigest: strings.Repeat("b", 64)}
	intent, err := RenderInitialPlacement(receipt, deployment, artifact, testHostProfile())
	if err != nil {
		t.Fatal(err)
	}
	if err := intent.ValidateForAdmission(); err != nil {
		t.Fatal(err)
	}
	if intent.CanonicalRoster.Rows[0].SeatID != "000000000082AXF7GZQT1D126Y" || intent.CanonicalRoster.Rows[0].FailureDomain != "FAULT-DOMAIN-1" ||
		intent.RuntimeManifests[0].ReplicationListenAddress != "10.0.0.21:7422" ||
		intent.RuntimeManifests[0].ReplicationPeerAddress != "10.0.0.22:7422" ||
		intent.RuntimeManifests[1].FileSystemUUID != deployment.Members[1].FileSystemUUID {
		t.Fatalf("rendered placement lost seat order or pins: %+v", intent.RuntimeManifests)
	}
	first, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderInitialPlacement(receipt, deployment, artifact, testHostProfile())
	if err != nil {
		t.Fatal(err)
	}
	second, err := protocol.EncodeJSON(rendered)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("placement rendering is not deterministic")
	}
	for _, test := range []struct {
		name   string
		change func(*InitialDeployment, *RuntimeArtifact, *placement.ManagedHostProfile)
	}{
		{"artifact", func(_ *InitialDeployment, a *RuntimeArtifact, _ *placement.ManagedHostProfile) { a.Digest = "bad" }},
		{"profile region", func(_ *InitialDeployment, _ *RuntimeArtifact, p *placement.ManagedHostProfile) {
			p.Region = oci.RegionSJC
		}},
		{"memory", func(_ *InitialDeployment, _ *RuntimeArtifact, p *placement.ManagedHostProfile) {
			p.AllocatableMemoryBytes = 6 << 30
		}},
		{"member", func(d *InitialDeployment, _ *RuntimeArtifact, _ *placement.ManagedHostProfile) {
			d.Members[0].MemberID = d.Members[1].MemberID
		}},
		{"address", func(d *InitialDeployment, _ *RuntimeArtifact, _ *placement.ManagedHostProfile) {
			d.Members[0].PrivateIP = "10.0.0.99"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changedDeployment, changedArtifact, changedProfile := deployment, artifact, testHostProfile()
			test.change(&changedDeployment, &changedArtifact, &changedProfile)
			if _, err := RenderInitialPlacement(receipt, changedDeployment, changedArtifact, changedProfile); err == nil {
				t.Fatal("placement rendered from inputs that differ from prepared material")
			}
		})
	}
}

func TestInitialDeploymentRejectsUnsafeInputs(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*InitialDeployment)
	}{
		{"seat order", func(d *InitialDeployment) {
			d.Members[0].SeatID, d.Members[1].SeatID = d.Members[1].SeatID, d.Members[0].SeatID
		}},
		{"shared fault domain", func(d *InitialDeployment) { d.Members[1].FailureDomain = d.Members[0].FailureDomain }},
		{"public address", func(d *InitialDeployment) { d.Members[0].PrivateIP = "203.0.113.10" }},
		{"same ports", func(d *InitialDeployment) { d.ClientPort = d.ReplicationPort }},
		{"foreign S3 region", func(d *InitialDeployment) { d.LiveS3.Region = "us-sanjose-1" }},
		{"relative root", func(d *InitialDeployment) { d.ManagedRuntimeRoot = "srv/ts-managed" }},
		{"database token", func(d *InitialDeployment) { d.PlacementDatabaseID = "db.1" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			deployment := testDeployment(t)
			test.change(&deployment)
			if _, err := deployment.DraftSpec(); err == nil {
				t.Fatal("unsafe deployment input was drafted")
			}
		})
	}
}

func TestRecipientKeyReadersRequireOwnerOnlyPEM(t *testing.T) {
	directory := t.TempDir()
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, kind string, key any, mode os.FileMode) string {
		t.Helper()
		var der []byte
		var err error
		if kind == "PUBLIC KEY" {
			der, err = x509.MarshalPKIXPublicKey(key)
		} else {
			der, err = x509.MarshalPKCS8PrivateKey(key)
		}
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	recipientPath := write("recipient.pem", "PRIVATE KEY", recipient, 0o600)
	signerPath := write("signer.pem", "PRIVATE KEY", signer, 0o600)
	publicPath := write("signer.pub", "PUBLIC KEY", public, 0o644)
	loaded, err := ReadRecipientKey(recipientPath)
	if err != nil || !bytes.Equal(loaded.Bytes(), recipient.Bytes()) {
		t.Fatalf("recipient key: %v", err)
	}
	loadedSigner, err := ReadRecipientSigner(signerPath)
	if err != nil || !loadedSigner.Equal(signer) {
		t.Fatalf("recipient signer: %v", err)
	}
	loadedPublic, err := ReadRecipientSignerPublic(publicPath)
	if err != nil || !loadedPublic.Equal(public) {
		t.Fatalf("recipient signer public key: %v", err)
	}
	if _, err := ReadRecipientSigner(recipientPath); err == nil {
		t.Fatal("X25519 key was accepted as the Ed25519 signer")
	}
	if err := os.Chmod(signerPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRecipientSigner(signerPath); err == nil {
		t.Fatal("group-readable signer key was accepted")
	}
	link := filepath.Join(directory, "link.pem")
	if err := os.Symlink(recipientPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRecipientKey(link); err == nil {
		t.Fatal("symlinked recipient key was accepted")
	}
}

func TestInitialCatalogEncodesTerraBaseUTF8Field(t *testing.T) {
	catalog, err := InitialCatalog("1G000000000000000000000001", DeploymentDocumentFields)
	if err != nil {
		t.Fatal(err)
	}
	// Vector computed independently by TerraBase d2017ca terrabase-init.
	schema := "544253434830303124000000010001000000000000000400000500" + "7469746c6550975cec"
	if got := hex.EncodeToString(catalog.Bytes[80 : len(catalog.Bytes)-4]); got != schema ||
		catalog.SchemaDigest != "0d645cd6d847a903aaf2b34a6fa3b9ca3047c9b0a283218a4fa29cd0b6085090" ||
		len(catalog.Bytes) != 120 {
		t.Fatalf("TBSCH001 bytes %s digest %s", got, catalog.SchemaDigest)
	}
	collection, _ := canonicalID(catalog.CollectionID)
	if !validInitialCatalog(catalog, collection) {
		t.Fatal("field catalog failed the authority envelope check")
	}
	empty, err := InitialCatalog("1G000000000000000000000001", nil)
	if err != nil || len(empty.Bytes) != 102 || !validInitialCatalog(empty, collection) {
		t.Fatalf("empty catalog changed: %v", err)
	}
	for _, fields := range [][]CatalogUTF8Field{
		{{ID: 0, Name: "title"}}, {{ID: 1, Name: "Title"}}, {{ID: 1, Name: "a"}, {ID: 1, Name: "b"}},
		{{ID: 1, Name: "a"}, {ID: 2, Name: "a"}},
	} {
		if _, err := InitialCatalog(catalog.CollectionID, fields); err == nil {
			t.Fatalf("invalid fields accepted: %+v", fields)
		}
	}
}
