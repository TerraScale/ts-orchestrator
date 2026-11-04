package managedmaterial

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
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
		{"member", func(d *InitialDeployment, _ *RuntimeArtifact, _ *placement.ManagedHostProfile) {
			d.Members[0].MemberID = d.Members[1].MemberID
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
