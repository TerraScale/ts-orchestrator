package identityrekey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nkeys"
)

func TestCheckpointIssueVerify(t *testing.T) {
	checkpoint, key, roots, now := checkpointFixture(t)
	envelope, wire := issueCheckpoint(t, checkpoint, key, now)
	for _, slot := range checkpoint.Slots {
		verified, err := VerifyAcceptedIdentityCheckpoint(wire, roots, trust.RootChain{Version: 1}, expectation(checkpoint, slot), now)
		if err != nil {
			t.Fatal(err)
		}
		if !verified.IsVerified() || verified.Fingerprint() != sha256Hex(wire) || !verified.ExpiresAt().Equal(envelope.ExpiresAt) ||
			!bytes.Equal(verified.Wire(), wire) {
			t.Fatal("verified checkpoint lost its proof identity")
		}
		copy := verified.Checkpoint()
		copy.Slots[0].ConfigSHA256["controller.json"] = "modified"
		copy.Slots[0].LaunchMaterialSHA256["operator-ssh-key.pub"] = "modified"
		copy.Slots[0].InstanceOCID = "modified"
		copy.Slots[0].MaterialReferences[0].SHA256 = "modified"
		copyWire := verified.Wire()
		copyWire[0] = 'x'
		if verified.Checkpoint().Slots[0].ConfigSHA256["controller.json"] == "modified" ||
			verified.Checkpoint().Slots[0].InstanceOCID == "modified" || verified.Checkpoint().Slots[0].LaunchMaterialSHA256["operator-ssh-key.pub"] == "modified" || !bytes.Equal(verified.Wire(), wire) {
			t.Fatal("verified checkpoint leaked mutable data")
		}
		if verified.Checkpoint().Slots[0].MaterialReferences[0].SHA256 == "modified" {
			t.Fatal("verified checkpoint leaked its material baseline")
		}
	}
	if (VerifiedIdentityCheckpoint{}).IsVerified() {
		t.Fatal("zero value grants authority")
	}
}

func checkpointFixture(t *testing.T) (AcceptedIdentityCheckpoint, ed25519.PrivateKey, trust.Keyring, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := AcceptedIdentityCheckpoint{SchemaVersion: 1, OperationID: entityid.Derive("rekey-operation"),
		DeploymentID: entityid.Derive("new-deployment"), ClusterID: entityid.Derive("new-cluster"), Environment: "canary", Cell: "GRU",
		SeedSlot:                 "controller-a",
		MaterialGenerationSHA256: sha256Hex([]byte("signed generation")), Broker: BrokerIdentity{
			Operator: publicKey(t, true), SystemAccount: publicKey(t, false), CellAccount: publicKey(t, false),
			HostSigner: publicKey(t, false), AccountSigner: publicKey(t, false), RoleSigner: publicKey(t, false),
			InterRegionAccount: publicKey(t, false)}}
	for i := range 3 {
		checkpoint.Slots = append(checkpoint.Slots, SlotBinding{Slot: "controller-" + string(rune('a'+i)),
			PreviousAcceptanceSHA256: sha256Hex([]byte(fmt.Sprintf("opaque legacy acceptance %d", i))),
			PreviousMaterialSHA256:   map[string]string{"installed": sha256Hex([]byte("old material chain")), "durable": sha256Hex([]byte("old material chain"))},
			InstanceOCID:             fmt.Sprintf("ocid1.instance.oc1.sa-saopaulo-1.existing%d", i),
			ImageOCID:                "ocid1.image.oc1.sa-saopaulo-1.observed-existing-image",
			PrimaryVNICOCID:          fmt.Sprintf("ocid1.vnic.oc1.sa-saopaulo-1.existing%d", i),
			PrimaryPrivateIP:         fmt.Sprintf("10.251.0.%d", 11+i),
			Binary:                   BinaryPin{SHA256: sha256Hex([]byte("approved executable")), Size: 4096, Architecture: "amd64"},
			ConfigSHA256: map[string]string{"controller.json": sha256Hex([]byte(fmt.Sprintf("installed config %d", i))),
				"placement.json":         sha256Hex([]byte("installed placement")),
				"oci-region.json":        sha256Hex([]byte("installed region")),
				"oci-region-intent.json": sha256Hex([]byte("installed intent"))},
			LaunchMaterialSHA256: map[string]string{"host-enrollment-public.json": sha256Hex([]byte("enrollment")), "operator-ssh-key.pub": sha256Hex([]byte("ssh")),
				"managed-host-image-receipt.json": sha256Hex([]byte("image receipt")), "managed-host-image-delegation.json": sha256Hex([]byte("image delegation"))},
			MaterialReferences: []bootstrap.SecretReference{{Purpose: bootstrap.SecretController,
				Slot: "controller-" + string(rune('a'+i)), TargetFile: "controller-" + string(rune('a'+i)) + ".creds",
				SecretOCID: fmt.Sprintf("ocid1.vaultsecret.oc1.sa-saopaulo-1.material%d", i), VersionNumber: 1,
				SHA256: sha256Hex([]byte(fmt.Sprintf("installed credential %d", i))), MaxBytes: 16 << 10}},
			Store: StoreIdentity{Directory: "/var/lib/terrascale-orchestrator", ServerName: fmt.Sprintf("gru-1-ctl-%d", i+1),
				RaftNodeID: fmt.Sprintf("NODE000%d", i), ServerNameSHA256: sha256Hex([]byte(fmt.Sprintf("gru-1-ctl-%d\n", i+1))),
				NodeIdentitySHA256: sha256Hex([]byte(fmt.Sprintf("existing node identity %d", i)))}})
	}
	return checkpoint, key, roots, now
}

func publicKey(t *testing.T, operator bool) string {
	t.Helper()
	var key nkeys.KeyPair
	var err error
	if operator {
		key, err = nkeys.CreateOperator()
	} else {
		key, err = nkeys.CreateAccount()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func expectation(checkpoint AcceptedIdentityCheckpoint, slot SlotBinding) CheckpointExpectation {
	slot.ConfigSHA256 = maps.Clone(slot.ConfigSHA256)
	slot.LaunchMaterialSHA256 = maps.Clone(slot.LaunchMaterialSHA256)
	slot.MaterialReferences = slices.Clone(slot.MaterialReferences)
	return CheckpointExpectation{OperationID: checkpoint.OperationID, DeploymentID: checkpoint.DeploymentID,
		ClusterID: checkpoint.ClusterID, Environment: checkpoint.Environment, Cell: checkpoint.Cell,
		SeedSlot: checkpoint.SeedSlot, ManagedMaterial: checkpoint.ManagedMaterial,
		MaterialGenerationSHA256: checkpoint.MaterialGenerationSHA256, Broker: checkpoint.Broker, Slot: slot}
}

func issueCheckpoint(t *testing.T, checkpoint AcceptedIdentityCheckpoint, key ed25519.PrivateKey, now time.Time) (trust.Envelope, []byte) {
	t.Helper()
	envelope, err := IssueAcceptedIdentityCheckpoint(checkpoint, now, now.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return envelope, wire
}
