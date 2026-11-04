package cli

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

type customerOpenSigningKeys struct {
	recipientSigner ed25519.PrivateKey
	controller      ed25519.PrivateKey
	bundle          managedmaterial.InitialBundle
}

func customerOpenFixture(t *testing.T) (string, string, string, string, managedmaterial.InitialSpec,
	customerPreparationReply, customerOpenSigningKeys,
) {
	t.Helper()
	directory := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, recipientSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := managedmaterial.InitialCatalog("1G000000000000000000000001", nil)
	if err != nil {
		t.Fatal(err)
	}
	spec := managedmaterial.InitialSpec{
		PlacementDatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000Z3WK359G2W66CVT8",
		Scope: managedmaterial.AuthorityScope{ClusterID: "0102030405060708090a0b0c0d0e0f10",
			TenantID:   "0G000000000000000000000001",
			DatabaseID: "10000000000000000000000001", ShardID: 7, Epoch: 1},
		LiveS3: managedmaterial.LiveS3Target{Bucket: "alpha-live", Region: "sa-saopaulo-1",
			Endpoint:   "https://alpha.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
			Credential: oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3}},
		Catalogs: []managedmaterial.InitialCatalogInput{{CollectionID: catalog.CollectionID, CanonicalCatalog: catalog.Bytes}},
		Members: [2]managedmaterial.InitialMember{
			{SeatID: "000000000082AXF7GZQT1D126Y", MemberID: "20000000000000000000000001",
				Incarnation: "01010101010101010101010101010101", ServerName: "a.replication.example",
				FailureDomain: "FAULT-DOMAIN-1", MaterialDirectory: "/var/lib/terrabase/attempt-a/material",
				ReplicationIP: "10.0.0.11", ReplicationPort: 9443, ClientIP: "10.0.0.11", ClientPort: 9465},
			{SeatID: "0000000000XG8SBD7XGE97V28G", MemberID: "20000000000000000000000002",
				Incarnation: "02020202020202020202020202020202", ServerName: "b.replication.example",
				FailureDomain: "FAULT-DOMAIN-2", MaterialDirectory: "/var/lib/terrabase/attempt-b/material",
				ReplicationIP: "10.0.0.12", ReplicationPort: 9443, ClientIP: "10.0.0.12", ClientPort: 9465},
		},
		Recipient: managedmaterial.RecipientGrant{PublicKey: recipient.PublicKey().Bytes(), ExpiresAt: now.Add(time.Hour)},
	}
	spec.Recipient.Signature = ed25519.Sign(recipientSigner, managedmaterial.RecipientGrantMessage(spec))
	bundle, err := managedmaterial.GenerateInitial(spec, recipientSigner.Public().(ed25519.PublicKey), now)
	if err != nil {
		t.Fatal(err)
	}
	specWire, err := protocol.EncodeJSON(spec)
	if err != nil {
		t.Fatal(err)
	}
	specDigest := sha256.Sum256(specWire)
	specSHA := hex.EncodeToString(specDigest[:])
	object := managedmaterial.ObjectReference{
		Name:      "material/v2/gru/" + spec.PlacementDatabaseID + "/" + spec.PartitionID + "/g1-" + specSHA + ".json",
		VersionID: "version-1", ETag: "etag-1", SHA256: strings.Repeat("a", 64), SpecSHA256: specSHA,
	}
	receipt, err := managedmaterial.SignPreparationReceipt("gru", spec.PartitionID, spec, bundle,
		object, controllerPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	reply := customerPreparationReply{Receipt: receipt, Customer: bundle.Customer}
	replyWire, err := protocol.EncodeJSON(reply)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(controllerPublic)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(recipient)
	if err != nil {
		t.Fatal(err)
	}
	specPath := filepath.Join(directory, "spec.json")
	replyPath := filepath.Join(directory, "reply.json")
	controllerPath := filepath.Join(directory, "controller.pem")
	recipientPath := filepath.Join(directory, "recipient.pem")
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{specPath, specWire, 0o644}, {replyPath, replyWire, 0o644},
		{controllerPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644},
		{recipientPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600},
	} {
		if err := os.WriteFile(file.path, file.data, file.mode); err != nil {
			t.Fatal(err)
		}
	}
	return specPath, replyPath, controllerPath, recipientPath, spec, reply,
		customerOpenSigningKeys{recipientSigner: recipientSigner, controller: controllerPrivate, bundle: bundle}
}

func customerOpenArgs(spec, reply, controller, recipient, output string) []string {
	return []string{"open-customer-material", "--spec", spec, "--reply", reply,
		"--controller-key", controller, "--cell", "gru", "--recipient-key", recipient, "--out", output}
}

func TestOpenCustomerMaterialSignedReplyAndOwnerOnlyOutput(t *testing.T) {
	specPath, replyPath, controllerPath, recipientPath, _, _, _ := customerOpenFixture(t)
	output := filepath.Join(t.TempDir(), "customer.json")
	args := customerOpenArgs(specPath, replyPath, controllerPath, recipientPath, output)
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var material managedmaterial.CustomerMaterial
	if err := protocol.DecodeStrict(wire, &material, 16<<10); err != nil ||
		material.Version != 1 || !strings.HasPrefix(material.Token, "tbk1.") ||
		!strings.Contains(material.HTTPSCAPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("owner output differs from prepared customer material: %v", err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("customer output is not owner-only: %v", err)
	}
	if err := run(args); err == nil {
		t.Fatal("customer output was overwritten")
	}
	after, err := os.ReadFile(output)
	if err != nil || string(after) != string(wire) {
		t.Fatal("existing customer output changed")
	}
}
