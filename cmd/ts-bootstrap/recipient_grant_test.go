package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

type recipientSpecFixture struct {
	directory, draftPath, recipientPath, signerPath, signerPublicPath string
	now                                                               time.Time
	signerPublic                                                      ed25519.PublicKey
}

func newRecipientSpecFixture(t *testing.T) recipientSpecFixture {
	t.Helper()
	directory := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	_, _, _, recipientPath, spec, _, _ := customerOpenFixture(t)
	spec.Recipient = managedmaterial.RecipientGrant{}
	draft, err := protocol.EncodeJSON(spec)
	if err != nil {
		t.Fatal(err)
	}
	draftPath := filepath.Join(directory, "draft.json")
	if err := os.WriteFile(draftPath, draft, 0o600); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	signerPath := filepath.Join(directory, "recipient-signer.pem")
	signerPublicPath := filepath.Join(directory, "recipient-signer-public.pem")
	if err := os.WriteFile(signerPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signerPublicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return recipientSpecFixture{directory: directory, draftPath: draftPath, recipientPath: recipientPath,
		signerPath: signerPath, signerPublicPath: signerPublicPath, now: now, signerPublic: public}
}

func (fixture recipientSpecFixture) args(output, expiry string) []string {
	return []string{"--input", fixture.draftPath, "--recipient-key", fixture.recipientPath,
		"--signer-key", fixture.signerPath, "--signer-public-key", fixture.signerPublicPath,
		"--expires-at", expiry, "--out", output}
}

func TestSignInitialMaterialSpecFeedsProducerAndCustomerOpener(t *testing.T) {
	fixture := newRecipientSpecFixture(t)
	output := filepath.Join(fixture.directory, "material-spec.json")
	if err := signInitialMaterialSpecAt(fixture.args(output, fixture.now.Add(time.Hour).Format(time.RFC3339)), fixture.now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("signed spec must be an owner-only file: %v", err)
	}
	wire, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var spec managedmaterial.InitialSpec
	if err := protocol.DecodeStrict(wire, &spec, maxCustomerSpecBytes); err != nil {
		t.Fatal(err)
	}
	canonical, err := protocol.EncodeJSON(spec)
	if err != nil || !bytes.Equal(wire, canonical) {
		t.Fatalf("signed spec is not canonical JSON: %v", err)
	}
	if !ed25519.Verify(fixture.signerPublic, managedmaterial.RecipientGrantMessage(spec), spec.Recipient.Signature) {
		t.Fatal("producer's exact recipient grant message was not signed")
	}
	bundle, err := managedmaterial.GenerateInitial(spec, fixture.signerPublic, fixture.now)
	if err != nil {
		t.Fatalf("production material producer rejected the signed spec: %v", err)
	}
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	specSHA := sha256.Sum256(wire)
	sha := hex.EncodeToString(specSHA[:])
	receipt, err := managedmaterial.SignPreparationReceipt("gru", spec.PartitionID, spec, bundle,
		managedmaterial.ObjectReference{Name: "material/v2/gru/" + spec.PlacementDatabaseID + "/" + spec.PartitionID + "/g1-" + sha + ".json",
			VersionID: "version-1", ETag: "etag-1", SHA256: strings.Repeat("a", 64), SpecSHA256: sha},
		controllerPrivate, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	reply := customerPreparationReply{Receipt: receipt, Customer: bundle.Customer}
	replyWire, err := protocol.EncodeJSON(reply)
	if err != nil {
		t.Fatal(err)
	}
	replyPath := filepath.Join(fixture.directory, "reply.json")
	if err := os.WriteFile(replyPath, replyWire, 0o600); err != nil {
		t.Fatal(err)
	}
	controllerDER, err := x509.MarshalPKIXPublicKey(controllerPublic)
	if err != nil {
		t.Fatal(err)
	}
	controllerPath := filepath.Join(fixture.directory, "controller.pem")
	if err := os.WriteFile(controllerPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: controllerDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	customerPath := filepath.Join(fixture.directory, "customer.json")
	if err := openCustomerMaterialAt([]string{"--spec", output, "--reply", replyPath,
		"--controller-key", controllerPath, "--cell", "gru", "--recipient-key", fixture.recipientPath,
		"--out", customerPath}); err != nil {
		t.Fatalf("supported customer opener rejected producer reply: %v", err)
	}
	material, err := os.ReadFile(customerPath)
	if err != nil || !bytes.Contains(material, []byte(`"token":"tbk1.`)) ||
		!bytes.Contains(material, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("customer material was not opened by the production command: %v", err)
	}
	if err := signInitialMaterialSpecAt(fixture.args(output, fixture.now.Add(time.Hour).Format(time.RFC3339)), fixture.now); err == nil {
		t.Fatal("signed spec output was overwritten")
	}
}

func TestSignInitialMaterialSpecBindsSQLTableSetToRecipientGrant(t *testing.T) {
	fixture := newRecipientSpecFixture(t)
	wire, err := os.ReadFile(fixture.draftPath)
	if err != nil {
		t.Fatal(err)
	}
	var spec managedmaterial.InitialSpec
	if err := protocol.DecodeStrict(wire, &spec, maxCustomerSpecBytes); err != nil {
		t.Fatal(err)
	}
	spec.SQLTables = []managedmaterial.InitialSQLTable{{
		TableID: "44444444-4444-7444-8444-444444444444", Name: "items",
		KeyColumn: "id", PayloadColumn: "body",
	}}
	for index := range spec.Members {
		spec.Members[index].SQLListenPort = 5432
	}
	wire, err = protocol.EncodeJSON(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.draftPath, wire, 0o600); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(fixture.directory, "sql-material-spec.json")
	if err := signInitialMaterialSpecAt(fixture.args(output,
		fixture.now.Add(time.Hour).Format(time.RFC3339)), fixture.now); err != nil {
		t.Fatalf("sign SQL-enabled initial material spec: %v", err)
	}
	signedWire, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.DecodeStrict(signedWire, &spec, maxCustomerSpecBytes); err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(fixture.signerPublic, managedmaterial.RecipientGrantMessage(spec), spec.Recipient.Signature) {
		t.Fatal("SQL recipient grant signature does not bind the exact table definitions")
	}
	changed := spec
	changed.SQLTables = slices.Clone(spec.SQLTables)
	changed.SQLTables[0].PayloadColumn = "value"
	if bytes.Equal(managedmaterial.RecipientGrantMessage(spec), managedmaterial.RecipientGrantMessage(changed)) {
		t.Fatal("recipient grant message did not bind SQL column definitions")
	}
	if _, err := managedmaterial.GenerateInitial(spec, fixture.signerPublic, fixture.now); err != nil {
		t.Fatalf("SQL-enabled recipient grant was rejected by material producer: %v", err)
	}
	invalid := spec
	invalid.SQLTables = slices.Clone(spec.SQLTables)
	invalid.SQLTables[0].Name = "pg_items"
	invalid.Recipient = managedmaterial.RecipientGrant{}
	invalidWire, err := protocol.EncodeJSON(invalid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.draftPath, invalidWire, 0o600); err != nil {
		t.Fatal(err)
	}
	invalidOutput := filepath.Join(fixture.directory, "invalid-sql-material-spec.json")
	if err := signInitialMaterialSpecAt(fixture.args(invalidOutput,
		fixture.now.Add(time.Hour).Format(time.RFC3339)), fixture.now); err == nil {
		t.Fatal("recipient-grant command signed an invalid SQL table name")
	}
	if _, err := os.Lstat(invalidOutput); !os.IsNotExist(err) {
		t.Fatalf("invalid SQL table request wrote a signed spec: %v", err)
	}
}

func TestSignInitialMaterialSpecRejectsExpirySignerAndKeyProblems(t *testing.T) {
	fixture := newRecipientSpecFixture(t)
	expiry := fixture.now.Add(time.Hour).Format(time.RFC3339)
	test := func(name string, args []string) {
		t.Helper()
		output := filepath.Join(fixture.directory, name+".json")
		args[len(args)-1] = output
		if err := signInitialMaterialSpecAt(args, fixture.now); err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("%s published an output after failure: %v", name, err)
		}
	}
	for _, expiry := range []string{
		fixture.now.Format(time.RFC3339), fixture.now.Add(31 * 24 * time.Hour).Format(time.RFC3339),
		fixture.now.Add(time.Hour).Format("2006-01-02T15:04:05+00:00"),
	} {
		test("bad-expiry-"+strings.ReplaceAll(expiry, ":", "-"), fixture.args("unused", expiry))
	}
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongDER, err := x509.MarshalPKIXPublicKey(wrongPublic)
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(fixture.directory, "wrong-public.pem")
	if err := os.WriteFile(wrongPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wrongDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	args := fixture.args("unused", expiry)
	args[7] = wrongPath
	test("wrong-signer", args)
	if err := os.Chmod(fixture.recipientPath, 0o644); err != nil {
		t.Fatal(err)
	}
	test("loose-recipient", fixture.args("unused", expiry))
	if err := os.Chmod(fixture.recipientPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.signerPath, 0o644); err != nil {
		t.Fatal(err)
	}
	test("loose-signer", fixture.args("unused", expiry))
	if err := os.Chmod(fixture.signerPath, 0o600); err != nil {
		t.Fatal(err)
	}
	linkedPath := filepath.Join(fixture.directory, "recipient-link.pem")
	if err := os.Symlink(fixture.recipientPath, linkedPath); err != nil {
		t.Fatal(err)
	}
	args = fixture.args("unused", expiry)
	args[3] = linkedPath
	test("linked-recipient", args)
}
