package managedmaterial

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestPreseededSelfConsistentMaterialCannotGainR3Authority(t *testing.T) {
	service, spec, objects, receipts := preparationFixture(t)
	now := time.Now().UTC()
	bundle, err := GenerateInitial(spec, service.RecipientSigner, now)
	if err != nil {
		t.Fatal(err)
	}
	// A first writer can mint its own valid authority and TLS material and
	// encrypt an attacker-known token to the real customer's recipient key.
	// Structural checks alone accepted this bundle before the provisioning seal.
	id := bytes.Repeat([]byte{0x11}, 16)
	secret := bytes.Repeat([]byte{0x22}, 32)
	tokenID := base64.RawURLEncoding.EncodeToString(id)
	token := "tbk1." + tokenID + "." + base64.RawURLEncoding.EncodeToString(secret)
	message := append([]byte("TB-APIKEY-V1\x00"), id...)
	message = append(message, secret...)
	verifier := sha256.Sum256(message)
	verifierHex := hex.EncodeToString(verifier[:])
	for index := range bundle.Members {
		files := bundle.Members[index].Files
		var registry apiKeyRegistry
		if err := json.Unmarshal(files["client-api-keys.json"].Contents, &registry, json.RejectUnknownMembers(true)); err != nil {
			t.Fatal(err)
		}
		registry.Keys[0].ID = tokenID
		registry.Keys[0].VerifierSHA256 = verifierHex
		wire, err := json.Marshal(registry)
		if err != nil {
			t.Fatal(err)
		}
		files["client-api-keys.json"] = makeFile(wire)
		var manifest struct {
			Version                uint64 `json:"version"`
			ClientConfigSHA256     string `json:"client_config_sha256"`
			CertificateChainSHA256 string `json:"certificate_chain_sha256"`
			PrivateKeySHA256       string `json:"private_key_sha256"`
			APIKeyRegistrySHA256   string `json:"api_key_registry_sha256"`
		}
		if err := json.Unmarshal(files["client-managed-manifest.json"].Contents, &manifest, json.RejectUnknownMembers(true)); err != nil {
			t.Fatal(err)
		}
		manifest.APIKeyRegistrySHA256 = files["client-api-keys.json"].SHA256
		wire, err = json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		files["client-managed-manifest.json"] = makeFile(wire)
	}
	_, caPEM := pem.Decode(bundle.Members[0].Files["client-chain.pem"].Contents)
	bundle.Customer, err = encryptCustomerToken(spec, token, verifierHex, caPEM)
	if err != nil || validateBundleForSpec(spec, bundle) != nil {
		t.Fatalf("attacker bundle is not self-consistent: %v", err)
	}
	specSHA, err := specDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	name, err := service.Repository.objectName(spec.PlacementDatabaseID, spec.PartitionID, 1, specSHA)
	if err != nil {
		t.Fatal(err)
	}
	stored := storedBundle{Version: 2, Region: string(service.Repository.config.Region),
		Cell: service.Cell, ObjectName: name, Generation: 1, SpecSHA256: specSHA, Spec: spec, Bundle: bundle}
	_, attackerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input, err := stored.provisioningInput()
	if err != nil {
		t.Fatal(err)
	}
	stored.ProvisioningSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(attackerKey, input))
	objects.body, err = protocol.EncodeJSON(stored)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(objects.body)
	objects.bodySHA = hex.EncodeToString(digest[:])
	objects.name, objects.namespace, objects.bucket = name, service.Repository.config.Namespace, service.Repository.config.Bucket
	objects.version, objects.etag = "attacker-version", `"attacker-etag"`
	if _, err := service.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, now); !errors.Is(err, ErrMaterialConflict) {
		t.Fatalf("attacker's first-writer object was adopted: %v", err)
	}
	if receipts.entry != nil || receipts.commitCount != 0 || objects.putCount != 0 {
		t.Fatal("untrusted object obtained a receipt or a second create was attempted")
	}
	if _, err := service.Repository.ReadPinned(t.Context(), ObjectReference{Name: name,
		VersionID: objects.version, ETag: objects.etag, SHA256: objects.bodySHA, SpecSHA256: specSHA},
		service.ControllerKey.Public().(ed25519.PublicKey)); !errors.Is(err, ErrMaterialConflict) {
		t.Fatalf("direct pinned read accepted attacker object: %v", err)
	}
}

func TestProvisioningRejectsRegistryEnvelopeSubstitution(t *testing.T) {
	service, spec, _, _ := preparationFixture(t)
	bundle, err := GenerateInitial(spec, service.RecipientSigner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	changed := bundle
	changed.Members[0].Files = make(map[string]File, len(bundle.Members[0].Files))
	for name, file := range bundle.Members[0].Files {
		changed.Members[0].Files[name] = file
	}
	var registry apiKeyRegistry
	if err := json.Unmarshal(changed.Members[0].Files["client-api-keys.json"].Contents, &registry); err != nil {
		t.Fatal(err)
	}
	registry.Keys[0].VerifierSHA256 = hex.EncodeToString(bytes.Repeat([]byte{0xee}, 32))
	wire, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	changed.Members[0].Files["client-api-keys.json"] = makeFile(wire)
	if err := validateBundleForSpec(spec, changed); !errors.Is(err, ErrMaterialConflict) {
		t.Fatalf("registry verifier differs from recipient commitment: %v", err)
	}
	changed = bundle
	changed.Customer.HTTPSCASHA256 = hex.EncodeToString(bytes.Repeat([]byte{0xee}, 32))
	if err := validateBundleForSpec(spec, changed); !errors.Is(err, ErrMaterialConflict) {
		t.Fatalf("customer HTTPS CA differs from host chain: %v", err)
	}
}
