package bootstrapmaterial

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Material publication admits exactly the region catalog, so a new catalog
// cell needs no edit here and an uncataloged region stays rejected.
func TestMaterialRegionsFollowTheRegionCatalog(t *testing.T) {
	for _, entry := range catalog.Entries() {
		if !supportedMaterialRegion(entry.OCIRegion) {
			t.Fatalf("catalog region %s rejected", entry.OCIRegion)
		}
	}
	for _, region := range []string{"", "xx-nowhere-1", "SA-SAOPAULO-1", "GRU"} {
		if supportedMaterialRegion(region) {
			t.Fatalf("uncataloged region %q admitted", region)
		}
	}
}

type fakeSecret struct {
	id, name, content string
}

type fakeVault struct {
	target          VaultTarget
	region          string
	byName          map[string]fakeSecret
	byID            map[string]fakeSecret
	create          int
	uncertain       bool
	failBeforeStore bool
	wrongBytes      bool
	wrongSecretKind bool
	duplicate       bool
	tokens          []string
}

func newFakeVault(target VaultTarget) *fakeVault {
	return &fakeVault{target: target, region: strings.Split(target.VaultOCID, ".")[3],
		byName: make(map[string]fakeSecret), byID: make(map[string]fakeSecret)}
}

func (fake *fakeVault) ListSecrets(_ context.Context, request ocivault.ListSecretsRequest) (ocivault.ListSecretsResponse, error) {
	if request.CompartmentId == nil || *request.CompartmentId != fake.target.CompartmentOCID || request.VaultId == nil ||
		*request.VaultId != fake.target.VaultOCID || request.Name == nil {
		return ocivault.ListSecretsResponse{}, errors.New("wrong target")
	}
	if item, ok := fake.byName[*request.Name]; ok {
		items := []ocivault.SecretSummary{{Id: new(item.id), SecretName: new(item.name),
			CompartmentId: new(fake.target.CompartmentOCID), VaultId: new(fake.target.VaultOCID),
			LifecycleState: ocivault.SecretSummaryLifecycleStateActive}}
		if fake.duplicate {
			items = append(items, items[0])
		}
		return ocivault.ListSecretsResponse{Items: items}, nil
	}
	return ocivault.ListSecretsResponse{}, nil
}

func (fake *fakeVault) CreateSecret(_ context.Context, request ocivault.CreateSecretRequest) (ocivault.CreateSecretResponse, error) {
	if request.SecretName == nil || request.OpcRetryToken == nil || request.CompartmentId == nil ||
		*request.CompartmentId != fake.target.CompartmentOCID || request.VaultId == nil ||
		*request.VaultId != fake.target.VaultOCID || request.KeyId == nil || *request.KeyId != fake.target.KMSKeyOCID {
		return ocivault.CreateSecretResponse{}, errors.New("wrong create target")
	}
	content, ok := request.SecretContent.(ocivault.Base64SecretContentDetails)
	if !ok || content.Content == nil {
		return ocivault.CreateSecretResponse{}, errors.New("wrong content type")
	}
	fake.create++
	fake.tokens = append(fake.tokens, *request.OpcRetryToken)
	if fake.failBeforeStore {
		fake.failBeforeStore = false
		return ocivault.CreateSecretResponse{}, errors.New("create outcome unknown")
	}
	kind := "vaultsecret"
	if fake.wrongSecretKind {
		kind = "secret"
	}
	item := fakeSecret{id: fmt.Sprintf("ocid1.%s.oc1.%s.ffvlrlvkaaaw6.a%d", kind, fake.region, fake.create), name: *request.SecretName, content: *content.Content}
	fake.byName[item.name], fake.byID[item.id] = item, item
	if fake.uncertain {
		fake.uncertain = false
		return ocivault.CreateSecretResponse{}, errors.New("uncertain transport")
	}
	return ocivault.CreateSecretResponse{Secret: ocivault.Secret{Id: new(item.id)}}, nil
}

func (fake *fakeVault) GetSecret(_ context.Context, request ocivault.GetSecretRequest) (ocivault.GetSecretResponse, error) {
	if request.SecretId == nil {
		return ocivault.GetSecretResponse{}, errors.New("missing id")
	}
	item, ok := fake.byID[*request.SecretId]
	if !ok {
		return ocivault.GetSecretResponse{}, errors.New("missing secret")
	}
	return ocivault.GetSecretResponse{Secret: ocivault.Secret{Id: new(item.id), SecretName: new(item.name),
		CompartmentId: new(fake.target.CompartmentOCID), VaultId: new(fake.target.VaultOCID),
		KeyId: new(fake.target.KMSKeyOCID), LifecycleState: ocivault.SecretLifecycleStateActive,
		CurrentVersionNumber: new(int64(1))}}, nil
}

func (fake *fakeVault) GetSecretBundle(_ context.Context, request ocisecrets.GetSecretBundleRequest) (ocisecrets.GetSecretBundleResponse, error) {
	if request.SecretId == nil || request.VersionNumber == nil || *request.VersionNumber != 1 {
		return ocisecrets.GetSecretBundleResponse{}, errors.New("not exact version one")
	}
	item, ok := fake.byID[*request.SecretId]
	if !ok {
		return ocisecrets.GetSecretBundleResponse{}, errors.New("missing bundle")
	}
	if fake.wrongBytes {
		item.content = base64.StdEncoding.EncodeToString([]byte("wrong"))
	}
	return ocisecrets.GetSecretBundleResponse{SecretBundle: ocisecrets.SecretBundle{SecretId: new(item.id),
		VersionNumber: new(int64(1)), SecretBundleContent: ocisecrets.Base64SecretBundleContentDetails{Content: new(item.content)}}}, nil
}

func testTarget() VaultTarget {
	return VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..aaaaaa", VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.aaaaaa",
		KMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.aaaaaa"}
}

func TestVaultTargetAcceptsActualMultisegmentOCID(t *testing.T) {
	target := testTarget()
	target.VaultOCID = "ocid1.vault.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.abtxeljrrjahmb7sqvwq2hlh3sa75a6qbrp44mcdg4kuof7vcyr2it3qs5oq"
	target.KMSKeyOCID = "ocid1.key.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.aaaakey"
	if err := target.Validate("sa-saopaulo-1"); err != nil {
		t.Fatalf("actual GRU Vault OCID shape rejected: %v", err)
	}
	for _, wrong := range []VaultTarget{
		{CompartmentOCID: target.CompartmentOCID, VaultOCID: "ocid1.key.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.aaaakey", KMSKeyOCID: target.KMSKeyOCID},
		{CompartmentOCID: target.CompartmentOCID, VaultOCID: "ocid1.vault.oc1.eu-frankfurt-1.ffvlrlvkaaaw6.aaaavault", KMSKeyOCID: target.KMSKeyOCID},
		{CompartmentOCID: target.CompartmentOCID, VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.ffvlrlvkaaaw6..aaaavault", KMSKeyOCID: target.KMSKeyOCID},
		{CompartmentOCID: target.CompartmentOCID, VaultOCID: target.VaultOCID, KMSKeyOCID: "ocid1.secret.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.aaaasecret"},
	} {
		if err := wrong.Validate("sa-saopaulo-1"); err == nil {
			t.Fatalf("wrong resource or region accepted: %+v", wrong)
		}
	}
}

func TestMappedRegionalVaultPublicationAndCrossRegionRejection(t *testing.T) {
	for _, test := range []struct{ cell, region string }{
		{"sfo", "us-sanjose-1"}, {"fra", "eu-frankfurt-1"},
	} {
		t.Run(test.cell, func(t *testing.T) {
			cfg := testConfig()
			cfg.Cell, cfg.Region = test.cell, test.region
			directory := filepath.Join(t.TempDir(), "material")
			if _, err := Generate(directory, cfg, time.Now().UTC().Truncate(time.Second)); err != nil {
				t.Fatal(err)
			}
			target := VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..aaaaaa",
				VaultOCID:  "ocid1.vault.oc1." + test.region + ".aaaaaa",
				KMSKeyOCID: "ocid1.key.oc1." + test.region + ".aaaaaa"}
			if err := target.Validate(test.region); err != nil {
				t.Fatalf("mapped Vault target rejected: %v", err)
			}
			if err := target.Validate("sa-saopaulo-1"); err == nil {
				t.Fatal("Vault target accepted for another OCI region")
			}
			fake := newFakeVault(target)
			if _, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC()); err != nil {
				t.Fatalf("regional material could not be published: %v", err)
			}
			if fake.create != 27 {
				t.Fatalf("regional publication created %d secrets", fake.create)
			}
			wrong := target
			wrong.KMSKeyOCID = "ocid1.key.oc1.sa-saopaulo-1.aaaaaa"
			if _, err := Provision(t.Context(), directory, wrong, fake, fake, time.Now().UTC()); err == nil {
				t.Fatal("cross-region KMS key accepted")
			}
		})
	}
}

func makeSource(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "material")
	if _, err := Generate(directory, testConfig(), time.Now().UTC().Truncate(time.Second)); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestProvisionExactReadbackAndStableReplay(t *testing.T) {
	directory := makeSource(t)
	target := testTarget()
	fake := newFakeVault(target)
	first, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.References) != 27 || fake.create != 27 {
		t.Fatalf("references=%d creates=%d", len(first.References), fake.create)
	}
	for _, reference := range first.References {
		if reference.Reference.Purpose == "owner-only" ||
			reference.Reference.TargetFile == "operator.creds" ||
			reference.Reference.TargetFile == "operator-tls-cert.pem" ||
			reference.Reference.TargetFile == "operator-tls-key.pem" {
			t.Fatalf("offline operator credential was published: %s", reference.Reference.TargetFile)
		}
	}
	second, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC())
	if err != nil || len(second.References) != 27 || fake.create != 27 {
		t.Fatalf("replay references=%d creates=%d err=%v", len(second.References), fake.create, err)
	}
}

func TestProvisionRequiresVaultSecretOCIDKind(t *testing.T) {
	directory := makeSource(t)
	target := testTarget()
	fake := newFakeVault(target)
	fake.wrongSecretKind = true
	if _, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC()); !errors.Is(err, ErrProvision) {
		t.Fatalf("wrong OCI resource kind error = %v", err)
	}
}

func TestProvisionRejectsWrongSecretKindInJournal(t *testing.T) {
	directory := makeSource(t)
	target := testTarget()
	fake := newFakeVault(target)
	if _, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(directory, journalName)
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wrongKind := strings.Replace(string(wire), "ocid1.vaultsecret.oc1.", "ocid1.secret.oc1.", 1)
	if wrongKind == string(wire) {
		t.Fatal("published journal did not contain a Vault secret OCID")
	}
	if err := os.WriteFile(path, []byte(wrongKind), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC()); !errors.Is(err, ErrProvision) {
		t.Fatalf("wrong-kind journal secret error = %v", err)
	}
}

func TestRegionalSecretOCIDRequiresVaultSecretKind(t *testing.T) {
	valid := "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if !regionalResourceOCID(valid, "vaultsecret", "sa-saopaulo-1") {
		t.Fatal("canonical synthetic Vault secret OCID was rejected")
	}
	if regionalResourceOCID("ocid1.secret.oc1.sa-saopaulo-1.synthetic", "vaultsecret", "sa-saopaulo-1") {
		t.Fatal("wrong OCI resource kind was accepted as a Vault secret")
	}
}

func TestProvisionRecoversUncertainCreateOnlyAfterExactReadback(t *testing.T) {
	directory := makeSource(t)
	target := testTarget()
	fake := newFakeVault(target)
	fake.uncertain = true
	if _, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC()); err == nil || fake.create != 1 {
		t.Fatalf("uncertain first create: creates=%d err=%v", fake.create, err)
	}
	fake.wrongBytes = true
	if _, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC()); err == nil || fake.create != 1 {
		t.Fatalf("wrong readback accepted or new create issued: creates=%d err=%v", fake.create, err)
	}
	fake.wrongBytes = false
	if _, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC()); err != nil || fake.create != 27 {
		t.Fatalf("exact recovery failed: creates=%d err=%v", fake.create, err)
	}
}

func TestProvisionExpiredRetryWindowHolds(t *testing.T) {
	directory := makeSource(t)
	target := testTarget()
	fake := newFakeVault(target)
	fake.uncertain = true
	now := time.Now().UTC()
	if _, err := Provision(t.Context(), directory, target, fake, fake, now); err == nil {
		t.Fatal("uncertain create unexpectedly succeeded")
	}
	// Simulate OCI listing lag beyond the retry-token validity boundary.
	clear(fake.byName)
	clear(fake.byID)
	if _, err := Provision(t.Context(), directory, target, fake, fake, now.Add(23*time.Hour)); err == nil || fake.create != 1 {
		t.Fatalf("expired retry token reused: creates=%d err=%v", fake.create, err)
	}
	if _, err := os.Stat(filepath.Join(directory, journalName)); err != nil {
		t.Fatal(err)
	}
}

func TestProvisionRetriesUnknownCreateWithSameToken(t *testing.T) {
	directory := makeSource(t)
	target := testTarget()
	fake := newFakeVault(target)
	fake.failBeforeStore = true
	now := time.Now().UTC()
	if _, err := Provision(t.Context(), directory, target, fake, fake, now); err == nil || fake.create != 1 {
		t.Fatalf("first uncertain request: creates=%d err=%v", fake.create, err)
	}
	if _, err := Provision(t.Context(), directory, target, fake, fake, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// The failed first create is retried, then all 27 secrets are published.
	if fake.create != 28 || len(fake.tokens) != 28 || fake.tokens[0] != fake.tokens[1] {
		t.Fatalf("retry did not retain token: creates=%d tokens=%v", fake.create, fake.tokens[:2])
	}
}

func TestProvisionRejectsDuplicateSecretAndWrongTarget(t *testing.T) {
	directory := makeSource(t)
	target := testTarget()
	fake := newFakeVault(target)
	fake.uncertain = true
	if _, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC()); err == nil {
		t.Fatal("uncertain create succeeded")
	}
	fake.duplicate = true
	if _, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC()); err == nil || fake.create != 1 {
		t.Fatalf("duplicate secret accepted: creates=%d err=%v", fake.create, err)
	}
	wrong := target
	wrong.VaultOCID = "ocid1.vault.oc1.sa-saopaulo-1.bbbbbb"
	if _, err := Provision(t.Context(), directory, wrong, fake, fake, time.Now().UTC()); err == nil {
		t.Fatal("journal was retargeted to another Vault")
	}
}
