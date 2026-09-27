package bootstrapmaterial

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

type fakeSecret struct {
	id, name, content string
}

type fakeVault struct {
	target          VaultTarget
	byName          map[string]fakeSecret
	byID            map[string]fakeSecret
	create          int
	uncertain       bool
	failBeforeStore bool
	wrongBytes      bool
	duplicate       bool
	tokens          []string
}

func newFakeVault(target VaultTarget) *fakeVault {
	return &fakeVault{target: target, byName: make(map[string]fakeSecret), byID: make(map[string]fakeSecret)}
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
	item := fakeSecret{id: fmt.Sprintf("ocid1.secret.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.a%d", fake.create), name: *request.SecretName, content: *content.Content}
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
	if err := target.Validate(); err != nil {
		t.Fatalf("actual GRU Vault OCID shape rejected: %v", err)
	}
	for _, wrong := range []VaultTarget{
		{CompartmentOCID: target.CompartmentOCID, VaultOCID: "ocid1.key.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.aaaakey", KMSKeyOCID: target.KMSKeyOCID},
		{CompartmentOCID: target.CompartmentOCID, VaultOCID: "ocid1.vault.oc1.eu-frankfurt-1.ffvlrlvkaaaw6.aaaavault", KMSKeyOCID: target.KMSKeyOCID},
		{CompartmentOCID: target.CompartmentOCID, VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.ffvlrlvkaaaw6..aaaavault", KMSKeyOCID: target.KMSKeyOCID},
		{CompartmentOCID: target.CompartmentOCID, VaultOCID: target.VaultOCID, KMSKeyOCID: "ocid1.secret.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.aaaasecret"},
	} {
		if err := wrong.Validate(); err == nil {
			t.Fatalf("wrong resource or region accepted: %+v", wrong)
		}
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
	if len(first.References) != 25 || fake.create != 25 {
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
	if err != nil || len(second.References) != 25 || fake.create != 25 {
		t.Fatalf("replay references=%d creates=%d err=%v", len(second.References), fake.create, err)
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
	if _, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC()); err != nil || fake.create != 25 {
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
	// The failed first create is retried, then all 25 secrets are published.
	if fake.create != 26 || len(fake.tokens) != 26 || fake.tokens[0] != fake.tokens[1] {
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
