package bootstrapmaterial

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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

func makeSource(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "material")
	if _, err := Generate(directory, testConfig(), time.Now().UTC().Truncate(time.Second)); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestProvisionExactReadbackAndStableReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("heavy provisioning, recovery or multi-node integration runs in Slow")
	}
	directory := makeSource(t)
	target := testTarget()
	fake := newFakeVault(target)
	first, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.References) != 30 || fake.create != 30 {
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
	if err != nil || len(second.References) != 30 || fake.create != 30 {
		t.Fatalf("replay references=%d creates=%d err=%v", len(second.References), fake.create, err)
	}
}

func TestProvisionRecoversUncertainCreateOnlyAfterExactReadback(t *testing.T) {
	if testing.Short() {
		t.Skip("heavy provisioning, recovery or multi-node integration runs in Slow")
	}
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
	if _, err := Provision(t.Context(), directory, target, fake, fake, time.Now().UTC()); err != nil || fake.create != 30 {
		t.Fatalf("exact recovery failed: creates=%d err=%v", fake.create, err)
	}
}
