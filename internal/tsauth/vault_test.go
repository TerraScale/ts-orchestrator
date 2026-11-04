package tsauth

import (
	"context"
	"encoding/base64"
	"errors"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
	"strconv"
	"testing"
)

var testTarget = Target{CompartmentID: "ocid1.compartment.oc1..control", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.vault",
	KeyID: "ocid1.key.oc1.sa-saopaulo-1.key"}

// fakeVault keeps secrets in memory. ListSecrets ignores the name filter so
// that a test controls which page holds a match.
type fakeVault struct {
	t                   *testing.T
	items               []ocivault.SecretSummary
	pageSize            int
	bundles             map[string]ocisecrets.SecretBundleContentDetails
	createErr           error
	createErrAfterStore error
	lists               []ocivault.ListSecretsRequest
	creates             []ocivault.CreateSecretRequest
	reads               []ocisecrets.GetSecretBundleByNameRequest
}

func newVault(t *testing.T) *fakeVault {
	return &fakeVault{t: t, bundles: map[string]ocisecrets.SecretBundleContentDetails{}}
}

func (v *fakeVault) add(name string, state ocivault.SecretSummaryLifecycleStateEnum) string {
	id := "ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaa" + strconv.Itoa(len(v.items)+1)
	v.items = append(v.items, ocivault.SecretSummary{Id: new(id), SecretName: new(name), LifecycleState: state})
	return id
}

func (v *fakeVault) ListSecrets(_ context.Context, request ocivault.ListSecretsRequest) (ocivault.ListSecretsResponse, error) {
	v.lists = append(v.lists, request)
	start := 0
	if request.Page != nil {
		start, _ = strconv.Atoi(*request.Page)
	}
	end := len(v.items)
	if v.pageSize > 0 && start+v.pageSize < end {
		end = start + v.pageSize
	}
	response := ocivault.ListSecretsResponse{Items: v.items[start:end]}
	if end < len(v.items) {
		response.OpcNextPage = new(strconv.Itoa(end))
	}
	return response, nil
}

func (v *fakeVault) CreateSecret(_ context.Context, request ocivault.CreateSecretRequest) (ocivault.CreateSecretResponse, error) {
	v.creates = append(v.creates, request)
	if v.createErr != nil {
		return ocivault.CreateSecretResponse{}, v.createErr
	}
	details := request.CreateSecretDetails
	content, ok := details.SecretContent.(ocivault.Base64SecretContentDetails)
	if !ok || details.SecretName == nil || content.Content == nil {
		v.t.Errorf("create request %+v", details)
		return ocivault.CreateSecretResponse{}, errors.New("bad request")
	}
	id := v.add(*details.SecretName, ocivault.SecretSummaryLifecycleStateCreating)
	v.bundles[*details.SecretName] = ocisecrets.Base64SecretBundleContentDetails{Content: content.Content}
	if v.createErrAfterStore != nil {
		return ocivault.CreateSecretResponse{}, v.createErrAfterStore
	}
	return ocivault.CreateSecretResponse{Secret: ocivault.Secret{Id: new(id)}}, nil
}

func (v *fakeVault) GetSecretBundleByName(_ context.Context, request ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error) {
	v.reads = append(v.reads, request)
	content, ok := v.bundles[*request.SecretName]
	if !ok {
		return ocisecrets.GetSecretBundleByNameResponse{}, errors.New("secret not found")
	}
	return ocisecrets.GetSecretBundleByNameResponse{SecretBundle: ocisecrets.SecretBundle{SecretBundleContent: content}}, nil
}

// stored decodes the bundle of name.
func (v *fakeVault) stored(name string) string {
	bundle, _ := v.bundles[name].(ocisecrets.Base64SecretBundleContentDetails)
	if bundle.Content == nil {
		v.t.Fatalf("no secret %s", name)
	}
	value, err := base64.StdEncoding.DecodeString(*bundle.Content)
	if err != nil {
		v.t.Fatal(err)
	}
	return string(value)
}

func never(t *testing.T) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		t.Fatal("value requested for an existing secret")
		return "", nil
	}
}

func TestEnsureCreatesOnce(t *testing.T) {
	vault := newVault(t)
	value := testSecrets()[EnvMasterKey]
	stored, err := Ensure(t.Context(), vault, testTarget, "gru-1", EnvMasterKey, func(context.Context) (string, error) { return value, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(vault.creates) != 1 {
		t.Fatalf("%d creates", len(vault.creates))
	}
	request := vault.creates[0]
	details := request.CreateSecretDetails
	name := SecretName("gru-1", EnvMasterKey)
	if name != "gru-1-ts-auth-master-key" || *details.SecretName != name || *details.CompartmentId != testTarget.CompartmentID ||
		*details.VaultId != testTarget.VaultID || *details.KeyId != testTarget.KeyID {
		t.Fatalf("create %+v", details)
	}
	if content := details.SecretContent.(ocivault.Base64SecretContentDetails); content.Stage != ocivault.SecretContentDetailsStageCurrent {
		t.Fatalf("stage %s", content.Stage)
	}
	if vault.stored(name) != value {
		t.Fatal("stored content differs")
	}
	if request.OpcRetryToken == nil || *request.OpcRetryToken == "" {
		t.Fatal("create without retry token")
	}
	if !stored.Created || stored.ID != "ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaa1" || stored.Secret != name || stored.Key != EnvMasterKey {
		t.Fatalf("stored %+v", stored)
	}
	if lookup := vault.lists[0]; *lookup.Name != name || *lookup.VaultId != testTarget.VaultID || *lookup.CompartmentId != testTarget.CompartmentID {
		t.Fatalf("list %+v", lookup)
	}
	again, err := Ensure(t.Context(), vault, testTarget, "gru-1", EnvMasterKey, never(t))
	if err != nil || again.Created || again.ID != stored.ID || len(vault.creates) != 1 {
		t.Fatalf("rerun %+v: %v", again, err)
	}
}

func TestEnsureRefusesUnusableSecret(t *testing.T) {
	vault := newVault(t)
	vault.add(SecretName("gru-1", EnvMasterKey), ocivault.SecretSummaryLifecycleStatePendingDeletion)
	if _, err := Ensure(t.Context(), vault, testTarget, "gru-1", EnvMasterKey, never(t)); err == nil || len(vault.creates) != 0 {
		t.Fatalf("unusable secret: %v, %d creates", err, len(vault.creates))
	}
}
