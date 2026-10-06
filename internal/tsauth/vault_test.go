package tsauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
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

// withSecrets stores every secret of cell as a base64 bundle.
func (v *fakeVault) withSecrets(cell string, secrets map[string]string) *fakeVault {
	for key, value := range secrets {
		v.bundles[SecretName(cell, key)] = ocisecrets.Base64SecretBundleContentDetails{Content: new(base64.StdEncoding.EncodeToString([]byte(value)))}
	}
	return v
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

func TestEnsureKeepsExistingSecret(t *testing.T) {
	for _, state := range []ocivault.SecretSummaryLifecycleStateEnum{ocivault.SecretSummaryLifecycleStateActive, ocivault.SecretSummaryLifecycleStateCreating} {
		vault := newVault(t)
		id := vault.add(SecretName("gru-1", EnvOperatorKey), state)
		stored, err := Ensure(t.Context(), vault, testTarget, "gru-1", EnvOperatorKey, never(t))
		if err != nil || stored.Created || stored.ID != id || (state == ocivault.SecretSummaryLifecycleStateCreating) != stored.Provisioning || len(vault.creates) != 0 {
			t.Errorf("%s: %+v: %v", state, stored, err)
		}
	}
}

func TestEnsureVaultRecoversCreateConflictByRereading(t *testing.T) {
	vault := newVault(t)
	vault.createErrAfterStore = errors.New("secret name already exists")
	stored, err := Ensure(t.Context(), vault, testTarget, "gru-1", EnvMasterKey, func(context.Context) (string, error) {
		return testSecrets()[EnvMasterKey], nil
	})
	if err != nil || stored.Created || stored.ID == "" || !stored.Provisioning {
		t.Fatalf("conflict result %+v: %v", stored, err)
	}
}

func TestEnsureRefusesUnusableSecret(t *testing.T) {
	name := SecretName("gru-1", EnvMasterKey)
	for state, setup := range map[string]func(*fakeVault){
		"pending deletion": func(v *fakeVault) { v.add(name, ocivault.SecretSummaryLifecycleStatePendingDeletion) },
		"failed":           func(v *fakeVault) { v.add(name, ocivault.SecretSummaryLifecycleStateFailed) },
		"two of one name": func(v *fakeVault) {
			v.add(name, ocivault.SecretSummaryLifecycleStateActive)
			v.add(name, ocivault.SecretSummaryLifecycleStateActive)
		},
		"malformed OCID": func(v *fakeVault) {
			v.items = append(v.items, ocivault.SecretSummary{Id: new("ocid1.key.oc1..x"), SecretName: new(name),
				LifecycleState: ocivault.SecretSummaryLifecycleStateActive})
		},
	} {
		vault := newVault(t)
		setup(vault)
		if _, err := Ensure(t.Context(), vault, testTarget, "gru-1", EnvMasterKey, never(t)); err == nil || len(vault.creates) != 0 {
			t.Errorf("%s: %v, %d creates", state, err, len(vault.creates))
		}
	}
}

func TestEnsureFollowsPages(t *testing.T) {
	vault := newVault(t)
	vault.pageSize = 1
	vault.add("gru-1-other", ocivault.SecretSummaryLifecycleStateActive)
	id := vault.add(SecretName("gru-1", EnvAuditSigningKey), ocivault.SecretSummaryLifecycleStateActive)
	stored, err := Ensure(t.Context(), vault, testTarget, "gru-1", EnvAuditSigningKey, never(t))
	if err != nil || stored.ID != id || len(vault.lists) != 2 || *vault.lists[1].Page != "1" {
		t.Fatalf("stored %+v after %d lists: %v", stored, len(vault.lists), err)
	}
}

func TestEnsureRejectsBeforeCreate(t *testing.T) {
	vault := newVault(t)
	_, err := Ensure(t.Context(), vault, testTarget, "gru-1", EnvMasterKey, func(context.Context) (string, error) { return sentinel, nil })
	if err == nil || len(vault.creates) != 0 || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("invalid value: %v, %d creates", err, len(vault.creates))
	}
	vault.createErr = errors.New("service unavailable")
	value := testSecrets()[EnvMasterKey]
	_, err = Ensure(t.Context(), vault, testTarget, "gru-1", EnvMasterKey, func(context.Context) (string, error) { return value, nil })
	if err == nil || !strings.Contains(err.Error(), "gru-1-ts-auth-master-key") || strings.Contains(err.Error(), value) {
		t.Fatalf("create error: %v", err)
	}
}

func TestGenerate(t *testing.T) {
	first, err := Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := base64.StdEncoding.DecodeString(first); err != nil || len(decoded) != 32 || first == second {
		t.Fatalf("generated %d bytes, distinct %v: %v", len(decoded), first != second, err)
	}
}

func TestReadBackDoesNotRetryPermanentVaultErrors(t *testing.T) {
	client := &readErrorBundle{err: errors.New("authorization denied")}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := readBack(ctx, client, testTarget.VaultID, "gru-1", EnvMasterKey, false); err == nil {
		t.Fatal("permanent read error was accepted")
	}
	if client.calls != 1 {
		t.Fatalf("permanent read error retried %d times", client.calls)
	}
}

type readErrorBundle struct {
	err   error
	calls int
}

func (c *readErrorBundle) GetSecretBundleByName(context.Context, ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error) {
	c.calls++
	return ocisecrets.GetSecretBundleByNameResponse{}, c.err
}

func TestSecretNames(t *testing.T) {
	var names []string
	for _, key := range Secrets {
		names = append(names, SecretName("gru-1", key))
	}
	if got := fmt.Sprint(names); got != "[gru-1-ts-auth-master-key gru-1-ts-auth-audit-signing-key gru-1-ts-auth-operator-key "+
		"gru-1-ts-auth-dashboard-client-secret gru-1-ts-auth-terrascale-api-key gru-1-ts-auth-terrascale-project-id]" {
		t.Fatal(got)
	}
}
