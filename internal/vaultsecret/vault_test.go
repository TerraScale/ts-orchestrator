package vaultsecret

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

var testTarget = Target{CompartmentID: "ocid1.compartment.oc1..operator", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.vault",
	KeyID: "ocid1.key.oc1.sa-saopaulo-1.key"}

// sentinel must never reach an error or output.
const sentinel = "-----BEGIN PRIVATE KEY-----sentinel"

// fakeVault keeps secrets in memory.
type fakeVault struct {
	items   []ocivault.SecretSummary
	bundles map[string]ocisecrets.SecretBundleContentDetails
	creates []ocivault.CreateSecretRequest
	reads   []ocisecrets.GetSecretBundleByNameRequest
}

func newVault() *fakeVault {
	return &fakeVault{bundles: map[string]ocisecrets.SecretBundleContentDetails{}}
}

func (v *fakeVault) store(name, value string) {
	v.items = append(v.items, ocivault.SecretSummary{Id: new("ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaa" + strconv.Itoa(len(v.items)+1)),
		SecretName: new(name), LifecycleState: ocivault.SecretSummaryLifecycleStateActive})
	v.bundles[name] = ocisecrets.Base64SecretBundleContentDetails{Content: new(base64.StdEncoding.EncodeToString([]byte(value)))}
}

func (v *fakeVault) ListSecrets(_ context.Context, request ocivault.ListSecretsRequest) (ocivault.ListSecretsResponse, error) {
	return ocivault.ListSecretsResponse{Items: v.items}, nil
}

func (v *fakeVault) CreateSecret(_ context.Context, request ocivault.CreateSecretRequest) (ocivault.CreateSecretResponse, error) {
	v.creates = append(v.creates, request)
	details := request.CreateSecretDetails
	content := details.SecretContent.(ocivault.Base64SecretContentDetails)
	value, _ := base64.StdEncoding.DecodeString(*content.Content)
	v.store(*details.SecretName, string(value))
	return ocivault.CreateSecretResponse{Secret: ocivault.Secret{Id: v.items[len(v.items)-1].Id}}, nil
}

func (v *fakeVault) GetSecretBundleByName(_ context.Context, request ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error) {
	v.reads = append(v.reads, request)
	content, ok := v.bundles[*request.SecretName]
	if !ok {
		return ocisecrets.GetSecretBundleByNameResponse{}, errors.New("secret not found")
	}
	return ocisecrets.GetSecretBundleByNameResponse{SecretBundle: ocisecrets.SecretBundle{SecretBundleContent: content}}, nil
}

func TestPutStoresOnceAndProvesTheCopy(t *testing.T) {
	vault := newVault()
	value := []byte(sentinel + "\n")
	stored, err := Put(t.Context(), vault, vault, testTarget, "gru-1-trust-root-private-key", value)
	if err != nil || !stored.Created || stored.Secret != "gru-1-trust-root-private-key" || len(vault.creates) != 1 {
		t.Fatalf("put %+v after %d creates: %v", stored, len(vault.creates), err)
	}
	details := vault.creates[0].CreateSecretDetails
	if *details.CompartmentId != testTarget.CompartmentID || *details.VaultId != testTarget.VaultID || *details.KeyId != testTarget.KeyID ||
		vault.creates[0].OpcRetryToken == nil || strings.Contains(*details.Description, sentinel) {
		t.Fatalf("create %+v", details)
	}
	// A rerun creates nothing and reads the stored copy back byte for byte.
	again, err := Put(t.Context(), vault, vault, testTarget, "gru-1-trust-root-private-key", value)
	if err != nil || again.Created || again.ID != stored.ID || len(vault.creates) != 1 || len(vault.reads) != 2 {
		t.Fatalf("rerun %+v after %d creates, %d reads: %v", again, len(vault.creates), len(vault.reads), err)
	}
	if *vault.reads[1].VaultId != testTarget.VaultID || vault.reads[1].Stage != ocisecrets.GetSecretBundleByNameStageCurrent {
		t.Fatalf("read %+v", vault.reads[1])
	}
}

func TestPutRefusesWithoutLeakingTheValue(t *testing.T) {
	vault := newVault()
	vault.store("gru-1-netbird-owner-password", "older "+sentinel)
	for name, test := range map[string]struct {
		secret string
		value  []byte
	}{
		"differs":    {"gru-1-netbird-owner-password", []byte(sentinel)},
		"bad name":   {"gru-1/netbird/key", []byte(sentinel)},
		"upper case": {"GRU-1-NETBIRD", []byte(sentinel)},
		"no service": {"gru-1", []byte(sentinel)},
		"empty":      {"gru-1-netbird-empty", nil},
		"too large":  {"gru-1-netbird-large", bytes.Repeat([]byte(sentinel), maxValue)},
	} {
		if _, err := Put(t.Context(), vault, vault, testTarget, test.secret, test.value); err == nil || strings.Contains(err.Error(), "sentinel") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(vault.creates) != 0 {
		t.Fatalf("%d creates", len(vault.creates))
	}
}

func TestWriteFileReplacesOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := writeMemoryFile(root, filepath.Base(path), []byte("new")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if data, _ := os.ReadFile(path); err != nil || info.Mode().Perm() != 0o600 || string(data) != "new" {
		t.Fatalf("mode %v, content %q: %v", info.Mode(), data, err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("left %d files", len(entries))
	}
}

// TestResolveReadsCurrentValuesWithoutLeaking reads each ref from its Vault's
// region and names the secret, never a value, when a read or value fails.
func TestResolveReadsCurrentValuesWithoutLeaking(t *testing.T) {
	vault := newVault()
	vault.store("gru-1-ts-auth-master-key", sentinel)
	vault.store("gru-1-ts-auth-operator-key", "op")
	refs := map[string]Ref{"MASTER": {Vault: testTarget.VaultID, Name: "gru-1-ts-auth-master-key"},
		"OPERATOR": {Vault: testTarget.VaultID, Name: "gru-1-ts-auth-operator-key"}}
	var regions []string
	client := func(region string) (BundleClient, error) {
		regions = append(regions, region)
		return vault, nil
	}
	values, err := Resolve(t.Context(), refs, client)
	if err != nil || values["MASTER"] != sentinel || values["OPERATOR"] != "op" || len(values) != 2 {
		t.Fatalf("resolved %d values: %v", len(values), err)
	}
	if fmt.Sprint(regions) != "[sa-saopaulo-1 sa-saopaulo-1]" {
		t.Fatalf("regions %v", regions)
	}
	for _, request := range vault.reads {
		if *request.VaultId != testTarget.VaultID || request.Stage != ocisecrets.GetSecretBundleByNameStageCurrent {
			t.Fatalf("request %+v", request)
		}
	}
	vault.store("gru-1-ts-auth-nul", "a\x00"+sentinel)
	vault.store("gru-1-ts-auth-large", strings.Repeat("k", maxValue+1))
	many := map[string]Ref{}
	for i := range 7 {
		name := "gru-1-ts-auth-big-" + strconv.Itoa(i)
		vault.store(name, strings.Repeat("k", maxValue))
		many["BIG_"+strconv.Itoa(i)] = Ref{Vault: testTarget.VaultID, Name: name}
	}
	for name, refs := range map[string]map[string]Ref{
		"missing": {"K": {Vault: testTarget.VaultID, Name: "gru-1-ts-auth-missing"}},
		"nul":     {"K": {Vault: testTarget.VaultID, Name: "gru-1-ts-auth-nul"}},
		"large":   {"K": {Vault: testTarget.VaultID, Name: "gru-1-ts-auth-large"}},
		"vault":   {"K": {Vault: "vault", Name: "gru-1-ts-auth-master-key"}},
		"too big": many,
	} {
		if _, err := Resolve(t.Context(), refs, client); err == nil || strings.Contains(err.Error(), "sentinel") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Resolve(t.Context(), refs, func(string) (BundleClient, error) { return nil, errors.New("no instance principal") }); err == nil {
		t.Error("resolved without a client")
	}
	t.Setenv("OCI_GO_SDK_DEBUG", "1")
	if _, err := Resolve(t.Context(), refs, client); err == nil {
		t.Error("resolved while the OCI SDK logs bodies")
	}
}
