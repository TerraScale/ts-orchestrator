package vaultsecret

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
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

type versionedVault struct {
	*fakeVault
	id      *string
	version *int64
}

func (vault versionedVault) GetSecretBundleByName(ctx context.Context, request ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error) {
	response, err := vault.fakeVault.GetSecretBundleByName(ctx, request)
	response.SecretId, response.VersionNumber = vault.id, vault.version
	return response, err
}

func TestReadVersionedRequiresAuthoritativeMetadata(t *testing.T) {
	vault := newVault()
	name := "gru-1-orch-dashboard-token"
	vault.store(name, sentinel)
	for _, tc := range []struct {
		id      *string
		version *int64
		ok      bool
	}{{new("secret-id"), new(int64(7)), true}, {nil, new(int64(7)), false}, {new(""), new(int64(7)), false}, {new("secret-id"), nil, false}, {new("secret-id"), new(int64(0)), false}} {
		value, err := ReadVersioned(t.Context(), versionedVault{vault, tc.id, tc.version}, testTarget.VaultID, name)
		if tc.ok {
			if err != nil || value.Value != sentinel || value.SecretID != "secret-id" || value.Number != 7 {
				t.Fatal("versioned read did not preserve the bundle's value and version")
			}
		} else if err == nil || strings.Contains(err.Error(), sentinel) || value.Value != "" {
			t.Fatal("versioned read accepted missing metadata or exposed a value")
		}
	}
}

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

func TestName(t *testing.T) {
	for key, want := range map[string]string{"TS_AUTH_MASTER_KEY": "gru-1-ts-auth-master-key",
		"NETBIRD_RELAY_AUTH_SECRET": "gru-1-netbird-relay-auth-secret", "TRUST_ROOT_PRIVATE_KEY": "gru-1-trust-root-private-key"} {
		if got := Name("gru-1", key); got != want || !nameRE.MatchString(got) {
			t.Errorf("Name(gru-1, %s) = %s", key, got)
		}
	}
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

func TestRender(t *testing.T) {
	vault := newVault()
	vault.store("gru-1-netbird-relay-auth-secret", `a"b\`)
	vault.store("gru-1-netbird-datastore-encryption-key", "c2VjcmV0")
	template := []byte("authSecret: {{NETBIRD_RELAY_AUTH_SECRET}}\nkey: {{NETBIRD_DATASTORE_ENCRYPTION_KEY}}\nagain: {{NETBIRD_RELAY_AUTH_SECRET}}\n")
	rendered, names, err := Render(t.Context(), vault, testTarget.VaultID, "gru-1", template)
	if err != nil {
		t.Fatal(err)
	}
	if want := "authSecret: \"a\\\"b\\\\\"\nkey: \"c2VjcmV0\"\nagain: \"a\\\"b\\\\\"\n"; string(rendered) != want {
		t.Fatalf("rendered %q", rendered)
	}
	if fmt.Sprint(names) != "[gru-1-netbird-relay-auth-secret gru-1-netbird-datastore-encryption-key]" || len(vault.reads) != 2 {
		t.Fatalf("read %v in %d requests", names, len(vault.reads))
	}
	for name, template := range map[string]string{
		"missing secret":   "x: {{NETBIRD_SESSION_COOKIE_ENCRYPTION_KEY}}",
		"bad placeholder":  "x: {{ netbird }}",
		"open placeholder": "x: {{NETBIRD_RELAY_AUTH_SECRET",
	} {
		if _, _, err := Render(t.Context(), vault, testTarget.VaultID, "gru-1", []byte(template)); err == nil || strings.Contains(err.Error(), "c2VjcmV0") {
			t.Errorf("%s: %v", name, err)
		}
	}
	vault.store("gru-1-netbird-invalid", "\xff"+sentinel)
	if _, _, err := Render(t.Context(), vault, testTarget.VaultID, "gru-1", []byte("{{NETBIRD_INVALID}}")); err == nil || strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("invalid UTF-8: %v", err)
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

func TestRunRejectsBeforeOCI(t *testing.T) {
	vault := "--vault-id=ocid1.vault.oc1.sa-saopaulo-1.x.y"
	for name, test := range map[string]struct {
		args []string
		want string
	}{
		"put flags":      {[]string{"put", vault}, "put requires"},
		"put ocids":      {[]string{"put", vault, "--key-id=k", "--compartment-id=c", "--name=n", "--file=f"}, "put needs"},
		"render flags":   {[]string{"render", vault}, "render requires"},
		"render scope":   {[]string{"render", vault, "--scope=GRU", "--template=t", "--out=o"}, "render needs"},
		"render region":  {[]string{"render", "--vault-id=ocid1.vault.oc1.mars-1.x", "--scope=gru-1", "--template=t", "--out=o"}, "render needs"},
		"unknown":        {[]string{"get"}, "unknown vault command"},
		"positional arg": {[]string{"put", "extra"}, "unexpected"},
	} {
		var output bytes.Buffer
		if err := Run(t.Context(), test.args, &output); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	t.Setenv("OCI_GO_SDK_DEBUG", "1")
	if err := Run(t.Context(), []string{"render", vault, "--scope=gru-1", "--template=t", "--out=o"}, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "OCI_GO_SDK_DEBUG") {
		t.Fatalf("debug logging: %v", err)
	}
	// The guard sits in the shared store, so ts-auth's reads and writes stop too.
	store := newVault()
	store.store("gru-1-netbird-relay-auth-secret", sentinel)
	_, readErr := Read(t.Context(), store, testTarget.VaultID, "gru-1-netbird-relay-auth-secret")
	_, ensureErr := Ensure(t.Context(), store, testTarget, "gru-1-netbird-new", "", func(context.Context) (string, error) { return sentinel, nil })
	if readErr == nil || ensureErr == nil || len(store.reads) != 0 || len(store.creates) != 0 {
		t.Fatalf("debug logging reached OCI: %v, %v", readErr, ensureErr)
	}
}

func TestRetrySecretReadClassifiesOCIStatus(t *testing.T) {
	for status, want := range map[int]bool{http.StatusNotFound: true, http.StatusConflict: true, http.StatusUnauthorized: false, http.StatusBadRequest: false} {
		if got := retrySecretRead(fmt.Errorf("wrapped: %w", testSecretServiceError{status: status})); got != want {
			t.Errorf("status %d: retry=%v, want %v", status, got, want)
		}
	}
}

type testSecretServiceError struct{ status int }

func (e testSecretServiceError) Error() string           { return "OCI service error" }
func (e testSecretServiceError) GetHTTPStatusCode() int  { return e.status }
func (e testSecretServiceError) GetMessage() string      { return "" }
func (e testSecretServiceError) GetCode() string         { return "" }
func (e testSecretServiceError) GetOpcRequestID() string { return "" }

// TestValidateRefs accepts a role's own secrets in a regional Vault and
// refuses anything that would let a profile reach another role's or another
// cell's secrets, an unknown Vault, or an environment key it also sets.
func TestValidateRefs(t *testing.T) {
	ref := func(name string) Ref { return Ref{Vault: testTarget.VaultID, Name: name} }
	valid := map[string]Ref{"TS_AUTH_MASTER_KEY": ref("gru-1-ts-auth-master-key"), "b_2": ref("gru-12-ts-auth-x"), "RING": ref("gru-ts-auth-signing-key-ring")}
	if err := ValidateRefs("gru", "ts-auth", valid, map[string]string{"TS_AUTH_PUBLIC_ORIGIN": "https://x"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRefs("gru", "ts-auth", nil, nil); err != nil {
		t.Fatal(err)
	}
	tooMany := map[string]Ref{}
	for i := range MaxRefs + 1 {
		tooMany["K"+strconv.Itoa(i)] = ref("gru-1-ts-auth-k" + strconv.Itoa(i))
	}
	for _, role := range []string{"netbird", "api", "api-gateway", "trust", "cloudflare", "orch", "orch-dashboard", "ts", "ts-dashboard", "ts-dashboard-x", "ts-orchestrator"} {
		if err := ValidateRefs("gru", role, map[string]Ref{"K": ref("gru-1-" + role + "-k")}, nil); err == nil {
			t.Errorf("role %s reached the cell's infrastructure secrets", role)
		}
		if err := ValidateRefs("gru", role, nil, nil); err != nil {
			t.Errorf("role %s without secrets: %v", role, err)
		}
	}
	for name, test := range map[string]struct {
		refs map[string]Ref
		env  map[string]string
	}{
		"other role":       {refs: map[string]Ref{"K": ref("gru-1-netbird-admin-pat")}},
		"other cell":       {refs: map[string]Ref{"K": ref("sfo-1-ts-auth-master-key")}},
		"zero index":       {refs: map[string]Ref{"K": ref("gru-01-ts-auth-master-key")}},
		"no key":           {refs: map[string]Ref{"K": ref("gru-1-ts-auth")}},
		"role only prefix": {refs: map[string]Ref{"K": ref("gru-1-ts-authx-key")}},
		"upper case":       {refs: map[string]Ref{"K": ref("gru-1-ts-auth-Key")}},
		"slash":            {refs: map[string]Ref{"K": ref("gru-1-ts-auth-a/b")}},
		"bad key":          {refs: map[string]Ref{"1K": ref("gru-1-ts-auth-k")}},
		"key with =":       {refs: map[string]Ref{"K=V": ref("gru-1-ts-auth-k")}},
		"also in env":      {refs: map[string]Ref{"K": ref("gru-1-ts-auth-k")}, env: map[string]string{"K": "v"}},
		"no vault":         {refs: map[string]Ref{"K": {Name: "gru-1-ts-auth-k"}}},
		"key not vault":    {refs: map[string]Ref{"K": {Vault: testTarget.KeyID, Name: "gru-1-ts-auth-k"}}},
		"unknown region":   {refs: map[string]Ref{"K": {Vault: "ocid1.vault.oc1.mars-1.vault", Name: "gru-1-ts-auth-k"}}},
		"other cell Vault": {refs: map[string]Ref{"K": {Vault: "ocid1.vault.oc1.us-sanjose-1.vault", Name: "gru-1-ts-auth-k"}}},
		"too many":         {refs: tooMany},
	} {
		if err := ValidateRefs("gru", "ts-auth", test.refs, test.env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := ValidateRefs("lab", "ts-auth", map[string]Ref{"K": ref("lab-1-ts-auth-k")}, nil); err == nil {
		t.Error("a cell outside the catalog named a Vault")
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
