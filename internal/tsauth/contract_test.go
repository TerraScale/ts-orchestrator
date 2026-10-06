package tsauth

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const (
	testProjectID = "0192f0c4-7d1e-7a2b-9c3d-4e5f6a7b8c9d"
	sentinel      = "SENTINEL-do-not-print"
)

func validProfile() map[string]string {
	return map[string]string{EnvPublicOrigin: PublicOrigin, EnvAPIURL: APIURL, EnvDatabase: Database, EnvAudiences: APIURL,
		EnvDashboardRedirectURIs: DashboardRedirectURI, EnvDashboardLogoutURIs: DashboardLogoutURI}
}

// validRefs names every secret in the gru-1 Vault.
func validRefs() map[string]vaultsecret.Ref {
	refs := map[string]vaultsecret.Ref{}
	for _, key := range Secrets {
		refs[key] = vaultsecret.Ref{Vault: testTarget.VaultID, Name: SecretName("gru-1", key)}
	}
	return refs
}

// testSecrets are distinct valid secrets: three 32-byte keys, an API key and
// the project ID.
func testSecrets() map[string]string {
	secrets := map[string]string{EnvAPIKey: "tb_0123456789abcdefghijABCDEFGHIJ0123456789", EnvProjectID: testProjectID}
	for index, key := range Generated {
		secrets[key] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 1)}, 32))
	}
	return secrets
}

// leaks reports a secret value that appears in err.
func leaks(err error, values ...string) string {
	for _, value := range values {
		if value != "" && strings.Contains(err.Error(), value) {
			return value
		}
	}
	return ""
}

func TestValidateProfile(t *testing.T) {
	if err := ValidateProfile(Cell, nil, validProfile(), validRefs()); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProfile("sfo", nil, validProfile(), validRefs()); err == nil {
		t.Fatal("accepted a ts-auth profile outside the reviewed cell")
	}
	if _, set := validProfile()[EnvProjectID]; set || !slices.Contains(Secrets, EnvProjectID) {
		t.Fatal("project ID belongs to the secrets")
	}
	missing, extra := validRefs(), validRefs()
	delete(missing, EnvMasterKey)
	extra["TS_AUTH_SMTP_PASSWORD"] = vaultsecret.Ref{Vault: testTarget.VaultID, Name: "gru-1-ts-auth-smtp-password"}
	for name, refs := range map[string]map[string]vaultsecret.Ref{"no refs": nil, "missing ref": missing, "extra ref": extra} {
		if err := ValidateProfile(Cell, nil, validProfile(), refs); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	with := func(key, value string) map[string]string {
		env := validProfile()
		env[key] = value
		return env
	}
	without := func(key string) map[string]string {
		env := validProfile()
		delete(env, key)
		return env
	}
	cases := map[string]map[string]string{
		"listen":           with(EnvListen, "http://0.0.0.0:8080"),
		"bundle dir":       with(EnvBundleExtract, "/tmp"),
		"smtp password":    with("TS_AUTH_SMTP_PASSWORD", sentinel),
		"service clients":  with("TS_AUTH_SERVICE_CLIENTS", "ci:"+sentinel+sentinel),
		"wrong api url":    with(EnvAPIURL, "https://api.terrascale.tech"),
		"wrong database":   with(EnvDatabase, "ts-auth"),
		"missing origin":   without(EnvPublicOrigin),
		"missing database": without(EnvDatabase),
		// The selector's project comes from the secrets, never the profile.
		"database selector": with(EnvDatabase, testProjectID+"/auth"),
		"other callback":    with(EnvDashboardRedirectURIs, "https://evil.example/login/callback"),
		"extra callback":    with(EnvDashboardRedirectURIs, DashboardRedirectURI+";http://localhost:5173/login/callback"),
		"missing callback":  without(EnvDashboardRedirectURIs),
		"missing logout":    without(EnvDashboardLogoutURIs),
		"dashboard root":    with(EnvDashboardLogoutURIs, DashboardOrigin+"/"),
		"other audience":    with(EnvAudiences, "https://api.terrascale.tech"),
		"missing audience":  without(EnvAudiences),
		"old origin":        with(EnvPublicOrigin, "https://auth.terrascale.tech"),
	}
	for _, key := range Secrets {
		cases["secret "+key] = with(key, sentinel)
	}
	for name, env := range cases {
		err := ValidateProfile(Cell, nil, env, validRefs())
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if leak := leaks(err, sentinel); leak != "" {
			t.Errorf("%s: error prints a secret: %v", name, err)
		}
	}
	if err := ValidateProfile(Cell, []string{"--listen", "x"}, validProfile(), validRefs()); err == nil {
		t.Error("accepted arguments")
	}
}

// TestValidateSecrets checks the values a host read from the Vault before a
// replica gets them; errors name keys, never values.
func TestValidateSecrets(t *testing.T) {
	if err := ValidateSecrets(testSecrets()); err != nil {
		t.Fatal(err)
	}
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 31))
	values := append(slices.Collect(maps.Values(testSecrets())), sentinel, short)
	with := func(key, value string) map[string]string {
		secrets := testSecrets()
		secrets[key] = value
		return secrets
	}
	missing := testSecrets()
	delete(missing, EnvOperatorKey)
	master := testSecrets()[EnvMasterKey]
	for name, secrets := range map[string]map[string]string{
		"missing key":        missing,
		"unknown key":        with("TS_AUTH_OTHER", sentinel),
		"31-byte key":        with(EnvMasterKey, short),
		"key with a newline": with(EnvMasterKey, master[:20]+"\n"+master[20:]),
		"api key with space": with(EnvAPIKey, "tb_ "+sentinel),
		"empty api key":      with(EnvAPIKey, ""),
		"4097-char api key":  with(EnvAPIKey, strings.Repeat("k", 4097)),
		"non-uuid project":   with(EnvProjectID, "ts-auth"),
		"uppercase project":  with(EnvProjectID, strings.ToUpper(testProjectID)),
		"none":               nil,
	} {
		err := ValidateSecrets(secrets)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if leak := leaks(err, values...); leak != "" {
			t.Errorf("%s: error prints a secret: %v", name, err)
		}
	}
}

func TestLayoutEnv(t *testing.T) {
	profile := validProfile()
	secrets := testSecrets()
	env := Layout("/srv/ts-managed/ts-auth").Env(profile, secrets, 8080)
	want := validProfile()
	maps.Copy(want, secrets)
	// ts-auth reads TS_AUTH_DATABASE as <project-uuid>/<database> and gets no
	// separate project ID.
	want[EnvDatabase] = testProjectID + "/auth"
	delete(want, EnvProjectID)
	want[EnvListen] = "http://0.0.0.0:8080"
	want[EnvBundleExtract] = "/srv/ts-managed/ts-auth/bundle"
	if !maps.Equal(env, want) {
		t.Fatalf("env %v", slices.Sorted(maps.Keys(env)))
	}
	if !maps.Equal(profile, validProfile()) {
		t.Fatal("Env modified the profile")
	}
}

func probeServer(t *testing.T, health, ready int, healthBody, readyBody string) int {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case HealthPath:
			w.WriteHeader(health)
			_, _ = w.Write([]byte(healthBody))
		case ReadyPath:
			w.WriteHeader(ready)
			_, _ = w.Write([]byte(readyBody))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server.Listener.Addr().(*net.TCPAddr).Port
}

func TestProbe(t *testing.T) {
	if err := Probe(t.Context(), probeServer(t, 200, 200, `{"status":"ok"}`, `{"status":"ready"}`)); err != nil {
		t.Fatal(err)
	}
	err := Probe(t.Context(), probeServer(t, 200, 503, `{"status":"ok"}`, `{"status":"not_ready"}`))
	if err == nil || !strings.Contains(err.Error(), ReadyPath) {
		t.Fatalf("not ready: %v", err)
	}
	if err := Probe(t.Context(), probeServer(t, 200, 200, `{"status":"bad"}`, `{"status":"ready"}`)); err == nil {
		t.Fatal("accepted a bad health status")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	if err := Probe(t.Context(), port); err == nil {
		t.Fatal("closed port probed ready")
	}
}

func writeRelease(t *testing.T, name string, content, summed []byte) (string, string) {
	dir := t.TempDir()
	binary := filepath.Join(dir, name)
	sum := sha256.Sum256(summed)
	if err := os.WriteFile(binary, content, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary+".sha256", []byte(hex.EncodeToString(sum[:])+"  "+name+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return binary, binary + ".sha256"
}

func TestVerifyRelease(t *testing.T) {
	content, err := os.ReadFile("../terrabase/testdata/terrabase-linux-arm64")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	digest, err := VerifyRelease(writeRelease(t, "ts-auth-linux-arm64", content, content))
	if err != nil || digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest %q: %v", digest, err)
	}
	if _, err := VerifyRelease(writeRelease(t, "terrabase-linux-arm64", content, content)); err == nil {
		t.Fatal("accepted a TerraBase asset")
	}
	if _, err := VerifyRelease(writeRelease(t, "ts-auth-linux-arm64", content, []byte("\x7fELF other"))); err == nil {
		t.Fatal("accepted a checksum mismatch")
	}
	x86 := bytes.Clone(content)
	binary.LittleEndian.PutUint16(x86[18:20], uint16(elf.EM_X86_64))
	if _, err := VerifyRelease(writeRelease(t, "ts-auth-linux-arm64", x86, x86)); err == nil {
		t.Fatal("accepted x86-64 as an arm64 asset")
	}
	if _, err := VerifyRelease(writeRelease(t, "ts-auth-linux-amd64", x86, x86)); err != nil {
		t.Fatalf("amd64 asset: %v", err)
	}
}
