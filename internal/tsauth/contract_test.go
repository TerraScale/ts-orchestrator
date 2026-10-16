package tsauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const (
	testProjectID = "01K78000000000000000000001"
	sentinel      = "SENTINEL-do-not-print"
)

func validProfile() map[string]string { return cellProfile("gru") }

// cellProfile is a valid profile naming cell's endpoints.
func cellProfile(cell string) map[string]string {
	return map[string]string{EnvPublicOrigin: PublicOrigin(cell), EnvAPIURL: APIURL(cell), EnvDatabase: Database, EnvAudiences: APIURL(cell),
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

func TestValidateMembers(t *testing.T) {
	members := map[string]string{"TERRABASE_PEER_PORT": "9443", "TERRABASE_CLIENT_PORT": "9465",
		"TERRABASE_PEERS": "gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443"}
	ca := testCertificate(t, true)
	with := func(endpoints, roots string) map[string]string {
		env := validProfile()
		env[EnvAPIEndpoints], env[EnvAPICA], env[EnvAPIFailover] = endpoints, roots, "true"
		return env
	}
	if err := ValidateMembers(validProfile(), nil); err != nil {
		t.Fatalf("a profile storing through %s: %v", EnvAPIURL, err)
	}
	if err := ValidateMembers(with("https://10.251.0.23:9465", ca), nil); err != nil {
		t.Fatalf("a controller config without a terrabase profile yet: %v", err)
	}
	if err := ValidateMembers(with("https://10.251.0.23:9465", ""), nil); err == nil {
		t.Fatal("accepted endpoints without roots before the terrabase profile")
	}
	for _, endpoints := range []string{"https://10.251.0.21:9465;https://10.251.0.22:9465", "https://10.251.0.22:9465"} {
		if err := ValidateMembers(with(endpoints, ca+ca), members); err != nil {
			t.Fatalf("%s: %v", endpoints, err)
		}
	}
	for name, env := range map[string]map[string]string{
		"endpoints alone":   with("https://10.251.0.21:9465", ""),
		"roots alone":       with("", ca),
		"not a member":      with("https://10.251.0.23:9465", ca),
		"peer port":         with("https://10.251.0.21:9443", ca),
		"plain HTTP":        with("http://10.251.0.21:9465", ca),
		"repeated member":   with("https://10.251.0.21:9465;https://10.251.0.21:9465", ca),
		"trailing slash":    with("https://10.251.0.21:9465/", ca),
		"leaf certificate":  with("https://10.251.0.21:9465", testCertificate(t, false)),
		"key in the roots":  with("https://10.251.0.21:9465", ca+"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
		"text in the roots": with("https://10.251.0.21:9465", ca+"trailing"),
		"five roots":        with("https://10.251.0.21:9465", strings.Repeat(ca, 5)),
	} {
		if err := ValidateMembers(env, members); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	pinned := with("https://10.251.0.21:9465", ca)
	delete(pinned, EnvAPIFailover)
	if err := ValidateMembers(pinned, members); err != nil {
		t.Fatalf("one pinned member: %v", err)
	}
	for _, failover := range []string{"", "false", "yes"} {
		env := with("https://10.251.0.21:9465;https://10.251.0.22:9465", ca)
		env[EnvAPIFailover] = failover
		if failover == "" {
			delete(env, EnvAPIFailover)
		}
		if err := ValidateMembers(env, members); err == nil {
			t.Errorf("accepted several members with %s=%q", EnvAPIFailover, failover)
		}
	}
	delete(members, "TERRABASE_CLIENT_PORT")
	if err := ValidateMembers(with("https://10.251.0.21:9465", ca), members); err == nil {
		t.Fatal("accepted endpoints of members without a client listener")
	}
}

// testCertificate is a self-signed PEM certificate, a CA or a leaf.
func testCertificate(t *testing.T, ca bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TerraBase member CA gru-1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: ca, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestValidateProfile(t *testing.T) {
	if err := ValidateProfile("gru", nil, validProfile(), validRefs()); err != nil {
		t.Fatal(err)
	}
	if validProfile()[EnvPublicOrigin] != "https://gru.auth.terrascale.tech" || validProfile()[EnvAPIURL] != "https://gru.api.terrascale.tech" ||
		Issuer("gru") != "https://gru.auth.terrascale.tech/terrascale" {
		t.Fatal("gru endpoints changed")
	}
	// Every catalog cell serves ts-auth at its own endpoints and only there.
	for _, cell := range []string{"sfo", "fra"} {
		if err := ValidateProfile(cell, nil, cellProfile(cell), validRefs()); err != nil {
			t.Fatalf("%s: %v", cell, err)
		}
		if PublicOrigin(cell) != "https://"+cell+".auth.terrascale.tech" || APIURL(cell) != "https://"+cell+".api.terrascale.tech" {
			t.Fatalf("%s endpoints %s, %s", cell, PublicOrigin(cell), APIURL(cell))
		}
		if err := ValidateProfile(cell, nil, validProfile(), validRefs()); err == nil {
			t.Fatalf("%s accepted gru's endpoints", cell)
		}
		for _, key := range []string{EnvPublicOrigin, EnvAPIURL, EnvAudiences} {
			for _, foreign := range []string{validProfile()[key], "https://evil.example"} {
				env := cellProfile(cell)
				env[key] = foreign
				if err := ValidateProfile(cell, nil, env, validRefs()); err == nil {
					t.Errorf("%s accepted %s=%s", cell, key, foreign)
				}
			}
		}
	}
	for _, cell := range []string{"", "xxx", "GRU", "gru-1"} {
		if err := ValidateProfile(cell, nil, cellProfile(cell), validRefs()); err == nil {
			t.Errorf("accepted cell %q outside the catalog", cell)
		}
	}
	if _, set := validProfile()[EnvProjectID]; set || !slices.Contains(Secrets, EnvProjectID) {
		t.Fatal("project ID belongs to the secrets")
	}
	missing, extra, optional := validRefs(), validRefs(), validRefs()
	delete(missing, EnvMasterKey)
	extra["TS_AUTH_STRIPE_SECRET_KEY"] = vaultsecret.Ref{Vault: testTarget.VaultID, Name: "gru-1-ts-auth-stripe-secret-key"}
	optional["TS_AUTH_SMTP_USERNAME"] = vaultsecret.Ref{Vault: testTarget.VaultID, Name: "gru-1-ts-auth-smtp-username"}
	optional["TS_AUTH_SMTP_PASSWORD"] = vaultsecret.Ref{Vault: testTarget.VaultID, Name: "gru-1-ts-auth-smtp-password"}
	optional["TS_AUTH_SERVICE_CLIENTS"] = vaultsecret.Ref{Vault: testTarget.VaultID, Name: "gru-1-ts-auth-service-clients"}
	if err := ValidateProfile("gru", nil, validProfile(), optional); err != nil {
		t.Fatalf("optional SMTP credential and service client refs: %v", err)
	}
	for name, refs := range map[string]map[string]vaultsecret.Ref{"no refs": nil, "missing ref": missing, "extra ref": extra} {
		if err := ValidateProfile("gru", nil, validProfile(), refs); err == nil {
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
		"smtp username":    with("TS_AUTH_SMTP_USERNAME", sentinel),
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
		err := ValidateProfile("gru", nil, env, validRefs())
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if leak := leaks(err, sentinel); leak != "" {
			t.Errorf("%s: error prints a secret: %v", name, err)
		}
	}
	if err := ValidateProfile("gru", []string{"--listen", "x"}, validProfile(), validRefs()); err == nil {
		t.Error("accepted arguments")
	}
}

// TestValidateSecrets checks the values a host read from the Vault before a
// replica gets them; errors name keys, never values.
func TestValidateSecrets(t *testing.T) {
	if err := ValidateSecrets(testSecrets()); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecrets(with2(testSecrets(), "TS_AUTH_SERVICE_CLIENTS", "smoke:"+sentinel)); err != nil {
		t.Fatalf("service clients: %v", err)
	}
	if err := ValidateSecrets(with2(testSecrets(), EnvProjectID, "0192f0c4-7d1e-7a2b-9c3d-4e5f6a7b8c9d")); err == nil {
		t.Fatal("accepted a UUIDv7 project")
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
		"empty optional":     with("TS_AUTH_SMTP_PASSWORD", ""),
		"31-byte key":        with(EnvMasterKey, short),
		"key with a newline": with(EnvMasterKey, master[:20]+"\n"+master[20:]),
		"api key with space": with(EnvAPIKey, "tb_ "+sentinel),
		"empty api key":      with(EnvAPIKey, ""),
		"4097-char api key":  with(EnvAPIKey, strings.Repeat("k", 4097)),
		"non-ulid project":   with(EnvProjectID, "ts-auth"),
		"lowercase project":  with(EnvProjectID, strings.ToLower(testProjectID)),
		"uppercase uuid":     with(EnvProjectID, "0192F0C4-7D1E-7A2B-9C3D-4E5F6A7B8C9D"),
		"uuid v4 project":    with(EnvProjectID, "0192f0c4-7d1e-4a2b-9c3d-4e5f6a7b8c9d"),
		"nil uuid project":   with(EnvProjectID, "00000000-0000-0000-0000-000000000000"),
		"uuid variant":       with(EnvProjectID, "0192f0c4-7d1e-7a2b-7c3d-4e5f6a7b8c9d"),
		"uuid whitespace":    with(EnvProjectID, "0192f0c4-7d1e-7a2b-9c3d-4e5f6a7b8c9d\n"),
		"overflow project":   with(EnvProjectID, "81K78000000000000000000001"),
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

func TestProjectIDsRequireCanonicalULID(t *testing.T) {
	for _, project := range Projects {
		t.Run(project.Name, func(t *testing.T) {
			if err := validSecret(project.ProjectIDKey, testProjectID); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"0192f0c4-7d1e-7a2b-9c3d-4e5f6a7b8c9d", strings.ToLower(testProjectID), "00000000000000000000000000"} {
				if err := validSecret(project.ProjectIDKey, id); err == nil {
					t.Fatalf("accepted noncanonical project %q", id)
				}
			}
		})
	}
}

func TestLayoutEnv(t *testing.T) {
	profile := validProfile()
	secrets := testSecrets()
	env := Layout("/srv/ts-managed/ts-auth").Env(profile, secrets, 8080)
	want := validProfile()
	maps.Copy(want, secrets)
	// ts-auth reads TS_AUTH_DATABASE as <project-ulid>/<database> and gets no
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

func with2(secrets map[string]string, key, value string) map[string]string {
	secrets[key] = value
	return secrets
}
