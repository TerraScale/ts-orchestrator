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
)

const (
	testProjectID = "0192f0c4-7d1e-7a2b-9c3d-4e5f6a7b8c9d"
	sentinel      = "SENTINEL-do-not-print"
)

func validProfile() map[string]string {
	return map[string]string{EnvPublicOrigin: PublicOrigin, EnvAPIURL: APIURL, EnvDatabase: Database}
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
	if err := ValidateProfile(Cell, nil, validProfile()); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProfile("sfo", nil, validProfile()); err == nil {
		t.Fatal("accepted a ts-auth profile outside the reviewed cell")
	}
	if _, set := validProfile()[EnvProjectID]; set || !slices.Contains(Secrets, EnvProjectID) {
		t.Fatal("project ID belongs to the env file")
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
		"wrong api url":    with(EnvAPIURL, "https://api.terrascale.tech"),
		"wrong database":   with(EnvDatabase, "ts-auth"),
		"missing origin":   without(EnvPublicOrigin),
		"missing database": without(EnvDatabase),
	}
	for _, key := range Secrets {
		cases["secret "+key] = with(key, sentinel)
	}
	for name, env := range cases {
		err := ValidateProfile(Cell, nil, env)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if leak := leaks(err, sentinel); leak != "" {
			t.Errorf("%s: error prints a secret: %v", name, err)
		}
	}
	if err := ValidateProfile(Cell, []string{"--listen", "x"}, validProfile()); err == nil {
		t.Error("accepted arguments")
	}
}

func TestEnvFileRoundTrip(t *testing.T) {
	secrets := testSecrets()
	data, err := RenderEnvFile(secrets)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(string(data), "\n"); lines != len(Secrets) {
		t.Fatalf("rendered %d lines", lines)
	}
	parsed, err := ParseEnvFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(parsed, secrets) {
		t.Fatal("round trip changed the secrets")
	}
}

func TestEnvFileRejections(t *testing.T) {
	secrets := testSecrets()
	data, err := RenderEnvFile(secrets)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(data)
	lines := strings.SplitAfter(valid, "\n")
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 31))
	values := append(slices.Collect(maps.Values(secrets)), sentinel, short)
	replace := func(key, value string) string {
		return strings.Replace(valid, key+"="+secrets[key], key+"="+value, 1)
	}
	for name, file := range map[string]string{
		"missing key":         strings.Join(lines[:len(Secrets)-1], ""),
		"unknown key":         valid + "TS_AUTH_OTHER=" + sentinel + "\n",
		"repeated key":        valid + lines[0],
		"line without =":      valid + sentinel + "\n",
		"31-byte key":         replace(EnvMasterKey, short),
		"api key with space":  replace(EnvAPIKey, "tb_ "+sentinel),
		"empty api key":       replace(EnvAPIKey, ""),
		"4097-char api key":   replace(EnvAPIKey, strings.Repeat("k", 4097)),
		"non-uuid project":    replace(EnvProjectID, "ts-auth"),
		"uppercase project":   replace(EnvProjectID, strings.ToUpper(testProjectID)),
		"crlf":                strings.ReplaceAll(valid, "\n", "\r\n"),
		"crlf on a generated": strings.Replace(valid, "\n", "\r\n", 1),
		"empty":               "",
	} {
		_, err := ParseEnvFile([]byte(file))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if leak := leaks(err, values...); leak != "" {
			t.Errorf("%s: error prints a secret: %v", name, err)
		}
	}
	// A key that only decodes because base64 skips CR and LF would split
	// the rendered file.
	broken := testSecrets()
	broken[EnvMasterKey] = broken[EnvMasterKey][:20] + "\n" + broken[EnvMasterKey][20:]
	if _, err := RenderEnvFile(broken); err == nil {
		t.Error("rendered a key carrying a newline")
	}
}

func TestLayoutEnv(t *testing.T) {
	profile := validProfile()
	secrets := testSecrets()
	env := Layout("/srv/ts-managed/ts-auth").Env(profile, secrets, 8080)
	want := validProfile()
	maps.Copy(want, secrets)
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
