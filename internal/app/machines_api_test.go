package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/machinesapi"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

// A lab controller with machines_api opens the app and tenant stores and
// serves them to a platform member's ts-auth token.
func TestControllerServesMachinesAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := key.PublicKey.Bytes()
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		data, _ := json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "EC", "crv": "P-256", "kid": "k1",
			"x": base64.RawURLEncoding.EncodeToString(public[1:33]), "y": base64.RawURLEncoding.EncodeToString(public[33:])}}})
		_, _ = w.Write(data)
	}))
	defer jwks.Close()

	root := t.TempDir()
	port, apiPort := freeTCPPort(t), freeTCPPort(t)
	controllerNKey, controllerSeed := testNKey(t)
	testEd25519(t, root, "controller.key")
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	resources := placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20}
	issuer, audience := "https://gru.auth.terrascale.tech/terrascale", "https://gru.orch.terrascale.tech"
	controllerConfig := testJSONFile(t, root, "controller.json", Config{
		NATS: natscell.Config{Cell: "gru", Instance: "one", Replicas: 1, Lab: true, NKeySeedFile: controllerSeed,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: port, StoreDir: filepath.Join(root, "nats"),
				StoreMaxBytes: 2 << 30, Users: []natscell.NKeyGrant{{PublicKey: controllerNKey, Role: "controller"}}}},
		Controller: ControllerConfig{CandidateID: "one", ResponseKeyFile: filepath.Join(root, "controller.key"),
			ArtifactStoreMaxBytes: 64 << 20, TrustedSigners: []TrustedSignerConfig{{Actor: "ops",
				PublicKey: base64.StdEncoding.EncodeToString(operatorPublic), Roles: []string{"web"}, Environments: []string{"test"}}},
			Workloads: map[string]WorkloadProfile{"terrabase": {Resources: resources}, "web": {Resources: resources}},
			MachinesAPI: &machinesapi.Config{ListenAddress: fmt.Sprintf("127.0.0.1:%d", apiPort), Issuer: issuer,
				Audience: audience, JWKSURLs: []string{jwks.URL}, Clients: []string{"ts-orch-cli"},
				Members: map[string][]string{machinesapi.PlatformOrg: {"admin"}}},
		},
	})
	runCtx, stop := context.WithCancel(ctx)
	output := &readyWriter{ready: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- Run(runCtx, []string{"run", "--config", controllerConfig}, output) }()
	defer func() {
		stop()
		<-done
	}()
	select {
	case <-output.ready:
	case err := <-done:
		done <- err
		t.Fatalf("controller exited before ready: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	get := func(token string) (int, []byte) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/apps", apiPort), nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, body
	}
	if code, body := get(""); code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /v1/apps = %d %s", code, body)
	}
	now := time.Now().Unix()
	code, body := get(signTestAccessToken(t, key, "k1", map[string]any{"iss": issuer, "aud": audience, "sub": "admin",
		"client_id": "ts-orch-cli", "scope": "orch:read", "iat": now, "exp": now + 600}))
	// The app store opened empty: no app has moved onto it yet.
	if code != http.StatusOK || strings.TrimSpace(string(body)) != `{"apps":[]}` {
		t.Fatalf("GET /v1/apps = %d %s", code, body)
	}
}

func signTestAccessToken(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signed := encode(map[string]string{"alg": "ES256", "typ": "at+jwt", "kid": kid}) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}
