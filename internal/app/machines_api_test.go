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
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
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
	controllerConfig := testJSONFile(t, root, "controller.json", Config{Version: ConfigVersion,
		NATS: natscell.Config{Cell: "gru", Instance: "one", Replicas: 1, Lab: true, NKeySeedFile: controllerSeed,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: port, StoreDir: filepath.Join(root, "nats"),
				StoreMaxBytes: 4 << 30, Users: []natscell.NKeyGrant{{PublicKey: controllerNKey, Role: "controller", Global: true}}}},
		Controller: ControllerConfig{SpecTrust: authorityTestSpecTrust(t, root, "gru"), CandidateID: "0000000000DV8998ZCQW1J2V2R", ResponseKeyFile: filepath.Join(root, "controller.key"),
			ArtifactStoreMaxBytes: 64 << 20, TrustedSigners: []TrustedSignerConfig{{Actor: "ops",
				PublicKey: base64.StdEncoding.EncodeToString(operatorPublic), Roles: []string{"web"}, Environments: []string{"test"}}},
			Workloads: map[string]WorkloadProfile{"terrabase": {Resources: resources}, "web": {Resources: resources}},
			MachinesAPI: &machinesapi.Config{ListenAddress: fmt.Sprintf("127.0.0.1:%d", apiPort), Issuer: issuer,
				Audience: audience, JWKSURLs: []string{jwks.URL}, Clients: []string{"00000000000000000000000001"},
				PlatformOrganizationID: "0000000000N2TZG5XH1FX62SDF", Members: map[string][]string{"0000000000N2TZG5XH1FX62SDF": {"00000000000000000000000002"}}},
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
	code, body := get(signTestAccessToken(t, key, "k1", map[string]any{"iss": issuer, "aud": audience, "sub": "00000000000000000000000002",
		"client_id": "00000000000000000000000001", "scope": "orch:read", "iat": now, "exp": now + 600}))
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

// A production controller serves the Machines API only while the adopted
// cell spec carries machines_api, on its broker address, and stops when the
// section goes, without a restart.
func TestMachinesAPIFollowsTheCellSpec(t *testing.T) {
	machinesAPICheck = 50 * time.Millisecond
	t.Cleanup(func() { machinesAPICheck = 5 * time.Second })
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	host := "127.0.0.42"
	broker, err := natscell.Start(ctx, natscell.Config{Cell: "gru", Instance: "machines-spec", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: host, Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "0000000000N8R21NWNZ7QZ2X0N", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	cfg := Config{NATS: natscell.Config{Cell: "gru", Replicas: 1, Embedded: &natscell.Embedded{Host: host}}}
	var current atomic.Pointer[cellspec.MachinesAPI]
	loopCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- machinesAPILoop(loopCtx, cfg, broker, control, func() bool { return true }, current.Load, nil)
	}()
	health := func() int {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s:%d/healthz", host, cellspec.MachinesAPIPort), nil)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return 0
		}
		response.Body.Close()
		return response.StatusCode
	}
	await := func(want int) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); health() != want; {
			if time.Now().After(deadline) {
				t.Fatalf("health %d, want %d", health(), want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	await(0)
	current.Store(&cellspec.MachinesAPI{Issuer: "https://gru.auth.terrascale.tech/terrascale", Audience: "https://gru.orch.terrascale.tech",
		JWKSURLs: []string{"http://127.0.0.1:1/jwks.json"}, Clients: []string{"00000000000000000000000001"}})
	await(http.StatusOK)
	current.Store(nil)
	await(0)
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
