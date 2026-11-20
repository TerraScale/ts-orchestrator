package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go"
)

const waitWorkflow = "TerraScale/terrascale/.github/workflows/ci.yml@refs/heads/main"

type waitLab struct {
	regions string
	mode    atomic.Int32
}

func startWaitLab(conn *nats.Conn, root string) (*waitLab, func()) {
	lab := &waitLab{regions: filepath.Join(root, "signed-wait-regions.json")}
	must(os.WriteFile(lab.regions, []byte(`[{"region":"gru"},{"region":"fra"},{"region":"sjc"}]`), 0600))
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	encode := base64.RawURLEncoding.EncodeToString
	mint := func() string {
		header := encode([]byte(`{"alg":"RS256","kid":"rollout-wait"}`))
		claims, err := json.Marshal(map[string]any{"iss": "https://token.actions.githubusercontent.com", "aud": "ts-orch",
			"exp": time.Now().Add(time.Minute).Unix(), "repository": "TerraScale/terrascale", "repository_owner": "TerraScale", "ref": "refs/heads/main",
			"sha": revision, "run_id": "101", "run_attempt": "1", "event_name": "push", "job_workflow_ref": waitWorkflow})
		must(err)
		payload := header + "." + encode(claims)
		digest := sha256.Sum256([]byte(payload))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		must(err)
		return payload + "." + encode(signature)
	}
	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			must(json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "rollout-wait",
				"n": encode(key.N.Bytes()), "e": encode(big.NewInt(int64(key.E)).Bytes())}}}))
			return
		}
		must(json.NewEncoder(w).Encode(map[string]string{"value": mint()}))
	}))
	verifier := releasepush.NewVerifier()
	verifier.JWKSURL = oidc.URL + "/jwks"
	observation := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		region := strings.TrimSuffix(r.Host, ".mesh.terrascale.tech")
		h := &releasepush.Handler{Verifier: verifier, AppRelease: func(ctx context.Context, service, nonce string) (releasepush.AppReleaseObservation, error) {
			proof, err := mesh.ReadAppRelease(ctx, conn, region, service, nonce)
			if err != nil || region != "fra" || proof.Release == nil || proof.Placement == nil {
				return proof, err
			}
			switch lab.mode.Load() {
			case 1:
				proof.ServingGeneration--
			case 2:
				proof.Placement.Generation++
			case 3:
				proof.Placement.Regions = []string{"fra", "gru"}
			case 4:
				proof.Release.RunAttempt++
			case 5:
				proof.Placement = nil
			case 6:
				proof.BakeGeneration--
			}
			return proof, nil
		}}
		h.Observe(w, r)
	}))
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	ca := x509.NewCertPool()
	ca.AddCert(observation.Certificate())
	transport.TLSClientConfig = &tls.Config{RootCAs: ca, ServerName: "127.0.0.1"}
	transport.Proxy = nil
	dialer := net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasSuffix(address, ".mesh.terrascale.tech:443") {
			address = observation.Listener.Addr().String()
		}
		return dialer.DialContext(ctx, network, address)
	}
	http.DefaultTransport = transport
	verifier.Client.Transport = transport
	variables := map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": oidc.URL + "?fixture=1", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "rollout-fixture"}
	previousEnvironment := map[string]*string{}
	for name, value := range variables {
		if previous, present := os.LookupEnv(name); present {
			previousEnvironment[name] = &previous
		}
		must(os.Setenv(name, value))
	}
	return lab, func() {
		http.DefaultTransport = previous
		transport.CloseIdleConnections()
		for name := range variables {
			if previous := previousEnvironment[name]; previous != nil {
				must(os.Setenv(name, *previous))
			} else {
				must(os.Unsetenv(name))
			}
		}
		observation.Close()
		oidc.Close()
	}
}

func (l *waitLab) wait(ctx context.Context, output io.Writer, service, image, run, scope string) error {
	args := []string{"--service", service, "--image", image, "--regions", l.regions, "--revision", revision, "--run-id", run, "--run-attempt", "1"}
	if scope != "" {
		args = append(args, "--scope", scope)
	}
	return releasepush.WaitSignedApp(ctx, args, output)
}

type stopAfterGRU struct {
	bytes.Buffer
	stop context.CancelFunc
}

func (w *stopAfterGRU) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte(`"state":"gru_ready"`)) {
		w.stop()
	}
	return w.Buffer.Write(data)
}

func globalWaitCases(ctx context.Context, conn *nats.Conn, root, image string, generation int64) {
	lab, close := startWaitLab(conn, root)
	defer close()
	var output bytes.Buffer
	must(lab.wait(ctx, &output, "terrabase", image, "101", ""))
	require(strings.Contains(output.String(), `"state":"gru_ready"`) && strings.Contains(output.String(), `"state":"done"`) &&
		strings.Contains(output.String(), fmt.Sprintf(`"generation":%d`, generation)), "global signed wait lost GRU progress or generation: "+output.String())
	lab.mode.Store(2)
	err := lab.wait(ctx, io.Discard, "terrabase", image, "101", "")
	require(err != nil && strings.Contains(err.Error(), "conflicting signed generation"), fmt.Sprintf("conflicting generation passed: %v", err))
	lab.mode.Store(3)
	err = lab.wait(ctx, io.Discard, "terrabase", image, "101", "")
	require(err != nil && strings.Contains(err.Error(), "sjc undeclared"), fmt.Sprintf("conflicting placement passed: %v", err))
	for _, mode := range []int32{1, 4, 5, 6} {
		lab.mode.Store(mode)
		waiting, cancel := context.WithCancel(ctx)
		progress := &stopAfterGRU{stop: cancel}
		err := lab.wait(waiting, progress, "terrabase", image, "101", "")
		cancel()
		require(err != nil && strings.Contains(err.Error(), "pending in fra") && !strings.Contains(progress.String(), `"state":"done"`),
			fmt.Sprintf("missing or stale FRA evidence (%d) completed: %v %s", mode, err, progress.String()))
	}
	err = lab.wait(ctx, io.Discard, "ts-dashboard", strings.Replace(image, "terrabase@", "terrascale-dashboard@", 1), "101", "gru")
	require(err != nil && strings.Contains(err.Error(), "HTTP 401"), fmt.Sprintf("other workload gained signed observation access: %v", err))
	logStep("signed wait proves a global generation and keeps stale runtime, attempts and conflicting placement from completing")
}

func scopedWaitCases(ctx context.Context, conn *nats.Conn, root, gruRoot string, spec swarmruntime.ServiceSpec) {
	spec.Regions = []string{"gru"}
	spec.Port, spec.Args = 18088, []string{"--port", "18088"}
	release := &mesh.Deployment{Repository: "TerraScale/terrascale", Workflow: waitWorkflow, Image: spec.Image, Revision: revision, RunID: "103", RunAttempt: 1}
	generation := declaration(ctx, conn, &spec, spec.Name, release)
	evidence(ctx, gruRoot, generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() && r.Bake.Reason == "" })
	lab, close := startWaitLab(conn, root)
	defer close()
	var output bytes.Buffer
	must(lab.wait(ctx, &output, spec.Name, spec.Image, "103", "gru"))
	require(strings.Contains(output.String(), `"state":"gru_ready"`) && strings.Contains(output.String(), `"state":"done"`) && strings.Contains(output.String(), `"regions":["gru"]`),
		"scoped wait did not prove only GRU: "+output.String())
	err := lab.wait(ctx, io.Discard, spec.Name, spec.Image, "103", "")
	require(err != nil && strings.Contains(err.Error(), "fra, sjc undeclared") && strings.Contains(err.Error(), fmt.Sprint(generation)), fmt.Sprintf("global wait accepted the GRU-only declaration: %v", err))
	logStep("approved GRU-only signed generation passes scoped wait and the global wait immediately names undeclared FRA and SJC")
}
