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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
const canaryWaitWorkflow = "TerraScale/ts-orchestrator/.github/workflows/app-canary.yml@refs/heads/main"
const rollbackScope = "fra,sjc"

type waitLab struct {
	regions string
	mode    atomic.Int32
	observe func(context.Context, string, string, string) (releasepush.AppReleaseObservation, error)
}

func startWaitLab(conn *nats.Conn, root, workflow string) (*waitLab, func()) {
	lab := &waitLab{regions: filepath.Join(root, "signed-wait-regions.json"), observe: func(ctx context.Context, region, service, nonce string) (releasepush.AppReleaseObservation, error) {
		return mesh.ReadAppRelease(ctx, conn, region, service, nonce)
	}}
	must(os.WriteFile(lab.regions, []byte(`[{"region":"gru"},{"region":"fra"},{"region":"sjc"}]`), 0600))
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	encode := base64.RawURLEncoding.EncodeToString
	repository, _, _ := strings.Cut(workflow, "/.github/")
	trigger := "push"
	if workflow == canaryWaitWorkflow {
		trigger = "workflow_run"
	}
	mint := func() string {
		header := encode([]byte(`{"alg":"RS256","kid":"rollout-wait"}`))
		claims, err := json.Marshal(map[string]any{"iss": "https://token.actions.githubusercontent.com", "aud": "ts-orch",
			"exp": time.Now().Add(time.Minute).Unix(), "repository": repository, "repository_owner": "TerraScale", "ref": "refs/heads/main",
			"sha": revision, "run_id": "101", "run_attempt": "1", "event_name": trigger, "job_workflow_ref": workflow})
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
			proof, err := lab.observe(ctx, region, service, nonce)
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
			case 7:
				proof.CheckedAt = proof.PassedAt.Add(-time.Hour)
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
	lab, close := startWaitLab(conn, root, waitWorkflow)
	defer close()
	var output bytes.Buffer
	must(lab.wait(ctx, &output, "terrabase", image, "101", ""))
	require(strings.Contains(output.String(), `"state":"gru_ready"`) && strings.Contains(output.String(), `"state":"done"`) &&
		strings.Contains(output.String(), fmt.Sprintf(`"generation":%d`, generation)), "global signed wait lost GRU progress or generation: "+output.String())
	type checks struct {
		Checked map[string]time.Time `json:"checked_at"`
	}
	var initial, final checks
	events := json.NewDecoder(&output)
	must(events.Decode(&initial))
	must(events.Decode(&final))
	for _, region := range []string{"fra", "gru", "sjc"} {
		require(!initial.Checked[region].IsZero() && final.Checked[region].After(initial.Checked[region]), "done omitted the newer live check for "+region)
	}
	lab.mode.Store(2)
	err := lab.wait(ctx, io.Discard, "terrabase", image, "101", "")
	require(err != nil && strings.Contains(err.Error(), "conflicting signed generation"), fmt.Sprintf("conflicting generation passed: %v", err))
	lab.mode.Store(3)
	err = lab.wait(ctx, io.Discard, "terrabase", image, "101", "")
	require(err != nil && strings.Contains(err.Error(), "sjc undeclared"), fmt.Sprintf("conflicting placement passed: %v", err))
	for _, mode := range []int32{1, 4, 5, 6, 7} {
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

func freshWaitCase(ctx context.Context, conn *nats.Conn, root, gruAddress, image string, generation int64) {
	lab, cleanup := startWaitLab(conn, root, waitWorkflow)
	defer cleanup()
	defer setHealth(ctx, gruAddress, 18085, "200")
	waiting, cancel := context.WithCancel(ctx)
	defer cancel()
	firstGRU := make(chan struct{})
	var gruProbes, sjcProbes atomic.Int32
	var regression atomic.Bool
	read := lab.observe
	lab.observe = func(ctx context.Context, region, service, nonce string) (releasepush.AppReleaseObservation, error) {
		if region == "sjc" && sjcProbes.Add(1) == 1 {
			select {
			case <-firstGRU:
				setHealth(ctx, gruAddress, 18085, "503")
			case <-ctx.Done():
				return releasepush.AppReleaseObservation{}, ctx.Err()
			}
		}
		proof, err := read(ctx, region, service, nonce)
		if region == "gru" {
			switch gruProbes.Add(1) {
			case 1:
				require(err == nil && proof.ServingGeneration == generation, "initial GRU probe did not prove exact readiness")
				close(firstGRU)
			case 2:
				regression.Store(err == nil && proof.ServingGeneration == 0 && proof.BakeGeneration == generation)
			case 3:
				cancel()
			}
		}
		return proof, err
	}
	var output bytes.Buffer
	err := lab.wait(waiting, &output, "terrabase", image, "101", "")
	require(err != nil && regression.Load() && strings.Contains(output.String(), `"state":"gru_ready"`) &&
		!strings.Contains(output.String(), `"state":"done"`), fmt.Sprintf("the final readiness check missed the GRU regression: %v %s", err, output.String()))
	logStep("after GRU stops serving during SJC's initial probe, final revalidation finds GRU unready at the same signed generation")
}

func heldWaitCases(ctx context.Context, conn *nats.Conn, root, image, heldRegion string, generation int64) {
	lab, cleanup := startWaitLab(conn, root, waitWorkflow)
	defer cleanup()
	newer, cancel := context.WithCancel(ctx)
	defer cancel()
	var heldProbes atomic.Int32
	read := lab.observe
	lab.observe = func(ctx context.Context, region, service, nonce string) (releasepush.AppReleaseObservation, error) {
		proof, err := read(ctx, region, service, nonce)
		if region == heldRegion && heldProbes.Add(1) == 3 {
			cancel()
		}
		return proof, err
	}
	err := lab.wait(ctx, io.Discard, "terrabase", image, "102", "")
	expected := fmt.Sprintf("%s: terrabase signed run 102 attempt 1 generation %d held at failed bake:", heldRegion, generation)
	require(err != nil && strings.Contains(err.Error(), expected), fmt.Sprintf("signed failure did not name its region and release: %v", err))
	err = lab.wait(newer, io.Discard, "terrabase", image, "103", "")
	require(errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "held at failed bake"),
		fmt.Sprintf("older signed failure ended the newer wait: %v", err))
	logStep("held signed bake fails the exact wait and leaves the newer run pending")
}

func scopedWaitCases(ctx context.Context, conn *nats.Conn, root, gruRoot, gruNamespace, launcher string, spec swarmruntime.ServiceSpec) {
	spec.Regions = []string{"gru"}
	spec.Port, spec.Args = 18088, []string{"--port", "18088"}
	spec.Image = "ghcr.io/terrascale/" + spec.Image
	path := filepath.Join(gruRoot, "scoped-wait.json")
	data, err := json.Marshal(spec)
	must(err)
	must(os.WriteFile(path, data, 0600))
	applied, err := serviceCLI(ctx, gruNamespace, launcher, gruRoot, "apply", "-f", path)
	require(err == nil, fmt.Sprintf("operator could not declare GRU placement: %v %s", err, applied))
	baseline := newGeneration(states(ctx, conn), "gru")
	selectServiceAt(ctx, gruRoot, gruNamespace, spec.Image, "103", spec.Name)
	observe(ctx, conn, func(map[string]state) bool {
		result := selectionResult(gruRoot, "103")
		require(result.State != "failed", "approved GRU-only host pull failed: "+result.Error)
		return result.State == "done"
	})
	generation := newGeneration(states(ctx, conn), "gru")
	require(generation > baseline, "host pull did not replace the operator generation")
	lab, close := startWaitLab(conn, root, waitWorkflow)
	defer close()
	var output bytes.Buffer
	must(lab.wait(ctx, &output, spec.Name, spec.Image, "103", "gru"))
	require(strings.Contains(output.String(), `"state":"gru_ready"`) && strings.Contains(output.String(), `"state":"done"`) && strings.Contains(output.String(), `"regions":["gru"]`),
		"scoped wait did not prove only GRU: "+output.String())
	err = lab.wait(ctx, io.Discard, spec.Name, spec.Image, "103", "")
	require(err != nil && strings.Contains(err.Error(), "fra, sjc undeclared") && strings.Contains(err.Error(), fmt.Sprint(generation)), fmt.Sprintf("global wait accepted the GRU-only declaration: %v", err))
	logStep("operator GRU placement survives verified host pull; scoped wait passes and global wait immediately names undeclared FRA and SJC")
}

func rollbackWaitCase(ctx context.Context, conn *nats.Conn, root, namespace, image, region string) {
	const canary, run = "app-canary", "206"
	image = strings.Replace(image, "terrabase@", "app-canary@", 1)
	denyReadiness := func(operation string) {
		output, err := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "iptables", operation, "OUTPUT", "-p", "tcp", "--dport", "8097", "-j", "REJECT").CombinedOutput()
		require(err == nil, fmt.Sprintf("canary readiness isolation: %v %s", err, output))
	}
	denyReadiness("-I")
	defer denyReadiness("-D")
	selectServiceAt(ctx, root, namespace, image, run, canary)
	client, control, err := swarmruntime.DialControl(root)
	must(err)
	defer control.Close()
	var failedGeneration int64
	observe(ctx, conn, func(map[string]state) bool {
		rows, err := swarmruntime.ListServiceSpecs(ctx, client)
		must(err)
		for _, row := range rows {
			if row.Name == canary && row.Generation > 0 {
				failedGeneration = row.Generation
				return true
			}
		}
		return false
	})
	must(swarmruntime.RemoveServiceSpec(ctx, client, canary))
	observe(ctx, conn, func(map[string]state) bool {
		result := selectionResult(root, run)
		if result.State == "accepted" {
			return false
		}
		require(result.State == "failed" && strings.Contains(result.Error, "rolled back to absence"), "signed canary did not roll back to absence: "+result.Error)
		return true
	})
	proof, err := mesh.ReadAppRelease(ctx, conn, region, canary, strings.Repeat("a", 64))
	must(err)
	require(proof.Release != nil && proof.Release.RunID == run && proof.Placement != nil && proof.Placement.RollbackOf == failedGeneration && !proof.Declared,
		fmt.Sprintf("regional rollback lost signed identity or ancestry: %+v", proof))
	lab, cleanup := startWaitLab(conn, root, canaryWaitWorkflow)
	defer cleanup()
	err = lab.wait(ctx, io.Discard, canary, image, run, rollbackScope)
	expected := fmt.Sprintf("%s: app-canary signed run %s attempt 1 generation %d rolled back to absence in generation %d", region, run, proof.Placement.RollbackOf, proof.Placement.Generation)
	require(err != nil && strings.Contains(err.Error(), expected), fmt.Sprintf("signed waiter did not report the actual rollback: %v", err))
	logStep("verified signed canary rolls back to absence and the scoped wait returns its exact regional rollback ancestry")
}
