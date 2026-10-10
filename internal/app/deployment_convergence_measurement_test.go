package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

const (
	deploymentConvergenceOptIn = "TS_ORCH_RUN_DEPLOYMENT_CONVERGENCE_MEASUREMENT"
	convergenceWarmupCount     = 5
	convergenceSampleCount     = 30
	convergencePollInterval    = 100 * time.Millisecond
)

// TestDeploymentConvergenceMeasurement is an opt-in, sequential app-boundary
// measurement using the real signed operator -> embedded JetStream -> host.Agent
// caller fixture. Its runner intentionally has in-memory semantics: it records
// the desired digest as running and does not launch an OS process.
//
// Run only on a frozen source tree with the local VM/lab idle:
// TS_ORCH_RUN_DEPLOYMENT_CONVERGENCE_MEASUREMENT=1 go test ./internal/app -run '^TestDeploymentConvergenceMeasurement$' -count=1 -v
// The reported duration starts immediately before operator deploy and ends
// when the host agent's runner has applied the matching digest. It includes
// the agent's 100 ms reconciliation poll, but excludes process startup, TLS,
// VM startup, and the later durable running receipt.
func TestDeploymentConvergenceMeasurement(t *testing.T) {
	if os.Getenv(deploymentConvergenceOptIn) != "1" {
		t.Skipf("opt-in measurement; set %s=1 on an idle lab host", deploymentConvergenceOptIn)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	var controllerDone, agentDone *convergenceTask
	var hostRuntime *natscell.Runtime
	root := t.TempDir()
	t.Cleanup(func() {
		cancel()
		waitForConvergenceFixtureExit(t, "host agent", agentDone)
		if hostRuntime != nil {
			if err := hostRuntime.Close(); err != nil {
				t.Errorf("close host NATS runtime: %v", err)
			}
		}
		waitForConvergenceFixtureExit(t, "controller", controllerDone)
	})
	portListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portListener.Addr().(*net.TCPAddr).Port
	if err := portListener.Close(); err != nil {
		t.Fatal(err)
	}

	controllerNKey, controllerSeed := testNKey(t)
	operatorNKey, operatorSeed := testNKey(t)
	hostNKey, hostSeed := testNKey(t)
	controllerPublic, _ := testEd25519(t, root, "controller.key")
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	hostPublic, hostPrivate := testEd25519(t, root, "host.key")
	grant := TrustedSignerConfig{
		Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"test"}, CanRegisterHosts: true, CanPlaceTerraBase: true,
	}
	controllerConfig := Config{Version: ConfigVersion,
		NATS: natscell.Config{
			Cell: "gru", Instance: "one", Replicas: 1, Lab: true, NKeySeedFile: controllerSeed,
			Embedded: &natscell.Embedded{
				Host: "127.0.0.1", Port: port, StoreDir: filepath.Join(root, "nats"), StoreMaxBytes: 4 << 30,
				Users: []natscell.NKeyGrant{
					{PublicKey: controllerNKey, Role: "controller"},
					{PublicKey: operatorNKey, Role: "operator"},
					{PublicKey: hostNKey, Role: "host", Node: "node-a"},
				},
			},
		},
		Controller: ControllerConfig{
			CandidateID: "0000000000DV8998ZCQW1J2V2R", ResponseKeyFile: filepath.Join(root, "controller.key"),
			ArtifactStoreMaxBytes: 64 << 20, TrustedSigners: []TrustedSignerConfig{grant},
			Workloads: map[string]WorkloadProfile{
				"terrabase": {Resources: placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20}},
			},
		},
	}
	controllerConfigPath := testJSONFile(t, root, "controller.json", controllerConfig)
	controllerOutput := &readyWriter{ready: make(chan struct{})}
	controllerDone = newConvergenceTask()
	go func() {
		controllerDone.finish(Run(ctx, []string{"run", "--config", controllerConfigPath}, controllerOutput))
	}()
	select {
	case <-controllerOutput.ready:
	case <-controllerDone.done:
		t.Fatalf("controller exited before ready: %v", controllerDone.result())
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	operatorConfig := Config{Version: ConfigVersion,
		NATS: natscell.Config{
			Cell: "gru", Instance: "operator", Replicas: 1, Lab: true,
			URL: fmt.Sprintf("nats://127.0.0.1:%d", port), NKeySeedFile: operatorSeed,
		},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "operator.key")},
	}
	operatorConfigPath := testJSONFile(t, root, "operator.json", operatorConfig)
	registration := host.Registration{
		Cell: "gru", Node: "node-a", Environment: "test", Roles: []string{"terrabase"},
		PublicKey: base64.StdEncoding.EncodeToString(hostPublic), NATSUserPublicKey: hostNKey, Generation: 1,
		Capacity: host.Capacity{CPU: 2, MemoryBytes: 256 << 20, DiskBytes: 512 << 20},
	}
	registrationPath := testJSONFile(t, root, "registration.json", registration)
	var output bytes.Buffer
	if err := Run(ctx, []string{"operator", "host-register", "--config", operatorConfigPath, "--registration", registrationPath}, &output); err != nil {
		t.Fatalf("signed host registration: %v", err)
	}
	var registrationReceipt host.Receipt
	if err := json.Unmarshal(output.Bytes(), &registrationReceipt); err != nil || registrationReceipt.Generation != 1 {
		t.Fatalf("registration receipt: %v: %s", err, output.String())
	}

	hostRuntime, err = natscell.Start(ctx, natscell.Config{
		Cell: "gru", Instance: "host-a", Replicas: 1, Lab: true,
		URL: operatorConfig.NATS.URL, NKeySeedFile: hostSeed, ClientRole: "host",
	})
	if err != nil {
		t.Fatal(err)
	}
	runner := newConvergenceMemoryRunner()
	clock := &testBrokerClock{}
	clock.healthy.Store(true)
	agent, err := host.NewAgent(host.AgentConfig{
		WorkloadIdentity: testHostWorkloadIdentity(),
		Cell:             "gru", Node: "node-a", Environment: "test", Roles: []string{"terrabase"},
		Conn: hostRuntime.Conn(), Identity: hostPrivate, NATSUserPublicKey: hostNKey, ControllerPublicKey: controllerPublic, Runner: runner,
		InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t),
		PollInterval: convergencePollInterval, ClockCheck: controllerClockCheck(clock),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentDone = newConvergenceTask()
	go func() { agentDone.finish(agent.Run(ctx)) }()
	waitForConvergenceHostSession(t, ctx, agentDone, operatorConfigPath, &output)

	source := delivery.ArtifactSource{
		Repository: "https://example.com/terrascale/terrabase",
		Commit:     strings.Repeat("a", 40),
		TreeDigest: strings.Repeat("b", 64),
	}
	artifacts := admitConvergenceArtifacts(t, ctx, root, operatorConfigPath, source, &output)
	for _, artifact := range artifacts {
		if err := runner.Expect(artifact.Digest); err != nil {
			t.Fatal(err)
		}
	}

	intentPaths := make([]string, len(artifacts))
	provenance := collectConvergenceProvenance(t)
	if len(provenance.DirtyPaths) != 0 {
		t.Fatalf("refusing measurement with dirty source paths: %s", strings.Join(provenance.DirtyPaths, ", "))
	}
	for index, artifact := range artifacts {
		intent := delivery.Intent{
			Source: source, ArtifactDigest: artifact.Digest, ManifestDigest: artifact.ManifestDigest,
			Cell: "gru", Role: "terrabase", Environment: "test", Generation: uint64(index + 1),
			DesiredReplicas: 1, ConfigDigest: delivery.ConfigDigestOf(nil, nil, nil),
			OperationID: entityid.Derive("test-convergence", fmt.Sprint(index+1)),
		}
		intentPaths[index] = testJSONFile(t, root, fmt.Sprintf("intent-%03d.json", index+1), intent)
	}

	warmups := make([]deploymentConvergenceSample, 0, convergenceWarmupCount)
	samples := make([]deploymentConvergenceSample, 0, convergenceSampleCount)
	for index, artifact := range artifacts {
		generation := uint64(index + 1)
		if err := runner.Arm(artifact.Digest, generation); err != nil {
			t.Fatal(err)
		}
		output.Reset()
		started := time.Now()
		if err := Run(ctx, []string{
			"operator", "deploy", "--config", operatorConfigPath, "--intent", intentPaths[index],
		}, &output); err != nil {
			t.Fatalf("submit deployment generation %d: %v", generation, err)
		}
		var submitted struct {
			OperationID string `json:"operationId"`
			Fingerprint string `json:"fingerprint"`
			Status      string `json:"status"`
		}
		if err := json.Unmarshal(output.Bytes(), &submitted); err != nil ||
			submitted.OperationID != fmt.Sprintf("convergence-%03d", generation) ||
			submitted.Fingerprint == "" || submitted.Status != "submitted" {
			t.Fatalf("submit receipt for generation %d: %v: %s", generation, err, output.String())
		}

		applyCtx, cancelApply := context.WithTimeout(ctx, 15*time.Second)
		completion, err := runner.Wait(applyCtx, agentDone, artifact.Digest)
		cancelApply()
		if err != nil {
			t.Fatalf("wait for generation %d Apply completion: %v", generation, err)
		}
		elapsed := completion.At.Sub(started)
		observed, err := runner.Observe(ctx, "terrabase")
		if err != nil || !observed.Running || observed.Digest != artifact.Digest ||
			completion.Digest != artifact.Digest || completion.Generation != generation ||
			completion.Fingerprint == "" || completion.Fingerprint != observed.Fingerprint {
			t.Fatalf("generation %d Apply mismatch: completion=%+v observation=%+v err=%v", generation, completion, observed, err)
		}
		if elapsed <= 0 {
			t.Fatalf("generation %d convergence duration is not positive: %s", generation, elapsed)
		}
		if err := waitForConvergenceAccepted(t, ctx, agentDone, operatorConfigPath, submitted.OperationID, submitted.Fingerprint, artifact, generation, &output); err != nil {
			t.Fatalf("generation %d accepted receipt: %v", generation, err)
		}
		sample := deploymentConvergenceSample{
			OperationID: submitted.OperationID, ArtifactDigest: artifact.Digest,
			Generation: generation, ApplyFingerprint: completion.Fingerprint,
			DurationNS: elapsed.Nanoseconds(),
		}
		if index < convergenceWarmupCount {
			warmups = append(warmups, sample)
		} else {
			samples = append(samples, sample)
		}
	}

	// Allow one additional reconciliation tick to expose duplicate Apply calls.
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(convergencePollInterval + 50*time.Millisecond):
	}
	if err := runner.ValidateCounts(); err != nil {
		t.Fatal(err)
	}
	if len(warmups) != convergenceWarmupCount || len(samples) != convergenceSampleCount {
		t.Fatalf("successful samples: warmups=%d measured=%d, want %d and %d", len(warmups), len(samples), convergenceWarmupCount, convergenceSampleCount)
	}

	if finalProvenance := collectConvergenceProvenance(t); !sameConvergenceSource(provenance, finalProvenance) {
		t.Fatalf("source changed during measurement: before=%+v after=%+v", provenance, finalProvenance)
	}
	result := deploymentConvergenceResult{
		Schema:    "ts-orchestrator.deployment-convergence.v1",
		Semantics: "time from before operator deploy invocation through matching digest completion of host.Agent Runner.Apply; measured runner is in-memory and does not start an OS process",
		Source:    provenance,
		Config: deploymentConvergenceConfig{
			Cell: "gru", Controllers: 1, Hosts: 1, EmbeddedNATS: true, NATSReplicas: 1,
			NKeyAuthenticated: true, LabMode: true, TLS: false, HostPollIntervalNS: int64(convergencePollInterval),
			JetStreamStore: "file-backed in per-test temporary directory", VMCount: 0,
			Runner: "in-memory observation runner; no process creation", OutstandingDeployments: 1,
			Warmups: convergenceWarmupCount, MeasuredSamples: convergenceSampleCount,
			DistinctPreAdmittedArtifacts: len(artifacts),
			ContentionAssumption:         "no concurrent builds, tests, staging, or VM/lab workload",
		},
		WarmupSuccesses: len(warmups), MeasuredSuccesses: len(samples),
		WarmupSamples: warmups, Samples: samples,
		Summary: summarizeConvergenceSamples(samples),
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	t.Logf("DEPLOYMENT_CONVERGENCE_RESULT=%s", encoded)
}

type convergenceExpectation struct {
	completion chan convergenceApply
	count      int
}

type convergenceApply struct {
	Digest      string
	Fingerprint string
	Generation  uint64
	At          time.Time
}

// convergenceMemoryRunner preserves the existing inMemoryRunner behavior while
// recording the exact callback completion and rejecting unexpected or repeated
// applies. It is test instrumentation only, not a production hook.
type convergenceMemoryRunner struct {
	mu           sync.Mutex
	expectations map[string]*convergenceExpectation
	activeDigest string
	activeGen    uint64
	observed     host.Observation
	violation    error
	violated     chan error
}

func newConvergenceMemoryRunner() *convergenceMemoryRunner {
	return &convergenceMemoryRunner{
		expectations: make(map[string]*convergenceExpectation),
		violated:     make(chan error, 1),
	}
}

func (r *convergenceMemoryRunner) Recover(context.Context) error { return nil }

func (r *convergenceMemoryRunner) Apply(_ context.Context, workload host.Workload) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	expectation, ok := r.expectations[workload.Digest]
	if !ok || workload.Digest != r.activeDigest || workload.Role != "terrabase" {
		return r.recordViolationLocked(fmt.Errorf("unexpected Apply role=%q digest=%q active=%q", workload.Role, workload.Digest, r.activeDigest))
	}
	if expectation.count != 0 {
		return r.recordViolationLocked(fmt.Errorf("duplicate Apply for digest %s generation %d", workload.Digest, r.activeGen))
	}
	r.observed = host.Observation{
		Role: workload.Role, Digest: workload.Digest, Fingerprint: workload.Fingerprint,
		Running: true, PID: 1,
	}
	completion := convergenceApply{
		Digest: workload.Digest, Fingerprint: workload.Fingerprint,
		Generation: r.activeGen, At: time.Now(),
	}
	expectation.count++
	expectation.completion <- completion
	return nil
}

func (r *convergenceMemoryRunner) Stop(_ context.Context, role string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observed = host.Observation{Role: role}
	return nil
}

func (r *convergenceMemoryRunner) Observe(_ context.Context, _ string) (host.Observation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.observed, nil
}

func (*convergenceMemoryRunner) Close(context.Context) error { return nil }

func (r *convergenceMemoryRunner) Expect(digest string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if digest == "" {
		return errors.New("cannot expect an empty artifact digest")
	}
	if _, exists := r.expectations[digest]; exists {
		return fmt.Errorf("artifact digest is not distinct: %s", digest)
	}
	r.expectations[digest] = &convergenceExpectation{completion: make(chan convergenceApply, 1)}
	return nil
}

func (r *convergenceMemoryRunner) Arm(digest string, generation uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.violation != nil {
		return r.violation
	}
	if r.activeDigest != "" {
		previous := r.expectations[r.activeDigest]
		if previous == nil || previous.count != 1 {
			return fmt.Errorf("cannot arm generation %d before prior generation %d completed exactly once", generation, r.activeGen)
		}
	}
	next := r.expectations[digest]
	if next == nil || next.count != 0 {
		return fmt.Errorf("generation %d has missing or previously applied digest %q", generation, digest)
	}
	r.activeDigest, r.activeGen = digest, generation
	return nil
}

func (r *convergenceMemoryRunner) Wait(ctx context.Context, agentDone *convergenceTask, digest string) (convergenceApply, error) {
	r.mu.Lock()
	expectation := r.expectations[digest]
	violation := r.violation
	r.mu.Unlock()
	if violation != nil {
		return convergenceApply{}, violation
	}
	if expectation == nil {
		return convergenceApply{}, fmt.Errorf("no Apply expectation registered for digest %s", digest)
	}
	select {
	case completion := <-expectation.completion:
		return completion, nil
	case err := <-r.violated:
		return convergenceApply{}, err
	case <-agentDone.done:
		return convergenceApply{}, fmt.Errorf("host agent exited before matching Apply: %w", agentDone.result())
	case <-ctx.Done():
		return convergenceApply{}, ctx.Err()
	}
}

func (r *convergenceMemoryRunner) ValidateCounts() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.violation != nil {
		return r.violation
	}
	for digest, expectation := range r.expectations {
		if expectation.count != 1 {
			return fmt.Errorf("digest %s Apply count=%d, want exactly one", digest, expectation.count)
		}
	}
	return nil
}

func (r *convergenceMemoryRunner) recordViolationLocked(err error) error {
	if r.violation == nil {
		r.violation = err
		select {
		case r.violated <- err:
		default:
		}
	}
	return err
}

type convergenceTask struct {
	done chan struct{}
	mu   sync.Mutex
	err  error
}

func newConvergenceTask() *convergenceTask {
	return &convergenceTask{done: make(chan struct{})}
}

func (task *convergenceTask) finish(err error) {
	task.mu.Lock()
	task.err = err
	task.mu.Unlock()
	close(task.done)
}

func (task *convergenceTask) result() error {
	task.mu.Lock()
	defer task.mu.Unlock()
	return task.err
}

func waitForConvergenceFixtureExit(t *testing.T, name string, task *convergenceTask) {
	t.Helper()
	if task == nil {
		return
	}
	select {
	case <-task.done:
		err := task.result()
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("%s shutdown: %v", name, err)
		}
	case <-time.After(10 * time.Second):
		t.Errorf("%s did not stop after cancellation", name)
	}
}

func waitForConvergenceHostSession(t *testing.T, ctx context.Context, agentDone *convergenceTask, operatorConfigPath string, output *bytes.Buffer) {
	t.Helper()
	for {
		output.Reset()
		if err := Run(ctx, []string{"operator", "hosts", "--config", operatorConfigPath}, output); err == nil {
			var statuses []host.HostStatus
			if json.Unmarshal(output.Bytes(), &statuses) == nil && len(statuses) == 1 && !statuses[0].SessionExpiresAt.IsZero() {
				return
			}
		}
		select {
		case <-agentDone.done:
			t.Fatalf("host agent exited before session: %v", agentDone.result())
		case <-ctx.Done():
			t.Fatal("host did not establish a session:", ctx.Err())
		case <-time.After(convergencePollInterval):
		}
	}
}

func admitConvergenceArtifacts(t *testing.T, ctx context.Context, root, operatorConfigPath string, source delivery.ArtifactSource, output *bytes.Buffer) []delivery.ArtifactRecord {
	t.Helper()
	artifacts := make([]delivery.ArtifactRecord, 0, convergenceWarmupCount+convergenceSampleCount)
	for index := range convergenceWarmupCount + convergenceSampleCount {
		body := []byte(fmt.Sprintf("#!/bin/sh\n# convergence sample %03d\nsleep 30\n", index+1))
		artifactPath := filepath.Join(root, fmt.Sprintf("guest-%03d", index+1))
		if err := os.WriteFile(artifactPath, body, 0o755); err != nil {
			t.Fatal(err)
		}
		output.Reset()
		if err := Run(ctx, []string{
			"operator", "artifact-push", "--config", operatorConfigPath, "--file", artifactPath,
			"--repository", source.Repository, "--commit", source.Commit, "--tree-digest", source.TreeDigest,
			"--role", "terrabase", "--environment", "test",
		}, output); err != nil {
			t.Fatalf("pre-admit artifact %d: %v", index+1, err)
		}
		var record delivery.ArtifactRecord
		if err := json.Unmarshal(output.Bytes(), &record); err != nil {
			t.Fatalf("decode admitted artifact %d: %v: %s", index+1, err, output.String())
		}
		if record.Digest == "" || record.ManifestDigest == "" || record.Size != int64(len(body)) {
			t.Fatalf("invalid artifact record %d: %+v", index+1, record)
		}
		if index > 0 && slices.ContainsFunc(artifacts, func(previous delivery.ArtifactRecord) bool {
			return previous.Digest == record.Digest
		}) {
			t.Fatalf("artifact %d repeated an existing digest %s", index+1, record.Digest)
		}
		artifacts = append(artifacts, record)
	}
	return artifacts
}

func waitForConvergenceAccepted(t *testing.T, ctx context.Context, agentDone *convergenceTask, operatorConfigPath, operationID, fingerprint string, artifact delivery.ArtifactRecord, generation uint64, output *bytes.Buffer) error {
	t.Helper()
	for {
		output.Reset()
		err := Run(ctx, []string{
			"operator", "status", "--config", operatorConfigPath,
			"--operation-id", operationID, "--fingerprint", fingerprint,
		}, output)
		if err == nil {
			var receipt delivery.Receipt
			if json.Unmarshal(output.Bytes(), &receipt) == nil && receipt.Status == "accepted" {
				if receipt.OperationID != operationID || receipt.Fingerprint != fingerprint ||
					receipt.ArtifactDigest != artifact.Digest || receipt.ManifestDigest != artifact.ManifestDigest ||
					receipt.Generation != generation {
					return fmt.Errorf("accepted receipt does not match desired generation: %+v", receipt)
				}
				return nil
			}
		}
		select {
		case <-agentDone.done:
			return fmt.Errorf("host agent exited before acceptance: %w", agentDone.result())
		case <-ctx.Done():
			return fmt.Errorf("delivery did not reach accepted: %w; output=%s; command error=%v", ctx.Err(), output.String(), err)
		case <-time.After(convergencePollInterval):
		}
	}
}

func collectConvergenceProvenance(t *testing.T) deploymentConvergenceProvenance {
	t.Helper()
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("Go build information is unavailable")
	}
	revision := convergenceGitOutput(t, "rev-parse", "HEAD")
	tree := convergenceGitOutput(t, "rev-parse", "HEAD^{tree}")
	status := convergenceGitOutput(t, "status", "--porcelain=v1", "--untracked-files=normal")
	dirtyPaths := make([]string, 0)
	for line := range strings.SplitSeq(status, "\n") {
		if strings.TrimSpace(line) != "" {
			if len(line) >= 3 {
				dirtyPaths = append(dirtyPaths, strings.TrimSpace(line[3:]))
			} else {
				dirtyPaths = append(dirtyPaths, line)
			}
		}
	}
	modules := make(map[string]string)
	for _, dependency := range buildInfo.Deps {
		if dependency.Replace != nil {
			modules[dependency.Path] = fmt.Sprintf("%s => %s@%s", dependency.Version, dependency.Replace.Path, dependency.Replace.Version)
		} else {
			modules[dependency.Path] = dependency.Version
		}
	}
	cpuModel := convergenceCPUModel()
	measurementSource, err := os.ReadFile("deployment_convergence_measurement_test.go")
	if err != nil {
		t.Fatalf("read measurement source for provenance: %v", err)
	}
	measurementSourceHash := sha256.Sum256(measurementSource)
	return deploymentConvergenceProvenance{
		Revision: revision, Tree: tree, DirtyPaths: dirtyPaths,
		MeasurementFileSHA256: hex.EncodeToString(measurementSourceHash[:]),
		GoVersion:             buildInfo.GoVersion, RuntimeVersion: runtime.Version(),
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, NumCPU: runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0), GOMAXPROCSSetting: os.Getenv("GOMAXPROCS"),
		CPUModel: cpuModel, GOTOOLCHAIN: os.Getenv("GOTOOLCHAIN"), Modules: modules,
	}
}

func sameConvergenceSource(first, second deploymentConvergenceProvenance) bool {
	return first.Revision == second.Revision && first.Tree == second.Tree &&
		first.MeasurementFileSHA256 == second.MeasurementFileSHA256 &&
		slices.Equal(first.DirtyPaths, second.DirtyPaths)
}

func convergenceGitOutput(t *testing.T, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(output))
}

func convergenceCPUModel() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, found := strings.Cut(line, ":")
		if found && (strings.TrimSpace(key) == "model name" || strings.TrimSpace(key) == "Hardware" || strings.TrimSpace(key) == "Processor") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

type deploymentConvergenceProvenance struct {
	Revision              string            `json:"revision"`
	Tree                  string            `json:"tree"`
	MeasurementFileSHA256 string            `json:"measurement_file_sha256"`
	DirtyPaths            []string          `json:"dirty_paths"`
	GoVersion             string            `json:"go_version"`
	RuntimeVersion        string            `json:"runtime_version"`
	GOOS                  string            `json:"goos"`
	GOARCH                string            `json:"goarch"`
	NumCPU                int               `json:"num_cpu"`
	GOMAXPROCS            int               `json:"gomaxprocs"`
	GOMAXPROCSSetting     string            `json:"gomaxprocs_setting"`
	CPUModel              string            `json:"cpu_model"`
	GOTOOLCHAIN           string            `json:"gotoolchain"`
	Modules               map[string]string `json:"modules"`
}

type deploymentConvergenceConfig struct {
	Cell                         string `json:"cell"`
	Controllers                  int    `json:"controllers"`
	Hosts                        int    `json:"hosts"`
	EmbeddedNATS                 bool   `json:"embedded_nats"`
	NATSReplicas                 int    `json:"nats_replicas"`
	NKeyAuthenticated            bool   `json:"nkey_authenticated"`
	LabMode                      bool   `json:"lab_mode"`
	TLS                          bool   `json:"tls"`
	HostPollIntervalNS           int64  `json:"host_poll_interval_ns"`
	JetStreamStore               string `json:"jetstream_store"`
	VMCount                      int    `json:"vm_count"`
	Runner                       string `json:"runner"`
	OutstandingDeployments       int    `json:"outstanding_deployments"`
	Warmups                      int    `json:"warmups"`
	MeasuredSamples              int    `json:"measured_samples"`
	DistinctPreAdmittedArtifacts int    `json:"distinct_pre_admitted_artifacts"`
	ContentionAssumption         string `json:"contention_assumption"`
}

type deploymentConvergenceSample struct {
	OperationID      string `json:"operation_id"`
	ArtifactDigest   string `json:"artifact_digest"`
	Generation       uint64 `json:"generation"`
	ApplyFingerprint string `json:"apply_fingerprint"`
	DurationNS       int64  `json:"duration_ns"`
}

type deploymentConvergenceSummary struct {
	Method string `json:"method"`
	P50NS  int64  `json:"p50_ns"`
	P95NS  int64  `json:"p95_ns"`
	MaxNS  int64  `json:"max_ns"`
}

type deploymentConvergenceResult struct {
	Schema            string                          `json:"schema"`
	Semantics         string                          `json:"semantics"`
	Source            deploymentConvergenceProvenance `json:"source"`
	Config            deploymentConvergenceConfig     `json:"config"`
	WarmupSuccesses   int                             `json:"warmup_successes"`
	MeasuredSuccesses int                             `json:"measured_successes"`
	WarmupSamples     []deploymentConvergenceSample   `json:"warmup_samples"`
	Samples           []deploymentConvergenceSample   `json:"samples"`
	Summary           deploymentConvergenceSummary    `json:"summary"`
}

func summarizeConvergenceSamples(samples []deploymentConvergenceSample) deploymentConvergenceSummary {
	durations := make([]int64, len(samples))
	for index, sample := range samples {
		durations[index] = sample.DurationNS
	}
	slices.Sort(durations)
	median := durations[len(durations)/2-1] + (durations[len(durations)/2]-durations[len(durations)/2-1])/2
	p95Rank := (95*len(durations) + 99) / 100
	return deploymentConvergenceSummary{
		Method: "p50 median (mean of middle pair for even n); p95 nearest-rank ceil(0.95*n); max observed",
		P50NS:  median, P95NS: durations[p95Rank-1], MaxNS: durations[len(durations)-1],
	}
}
