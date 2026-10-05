package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
)

// TestTerraBaseReleaseDeployUpgradeRollback drives `operator terrabase-release`
// against an in-process controller and a host agent that launches the real
// C# TerraBase release binary: the first release passes the readiness gate,
// a second digest upgrades the member, and a release that never answers
// /healthz fails the gate and is rolled back to the previous digest.
//
// TS_TERRABASE_BINARY names a terrabase-linux-<arch> release asset with its
// .sha256 asset beside it. The host runs the member as a plain child process;
// the cgroup runner's drain has its own root-only test.
func TestTerraBaseReleaseDeployUpgradeRollback(t *testing.T) {
	release := tier.Qualification(t, "TS_TERRABASE_BINARY")[0]
	if _, err := terrabase.VerifyRelease(release, release+".sha256"); err != nil {
		t.Fatal(err)
	}
	testTerraBaseRelease(t, release, false)
}

// TestTerraBaseReleaseGateWithFakeMember runs the same scenario with an
// in-process stand-in for the binary: it serves /healthz on the admin port
// only when the host prepared its data directory and a member certificate
// that chains to the cell CA, and only for releases that are not broken.
func TestTerraBaseReleaseGateWithFakeMember(t *testing.T) {
	release := writeTerraBaseRelease(t, filepath.Join(t.TempDir(), "fake"), []byte(fakeTerraBaseMagic))
	testTerraBaseRelease(t, release, true)
}

// fakeTerraBaseMagic starts every release the fake member serves: the ELF
// header of an executable for this machine, the one the asset name states.
var fakeTerraBaseMagic = func() string {
	header := elf.Header64{Type: uint16(elf.ET_EXEC), Version: uint32(elf.EV_CURRENT), Ehsize: 64,
		Machine: uint16(map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[runtime.GOARCH])}
	copy(header.Ident[:], elf.ELFMAG)
	header.Ident[elf.EI_CLASS], header.Ident[elf.EI_DATA], header.Ident[elf.EI_VERSION] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, header)
	return b.String() + " fake terrabase"
}()

func testTerraBaseRelease(t *testing.T, release string, fake bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	root := t.TempDir()
	port, adminPort, peerPort := freeTCPPort(t), freeTCPPort(t), freeTCPPort(t)
	controllerNKey, controllerSeed := testNKey(t)
	operatorNKey, operatorSeed := testNKey(t)
	hostNKey, hostSeed := testNKey(t)
	controllerPublic, _ := testEd25519(t, root, "controller.key")
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	hostPublic, hostPrivate := testEd25519(t, root, "host.key")
	var output bytes.Buffer
	if err := terrabase.Run(ctx, []string{"member-ca", "--cell", "gru", "--out", filepath.Join(root, "ca")}, &output); err != nil {
		t.Fatal(err)
	}
	profile := WorkloadProfile{Resources: placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20},
		Env: map[string]string{terrabase.EnvAdminPort: strconv.Itoa(adminPort), terrabase.EnvPeerPort: strconv.Itoa(peerPort),
			terrabase.EnvPeers: fmt.Sprintf("node-a=127.0.0.1:%d", peerPort)}}
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"test"}, CanRegisterHosts: true,
		Repositories: []string{terrabase.Repository}}
	controllerConfigPath := testJSONFile(t, root, "controller.json", Config{
		NATS: natscell.Config{Cell: "gru", Instance: "one", Replicas: 1, Lab: true, NKeySeedFile: controllerSeed,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: port, StoreDir: filepath.Join(root, "nats"), StoreMaxBytes: 2 << 30,
				Users: []natscell.NKeyGrant{{PublicKey: controllerNKey, Role: "controller"}, {PublicKey: operatorNKey, Role: "operator"},
					{PublicKey: hostNKey, Role: "host", Node: "node-a"}}}},
		Controller: ControllerConfig{CandidateID: "one", ResponseKeyFile: filepath.Join(root, "controller.key"),
			ArtifactStoreMaxBytes: 512 << 20, TrustedSigners: []TrustedSignerConfig{grant},
			Workloads:           map[string]WorkloadProfile{"terrabase": profile},
			TerraBaseCACertFile: filepath.Join(root, "ca", "member-ca.pem"), TerraBaseCAKeyFile: filepath.Join(root, "ca", "member-ca.key")},
	})
	controllerOutput := &readyWriter{ready: make(chan struct{})}
	controllerDone := make(chan error, 1)
	go func() {
		controllerDone <- Run(ctx, []string{"run", "--config", controllerConfigPath}, controllerOutput)
	}()
	select {
	case <-controllerOutput.ready:
	case err := <-controllerDone:
		t.Fatalf("controller exited before ready: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	operatorConfig := Config{NATS: natscell.Config{Cell: "gru", Instance: "operator", Replicas: 1, Lab: true,
		URL: fmt.Sprintf("nats://127.0.0.1:%d", port), NKeySeedFile: operatorSeed},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "operator.key")}}
	operatorConfigPath := testJSONFile(t, root, "operator.json", operatorConfig)
	registrationPath := testJSONFile(t, root, "registration.json", host.Registration{Cell: "gru", Node: "node-a",
		Environment: "test", Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(hostPublic),
		NATSUserPublicKey: hostNKey, Generation: 1, Capacity: host.Capacity{CPU: 2, MemoryBytes: 256 << 20, DiskBytes: 512 << 20}})
	if err := Run(ctx, []string{"operator", "host-register", "--config", operatorConfigPath, "--registration", registrationPath}, &output); err != nil {
		t.Fatalf("host registration: %v", err)
	}
	hostRuntime, err := natscell.Start(ctx, natscell.Config{Cell: "gru", Instance: "host-a", Replicas: 1, Lab: true,
		URL: operatorConfig.NATS.URL, NKeySeedFile: hostSeed, ClientRole: "host"})
	if err != nil {
		t.Fatal(err)
	}
	defer hostRuntime.Close()
	clock := &testBrokerClock{}
	clock.healthy.Store(true)
	member := traversableTerraBaseRoot(t)
	runner := &childRunner{log: filepath.Join(root, "member.log"), fake: fake}
	agent, err := host.NewAgent(host.AgentConfig{WorkloadIdentity: testHostWorkloadIdentity(), Cell: "gru", Node: "node-a",
		Environment: "test", Roles: []string{"terrabase"}, Conn: hostRuntime.Conn(), Identity: hostPrivate,
		NATSUserPublicKey: hostNKey, ControllerPublicKey: controllerPublic, Runner: runner,
		InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t), TerraBaseRoot: member,
		PollInterval: 200 * time.Millisecond, ClockCheck: controllerClockCheck(clock)})
	if err != nil {
		t.Fatal(err)
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx) }()
	defer func() {
		cancel()
		<-agentDone
		<-controllerDone
		_ = runner.Close(context.Background())
	}()

	checkout, commit := terraBaseSourceCheckout(t)
	profilePath := testJSONFile(t, root, "profile.json", profile)
	releaseCommand := func(binary string, wait time.Duration) (string, error) {
		output.Reset()
		err := Run(ctx, []string{"operator", "terrabase-release", "--config", operatorConfigPath,
			"--binary", binary, "--sha256", binary + ".sha256", "--source-checkout", checkout, "--commit", commit,
			"--environment", "test", "--profile", profilePath, "--wait", wait.String()}, &output)
		t.Logf("terrabase-release %s: %v\n%s", filepath.Base(filepath.Dir(binary)), err, output.String())
		return output.String(), err
	}

	// Deploy: the member passes the readiness gate with the release digest.
	first, _ := terrabase.VerifyRelease(release, release+".sha256")
	if out, err := releaseCommand(release, time.Minute); err != nil || !strings.Contains(out, `"step":"ready"`) {
		t.Fatalf("deploy: %v\n%s\n%s", err, out, readFileString(runner.log))
	}
	assertTerraBaseMember(t, ctx, adminPort, member, runner, first)

	// Upgrade: a second digest of the same build.
	data, err := os.ReadFile(release)
	if err != nil {
		t.Fatal(err)
	}
	second := writeTerraBaseRelease(t, filepath.Join(root, "second"), append(data, []byte("\nTS-467 upgrade fixture\n")...))
	if out, err := releaseCommand(second, time.Minute); err != nil || !strings.Contains(out, `"previous":"`+first+`"`) {
		t.Fatalf("upgrade: %v\n%s\n%s", err, out, readFileString(runner.log))
	}
	secondDigest, _ := terrabase.VerifyRelease(second, second+".sha256")
	assertTerraBaseMember(t, ctx, adminPort, member, runner, secondDigest)

	// Rollback: an executable that exits at once never passes the gate, and
	// the fake member does not serve it either.
	falsePath, err := exec.LookPath("false")
	if err != nil {
		t.Fatal(err)
	}
	if falsePath, err = filepath.EvalSymlinks(falsePath); err != nil {
		t.Fatal(err)
	}
	broken, err := os.ReadFile(falsePath)
	if err != nil {
		t.Fatal(err)
	}
	third := writeTerraBaseRelease(t, filepath.Join(root, "broken"), broken)
	out, err := releaseCommand(third, 15*time.Second)
	if err == nil || !strings.Contains(err.Error(), "was rolled back to "+secondDigest) {
		t.Fatalf("broken release: %v\n%s", err, out)
	}
	assertTerraBaseMember(t, ctx, adminPort, member, runner, secondDigest)
	if !runner.drained() {
		t.Fatal("the host never stopped a member with a drain timeout")
	}
	if !fake {
		return
	}
	// A broken stdout is reported when the command exits, but it is never
	// read as a failed gate: the healthy release stays.
	fourth := writeTerraBaseRelease(t, filepath.Join(root, "fourth"), []byte(fakeTerraBaseMagic+" fourth"))
	err = Run(ctx, []string{"operator", "terrabase-release", "--config", operatorConfigPath,
		"--binary", fourth, "--sha256", fourth + ".sha256", "--source-checkout", checkout, "--commit", commit,
		"--environment", "test", "--profile", profilePath, "--wait", "1m"}, brokenWriter{})
	if err == nil || !strings.Contains(err.Error(), "stdout is gone") || strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("release with a broken stdout: %v", err)
	}
	fourthDigest, _ := terrabase.VerifyRelease(fourth, fourth+".sha256")
	assertTerraBaseMember(t, ctx, adminPort, member, runner, fourthDigest)

	// An interrupt before the intent was submitted changes nothing and is
	// not rolled back. One after the delivery was accepted is rolled back on
	// a fresh context: the release may have reached the members.
	for i, step := range []string{"artifact", "deploy"} {
		release := writeTerraBaseRelease(t, filepath.Join(root, "interrupted-"+step), []byte(fmt.Sprintf("%s interrupted %d", fakeTerraBaseMagic, i)))
		interrupted, interrupt := context.WithCancel(ctx)
		err := Run(interrupted, []string{"operator", "terrabase-release", "--config", operatorConfigPath,
			"--binary", release, "--sha256", release + ".sha256", "--source-checkout", checkout, "--commit", commit,
			"--environment", "test", "--profile", profilePath, "--wait", "1m"}, &interruptAfter{step: step, interrupt: interrupt})
		interrupt()
		want := map[string]string{"artifact": "did not reach the members", "deploy": "was rolled back to " + fourthDigest}[step]
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("release interrupted after %s: %v, want %q", step, err, want)
		}
		assertTerraBaseMember(t, ctx, adminPort, member, runner, fourthDigest)
	}

	// A publish whose acknowledgement was lost is read back from the durable
	// operation and gated like any release: here it was delivered and serves.
	submitTerraBaseIntent = func(ctx context.Context, cfg Config, runtime *natscell.Runtime, intent delivery.Intent) (delivery.Intent, string, error) {
		intent, fingerprint, err := submitIntent(ctx, cfg, runtime, intent)
		return intent, fingerprint, errors.Join(err, errors.New("publish delivery intent: acknowledgement lost"))
	}
	t.Cleanup(func() { submitTerraBaseIntent = submitIntent })
	lost := writeTerraBaseRelease(t, filepath.Join(root, "lost-ack"), []byte(fakeTerraBaseMagic+" lost acknowledgement"))
	if out, err := releaseCommand(lost, time.Minute); err != nil || !strings.Contains(out, `"step":"ready"`) {
		t.Fatalf("release whose publish acknowledgement was lost: %v\n%s", err, out)
	}
	submitTerraBaseIntent = submitIntent
	lostDigest, _ := terrabase.VerifyRelease(lost, lost+".sha256")
	assertTerraBaseMember(t, ctx, adminPort, member, runner, lostDigest)
}

// interruptAfter cancels the command once it prints the named step.
type interruptAfter struct {
	step      string
	interrupt context.CancelFunc
}

func (w *interruptAfter) Write(data []byte) (int, error) {
	if strings.Contains(string(data), `"step":"`+w.step+`"`) {
		w.interrupt()
	}
	return len(data), nil
}

// traversableTerraBaseRoot is a TerraBase root below a directory every user
// may traverse but only its owner may change, as the host requires.
func traversableTerraBaseRoot(t *testing.T) string {
	t.Helper()
	parent, err := os.MkdirTemp("/tmp", "ts-terrabase-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "terrabase")
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("stdout is gone") }

func TestTerraBaseProfileRejectsArguments(t *testing.T) {
	profile := WorkloadProfile{Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 20, DiskBytes: 1 << 20},
		Args: []string{"--peer-client-ca=/etc/ssl/certs/ca-certificates.crt"},
		Env:  map[string]string{terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "gru-1-db-1=10.0.0.1:9443"}}
	if err := validateWorkloadProfiles(map[string]WorkloadProfile{"terrabase": profile}); err == nil {
		t.Fatal("accepted a TerraBase profile whose arguments override host-owned settings")
	}
	profile.Args = nil
	if err := validateWorkloadProfiles(map[string]WorkloadProfile{"terrabase": profile}); err != nil {
		t.Fatal(err)
	}
}

func assertTerraBaseMember(t *testing.T, ctx context.Context, adminPort int, member string, runner *childRunner, digest string) {
	t.Helper()
	if observed, _ := runner.Observe(ctx, "terrabase"); !observed.Running || observed.Digest != digest {
		t.Fatalf("member runs %s (running %v), want %s", observed.Digest, observed.Running, digest)
	}
	if err := terrabase.Healthy(ctx, adminPort); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"data", "bundle", "tls/member.key", "tls/member.pem", "tls/ca.pem"} {
		if _, err := os.Stat(filepath.Join(member, path)); err != nil {
			t.Fatal(err)
		}
	}
}

// terraBaseSourceCheckout is a one-commit repository standing in for a
// TerraBase checkout.
func terraBaseSourceCheckout(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("TerraBase\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "README.md"},
		{"-c", "user.name=ts", "-c", "user.email=ts@example.invalid", "commit", "-q", "-m", "source"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	commit, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return dir, strings.TrimSpace(string(commit))
}

// writeTerraBaseRelease writes data as the release asset of this machine with
// its .sha256.
func writeTerraBaseRelease(t *testing.T, dir string, data []byte) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "terrabase-linux-"+runtime.GOARCH)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if err := os.WriteFile(path+".sha256", []byte(hex.EncodeToString(sum[:])+"  "+filepath.Base(path)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTerraBasePlacementKeepsMembersOnListedHosts(t *testing.T) {
	profile := WorkloadProfile{Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 20, DiskBytes: 1 << 20},
		Env: map[string]string{terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "gru-1-db-1=10.0.0.1:9443"}}
	hosts := []placement.WorkloadHost{
		{Cell: "gru", Node: "gru-1-db-1", Roles: []string{"terrabase"}, CurrentSession: true, Admitted: true, Healthy: true, Capacity: placement.Resources{CPU: 2, MemoryBytes: 2 << 20, DiskBytes: 2 << 20}},
		{Cell: "gru", Node: "spare-1", Roles: []string{"terrabase"}, CurrentSession: true, Admitted: true, Healthy: true, Capacity: placement.Resources{CPU: 64, MemoryBytes: 64 << 30, DiskBytes: 64 << 30}},
	}
	failed := []placement.Assignment{{Node: "gru-1-db-1", Role: "terrabase"}}
	candidates, previous, err := terraBasePlacement(profile, 1, hosts, failed)
	if err != nil {
		t.Fatal(err)
	}
	assignments, err := placement.PlanWorkload(placement.WorkloadRequest{Cell: "gru", Role: "terrabase", Replicas: 1,
		Request: profile.Resources, Hosts: candidates, Previous: previous})
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 1 || assignments[0].Node != "gru-1-db-1" || assignments[0].Withdrawn {
		t.Fatalf("assignments %+v, want the failed member replaced in place on its listed host", assignments)
	}
	if failed[0].Pending {
		t.Fatal("terraBasePlacement changed its input")
	}
	if candidates, _, _ := terraBasePlacement(profile, 1, hosts, nil); len(candidates) != 1 || candidates[0].Node != "gru-1-db-1" {
		t.Fatalf("candidates %+v, want only the listed host", candidates)
	}
	if _, _, err := terraBasePlacement(profile, 2, hosts, nil); err == nil {
		t.Fatal("placed more members than the peer list names")
	}
}

func TestTerraBaseReleaseStateRules(t *testing.T) {
	now := time.Now()
	report := func(node, environment, digest, state string, generation uint64) host.HostStatus {
		return host.HostStatus{Reports: []host.Report{{Node: node, Role: "terrabase", Environment: environment,
			Digest: digest, State: state, Generation: generation, ObservedAt: now}}}
	}
	statuses := []host.HostStatus{report("a", "prod", "d1", "running", 4), report("b", "prod", "d2", "failed", 5),
		report("c", "test", "d9", "running", 2)}
	desired := []host.Desired{{Node: "a", Role: "terrabase", Generation: 4}, {Node: "x", Role: "terrabase", Generation: 7, Withdrawn: true}}
	current, next, err := terraBaseCurrent(statuses, desired, "prod")
	if err != nil || current != "d1" || next != 8 {
		t.Fatalf("current %q, next %d, %v; want the running digest and a generation above every desired", current, next, err)
	}
	if _, _, err := terraBaseCurrent(append(statuses, report("d", "prod", "d3", "running", 4)), desired, "prod"); err == nil {
		t.Fatal("running members on two digests were accepted")
	}
	intent := delivery.Intent{Role: "terrabase", Environment: "prod", ArtifactDigest: "d9", Generation: 2, DesiredReplicas: 1}
	if ready, err := terraBaseReady(statuses, intent, now); ready || err != nil {
		t.Fatalf("a member of another environment satisfied the gate: %v, %v", ready, err)
	}
	intent.ArtifactDigest, intent.Generation = "d2", 5
	if _, err := terraBaseReady(statuses, intent, now); err == nil {
		t.Fatal("a failed member did not fail the gate")
	}
	if heldAfterPlanning(delivery.Receipt{Status: "held", Error: delivery.PlannerRefusedHold + " 30 times (insufficient_capacity)"}) {
		t.Fatal("a planner hold, which writes no member, counted as a change")
	}
	if !heldAfterPlanning(delivery.Receipt{Status: "held", Error: "desired target conflicts with committed host state"}) {
		t.Fatal("a hold after planning did not count as a change")
	}
	for status, want := range map[string]bool{"rejected": true, "accepted": false} {
		if unchanged(delivery.Receipt{Status: status}) != want {
			t.Errorf("receipt %s: unchanged %v, want %v", status, !want, want)
		}
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func readFileString(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

// childRunner runs the workload as a plain child process with the host's
// base environment, and stops it like the cgroup runner: SIGTERM, then a
// kill once the drain timeout passes. With fake set it runs fakeMember
// instead of the executable.
type childRunner struct {
	log  string
	fake bool

	mu       sync.Mutex
	command  *exec.Cmd
	stop     func()
	exited   chan struct{}
	workload host.Workload
	drains   int
}

func (*childRunner) Recover(context.Context) error { return nil }

func (r *childRunner) Apply(ctx context.Context, w host.Workload) error {
	if err := r.Stop(ctx, w.Role); err != nil {
		return err
	}
	if r.fake {
		stop, exited, err := fakeMember(w)
		if err != nil {
			return err
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.stop, r.exited, r.workload = stop, exited, w
		return nil
	}
	log, err := os.OpenFile(r.log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer log.Close()
	command := exec.Command(w.Executable, w.Args...)
	command.Env = []string{"HOME=/", "LANG=C", "PATH=/usr/bin:/bin"}
	for key, value := range w.Env {
		command.Env = append(command.Env, key+"="+value)
	}
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		return err
	}
	exited := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(exited)
	}()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.command, r.exited, r.workload = command, exited, w
	return nil
}

func (r *childRunner) Stop(_ context.Context, role string) error {
	r.mu.Lock()
	command, stop, exited, drain := r.command, r.stop, r.exited, r.workload.DrainTimeout
	r.command, r.stop = nil, nil
	if (command != nil || stop != nil) && drain > 0 {
		r.drains++
	}
	r.mu.Unlock()
	if stop != nil {
		stop()
		return nil
	}
	if command == nil {
		return nil
	}
	_ = command.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(drain):
		_ = command.Process.Kill()
		<-exited
	}
	return nil
}

func (r *childRunner) Observe(_ context.Context, role string) (host.Observation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.command == nil && r.stop == nil {
		return host.Observation{Role: role}, nil
	}
	observed := host.Observation{Role: role, Digest: r.workload.Digest, Fingerprint: r.workload.Fingerprint,
		Running: true, PID: os.Getpid()}
	select {
	case <-r.exited:
		// Like the cgroup runner, an exited process keeps its record.
		observed.Running, observed.PID = false, 0
	default:
	}
	return observed, nil
}

// fakeMember stands in for the binary. It checks the environment the host
// prepared and serves /healthz on the admin port; a release that does not
// start with fakeTerraBaseMagic exits at once, like a crashing binary.
func fakeMember(w host.Workload) (func(), chan struct{}, error) {
	exited := make(chan struct{})
	executable, err := os.ReadFile(w.Executable)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.HasPrefix(executable, []byte(fakeTerraBaseMagic)) {
		// It starts, then crashes before it serves.
		time.AfterFunc(300*time.Millisecond, func() { close(exited) })
		return func() {}, exited, nil
	}
	ca, err := os.ReadFile(w.Env[terrabase.EnvPeerClientCA])
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	pair, err := tls.LoadX509KeyPair(w.Env[terrabase.EnvPeerCertificate], w.Env[terrabase.EnvPeerPrivateKey])
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		return nil, nil, fmt.Errorf("member TLS material: %v", err)
	}
	if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, nil, err
	}
	if info, err := os.Stat(w.Env[terrabase.EnvDataDirectory]); err != nil || !info.IsDir() {
		return nil, nil, fmt.Errorf("member data directory: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:"+w.Env[terrabase.EnvAdminPort])
	if err != nil {
		return nil, nil, err
	}
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"status":"ok","version":"fake"}`))
	})}
	go func() { _ = server.Serve(listener) }()
	return func() {
		_ = server.Close()
		close(exited)
	}, exited, nil
}

func (r *childRunner) Close(ctx context.Context) error { return r.Stop(ctx, "terrabase") }

func (r *childRunner) drained() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.drains > 0
}
