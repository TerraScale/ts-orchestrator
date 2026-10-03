package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

type recordingRefound struct{ slots []string }

func (r *recordingRefound) Replace(_ context.Context, slot string, _ []byte) error {
	r.slots = append(r.slots, slot)
	return nil
}

func recoveryFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	store := filepath.Join(root, "nats")
	if err := os.MkdirAll(filepath.Join(store, "jetstream", "ACCOUNT", "streams", "TS_CONTROL_LOG"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "jetstream", "ACCOUNT", "streams", "TS_CONTROL_LOG", "meta.inf"),
		[]byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "controller.json")
	clientPort, routePort := closedPort(t), closedPort(t)
	if err := os.WriteFile(config, []byte(`{"nats":{"cell":"gru","instance":"controller-a","replicas":3,`+
		`"embedded":{"host":"127.0.0.1","port":`+clientPort+`,"route_host":"127.0.0.1","route_port":`+routePort+
		`,"store_dir":"`+store+`"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previousInstall := localAdmittedInstall
	t.Cleanup(func() { localAdmittedInstall = previousInstall })
	localAdmittedInstall = func() (bootstrapstart.AcceptedInstall, error) {
		return bootstrapstart.AcceptedInstall{Cell: "GRU", Slot: "controller-a", SeedSlot: "controller-a",
			PrimaryPrivateIP: "127.0.0.1"}, nil
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	envelope, err := bootstrap.SignSlotRetirement(bootstrap.RetirementEvidence{SchemaVersion: 1,
		DeploymentID: "deployment-1", Cell: "GRU", Environment: "production", Role: "controller",
		Slot: "controller-b", PreviousAttempt: 1, PreviousGeneration: 1,
		PreviousResultDigest: strings.Repeat("c", 64), PriorInstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.b",
		PriorCreateKey: "founder-controller-b-key", Disposition: bootstrap.SlotRetirementDisposition,
		ObservedEvidenceDigest: strings.Repeat("e", 64), FencingAuthority: "authority-epoch-1", ObservedAt: now},
		now, now.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	retirement := filepath.Join(root, "controller-b.retirement")
	if err := os.WriteFile(retirement, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	return config, retirement, root
}

func TestRecoverQuorumRefoundRequiresBackupAndConfirmation(t *testing.T) {
	config, retirement, root := recoveryFixture(t)
	recorder := &recordingRefound{}
	previousInput, previousReplacer := recoveryInput, refoundReplacer
	t.Cleanup(func() { recoveryInput, refoundReplacer = previousInput, previousReplacer })
	refoundReplacer = func(context.Context, bootstrapstart.AcceptedInstall) (interface {
		Replace(context.Context, string, []byte) error
	}, error) {
		return recorder, nil
	}
	backup := filepath.Join(root, "backup")
	run := func(input string, args ...string) (string, error) {
		recoveryInput = strings.NewReader(input)
		var output bytes.Buffer
		err := Run(t.Context(), append([]string{"cluster", "recover-quorum"}, args...), &output)
		return output.String(), err
	}
	if out, err := run("", "--help"); err != nil || !strings.Contains(out, "refound") {
		t.Fatalf("help = %q, %v", out, err)
	}
	refoundArgs := []string{"refound", "--config", config, "--slot", "controller-b",
		"--retirement", retirement, "--backup", backup}
	if _, err := run("re-found gru/controller-b\n", refoundArgs...); err == nil {
		t.Fatal("refound ran without a verified backup")
	}
	if _, err := run("back up gru/controller-a\n", "backup", "--config", config, "--out", backup); err != nil {
		t.Fatal(err)
	}
	if out, err := run("", "verify-backup", "--dir", backup); err != nil || !strings.Contains(out, "verified") {
		t.Fatalf("verify = %q, %v", out, err)
	}
	if _, err := run("re-found gru/controller-b\n", refoundArgs...); err == nil ||
		!strings.Contains(err.Error(), "start the survivor controller service first") {
		t.Fatalf("refound ran while the survivor broker was stopped: %v", err)
	}
	// The data-bearing survivor runs again before any peer is re-founded.
	survivorBroker := listenOn(t, config)
	defer survivorBroker.Close()
	wrongSlot := append([]string(nil), refoundArgs...)
	wrongSlot[4] = "controller-c"
	if _, err := run("re-found gru/controller-c\n", wrongSlot...); err == nil {
		t.Fatal("refound accepted evidence for another slot")
	}
	if _, err := run("yes\n", refoundArgs...); err == nil || len(recorder.slots) != 0 {
		t.Fatalf("refound without confirmation: %v %v", err, recorder.slots)
	}
	out, err := run("re-found gru/controller-b\n", refoundArgs...)
	if err != nil || len(recorder.slots) != 1 || recorder.slots[0] != "controller-b" ||
		!strings.Contains(out, "attempt 2") {
		t.Fatalf("refound = %q, %v, %v", out, err, recorder.slots)
	}
	survivor := append([]string(nil), refoundArgs...)
	survivor[4] = "controller-a"
	if _, err := run("re-found gru/controller-a\n", survivor...); err == nil {
		t.Fatal("refound relaunched the local survivor")
	}
	if out, err := run("", "runbook", "--config", config); err != nil || !strings.Contains(out, "verify-backup") ||
		!strings.Contains(out, "render-retirement") {
		t.Fatalf("runbook = %q, %v", out, err)
	}
}

// Without quorum no reconciler renders a retirement request, so the
// break-glass path must be able to render one itself.
func TestRecoverQuorumRenderRetirement(t *testing.T) {
	config, _, root := recoveryFixture(t)
	previous := renderRetirement
	t.Cleanup(func() { renderRetirement = previous })
	var rendered []string
	renderRetirement = func(_ context.Context, slot, dir string) (string, error) {
		rendered = append(rendered, slot)
		return filepath.Join(dir, slot+".retirement-request.json"), nil
	}
	run := func(args ...string) (string, error) {
		var output bytes.Buffer
		err := Run(t.Context(), append([]string{"cluster", "recover-quorum", "render-retirement"}, args...), &output)
		return output.String(), err
	}
	if _, err := run("--config", config, "--slot", "controller-a", "--out", root); err == nil {
		t.Fatal("rendered a retirement for the local survivor")
	}
	if _, err := run("--config", config, "--slot", "controller-b", "--out", "relative"); err == nil {
		t.Fatal("rendered into a relative directory")
	}
	out, err := run("--config", config, "--slot", "controller-b", "--out", root)
	if err != nil || len(rendered) != 1 || rendered[0] != "controller-b" ||
		!strings.Contains(out, "sign-slot-retirement") {
		t.Fatalf("render = %q, %v, %v", out, err, rendered)
	}
}

// closedPort is a loopback port that refuses connections.
func closedPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
}

// listenOn starts a listener on the config's client port, standing in for a
// running survivor broker.
func listenOn(t *testing.T, config string) net.Listener {
	t.Helper()
	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		NATS struct {
			Embedded struct {
				Port int `json:"port"`
			} `json:"embedded"`
		} `json:"nats"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.NATS.Embedded.Port)))
	if err != nil {
		t.Fatal(err)
	}
	return listener
}
