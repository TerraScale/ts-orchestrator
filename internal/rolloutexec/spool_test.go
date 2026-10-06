package rolloutexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// boardFixture is one controller node: the leader's driver, the unit's
// relay and the node's root agent, over a real KV bucket and release root.
// The target release is not staged yet; its receipt is real.
type boardFixture struct {
	driver   KVDriver
	relay    *Relay
	agent    *Agent
	verifier selfupdate.ReceiptPolicy
	kv       jetstream.KeyValue
	key      ed25519.PrivateKey
	restarts *restarts
	spool    string
	from, to string
	target   []byte
	now      time.Time
}

func newBoardFixture(t *testing.T) *boardFixture {
	t.Helper()
	_, js := testNATS(t)
	kv, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: rollout.Bucket})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	layout := selfupdate.Layout{Root: filepath.Join(t.TempDir(), "root"), Owner: os.Getuid()}
	from := stageTestRelease(t, layout, "release from", "")
	target := []byte("release to")
	receipt, delegation, roots := signTestRelease(t, target, now)
	key, keys := testKey(t)
	r := &restarts{}
	f := &boardFixture{kv: kv, key: key, restarts: r, spool: filepath.Join(t.TempDir(), "spool"), from: from,
		to: digestOf(string(target)), target: target, now: now,
		verifier: selfupdate.ReceiptPolicy{Roots: roots, Environment: "canary", Architecture: runtime.GOARCH}}
	clock := func() time.Time { return now }
	f.driver = KVDriver{KV: kv, Cell: "gru", Key: key, Releases: fixedReceipt{receipt, delegation}, Now: clock}
	f.relay = &Relay{KV: kv, Cell: "gru", Unit: "ctl-b", SystemdUnit: agentUnit, Leaders: keys, Dir: f.spool, Layout: layout, Now: clock,
		Sources: []BinarySource{func(_ context.Context, _ string, dst io.Writer) error {
			_, err := dst.Write(f.target)
			return err
		}}}
	if err := os.MkdirAll(f.spool, 0o700); err != nil {
		t.Fatal(err)
	}
	f.agent = &Agent{Cell: "gru", Unit: "ctl-b", SystemdUnit: agentUnit, Layout: layout, Leaders: keys,
		Restart: r.restart, Now: clock}
	return f
}

func (f *boardFixture) step() Step {
	return Step{RolloutID: "rel1-controllers", Kind: rollout.KindController, Unit: "ctl-b",
		OperationID: rollout.OperationID("rel1-controllers", "ctl-b", rollout.PhaseCanary, 0), Action: StepPrepare,
		Digest: f.to, Replaces: f.from, Epoch: 7, ProofWindow: 10 * time.Minute}
}

// apply runs the root agent once, as one watchdog tick does.
func (f *boardFixture) apply(t *testing.T) {
	t.Helper()
	if err := ApplySpooled(t.Context(), f.agent, f.spool, f.verifier); err != nil {
		t.Fatal(err)
	}
}

func (f *boardFixture) reply(t *testing.T) (StepReply, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.agent.Layout.Root, ReplyFile(agentUnit)))
	if errors.Is(err, os.ErrNotExist) {
		return StepReply{}, false
	}
	var reply StepReply
	if err != nil || json.Unmarshal(data, &reply) != nil {
		t.Fatalf("reply file: %v", err)
	}
	return reply, true
}

type fixedReceipt struct{ receipt, delegation []byte }

func (r fixedReceipt) Receipt(context.Context, string) ([]byte, []byte, error) {
	return r.receipt, r.delegation, nil
}

// signTestRelease returns a per-source receipt of data, its delegation and
// the root that verifies them.
func signTestRelease(t *testing.T, data []byte, now time.Time) ([]byte, []byte, trust.Keyring) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Repeat("e", 40)
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: release.BinaryDomain, DeploymentID: source, Cell: "BUILD",
			Environment: "canary", Role: "artifact", Slots: []string{"linux-" + runtime.GOARCH}, Actions: []string{"sign"}}},
	}, now.Add(-time.Minute), now.Add(time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	machine := map[string]string{"amd64": "Advanced Micro Devices X86-64", "arm64": "AArch64"}[runtime.GOARCH]
	receipt, err := release.SignBinaryReceipt(release.BinaryReceipt{Schema: release.BinarySchema, SourceRevision: source,
		GoVersion: release.DefaultGoVersion, GOOS: "linux", GOARCH: runtime.GOARCH, ELFMachine: machine, Static: true,
		Bytes: int64(len(data)), SHA256: digestOf(string(data)), QualificationSHA256: digestOf("q")},
		"canary", delegation, roots, leafPrivate, now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	receiptWire, err := trust.EncodeEnvelope(receipt)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	return receiptWire, delegationWire, roots
}

// A step posted by the leader reaches the root agent through the unit's
// relay, which fetches the release; the agent stages it from the spool
// after verifying its receipt and bytes, activates it, and its reply comes
// back to the leader as the answer to that step only.
func TestStepsReachTheRootAgentThroughTheRelay(t *testing.T) {
	f := newBoardFixture(t)
	ctx := t.Context()
	// A reply to another step of the unit, or to a deposed leader's copy
	// of this step, is not an answer.
	for _, stale := range []string{`{"operation_id":"ro-old","unit":"ctl-b","epoch":7,"outcome":"refused"}`,
		`{"operation_id":"` + f.step().OperationID + `","unit":"ctl-b","epoch":6,"outcome":"refused"}`} {
		if _, err := f.kv.Put(ctx, ReplyKey("ctl-b"), []byte(stale)); err != nil {
			t.Fatal(err)
		}
		if reply, err := f.driver.Step(ctx, f.step()); err != nil || reply.Outcome != OutcomeRetry {
			t.Fatalf("step answered by %s = %+v %v", stale, reply, err)
		}
	}
	if reply, err := f.driver.Step(ctx, f.step()); err != nil || reply.Outcome != OutcomeRetry {
		t.Fatalf("step before the agent answered = %+v %v", reply, err)
	}
	if err := f.relay.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.spool, spoolReleasePrefix+f.to)); err != nil {
		t.Fatalf("relay did not spool the release: %v", err)
	}
	f.apply(t)
	if current, err := f.agent.Layout.Current(); err != nil || current != f.to || f.restarts.count() != 1 {
		t.Fatalf("agent did not activate the fetched release: %s %v, restarts %d", current, err, f.restarts.count())
	}
	if err := f.relay.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	if reply, err := f.driver.Step(ctx, f.step()); err != nil || reply.Outcome != OutcomeActivated {
		t.Fatalf("step after the agent answered = %+v %v", reply, err)
	}
	// The next timer tick retries the same step idempotently.
	f.apply(t)
	if reply, _ := f.reply(t); reply.Outcome != OutcomePending || f.restarts.count() != 1 {
		t.Fatalf("retried step = %+v, restarts %d", reply, f.restarts.count())
	}
}

// Everything in the spool belongs to the unprivileged controller, so the
// root agent acts only on a current step signed by a leader and on bytes
// its receipt names: a forged or expired step gets no answer at all, a
// spooled binary with other bytes is never staged, and a spool entry that
// links outside the spool is never read.
func TestRootAgentRefusesATamperedSpool(t *testing.T) {
	f := newBoardFixture(t)
	ctx := t.Context()
	if _, err := f.driver.Step(ctx, f.step()); err != nil {
		t.Fatal(err)
	}
	f.relay.Sources = nil
	if err := f.relay.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	genuine, err := os.ReadFile(filepath.Join(f.spool, spoolStep))
	if err != nil {
		t.Fatal(err)
	}
	unchanged := func(name string) {
		t.Helper()
		if current, err := f.agent.Layout.Current(); err != nil || current != f.from || f.restarts.count() != 0 {
			t.Fatalf("%s: the unit moved: %s %v, restarts %d", name, current, err, f.restarts.count())
		}
		if _, err := os.Stat(f.agent.Layout.ReleaseDir(f.to)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: the release was staged: %v", name, err)
		}
	}

	forgedKey, _ := testKey(t)
	command, _, err := VerifyStepCommand(genuine, "gru", "ctl-b", f.agent.Leaders, f.now)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := SignStepCommand(command, forgedKey, f.now, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.spool, spoolStep), forged, 0o600); err != nil {
		t.Fatal(err)
	}
	f.apply(t)
	if _, answered := f.reply(t); answered {
		t.Fatal("a forged step was answered")
	}
	unchanged("forged step")

	if err := os.WriteFile(filepath.Join(f.spool, spoolStep), genuine, 0o600); err != nil {
		t.Fatal(err)
	}
	f.agent.Now = func() time.Time { return f.now.Add(StepLifetime) }
	f.apply(t)
	if _, answered := f.reply(t); answered {
		t.Fatal("an expired step was answered")
	}
	f.agent.Now = func() time.Time { return f.now }

	if err := os.WriteFile(filepath.Join(f.spool, spoolReleasePrefix+f.to), []byte("release tx"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.apply(t)
	if reply, _ := f.reply(t); reply.Outcome != OutcomeRetry {
		t.Fatalf("step with tampered release bytes = %+v", reply)
	}
	unchanged("tampered bytes")

	outside := filepath.Join(t.TempDir(), "release")
	if err := os.WriteFile(outside, f.target, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.spool, spoolReleasePrefix+f.to)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(f.spool, spoolReleasePrefix+f.to)); err != nil {
		t.Fatal(err)
	}
	f.apply(t)
	if reply, _ := f.reply(t); reply.Outcome != OutcomeRetry {
		t.Fatalf("step with a release outside the spool = %+v", reply)
	}
	unchanged("escaping link")

	// A FIFO the controller put in the spool never blocks the root agent.
	if err := os.Remove(filepath.Join(f.spool, spoolReleasePrefix+f.to)); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(f.spool, spoolReleasePrefix+f.to), 0o600); err != nil {
		t.Fatal(err)
	}
	f.apply(t)
	if reply, _ := f.reply(t); reply.Outcome != OutcomeRetry {
		t.Fatalf("step whose release is a FIFO = %+v", reply)
	}
	if err := os.Remove(filepath.Join(f.spool, spoolStep)); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(f.spool, spoolStep), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ApplySpooled(t.Context(), f.agent, f.spool, f.verifier); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a FIFO step = %v", err)
	}
	unchanged("FIFO")
}

// The relay keeps only bytes that hash to the step's release.
func TestRelayDropsFetchedBytesOfAnotherRelease(t *testing.T) {
	f := newBoardFixture(t)
	f.target = []byte("release tx")
	if _, err := f.driver.Step(t.Context(), f.step()); err != nil {
		t.Fatal(err)
	}
	if err := f.relay.Pass(t.Context()); err == nil || !errors.Is(err, ErrInvalid) {
		t.Fatalf("relay of a wrong download = %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.spool, spoolReleasePrefix+f.to)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong bytes were spooled: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.spool, spoolStep)); err != nil {
		t.Fatalf("the step was not spooled for the agent to explain: %v", err)
	}
}
