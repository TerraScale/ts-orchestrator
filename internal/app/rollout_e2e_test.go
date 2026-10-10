package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rolloutexec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const rolloutTestSystemdUnit = "terrascale-orchestrator-controller.service"

// TestRolloutExecutorUpdatesARunningCell runs the cell's orchestrator
// self-update end to end on three real brokers: the authority leader's
// executor behind the real cluster gate, the replicated rollout store,
// signed health proofs, signed steps to real step agents over real release
// roots with their watchdogs, and the operator's rollout commands. Only the
// unit processes are simulated: each runs and proves the release its root's
// current link names, and a bad release never becomes healthy.
func TestRolloutExecutorUpdatesARunningCell(t *testing.T) {
	tier.Integration(t)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	root := t.TempDir()
	_, responseKey := testEd25519(t, root, "controller.key")
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	binaries := map[string]string{}
	digests := map[string]string{}
	for _, name := range []string{"from", "good", "bad", "good2"} {
		binaries[name] = filepath.Join(root, name+".bin")
		if err := os.WriteFile(binaries[name], []byte("orchestrator release "+name), 0o755); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte("orchestrator release " + name))
		digests[name] = hex.EncodeToString(sum[:])
	}
	ids := []string{"ctl-a", "ctl-b", "ctl-c"}
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"canary"}, CanRollOutOrchestrator: true}
	starts := &rolloutStartLog{}
	cell := startRolloutTestCell(t, ctx, rolloutTestCellConfig{root: root, cell: "lab", ids: ids, grant: grant,
		responseKey: responseKey, binaries: binaries, staged: []string{"good", "bad", "good2"}, starts: starts,
		configure: func(c *rolloutControl) { c.verify = testReceiptDigest }})
	runtimes, stores, units := cell.runtimes, cell.stores, cell.units

	operator := Config{NATS: natscell.Config{Cell: "lab", Replicas: 3, Lab: true},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "operator.key")}}
	command := func(name string, receipt string, to uint64) rolloutReply {
		t.Helper()
		receiptPath := ""
		if receipt != "" {
			receiptPath = filepath.Join(root, "receipt-"+receipt)
			if err := os.WriteFile(receiptPath, []byte("receipt:"+digests[receipt]), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		payload, err := rolloutPayload(name, receiptPath, "", to)
		if err != nil {
			t.Fatal(err)
		}
		for {
			var output bytes.Buffer
			err := operatorRollout(ctx, operator, runtimes[0], name, payload, &output)
			if err == nil {
				var reply rolloutReply
				if err := json.Unmarshal(output.Bytes(), &reply); err != nil {
					t.Fatal(err)
				}
				return reply
			}
			// The first request may race the first authority election.
			if ctx.Err() != nil || !errors.Is(err, nats.ErrNoResponders) && !strings.Contains(err.Error(), "authority") {
				t.Fatalf("rollout %s: %v", name, err)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	waitPhase := func(id string, phase rollout.Phase) {
		t.Helper()
		for {
			record, _, err := stores[0].Load(ctx, id)
			if err == nil && record.Phase == phase {
				return
			}
			if ctx.Err() != nil {
				t.Fatalf("rollout %s did not reach %s: %+v %v; starts %v", id, phase, record.Phase, err, starts.all())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitSettled := func(release string) {
		t.Helper()
		for _, id := range ids {
			for !units[id].settledOn(digests[release]) {
				if ctx.Err() != nil {
					t.Fatalf("unit %s did not settle on %s", id, release)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	if reply := command("status", "", 0); reply.Desired != nil || len(reply.History) != 0 {
		t.Fatalf("a new cell has a desired release: %+v", reply)
	}

	// Generation 1 moves the controllers one per wave, the seed last.
	if reply := command("publish", "good", 0); reply.Status != "published" || reply.Desired == nil || reply.Desired.Generation != 1 {
		t.Fatalf("publish = %+v", reply)
	}
	waitPhase(entityid.Derive("release-controllers", rollout.ReleaseRolloutID(1)), rollout.PhaseComplete)
	waitSettled("good")
	if order := starts.on(digests["good"]); !slices.Equal(order, []string{"ctl-b", "ctl-c", "ctl-a"}) {
		t.Fatalf("controllers moved as %v, want one per wave and the seed last", order)
	}

	// Generation 2 never becomes healthy: the proof deadline rolls the
	// canary back through selfupdate.Restore and marks the release bad.
	command("publish", "bad", 0)
	waitPhase(entityid.Derive("release-controllers", rollout.ReleaseRolloutID(2)), rollout.PhaseRolledBack)
	waitSettled("good")
	if moved := starts.on(digests["bad"]); !slices.Equal(moved, []string{"ctl-b"}) {
		t.Fatalf("units that ran the bad release = %v, want the canary only", moved)
	}
	if bad, err := units["ctl-b"].layout.KnownBad(); err != nil || !bad[digests["bad"]] {
		t.Fatalf("the canary's node does not refuse the bad release: %v %v", bad, err)
	}
	// The next tick reports why the program stopped.
	for {
		status := command("status", "", 0)
		if !status.DesiredKnownBad || status.Desired.Digest != digests["bad"] {
			t.Fatalf("status does not report the rejected release: %+v", status)
		}
		if status.Rollout != nil && strings.Contains(status.Rollout.Waiting, entityid.Derive("release-controllers", rollout.ReleaseRolloutID(2))+" stopped the program: rollout ended rolled-back") {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("status does not say why nothing runs: %+v", status.Rollout)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// A paused cell starts nothing until it is resumed.
	if reply := command("pause", "", 0); reply.Status != "paused" || !reply.Paused {
		t.Fatalf("pause = %+v", reply)
	}
	command("publish", "good2", 0)
	time.Sleep(2 * time.Second)
	if moved := starts.on(digests["good2"]); len(moved) != 0 {
		t.Fatalf("a paused cell moved %v", moved)
	}
	if reply := command("resume", "", 0); reply.Status != "resumed" || reply.Paused {
		t.Fatalf("resume = %+v", reply)
	}
	waitPhase(entityid.Derive("release-controllers", rollout.ReleaseRolloutID(3)), rollout.PhaseComplete)
	waitSettled("good2")

	// Rolling back to generation 1 is a new generation.
	reply := command("rollback", "", 1)
	if reply.Status != "rolled-back" || reply.Desired == nil || reply.Desired.Generation != 4 ||
		reply.Desired.RollbackOf != 1 || reply.Desired.Digest != digests["good"] {
		t.Fatalf("rollback = %+v", reply)
	}
	waitPhase(entityid.Derive("release-controllers", rollout.ReleaseRolloutID(4)), rollout.PhaseComplete)
	waitSettled("good")
	history := command("status", "", 0).History
	var generations []uint64
	for _, release := range history {
		generations = append(generations, release.Generation)
		if release.Receipt != nil {
			t.Fatal("status carries release receipts")
		}
	}
	if !slices.Equal(generations, []uint64{4, 3, 2, 1}) {
		t.Fatalf("history = %v", generations)
	}
}

// rolloutTestPolicy is short enough for a test and still soaks every wave.
// A wave's prepare phase gets ProofDeadlineSeconds: under the race detector
// on a loaded CI runner, staging six controllers took longer than 8 s and a
// good release rolled back.
// Rollback also needs gate recovery, an accepted step and a newer proof;
// the six-broker race lab can spend more than 20 s recovering on loaded CI.
var rolloutTestPolicy = rollout.Policy{CanaryUnits: 1, BatchSize: 1, CanarySoakSeconds: 1, BatchSoakSeconds: 1,
	MinHealthyReports: 2, ProofDeadlineSeconds: 30, RollbackDeadlineSeconds: 60, PreflightSeconds: 20,
	MaxAttempts: 1, MaxRollbackRetries: 1}

type rolloutTestCellConfig struct {
	root, cell  string
	ids         []string
	grant       TrustedSignerConfig
	responseKey ed25519.PrivateKey
	// services verifies release receipts; nil leaves configure to stub it.
	services *specRegistry
	binaries map[string]string
	staged   []string
	starts   *rolloutStartLog
	// verifier stages releases the nodes fetch; nil fetches none.
	verifier  selfupdate.Verifier
	configure func(*rolloutControl)
}

// rolloutTestCell is one region on three real brokers: every controller's
// rollout control as runController wires it (the first ID is the seed),
// operator rollout requests, and one simulated unit per controller whose
// watchdog is the node's root step agent.
type rolloutTestCell struct {
	runtimes []*natscell.Runtime
	stores   []*rollout.Store
	controls []*rolloutControl
	units    map[string]*rolloutTestUnit
}

func startRolloutTestCell(t *testing.T, ctx context.Context, config rolloutTestCellConfig) *rolloutTestCell {
	t.Helper()
	ids, root := config.ids, config.root
	previousSeed := rolloutSeedSlot
	rolloutSeedSlot = func(cfg Config) (string, error) { return cfg.NATS.Embedded.BrokerIDs[0], nil }
	t.Cleanup(func() { rolloutSeedSlot = previousSeed })
	policy := rolloutTestPolicy
	ports := reserveControllerPorts(t, 6)
	routes := make([]string, 3)
	for index := range routes {
		routes[index] = fmt.Sprintf("nats-route://127.0.0.1:%d", ports[3+index])
	}
	configs := make([]Config, 3)
	cell := &rolloutTestCell{runtimes: make([]*natscell.Runtime, 3), stores: make([]*rollout.Store, 3),
		units: map[string]*rolloutTestUnit{}}
	for index, id := range ids {
		configs[index] = Config{
			NATS: natscell.Config{Cell: config.cell, Instance: id, Replicas: 3, Lab: true,
				Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: ports[index], RouteHost: "127.0.0.1",
					RoutePort: ports[3+index], Routes: natscell.PeerRoutes(routes, routes[index]),
					StoreDir: filepath.Join(root, id), BrokerIDs: ids}},
			Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{config.grant}},
		}
		runtime, err := natscell.Start(ctx, configs[index].NATS)
		if err != nil {
			t.Fatal(err)
		}
		cell.runtimes[index] = runtime
		t.Cleanup(func() { _ = runtime.Close() })
	}
	for _, runtime := range cell.runtimes {
		for !runtime.FullClusterReady(3) {
			if ctx.Err() != nil {
				t.Fatal("cluster did not form")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	responsePublic := config.responseKey.Public().(ed25519.PublicKey)
	keys, err := trust.ParseKeyring(responsePublic)
	if err != nil {
		t.Fatal(err)
	}
	for index, id := range ids {
		cfg, runtime := configs[index], cell.runtimes[index]
		// The authority runtime keeps the context it started with.
		control := retryOpen(t, ctx, func(context.Context) (*authority.Runtime, error) {
			return authority.Start(ctx, runtime.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: config.cell, CandidateID: entityid.Derive("test-controller", id),
				Replicas: 3, LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond})
		})
		t.Cleanup(func() { _ = control.Close() })
		cell.stores[index] = retryOpen(t, ctx, func(attempt context.Context) (*rollout.Store, error) {
			return rollout.OpenStore(attempt, runtime.JetStream(), config.cell, 3, control)
		})
		rollouts, err := newRolloutControl(cfg, config.services, "")
		if err != nil {
			t.Fatal(err)
		}
		rollouts.policy = func() rollout.Policy { return policy }
		rollouts.interval = 200 * time.Millisecond
		rollouts.spool = filepath.Join(root, "spool-"+id)
		rollouts.layout = selfupdate.Layout{Root: filepath.Join(root, "release-"+id), Owner: os.Getuid()}
		if config.configure != nil {
			config.configure(rollouts)
		}
		rollouts.store.Store(cell.stores[index])
		rollouts.ready.Store(true)
		run, err := rollouts.start(ctx, cfg, runtime, control, config.responseKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = run(ctx) }()
		cell.controls = append(cell.controls, rollouts)
		signers, err := buildSignerPolicy(cfg)
		if err != nil {
			t.Fatal(err)
		}
		signers.rollouts = rollouts
		subscription, err := serveHostEnrollment(ctx, runtime.Conn(), config.cell, signers, control, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = subscription.Unsubscribe() })
		unit := newRolloutTestUnit(t, ctx, config.cell, root, id, runtime.Conn(), config.responseKey, config.binaries,
			config.staged, config.starts)
		unit.attachAgent(keys, rollouts.spool, config.verifier)
		cell.units[id] = unit
	}
	return cell
}

// testReceiptDigest stands in for receipt verification: "receipt:<digest>".
func testReceiptDigest(receipt, delegation []byte, now time.Time) (rollout.Release, error) {
	digest, ok := strings.CutPrefix(string(receipt), "receipt:")
	if !ok {
		return rollout.Release{}, errors.New("receipt does not verify")
	}
	return rollout.Release{Digest: digest, SourceRevision: strings.Repeat("e", 40), RunNumber: 9, Receipt: receipt,
		Delegation: delegation, CreatedAt: now}, nil
}

func retryOpen[T any](t *testing.T, ctx context.Context, open func(context.Context) (T, error)) T {
	t.Helper()
	for {
		attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
		value, err := open(attempt)
		cancel()
		if err == nil {
			return value
		}
		if ctx.Err() != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

type rolloutStartLog struct {
	mu     sync.Mutex
	starts [][2]string
}

func (l *rolloutStartLog) add(unit, digest string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.starts = append(l.starts, [2]string{unit, digest})
}

// on lists the units in the order they first started on digest.
func (l *rolloutStartLog) on(digest string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var units []string
	for _, start := range l.starts {
		if start[1] == digest && !slices.Contains(units, start[0]) {
			units = append(units, start[0])
		}
	}
	return units
}

func (l *rolloutStartLog) all() [][2]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.starts)
}

// rolloutTestUnit simulates one controller process over a real release
// root: a start runs selfupdate prepare, then proves the current release
// (health proofs and, for a pending activation, the version proof), unless
// the release is the bad one, which never becomes healthy. A watchdog
// confirms or rolls back activations as the systemd timer does.
type rolloutTestUnit struct {
	t         *testing.T
	ctx       context.Context
	cell      string
	id        string
	layout    selfupdate.Layout
	conn      *nats.Conn
	key       ed25519.PrivateKey
	baked     string
	bad       string
	proofFile string
	starts    *rolloutStartLog

	// agent applies the steps its controller spools, from the watchdog,
	// staging fetched releases through verifier.
	agent    *rolloutexec.Agent
	spool    string
	verifier selfupdate.Verifier

	mu   sync.Mutex
	stop context.CancelFunc
	runs string
}

// newRolloutTestUnit starts unit id of cell on the "from" binary, with the
// releases named in staged already staged; "bad" never becomes healthy.
func newRolloutTestUnit(t *testing.T, ctx context.Context, cell, root, id string, conn *nats.Conn,
	key ed25519.PrivateKey, binaries map[string]string, staged []string, starts *rolloutStartLog,
) *rolloutTestUnit {
	t.Helper()
	bad, err := os.ReadFile(binaries["bad"])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bad)
	unit := &rolloutTestUnit{t: t, ctx: ctx, cell: cell, id: id, conn: conn, key: key, baked: binaries["from"],
		bad: hex.EncodeToString(sum[:]), starts: starts,
		layout:    selfupdate.Layout{Root: filepath.Join(root, "release-"+id), Owner: os.Getuid()},
		proofFile: filepath.Join(root, id+"-proof.json")}
	for _, name := range staged {
		stageRolloutTestRelease(t, unit.layout, binaries[name])
	}
	if _, err := selfupdate.Seed(unit.layout, unit.baked); err != nil {
		t.Fatal(err)
	}
	if err := unit.restart(ctx, rolloutTestSystemdUnit); err != nil {
		t.Fatal(err)
	}
	go unit.watchdog()
	return unit
}

// stageRolloutTestRelease installs path as a staged release without a
// current link, as a verified stage would.
func stageRolloutTestRelease(t *testing.T, layout selfupdate.Layout, path string) string {
	t.Helper()
	digest, err := selfupdate.Seed(layout, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(layout.ReleaseDir(digest), "baked"), filepath.Join(layout.Root, "current")} {
		if err := os.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
	return digest
}

func (u *rolloutTestUnit) restart(_ context.Context, systemdUnit string) error {
	if systemdUnit != rolloutTestSystemdUnit {
		return fmt.Errorf("unexpected unit %s", systemdUnit)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.stop != nil {
		u.stop()
	}
	unlock, err := u.layout.Lock()
	if err != nil {
		return err
	}
	_, prepareErr := selfupdate.Prepare(u.layout, systemdUnit, u.baked, selfupdate.ProofCheck{}, time.Now())
	current, currentErr := u.layout.Current()
	activation, pending, pendingErr := u.layout.Pending()
	unlock()
	if err := errors.Join(prepareErr, currentErr, pendingErr); err != nil {
		return err
	}
	u.runs = current
	u.starts.add(u.id, current)
	ctx, stop := context.WithCancel(u.ctx)
	u.stop = stop
	if current == u.bad {
		return nil
	}
	if pending && activation.Target == current {
		now := time.Now().UTC()
		wire, err := selfupdate.SignVersionProof(selfupdate.VersionProof{Schema: selfupdate.ProofSchema,
			ActivationID: activation.ActivationID, Unit: systemdUnit, BinarySHA256: current,
			ProcessID: int64(os.Getpid()), ObservedAt: now}, u.key, now)
		if err != nil {
			return err
		}
		if err := os.WriteFile(u.proofFile, wire, 0o644); err != nil {
			return err
		}
	}
	publisher := rolloutexec.Publisher{Conn: u.conn, Cell: u.cell, Unit: u.id, Key: u.key, Interval: 200 * time.Millisecond,
		Executable: u.layout.BinaryPath(current), Healthy: func() bool { return true }}
	go func() { _ = publisher.Run(ctx) }()
	return nil
}

// attachAgent makes the unit's watchdog the node's root step agent, as in
// the image: it applies the steps the unit's controller spools into spool
// and leaves the restart it owes to the watchdog.
func (u *rolloutTestUnit) attachAgent(leaders trust.Keyring, spool string, verifier selfupdate.Verifier) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.agent = &rolloutexec.Agent{Cell: u.cell, Unit: u.id, SystemdUnit: rolloutTestSystemdUnit, Layout: u.layout,
		Leaders: leaders, Restart: func(context.Context, string) error { return nil }}
	u.spool, u.verifier = spool, verifier
}

// watchdog is the selfupdate watchdog timer of the unit: it applies the
// spooled rollout step, then confirms or rolls back the activation and
// restarts the unit it owes a restart.
func (u *rolloutTestUnit) watchdog() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-ticker.C:
		}
		u.mu.Lock()
		agent, spool, verifier := u.agent, u.spool, u.verifier
		u.mu.Unlock()
		if agent != nil {
			if err := rolloutexec.ApplySpooled(u.ctx, agent, spool, verifier); err != nil {
				u.t.Logf("unit %s step agent: %v", u.id, err)
			}
		}
		unlock, err := u.layout.Lock()
		if err != nil {
			continue
		}
		_, _, watchErr := selfupdate.Watch(u.layout, rolloutTestSystemdUnit,
			selfupdate.ProofCheck{File: u.proofFile, PublicKey: u.key.Public().(ed25519.PublicKey)}, time.Now())
		owed, owedErr := u.layout.RestartPending(rolloutTestSystemdUnit)
		unlock()
		if watchErr == nil && owedErr == nil && owed {
			_ = u.restart(u.ctx, rolloutTestSystemdUnit)
		}
	}
}

// settledOn reports a unit running digest with no pending activation.
func (u *rolloutTestUnit) settledOn(digest string) bool {
	u.mu.Lock()
	runs := u.runs
	u.mu.Unlock()
	unlock, err := u.layout.Lock()
	if err != nil {
		return false
	}
	defer unlock()
	_, pending, err := u.layout.Pending()
	return err == nil && !pending && runs == digest
}
