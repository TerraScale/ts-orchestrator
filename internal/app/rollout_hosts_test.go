package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rolloutexec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

type hostSinkFixture struct {
	control *rolloutControl
	board   jetstream.KeyValue
	js      jetstream.JetStream
	store   *rollout.Store
	key     ed25519.PrivateKey
	host    host.Registration
}

func newHostSinkFixture(t *testing.T) *hostSinkFixture {
	t.Helper()
	js := testRolloutJetStream(t)
	store, err := rollout.OpenStore(t.Context(), js, "gru", 1, rolloutTestFence{epoch: 7})
	if err != nil {
		t.Fatal(err)
	}
	board, err := js.KeyValue(t.Context(), rollout.Bucket)
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	control := &rolloutControl{cell: "gru", layout: selfupdate.Layout{Root: t.TempDir(), Owner: os.Getuid()}}
	control.hosts.Store(&rolloutHosts{collector: rolloutexec.NewCollector("gru", nil, nil), board: board,
		colocated: colocatedNodes("gru", []rollout.Unit{{ID: "controller-a", Group: "controllers"}}, renamedSlotA),
		last:      map[string]time.Time{}, held: map[string]time.Time{}})
	return &hostSinkFixture{control: control, board: board, js: js, store: store, key: key, host: host.Registration{Cell: "gru",
		Node: "gru-1-db-1", Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(public)}}
}

// renamedSlotA is a cell spec whose host grant names controller-a's VM
// ts-gru-1 (TS-609).
func renamedSlotA(slot string) string {
	if slot == "controller-a" {
		return "ts-gru-1"
	}
	return "gru-" + slot
}

func (f *hostSinkFixture) proof(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	now := time.Now().UTC()
	wire, err := rolloutexec.SignHealthProof(rolloutexec.HealthProof{Schema: rolloutexec.HealthSchema, Cell: "gru",
		Unit: f.host.Node, BinarySHA256: strings.Repeat("a", 64), ProcessID: 7, StartNonce: "00000000000000000000000000000001",
		ObservedAt: now}, key, now)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// exchange runs one exchange as if a proof interval had passed since the
// host's previous one.
func (f *hostSinkFixture) exchange(t *testing.T, exchange host.RolloutExchange) (host.RolloutStep, error) {
	t.Helper()
	hosts := f.control.hosts.Load()
	hosts.mu.Lock()
	delete(hosts.last, f.host.Node)
	hosts.mu.Unlock()
	return f.control.Exchange(t.Context(), f.host, exchange)
}

func (f *hostSinkFixture) joined(t *testing.T, node string) bool {
	t.Helper()
	_, err := f.board.Get(t.Context(), rollout.HostMembershipKey(node))
	return err == nil
}

func TestReleasePinsAfterHostJoins(t *testing.T) {
	f := newHostSinkFixture(t)
	ctx := t.Context()
	digest := strings.Repeat("a", 64)
	if _, err := f.store.PublishRelease(ctx, 7, rollout.Release{Digest: digest, Actor: "ops", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.exchange(t, host.RolloutExchange{Proof: f.proof(t, f.key)}); err != nil {
		t.Fatal(err)
	}
	keys, err := f.board.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if key != "release.desired" && !entityid.Valid(key) {
			t.Fatalf("host joining created a non-ULID key: %s", key)
		}
	}
	rollback, knownBad, err := f.store.ReleasePins(ctx)
	if err != nil || !slices.Equal(rollback, []string{digest}) || len(knownBad) != 0 {
		t.Fatalf("pins after host joined: %v %v %v", rollback, knownBad, err)
	}
	channel, err := openChannelBucket(ctx, f.js, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.control.consumeChannel(ctx, f.store, channel, 7, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	entry, err := channel.Get(ctx, releasechannel.StatusKey("GRU"))
	if err != nil {
		t.Fatal(err)
	}
	var status releasechannel.Status
	if err := protocol.DecodeTolerant(entry.Value(), &status, releasechannel.MaxValueBytes); err != nil {
		t.Fatal(err)
	}
	if status.Pins == nil || !slices.Equal(status.Pins.Rollback, []string{digest}) {
		t.Fatalf("published pins after host joined: %+v", status.Pins)
	}
}

// A host joins the release program with a proof its registered key signed,
// gets its pending step back, and its step agent's reply reaches the board.
func TestHostRolloutExchangeVerifiesTheProofAndRelaysTheStep(t *testing.T) {
	f := newHostSinkFixture(t)
	ctx := t.Context()
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.exchange(t, host.RolloutExchange{Proof: f.proof(t, other)}); err == nil || f.joined(t, f.host.Node) {
		t.Fatalf("a proof another key signed was accepted (%v) or joined the host", err)
	}
	step, err := f.exchange(t, host.RolloutExchange{Proof: f.proof(t, f.key)})
	if err != nil || len(step.Step) != 0 || !f.joined(t, f.host.Node) {
		t.Fatalf("first exchange = %+v %v, joined %v", step, err, f.joined(t, f.host.Node))
	}
	if _, ok := f.control.hosts.Load().collector.Latest(f.host.Node); !ok {
		t.Fatal("the host's proof did not reach the executor")
	}
	if _, err := f.board.Put(ctx, rolloutexec.StepKey(f.host.Node), []byte("signed step")); err != nil {
		t.Fatal(err)
	}
	reply := []byte(`{"operation_id":"0000000000N6KCZG3MWDGZ0WBE","unit":"gru-1-db-1","epoch":7,"outcome":"activated"}`)
	step, err = f.exchange(t, host.RolloutExchange{Proof: f.proof(t, f.key), Reply: reply})
	if err != nil || string(step.Step) != "signed step" {
		t.Fatalf("exchange with a pending step = %+v %v", step, err)
	}
	if entry, err := f.board.Get(ctx, rolloutexec.ReplyKey(f.host.Node)); err != nil || string(entry.Value()) != string(reply) {
		t.Fatalf("reply on the board = %v", err)
	}
	foreign := []byte(`{"operation_id":"0000000000N6KCZG3MWDGZ0WBE","unit":"gru-1-db-2","epoch":7,"outcome":"refused"}`)
	if _, err := f.exchange(t, host.RolloutExchange{Proof: f.proof(t, f.key), Reply: foreign}); err == nil {
		t.Fatal("a reply for another unit was relayed")
	}
	oversized := append([]byte(`{"unit":"gru-1-db-1","reason":"`), bytes.Repeat([]byte("x"), maxHostReply)...)
	if _, err := f.exchange(t, host.RolloutExchange{Proof: f.proof(t, f.key), Reply: oversized}); err == nil {
		t.Fatal("an oversized reply was relayed")
	}
	// A host may not exchange faster than it proves.
	if _, err := f.control.Exchange(ctx, f.host, host.RolloutExchange{Proof: f.proof(t, f.key)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.control.Exchange(ctx, f.host, host.RolloutExchange{Proof: f.proof(t, f.key)}); err == nil {
		t.Fatal("a second exchange inside one proof interval was accepted")
	}
	// A host that says an operator holds its restarts is held.
	if _, err := f.exchange(t, host.RolloutExchange{Proof: f.proof(t, f.key), Held: true}); err != nil ||
		!f.control.hosts.Load().heldBy(f.host.Node) {
		t.Fatalf("a held host is not held: %v", err)
	}
	if _, err := f.exchange(t, host.RolloutExchange{Proof: f.proof(t, f.key)}); err != nil || f.control.hosts.Load().heldBy(f.host.Node) {
		t.Fatalf("a released host is still held: %v", err)
	}
	// A host on a controller's VM, or one registered as a controller, is
	// never a host unit.
	for _, node := range []string{"gru-1-ctl-1", "controller-a", "ts-gru-1"} {
		colocated := f.host
		colocated.Node = node
		if _, err := f.control.Exchange(ctx, colocated, host.RolloutExchange{Proof: f.proof(t, f.key)}); err == nil {
			t.Fatalf("%s took part as a host", node)
		}
	}
}

// The leader serves a host the release from its own release root, only
// within the release.
func TestHostRolloutBinaryServesTheLeadersRelease(t *testing.T) {
	f := newHostSinkFixture(t)
	release := []byte(strings.Repeat("orchestrator ", 100))
	digest := digestOf(release)
	if err := os.MkdirAll(filepath.Dir(f.control.layout.BinaryPath(digest)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.control.layout.BinaryPath(digest), release, 0o555); err != nil {
		t.Fatal(err)
	}
	chunk, err := f.control.Binary(t.Context(), digest, 1000, 512)
	if err != nil || chunk.Size != int64(len(release)) || string(chunk.Data) != string(release[1000:]) {
		t.Fatalf("last chunk = %d bytes of %d, %v", len(chunk.Data), chunk.Size, err)
	}
	if _, err := f.control.Binary(t.Context(), digest, int64(len(release))+1, 512); err == nil {
		t.Fatal("a chunk past the release was served")
	}
	if _, err := f.control.Binary(t.Context(), strings.Repeat("b", 64), 0, 512); err == nil {
		t.Fatal("a release this node lacks was served")
	}
}

// Only joined hosts move, never one on a controller's VM, and TerraBase
// hosts share one group so a wave stops one seat at a time.
func TestHostUnitsAreTheJoinedHostsGroupedByTerraBaseSeats(t *testing.T) {
	f := newHostSinkFixture(t)
	for _, node := range []string{"gru-1-ctl-1", "ts-gru-1", "gru-1-db-1", "gru-1-db-2", "gru-1-api-1", "gru-1-db-4"} {
		wire, err := protocol.EncodeJSON(rollout.HostMembership{Node: node, PublicKey: "key-" + node})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.board.Create(t.Context(), rollout.HostMembershipKey(node), wire); err != nil {
			t.Fatal(err)
		}
	}
	registrations := []host.Registration{
		{Node: "gru-1-ctl-1", Roles: []string{"ts-auth"}, PublicKey: "key-gru-1-ctl-1"},
		// controller-a's VM after its rename (TS-609).
		{Node: "ts-gru-1", Roles: []string{"ts-auth"}, PublicKey: "key-ts-gru-1"},
		{Node: "gru-1-db-1", Roles: []string{"terrabase"}, PublicKey: "key-gru-1-db-1"},
		{Node: "gru-1-db-2", Roles: []string{"terrabase"}, PublicKey: "key-gru-1-db-2"},
		{Node: "gru-1-db-3", Roles: []string{"terrabase"}, PublicKey: "key-gru-1-db-3"},
		{Node: "gru-1-api-1", Roles: []string{"ts-auth"}, PublicKey: "key-gru-1-api-1"},
		// Replaced under its name: a stranger until it proves with its key.
		{Node: "gru-1-db-4", Roles: []string{"terrabase"}, PublicKey: "key-of-the-new-gru-1-db-4"},
	}
	list := func(context.Context) ([]host.HostStatus, error) {
		var statuses []host.HostStatus
		for _, registration := range registrations {
			statuses = append(statuses, host.HostStatus{Registration: registration})
		}
		return statuses, nil
	}
	load := hostUnits(list, f.board, colocatedNodes("gru", []rollout.Unit{{ID: "controller-a", Group: "controllers"}}, renamedSlotA))
	if _, err := load(t.Context()); err == nil || !strings.Contains(err.Error(), "gru-1-db-3 has not joined") {
		t.Fatalf("an unjoined host was omitted: %v", err)
	}
	if _, err := f.board.Put(t.Context(), joinedKey("gru-1-db-3"), []byte("key-gru-1-db-3")); err != nil {
		t.Fatal(err)
	}
	if _, err := load(t.Context()); err == nil || !strings.Contains(err.Error(), "gru-1-db-4 has not proved") {
		t.Fatalf("a replaced host was omitted: %v", err)
	}
	if _, err := f.board.Put(t.Context(), joinedKey("gru-1-db-4"), []byte("key-of-the-new-gru-1-db-4")); err != nil {
		t.Fatal(err)
	}
	units, err := load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	groups := map[string]string{}
	for _, unit := range units {
		groups[unit.ID] = unit.Group
	}
	if len(groups) != 5 || groups["gru-1-db-1"] != groups["gru-1-db-2"] || groups["gru-1-api-1"] == groups["gru-1-db-1"] {
		t.Fatalf("host units = %+v, want every db host in one group and the api host alone", units)
	}
	if _, err := hostUnits(func(context.Context) ([]host.HostStatus, error) { return nil, errors.New("no log") },
		f.board, nil)(t.Context()); err == nil {
		t.Fatal("an unreadable host list moved no host silently")
	}
}

func TestHostUnitsExcludeRetiredHistoryButKeepCurrentHostsWithoutSessions(t *testing.T) {
	f := newHostSinkFixture(t)
	statuses := []host.HostStatus{
		{Registration: host.Registration{Node: "retired-history", PublicKey: "old-key"}, Retired: true},
		{Registration: host.Registration{Node: "current-host", PublicKey: "current-key"}},
	}
	load := hostUnits(func(context.Context) ([]host.HostStatus, error) { return statuses, nil }, f.board,
		func(string) bool { return false })
	if _, err := load(t.Context()); err == nil || !strings.Contains(err.Error(), "current-host has not joined") {
		t.Fatalf("historical retirement blocked rollout or a missing current session was silently omitted: %v", err)
	}
	if _, err := f.board.Create(t.Context(), joinedKey("current-host"), []byte("current-key")); err != nil {
		t.Fatal(err)
	}
	units, err := load(t.Context())
	if err != nil || len(units) != 1 || units[0].ID != "current-host" {
		t.Fatalf("retired history participated or silent current host disappeared: %+v, %v", units, err)
	}
}

type passGate struct{}

func (passGate) Check(context.Context, rollout.Record, string) error { return nil }

// A host step waits while the TerraBase seat controller has a seat out of
// rotation; controller steps and preflight do not.
func TestRolloutGateHoldsHostStepsWhileASeatIsDrained(t *testing.T) {
	drained := map[string]bool{"gru-1-db-2": true}
	gate := rolloutGate{cluster: passGate{}, drainedSeats: func(context.Context) (map[string]bool, error) { return drained, nil }}
	hosts, controllers := rollout.Record{Kind: rollout.KindHost}, rollout.Record{Kind: rollout.KindController}
	if err := gate.Check(t.Context(), hosts, "gru-1-db-1"); !errors.Is(err, rolloutexec.ErrGateHeld) ||
		!strings.Contains(err.Error(), "gru-1-db-2") {
		t.Fatalf("host step with a drained seat = %v", err)
	}
	if err := gate.Check(t.Context(), controllers, "controller-a"); err != nil {
		t.Fatalf("controller step = %v", err)
	}
	if err := gate.Check(t.Context(), hosts, ""); err != nil {
		t.Fatalf("host preflight = %v", err)
	}
	drained = map[string]bool{}
	if err := gate.Check(t.Context(), hosts, "gru-1-db-1"); err != nil {
		t.Fatalf("host step with every seat in rotation = %v", err)
	}
	gate.drainedSeats = func(context.Context) (map[string]bool, error) { return nil, errors.New("no bucket") }
	if err := gate.Check(t.Context(), hosts, "gru-1-db-1"); !errors.Is(err, rolloutexec.ErrGateHeld) {
		t.Fatalf("host step with unreadable seats = %v", err)
	}
	gate.drainedSeats = nil
	gate.held = func(unit string) bool { return unit == "gru-1-db-1" }
	if err := gate.Check(t.Context(), hosts, "gru-1-db-1"); !errors.Is(err, rolloutexec.ErrGateHeld) {
		t.Fatalf("host step under a restart hold = %v", err)
	}
	if err := gate.Check(t.Context(), hosts, "gru-1-db-2"); err != nil {
		t.Fatalf("host step without a hold = %v", err)
	}
}

// terraBaseMembers is a cell's TerraBase desired state and reports.
type terraBaseMembers struct {
	desired map[string]uint64
	reports []host.Report
}

func (m terraBaseMembers) ListDesired(context.Context, string) ([]host.Desired, error) {
	var out []host.Desired
	for node, generation := range m.desired {
		out = append(out, host.Desired{Node: node, Role: "terrabase", Generation: generation})
	}
	return out, nil
}

func (m terraBaseMembers) ListHosts(context.Context) ([]host.HostStatus, error) {
	return []host.HostStatus{{Reports: m.reports}}, nil
}

// A TerraBase host steps only while every member serves its desired
// generation: a member down for any reason, or one a TerraBase release is
// still restarting, holds it; a host without a member is never held.
func TestTerraBaseHostsStepOnlyWhileEveryMemberServes(t *testing.T) {
	now := time.Now().UTC()
	running := func(node string, generation uint64) host.Report {
		return host.Report{Node: node, Role: "terrabase", Generation: generation, State: "running", ObservedAt: now}
	}
	members := terraBaseMembers{desired: map[string]uint64{"gru-1-db-1": 3, "gru-1-db-2": 3},
		reports: []host.Report{running("gru-1-db-1", 3), running("gru-1-db-2", 3)}}
	if err := terraBaseServing(members)(t.Context(), "gru-1-db-1"); err != nil {
		t.Fatalf("every member serves: %v", err)
	}
	for name, edit := range map[string]func(*terraBaseMembers){
		"a peer's member crashed":         func(m *terraBaseMembers) { m.reports[1].State = "failed" },
		"a release restarts a peer":       func(m *terraBaseMembers) { m.desired["gru-1-db-2"] = 4 },
		"a peer's report is stale":        func(m *terraBaseMembers) { m.reports[1].ObservedAt = now.Add(-host.ReportMaxAge) },
		"a peer reports no member at all": func(m *terraBaseMembers) { m.reports = m.reports[:1] },
	} {
		changed := terraBaseMembers{desired: maps.Clone(members.desired), reports: slices.Clone(members.reports)}
		edit(&changed)
		if err := terraBaseServing(changed)(t.Context(), "gru-1-db-1"); !errors.Is(err, rolloutexec.ErrGateHeld) {
			t.Errorf("%s: host step = %v", name, err)
		}
	}
	down := terraBaseMembers{desired: members.desired, reports: members.reports[:1]}
	if err := terraBaseServing(down)(t.Context(), "gru-1-api-1"); err != nil {
		t.Fatalf("a host without a member was held: %v", err)
	}
}

type fakeRolloutSession struct {
	mu        sync.Mutex
	step      []byte
	release   []byte
	exchanges []host.RolloutExchange
}

func (s *fakeRolloutSession) RolloutExchange(_ context.Context, exchange host.RolloutExchange) (host.RolloutStep, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exchanges = append(s.exchanges, exchange)
	return host.RolloutStep{Step: s.step}, nil
}

func (s *fakeRolloutSession) FetchRelease(_ context.Context, _ string, dst io.Writer) error {
	_, err := dst.Write(s.release)
	return err
}

func (*fakeRolloutSession) SessionLost() bool { return false }

func (s *fakeRolloutSession) last() (host.RolloutExchange, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.exchanges) == 0 {
		return host.RolloutExchange{}, 0
	}
	return s.exchanges[len(s.exchanges)-1], len(s.exchanges)
}

// A host agent proves its release with its own key, spools the leader's
// step with the release it fetched over its session, and passes its step
// agent's reply back.
func TestHostRolloutFollowerSpoolsTheLeadersStepAndRelaysTheReply(t *testing.T) {
	identityPublic, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaderPublic, leader, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release := []byte("orchestrator release for hosts")
	now := time.Now().UTC()
	step, err := rolloutexec.SignStepCommand(rolloutexec.StepCommand{Schema: rolloutexec.StepSchema, Cell: "gru",
		RolloutID: "0000000000XJEH5D70V6SZ16YY", Kind: rollout.KindHost, Unit: "gru-1-db-1",
		OperationID: rollout.OperationID("0000000000XJEH5D70V6SZ16YY", "gru-1-db-1", rollout.PhaseCanary, 0),
		Action:      rolloutexec.StepPrepare, Digest: digestOf(release), Replaces: strings.Repeat("a", 64), Epoch: 3,
		ProofWindowSeconds: 60}, leader, now, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	session := &fakeRolloutSession{step: step, release: release}
	spool := filepath.Join(t.TempDir(), "spool")
	layout := selfupdate.Layout{Root: t.TempDir(), Owner: os.Getuid()}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go followHostRollouts(hostRollout{cell: "gru", node: "gru-1-db-1", identity: identity, controller: leaderPublic,
		spool: spool, layout: layout, interval: 20 * time.Millisecond})(ctx, session)
	waitFor := func(what string, done func() bool) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); !done(); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
		}
	}
	waitFor("the spooled step and release", func() bool {
		spooled, err := os.ReadFile(filepath.Join(spool, "step.json"))
		fetched, fetchErr := os.ReadFile(filepath.Join(spool, "release-"+digestOf(release)))
		return err == nil && fetchErr == nil && string(spooled) == string(step) && string(fetched) == string(release)
	})
	exchange, _ := session.last()
	keys, err := trust.ParseKeyring(identityPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rolloutexec.VerifyHealthProof(exchange.Proof, "gru", "gru-1-db-1", keys, time.Now().UTC()); err != nil {
		t.Fatalf("the host's proof does not verify with its key: %v", err)
	}
	reply := []byte(`{"operation_id":"0000000000N6KCZG3MWDGZ0WBE","unit":"gru-1-db-1","epoch":3,"outcome":"activated"}`)
	if err := os.WriteFile(filepath.Join(layout.Root, rolloutexec.ReplyFile(selfupdate.HostUnit)), reply, 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor("the relayed reply", func() bool {
		exchange, _ := session.last()
		return string(exchange.Reply) == string(reply)
	})
}
