package host

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/nats-io/nats.go/jetstream"
)

func TestControllerRejectsObsoleteRetirementState(t *testing.T) {
	for _, value := range []string{`{"retired":true,"at":"2026-10-09T00:00:00Z"}`, `{"retired":false}`, `malformed`} {
		t.Run(value, func(t *testing.T) {
			c, _, store, mutations, key := testController(t)
			js, err := jetstream.New(c.conn)
			if err != nil {
				t.Fatal(err)
			}
			obsoleteKey := "retired.gru.node-a"
			revision, err := c.state.Put(t.Context(), obsoleteKey, []byte(value))
			if err != nil {
				t.Fatal(err)
			}
			restarted, err := NewController(t.Context(), ControllerConfig{Cell: c.cell, Conn: c.conn, JS: js,
				State: c.state, ControlLog: c.controlLog, Artifacts: store, ResponseKey: key, StateReplicas: 1,
				HostMutations: c.mutations, AuthorityEpoch: c.authorityEpoch, AuthorityGuard: c.authorityGuard})
			if restarted != nil {
				restarted.cacheCancel()
				t.Fatal("host controller can allocate over obsolete retirement state")
			}
			if err == nil || !strings.Contains(err.Error(), "obsolete retirement keys") {
				t.Fatalf("startup over obsolete state: %v", err)
			}
			entry, err := c.state.Get(t.Context(), obsoleteKey)
			if err != nil || entry.Revision() != revision || string(entry.Value()) != value {
				t.Fatalf("startup changed the old safety mark: %v", err)
			}
			if _, err := mutations.ReadHostMutation(t.Context(), authority.MutationRetirement, "gru.node-a"); !errors.Is(err, authority.ErrNotFound) {
				t.Fatalf("startup migrated obsolete state: %v", err)
			}
		})
	}
}

type unavailableRetirementKeys struct {
	jetstream.KeyValue
	err error
}

func (state unavailableRetirementKeys) ListKeysFiltered(context.Context, ...string) (jetstream.KeyLister, error) {
	return nil, state.err
}

func TestRetirementStorageValidationFailsClosed(t *testing.T) {
	failure := errors.New("host state unavailable")
	if _, err := loadRetirementQuarantines(t.Context(), nil, unavailableRetirementKeys{err: failure}, "gru"); !errors.Is(err, failure) {
		t.Fatalf("failed storage validation accepted: %v", err)
	}
}

func TestRetirementAndRenameKeepHistoricalUsageWindows(t *testing.T) {
	c, _, _, _, _ := testController(t)
	if err := c.InitializeUsageHistory(t.Context()); err != nil {
		t.Fatal(err)
	}
	registerTestHost(t, c)
	latest := func(kind authority.HostMutationKind) *jetstream.RawStreamMsg {
		t.Helper()
		entry, err := c.controlLog.GetLastMsgForSubject(t.Context(), "ts.control.gru.host."+string(kind)+".gru.node-a")
		if err != nil {
			t.Fatal(err)
		}
		return entry
	}
	first := latest(authority.MutationRegistration)
	beforeRename := time.Now().UTC()
	check := func(reader *Controller, from, to time.Time, want []string) {
		t.Helper()
		got, err := reader.ExpectedUsage(t.Context(), from, to)
		if err != nil || !slices.Equal(usageIdentities(got), want) {
			t.Fatalf("inventory [%s,%s) = %v, %v; want %v", from, to, got, err, want)
		}
	}
	check(c, first.Time, beforeRename, []string{"node-a"})
	registration, _, _, err := c.readRegistration(t.Context(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	registration.Node, registration.NATSUserPublicKey = "node-b", testNATSUserKey("node-b")
	registration.ID = entityid.Derive("host", "gru", "node-b")
	if _, err := c.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	if retired, err := c.RetireIdle(t.Context(), "node-a"); err != nil || !retired {
		t.Fatalf("retire renamed identity: %t %v", retired, err)
	}
	retired := latest(authority.MutationRetirement)
	check(c, first.Time, beforeRename, []string{"node-a"})
	check(c, first.Time, retired.Time, []string{"node-a", "node-b"})
	check(c, retired.Time, time.Now().UTC(), []string{"node-b"})
	if ok, err := c.RetireIdle(t.Context(), "node-a"); err != nil || !ok || latest(authority.MutationRetirement).Sequence != retired.Sequence {
		t.Fatalf("repeated retirement changed its historical boundary: %t %v", ok, err)
	}
	// A fresh cache must load the retired state from its startup baseline.
	successor := &Controller{cell: c.cell, controlLog: c.controlLog, mutations: c.mutations, authorityEpoch: c.authorityEpoch, authorityGuard: c.authorityGuard}
	if err := successor.InitializeUsageHistory(t.Context()); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC()
	check(successor, start, time.Now().UTC(), []string{"node-b"})
	if err := successor.Unretire(t.Context(), "node-a"); err != nil {
		t.Fatal(err)
	}
	unretired := latest(authority.MutationRetirement)
	check(c, retired.Time, unretired.Time, []string{"node-b"})
	check(c, first.Time, beforeRename, []string{"node-a"})
	check(c, unretired.Time, time.Now().UTC(), []string{"node-a", "node-b"})
	check(successor, unretired.Time, time.Now().UTC(), []string{"node-a", "node-b"})
	end := time.Now().UTC()
	intervals, err := c.ExpectedUsage(t.Context(), first.Time, end)
	if err != nil {
		t.Fatal(err)
	}
	nodeA := slices.DeleteFunc(intervals, func(interval hostload.UsageInterval) bool { return interval.Node != "node-a" })
	want := []hostload.UsageInterval{
		{Node: "node-a", Environment: registration.Environment, From: first.Time, To: retired.Time},
		{Node: "node-a", Environment: registration.Environment, From: unretired.Time, To: end},
	}
	if !slices.Equal(nodeA, want) {
		t.Fatalf("retirement gap disappeared: %v; want %v", nodeA, want)
	}
}

func TestHistoricalRetirementRequiresStateAndIdentity(t *testing.T) {
	for _, value := range []string{`{}`, `{"retired":null}`, `{"retired":"yes"}`, `{"retired":true,"node":"other"}`} {
		t.Run(value, func(t *testing.T) {
			c, _, _, mutations, _ := testController(t)
			if err := c.InitializeUsageHistory(t.Context()); err != nil {
				t.Fatal(err)
			}
			registerTestHost(t, c)
			from := time.Now().UTC()
			if _, err := mutations.CommitHostMutation(t.Context(), 1, authority.MutationRetirement, "gru.node-a", entityid.New(), 0, []byte(value)); err != nil {
				t.Fatal(err)
			}
			if _, err := c.ExpectedUsage(t.Context(), from, time.Now().UTC()); err == nil {
				t.Fatal("invalid retirement produced a complete inventory")
			}
			if _, err := c.retired(t.Context(), "node-a"); err == nil {
				t.Fatal("invalid retirement became a live host")
			}
		})
	}
}

func TestRetirementCannotBeWrittenByFencedController(t *testing.T) {
	c, _, _, mutations, _ := testController(t)
	c.authorityGuard = func(context.Context, uint64) error { return authority.ErrFenced }
	if _, err := c.RetireIdle(t.Context(), "node-a"); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("fenced retirement was accepted: %v", err)
	}
	if err := c.Unretire(t.Context(), "node-a"); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("fenced unretirement was accepted: %v", err)
	}
	if _, err := mutations.ReadHostMutation(t.Context(), authority.MutationRetirement, "gru.node-a"); !errors.Is(err, authority.ErrNotFound) {
		t.Fatalf("fenced controller left a retirement record: %v", err)
	}
}

type retirementInventoryStream struct {
	jetstream.Stream
	info func(context.Context, ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error)
}

func (s retirementInventoryStream) Info(ctx context.Context, opts ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error) {
	return s.info(ctx, opts...)
}

func TestRetirementRequiresSuccessfulIdleCheckInSameEpoch(t *testing.T) {
	for _, mode := range []string{"inventory failure", "epoch change"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _, mutations, _ := testController(t)
			registerTestHost(t, c)
			stream := c.controlLog
			failure := errors.New("inventory unavailable")
			c.controlLog = retirementInventoryStream{Stream: stream, info: func(ctx context.Context, opts ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error) {
				if mode == "inventory failure" {
					return nil, failure
				}
				info, err := stream.Info(ctx, opts...)
				c.authorityEpoch = func() uint64 { return 2 }
				return info, err
			}}
			ok, err := c.RetireIdle(t.Context(), "node-a")
			want := failure
			if mode == "epoch change" {
				want = authority.ErrFenced
			}
			if ok || !errors.Is(err, want) {
				t.Fatalf("retirement used failed or stale inventory: %t %v", ok, err)
			}
			if _, err := mutations.ReadHostMutation(t.Context(), authority.MutationRetirement, "gru.node-a"); !errors.Is(err, authority.ErrNotFound) {
				t.Fatalf("failed idle check hid a registered node: %v", err)
			}
		})
	}
}

func TestAllocationIntervalsMustOverlapNonRetiredTime(t *testing.T) {
	c := &Controller{cell: "gru"}
	from := time.Now().UTC()
	entries := []authority.LogEntry{
		{Kind: authority.MutationRetirement, SubjectKey: "gru.node-a", CreatedAt: from.Add(10 * time.Second), Payload: []byte(`{"retired":true}`)},
		{Kind: authority.MutationRetirement, SubjectKey: "gru.node-a", CreatedAt: from.Add(20 * time.Second), Payload: []byte(`{"retired":false}`)},
		{Kind: authority.MutationRetirement, SubjectKey: "gru.node-a", CreatedAt: from.Add(25 * time.Second), Payload: []byte(`{"retired":true}`)},
	}
	active, err := c.activeUsageIntervals(entries, from, from.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, interval := range []struct {
		from, to int
		active   bool
	}{{0, 10, true}, {10, 20, false}, {20, 25, true}, {25, 30, false}, {10, 25, true}} {
		got := len(intersectActiveUsage(active, "gru.node-a", from.Add(time.Duration(interval.from)*time.Second), from.Add(time.Duration(interval.to)*time.Second))) > 0
		if got != interval.active {
			t.Fatalf("allocation [%d,%d) overlap = %t; want %t", interval.from, interval.to, got, interval.active)
		}
	}
	got := intersectActiveUsage(active, "gru.node-a", from.Add(5*time.Second), from.Add(27*time.Second))
	want := []usageInterval{{from.Add(5 * time.Second), from.Add(10 * time.Second)}, {from.Add(20 * time.Second), from.Add(25 * time.Second)}}
	if !slices.Equal(got, want) {
		t.Fatalf("active overlap lost exact boundaries: %v; want %v", got, want)
	}
}
