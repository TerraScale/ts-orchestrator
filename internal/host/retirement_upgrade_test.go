package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/nats.go/jetstream"
)

type quarantineTestMutations struct {
	*memoryMutations
	fenced       bool
	beforeVerify func(context.Context) error
}

func (m *quarantineTestMutations) CommitHostMutationVerified(ctx context.Context, epoch uint64,
	kind authority.HostMutationKind, subject, operation string, expected uint64, payload []byte,
	verify func(context.Context) error,
) (uint64, error) {
	if m.fenced || epoch != 1 {
		return 0, authority.ErrFenced
	}
	if m.beforeVerify != nil {
		if err := m.beforeVerify(ctx); err != nil {
			return 0, err
		}
	}
	if err := verify(ctx); err != nil {
		return 0, err
	}
	sequence, err := m.CommitHostMutation(ctx, epoch, kind, subject, operation, expected, payload)
	if err != nil {
		return 0, err
	}
	stream, err := m.js.Stream(ctx, "TS_CONTROL_LOG")
	if err != nil {
		return 0, err
	}
	raw, err := stream.GetMsg(ctx, sequence)
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	entry := m.entries[m.key(kind, subject)]
	entry.CreatedAt = raw.Time
	m.entries[m.key(kind, subject)] = entry
	m.mu.Unlock()
	return sequence, nil
}

func quarantineFixture(t *testing.T) (*Controller, *memoryMutations, *quarantineTestMutations, RetirementQuarantine) {
	t.Helper()
	old, _, store, mutations, key := testController(t)
	registerTestHost(t, old)
	legacyKey := "retired.gru.node-a"
	legacy := []byte(`{"retired":true,"at":"2026-10-07T20:01:01.972229852Z"}`)
	revision, err := old.state.Put(t.Context(), legacyKey, legacy)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(legacy)
	claim := RetirementQuarantine{RetirementQuarantineSchema, "gru", "node-a", legacyKey, revision, hex.EncodeToString(digest[:])}
	js, err := jetstream.New(old.conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateRetirementQuarantine(t.Context(), js, claim); err != nil {
		t.Fatal(err)
	}
	verified := &quarantineTestMutations{memoryMutations: mutations}
	c, err := NewController(t.Context(), ControllerConfig{Cell: old.cell, Conn: old.conn, JS: js,
		State: old.state, ControlLog: old.controlLog, Artifacts: store, ResponseKey: key, StateReplicas: 1,
		HostMutations: verified, AuthorityEpoch: old.authorityEpoch, AuthorityGuard: old.authorityGuard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(old.cacheCancel)
	t.Cleanup(c.cacheCancel)
	return c, mutations, verified, claim
}

func TestRetirementQuarantineValidatesPinsAndIndependentClaims(t *testing.T) {
	for _, change := range []string{"legacy-deleted", "legacy-rewritten", "legacy-cleared", "claim-deleted", "claim-malformed", "claim-wrong-node", "claim-wrong-digest"} {
		t.Run(change, func(t *testing.T) {
			c, _, _, claim := quarantineFixture(t)
			switch change {
			case "legacy-deleted":
				if err := c.state.Delete(t.Context(), claim.LegacyKey, jetstream.LastRevision(claim.LegacyRevision)); err != nil {
					t.Fatal(err)
				}
			case "legacy-rewritten":
				entry, err := c.state.Get(t.Context(), claim.LegacyKey)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := c.state.Put(t.Context(), claim.LegacyKey, entry.Value()); err != nil {
					t.Fatal(err)
				}
			case "legacy-cleared":
				if _, err := c.state.Put(t.Context(), claim.LegacyKey, []byte(`{"retired":false,"at":"2026-10-07T20:01:01Z"}`)); err != nil {
					t.Fatal(err)
				}
			case "claim-deleted":
				if err := c.state.Delete(t.Context(), quarantineKey(claim.Cell, claim.Node)); err != nil {
					t.Fatal(err)
				}
			case "claim-malformed":
				if _, err := c.state.Put(t.Context(), quarantineKey(claim.Cell, claim.Node), []byte(`{"schema":null}`)); err != nil {
					t.Fatal(err)
				}
			case "claim-wrong-node":
				claim.Node = "node-b"
				data, _ := json.Marshal(claim)
				if _, err := c.state.Put(t.Context(), quarantineKey("gru", "node-a"), data); err != nil {
					t.Fatal(err)
				}
			case "claim-wrong-digest":
				claim.LegacySHA256 = strings.Repeat("0", 64)
				data, _ := json.Marshal(claim)
				if _, err := c.state.Put(t.Context(), quarantineKey(claim.Cell, claim.Node), data); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := loadRetirementQuarantines(t.Context(), c.conn, c.state, c.cell); err == nil {
				t.Fatal("changed or missing quarantine evidence admitted at startup")
			}
			if _, err := c.registration(t.Context(), "node-a"); !errors.Is(err, ErrHostRetiring) {
				t.Fatalf("running controller reopened quarantined identity: %v", err)
			}
		})
	}
}

func TestCreateRetirementQuarantineRejectsInvalidEvidence(t *testing.T) {
	for _, value := range []string{`{"retired":false,"at":"2026-10-07T20:01:01Z"}`, `{"retired":null,"at":"2026-10-07T20:01:01Z"}`, `{"retired":true}`, `malformed`} {
		t.Run(value, func(t *testing.T) {
			c, _, _, _, _ := testController(t)
			key := "retired.gru.node-a"
			revision, err := c.state.Put(t.Context(), key, []byte(value))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(value))
			js, _ := jetstream.New(c.conn)
			claim := RetirementQuarantine{RetirementQuarantineSchema, "gru", "node-a", key, revision, hex.EncodeToString(digest[:])}
			if _, err := CreateRetirementQuarantine(t.Context(), js, claim); err == nil {
				t.Fatal("invalid retirement evidence was authorized")
			}
			entry, err := c.state.Get(t.Context(), key)
			if err != nil || entry.Revision() != revision || string(entry.Value()) != value {
				t.Fatalf("authorization changed legacy evidence: %v", err)
			}
		})
	}
}

func TestRetirementQuarantineDenialAndCutoverBinding(t *testing.T) {
	c, mutations, _, claim := quarantineFixture(t)
	registration, _, _, err := c.readRegistration(t.Context(), claim.Node)
	if err != nil {
		t.Fatal(err)
	}
	checkDenied := func() {
		t.Helper()
		if _, err := c.Register(t.Context(), registration); !errors.Is(err, ErrHostRetiring) {
			t.Fatalf("quarantined registration accepted: %v", err)
		}
		if _, err := c.ApplyDesired(t.Context(), Desired{Node: claim.Node, AuthorityEpoch: 1}); !errors.Is(err, ErrHostRetiring) {
			t.Fatalf("quarantined allocation accepted: %v", err)
		}
		if err := c.Unretire(t.Context(), claim.Node); !errors.Is(err, ErrHostRetiring) {
			t.Fatalf("quarantined unretirement accepted: %v", err)
		}
		if _, err := c.RetireIdle(t.Context(), claim.Node); !errors.Is(err, ErrHostRetiring) {
			t.Fatalf("quarantined identity authorized another reclamation: %v", err)
		}
	}
	checkDenied()
	if _, err := c.RetireIdle(t.Context(), "node-b"); !errors.Is(err, ErrRetirementCutoverPending) {
		t.Fatalf("mixed-version ordinary retirement accepted: %v", err)
	}
	if err := c.Unretire(t.Context(), "node-b"); !errors.Is(err, ErrRetirementCutoverPending) {
		t.Fatalf("mixed-version ordinary unretirement accepted: %v", err)
	}
	js, _ := jetstream.New(c.conn)
	digest, err := RetirementQuarantineSetSHA256(t.Context(), js, c.cell)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorizeRetirementCutover(t.Context(), js, c.cell, strings.Repeat("0", 64), 0); err == nil {
		t.Fatal("wrong quarantine set accepted")
	}
	if _, err := AuthorizeRetirementCutover(t.Context(), js, c.cell, digest, 0); err != nil {
		t.Fatal(err)
	}
	if retired, err := c.RetireIdle(t.Context(), "node-b"); err != nil || !retired {
		t.Fatalf("authorized ordinary retirement failed: %t %v", retired, err)
	}
	checkDenied()
	if _, err := mutations.CommitHostMutation(t.Context(), 1, authority.MutationRetirement, "gru.node-a", "force-false", 0, []byte(`{"retired":false}`)); err != nil {
		t.Fatal(err)
	}
	checkDenied()
	// Even rewriting identical claim bytes changes its revision and requires
	// a newly reviewed complete cutover set.
	entry, err := c.state.Get(t.Context(), quarantineKey(c.cell, claim.Node))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.state.Put(t.Context(), entry.Key(), entry.Value()); err != nil {
		t.Fatal(err)
	}
	if err := c.requireRetirementCutover(t.Context()); !errors.Is(err, ErrRetirementCutoverPending) {
		t.Fatalf("changed claim did not invalidate cutover: %v", err)
	}
}

func TestRetirementCutoverRejectsAdditionalQuarantine(t *testing.T) {
	c, _, _, _ := quarantineFixture(t)
	js, _ := jetstream.New(c.conn)
	digest, err := RetirementQuarantineSetSHA256(t.Context(), js, c.cell)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorizeRetirementCutover(t.Context(), js, c.cell, digest, 0); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"retired":true,"at":"2026-10-07T20:01:01Z"}`)
	revision, err := c.state.Put(t.Context(), "retired.gru.node-b", legacy)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(legacy)
	claim := RetirementQuarantine{RetirementQuarantineSchema, "gru", "node-b", "retired.gru.node-b", revision, hex.EncodeToString(hash[:])}
	if _, err := CreateRetirementQuarantine(t.Context(), js, claim); err != nil {
		t.Fatal(err)
	}
	if err := c.requireRetirementCutover(t.Context()); !errors.Is(err, ErrRetirementCutoverPending) {
		t.Fatalf("new claim did not invalidate cutover: %v", err)
	}
	if _, err := AuthorizeRetirementCutover(t.Context(), js, c.cell, digest, 0); err == nil {
		t.Fatal("stale reviewed claim set was accepted")
	}
}

func TestRetirementQuarantineImportIsFencedAndRechecksEvidence(t *testing.T) {
	for _, failure := range []string{"guard", "commit-fence", "legacy-changed", "claim-changed"} {
		t.Run(failure, func(t *testing.T) {
			c, mutations, store, claim := quarantineFixture(t)
			switch failure {
			case "guard":
				c.authorityGuard = func(context.Context, uint64) error { return authority.ErrFenced }
			case "commit-fence":
				store.fenced = true
			case "legacy-changed", "claim-changed":
				key := claim.LegacyKey
				if failure == "claim-changed" {
					key = quarantineKey(claim.Cell, claim.Node)
				}
				store.beforeVerify = func(ctx context.Context) error {
					entry, err := c.state.Get(ctx, key)
					if err != nil {
						return err
					}
					_, err = c.state.Put(ctx, key, entry.Value())
					return err
				}
			}
			if err := c.importRetirementQuarantines(t.Context()); err == nil {
				t.Fatal("fenced or changed evidence was imported")
			}
			if _, err := mutations.ReadHostMutation(t.Context(), authority.MutationRetirement, "gru.node-a"); !errors.Is(err, authority.ErrNotFound) {
				t.Fatalf("rejected import wrote retirement: %v", err)
			}
		})
	}
}

func TestQuarantineLeaderImportsOnceAndBoundsHistoricalUsage(t *testing.T) {
	c, mutations, _, claim := quarantineFixture(t)
	legacyBefore, err := c.state.Get(t.Context(), claim.LegacyKey)
	if err != nil {
		t.Fatal(err)
	}
	var leader atomic.Bool
	c.authorityLeader = leader.Load
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-c.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("follower host control did not become ready")
	}
	if _, err := mutations.ReadHostMutation(ctx, authority.MutationRetirement, "gru.node-a"); !errors.Is(err, authority.ErrNotFound) {
		t.Fatal("follower imported a retirement")
	}
	if _, err := c.ExpectedUsage(ctx, time.Now().Add(-time.Minute), time.Now()); err == nil {
		t.Fatal("unimported legacy retirement produced complete historical inventory")
	}
	leader.Store(true)
	var imported authority.LogEntry
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		imported, err = mutations.ReadHostMutation(ctx, authority.MutationRetirement, "gru.node-a")
		if err == nil && !imported.CreatedAt.IsZero() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || imported.CreatedAt.IsZero() || imported.Epoch != 1 {
		t.Fatalf("new leader did not import a timestamped retirement: %+v %v", imported, err)
	}
	if err := c.importRetirementQuarantines(ctx); err != nil {
		t.Fatal(err)
	}
	repeated, err := mutations.ReadHostMutation(ctx, authority.MutationRetirement, "gru.node-a")
	if err != nil || repeated.Sequence != imported.Sequence {
		t.Fatalf("idempotent import moved its historical boundary: %v", err)
	}
	legacyAfter, err := c.state.Get(ctx, claim.LegacyKey)
	if err != nil || legacyAfter.Revision() != legacyBefore.Revision() || string(legacyAfter.Value()) != string(legacyBefore.Value()) {
		t.Fatalf("import changed the legacy safety mark: %v", err)
	}
	if _, err := c.ExpectedUsage(ctx, imported.CreatedAt.Add(-time.Nanosecond), time.Now()); err == nil || !strings.Contains(err.Error(), "predates the retirement history import") {
		t.Fatalf("pre-import history was fabricated: %v", err)
	}
	floor, err := c.quarantineHistoryFloor(ctx)
	if err != nil || !floor.Equal(imported.CreatedAt) {
		t.Fatalf("historical floor does not use the actual JetStream import timestamp: %s %v", floor, err)
	}
	if err := c.InitializeUsageHistory(ctx); err != nil {
		t.Fatal(err)
	}
	from := time.Now()
	usage, err := c.ExpectedUsage(ctx, from, from.Add(time.Second))
	if err != nil || len(usage) != 0 {
		t.Fatalf("post-import inventory included quarantined identity: %+v %v", usage, err)
	}
}
