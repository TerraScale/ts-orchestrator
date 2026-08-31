package authority

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

type authorityStore struct {
	jetstream.KeyValue
	get    func(context.Context, string) (jetstream.KeyValueEntry, error)
	create func(context.Context, string, []byte, ...jetstream.KVCreateOpt) (uint64, error)
	update func(context.Context, string, []byte, uint64) (uint64, error)
}

func (s authorityStore) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	return s.get(ctx, key)
}

func (s authorityStore) Create(
	ctx context.Context,
	key string,
	value []byte,
	options ...jetstream.KVCreateOpt,
) (uint64, error) {
	return s.create(ctx, key, value, options...)
}

func (s authorityStore) Update(
	ctx context.Context,
	key string,
	value []byte,
	revision uint64,
) (uint64, error) {
	if s.update == nil {
		return 0, errors.New("unexpected authority update")
	}
	return s.update(ctx, key, value, revision)
}

type authorityEntry struct {
	key      string
	value    []byte
	revision uint64
}

func (e authorityEntry) Bucket() string                  { return "ORCH_LEADERS" }
func (e authorityEntry) Key() string                     { return e.key }
func (e authorityEntry) Value() []byte                   { return e.value }
func (e authorityEntry) Revision() uint64                { return e.revision }
func (e authorityEntry) Created() time.Time              { return time.Now().UTC() }
func (e authorityEntry) Delta() uint64                   { return 0 }
func (e authorityEntry) Operation() jetstream.KeyValueOp { return jetstream.KeyValuePut }

func TestCoordinatorClaimsAbsentLeaseAndPublishesLeader(t *testing.T) {
	var stored RegionalAuthorityLeaseDocument
	store := authorityStore{
		get: func(context.Context, string) (jetstream.KeyValueEntry, error) {
			return nil, jetstream.ErrKeyNotFound
		},
		create: func(_ context.Context, key string, value []byte, _ ...jetstream.KVCreateOpt) (uint64, error) {
			if key != "authority.regional" {
				t.Fatalf("create key = %q", key)
			}
			if err := json.Unmarshal(value, &stored); err != nil {
				t.Fatalf("decode lease: %v", err)
			}
			return 1, nil
		},
	}
	coordinator := newRegionalAuthorityCoordinator(
		store,
		"gru-regional",
		"gru-controller-controller-1",
		"authority.regional",
		false,
	)
	t.Cleanup(coordinator.stopping)
	coordinator.nonce = sequenceNonce("request", "lease")

	if err := coordinator.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot := coordinator.Snapshot()
	if !snapshot.IsLeader || snapshot.State != "leader" || snapshot.Epoch != 1 || snapshot.KvRevision != 1 {
		t.Fatalf("leader snapshot = %#v", snapshot)
	}
	if stored.AuthorityId != "gru-regional" ||
		stored.CandidateId != "gru-controller-controller-1" ||
		stored.LeaseId != "lease-lease" ||
		stored.Epoch != 1 {
		t.Fatalf("stored lease = %#v", stored)
	}
}

func TestCoordinatorFollowsLiveForeignLeaseWithoutCAS(t *testing.T) {
	now := time.Now().UTC()
	document := RegionalAuthorityLeaseDocument{
		SchemaVersion:        1,
		AuthorityId:          "gru-regional",
		Epoch:                7,
		CandidateId:          "gru-controller-controller-2",
		LeaseId:              "foreign-lease",
		IssuedAt:             now,
		DurationMilliseconds: 15000,
	}
	value, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	store := authorityStore{
		get: func(context.Context, string) (jetstream.KeyValueEntry, error) {
			return authorityEntry{key: "authority.regional", value: value, revision: 12}, nil
		},
		create: func(context.Context, string, []byte, ...jetstream.KVCreateOpt) (uint64, error) {
			t.Fatal("live foreign lease triggered a create")
			return 0, nil
		},
	}
	coordinator := newRegionalAuthorityCoordinator(
		store,
		"gru-regional",
		"gru-controller-controller-1",
		"authority.regional",
		false,
	)
	t.Cleanup(coordinator.stopping)

	if err := coordinator.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot := coordinator.Snapshot()
	if snapshot.IsLeader || snapshot.State != "follower" || snapshot.Epoch != 7 || snapshot.KvRevision != 12 {
		t.Fatalf("follower snapshot = %#v", snapshot)
	}
}

func TestCoordinatorCASConflictPublishesFollowerFromWinner(t *testing.T) {
	now := time.Now().UTC()
	winner := RegionalAuthorityLeaseDocument{
		SchemaVersion:        1,
		AuthorityId:          "gru-regional",
		Epoch:                1,
		CandidateId:          "gru-controller-controller-2",
		LeaseId:              "winner-lease",
		IssuedAt:             now,
		DurationMilliseconds: 15000,
	}
	value, err := json.Marshal(winner)
	if err != nil {
		t.Fatal(err)
	}
	getCalls := 0
	store := authorityStore{
		get: func(context.Context, string) (jetstream.KeyValueEntry, error) {
			getCalls++
			if getCalls == 1 {
				return nil, jetstream.ErrKeyNotFound
			}
			return authorityEntry{key: "authority.regional", value: value, revision: 1}, nil
		},
		create: func(context.Context, string, []byte, ...jetstream.KVCreateOpt) (uint64, error) {
			return 0, jetstream.ErrKeyExists
		},
	}
	coordinator := newRegionalAuthorityCoordinator(
		store,
		"gru-regional",
		"gru-controller-controller-1",
		"authority.regional",
		false,
	)
	t.Cleanup(coordinator.stopping)
	coordinator.nonce = sequenceNonce("request", "lease")

	if err := coordinator.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot := coordinator.Snapshot()
	if snapshot.IsLeader || snapshot.State != "follower" || snapshot.Epoch != 1 || snapshot.KvRevision != 1 {
		t.Fatalf("CAS loser snapshot = %#v", snapshot)
	}
	if getCalls != 2 {
		t.Fatalf("get calls = %d, want initial read plus conflict reconciliation", getCalls)
	}
}

func TestCoordinatorPropagatesNonceFailureBeforeMutatingKV(t *testing.T) {
	want := errors.New("entropy unavailable")
	createCalls := 0
	store := authorityStore{
		get: func(context.Context, string) (jetstream.KeyValueEntry, error) {
			return nil, jetstream.ErrKeyNotFound
		},
		create: func(context.Context, string, []byte, ...jetstream.KVCreateOpt) (uint64, error) {
			createCalls++
			return 0, nil
		},
	}
	coordinator := newRegionalAuthorityCoordinator(
		store,
		"gru-regional",
		"gru-controller-controller-1",
		"authority.regional",
		false,
	)
	t.Cleanup(coordinator.stopping)
	coordinator.nonce = func() (string, error) { return "", want }

	if err := coordinator.tick(context.Background()); !errors.Is(err, want) {
		t.Fatalf("tick error = %v, want %v", err, want)
	}
	if createCalls != 0 {
		t.Fatalf("entropy failure performed %d creates", createCalls)
	}
	if snapshot := coordinator.Snapshot(); snapshot.IsLeader {
		t.Fatalf("entropy failure published leader: %#v", snapshot)
	}
}

func TestCoordinatorStartRejectsInvalidArgumentsWithTypedErrors(t *testing.T) {
	store := authorityStore{}
	tests := []struct {
		name string
		call func() error
		want string
	}{
		{
			name: "context",
			call: func() error {
				_, err := RegionalAuthorityCoordinatorStartAsync(nil, store, "gru", "controller-1")
				return err
			},
			want: "ctx",
		},
		{
			name: "store",
			call: func() error {
				_, err := RegionalAuthorityCoordinatorStartAsync(context.Background(), nil, "gru", "controller-1")
				return err
			},
			want: "store",
		},
		{
			name: "cell",
			call: func() error {
				_, err := RegionalAuthorityCoordinatorStartAsync(context.Background(), store, "GRU", "controller-1")
				return err
			},
			want: "cell",
		},
		{
			name: "instance",
			call: func() error {
				_, err := RegionalAuthorityCoordinatorStartGlobalAsync(context.Background(), store, "gru", "Controller-1")
				return err
			},
			want: "instance",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var argument *errs.Argument
			if err := test.call(); !errors.As(err, &argument) || argument.Param != test.want {
				t.Fatalf("error = %#v, want *errs.Argument for %s", err, test.want)
			}
		})
	}
}

func sequenceNonce(values ...string) func() (string, error) {
	index := 0
	return func() (string, error) {
		if index >= len(values) {
			return "", errors.New("nonce sequence exhausted")
		}
		value := values[index]
		index++
		return value, nil
	}
}
