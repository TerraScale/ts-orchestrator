package reaper

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
)

const (
	reaperStream               = "KV_ORCH_LEADERS"
	reaperLeaseSubject         = "$KV.ORCH_LEADERS.authority.global"
	reaperStateSubject         = "$KV.ORCH_LEADERS.reaper.state"
	reaperBarrierSubject       = "$KV.ORCH_LEADERS.reaper.barrier"
	maximumReaperStateBytes    = 56 << 10
	maximumReaperDocumentBytes = 128 << 10
)

var (
	ErrStateUnavailable = errors.New("reaper: authoritative state unavailable")
	ErrStateConflict    = errors.New("reaper: loaded state revision conflicted")
	ErrStateFenced      = errors.New("reaper: global authority fenced")
	ErrStateNotLoaded   = errors.New("reaper: session must load state before saving")
)

// NATSStateStoreConfig binds the actual GRU election identity to its global
// account connection. Recreate the reconciler/store after authority takeover.
// Lease, state and read barriers share one R3 stream so a stream CAS also fences
// an authority change. The caller owns the connection for the session lifetime.
type NATSStateStoreConfig struct {
	Connection     *nats.Conn
	CandidateID    string
	AuthorityEpoch uint64
	LeaseID        string
}

// NATSStateStore is one reconciler's optimistic state session. Never share one
// instance across reconcilers: Load establishes this session's expected state
// revision, and Save advances it only after proving the server commit. Production
// construction creates a separate store for each reaper.Reconciler.
// This fences durable state; provider adapters must independently fence effects.
type NATSStateStore struct {
	connection *nats.Conn
	js         jetstream.JetStream
	candidate  string
	epoch      uint64
	leaseID    string
	mu         sync.Mutex
	loaded     bool
	revision   uint64
}

var _ StateStore = (*NATSStateStore)(nil)

func NewNATSStateStore(config NATSStateStoreConfig) (*NATSStateStore, error) {
	if config.Connection == nil || config.AuthorityEpoch == 0 || config.AuthorityEpoch > math.MaxInt64 || !reaperToken(config.LeaseID) || !strings.HasPrefix(config.CandidateID, "global-controller-gru-") || !reaperToken(config.CandidateID) {
		return nil, ErrStateFenced
	}
	if err := reaperTransport(config.Connection); err != nil {
		return nil, err
	}
	js, err := jetstream.New(config.Connection)
	if err != nil {
		return nil, ErrStateUnavailable
	}
	return &NATSStateStore{connection: config.Connection, js: js, candidate: config.CandidateID, epoch: config.AuthorityEpoch, leaseID: config.LeaseID}, nil
}

func reaperToken(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func reaperTransport(connection *nats.Conn) error {
	if connection == nil || !connection.IsConnected() || !connection.AuthRequired() {
		return ErrStateUnavailable
	}
	options := connection.Opts
	if options.Nkey == "" || options.SignatureCB == nil || options.AllowReconnect || options.ReconnectBufSize >= 0 || options.TLSConfig == nil || options.TLSConfig.InsecureSkipVerify || options.TLSConfig.RootCAs == nil || (len(options.TLSConfig.Certificates) == 0 && options.TLSConfig.GetClientCertificate == nil && options.TLSCertCB == nil) {
		return ErrStateUnavailable
	}
	state, err := connection.TLSConnectionState()
	if err != nil || !state.HandshakeComplete || state.Version < tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		return ErrStateUnavailable
	}
	return nil
}

func (s *NATSStateStore) Load(ctx context.Context) (State, error) {
	if s == nil || ctx == nil {
		return State{}, ErrStateUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loaded = false
	operation, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for attempt := 0; attempt < 8; attempt++ {
		snapshot, err := s.snapshot(operation)
		if errors.Is(err, ErrStateConflict) {
			continue
		}
		if err != nil {
			return State{}, err
		}
		sequence, err := s.commit(operation, snapshot, snapshot.state, snapshot.recovered)
		if errors.Is(err, ErrStateConflict) {
			continue
		}
		if err != nil {
			return State{}, err
		}
		s.loaded = true
		s.revision = snapshot.revision
		if snapshot.recovered {
			s.revision = sequence
		}
		if snapshot.state == nil {
			return State{Entries: make(map[string]Entry)}, nil
		}
		return *snapshot.state, nil
	}
	return State{}, ErrStateConflict
}

func (s *NATSStateStore) Save(ctx context.Context, state State) error {
	if s == nil || ctx == nil {
		return ErrStateUnavailable
	}
	proposed, err := reaperStateBytes(&state)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return ErrStateNotLoaded
	}
	operation, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for attempt := 0; attempt < 8; attempt++ {
		snapshot, err := s.snapshot(operation)
		if errors.Is(err, ErrStateConflict) {
			continue
		}
		if err != nil {
			return err
		}
		current, err := reaperStateBytes(snapshot.state)
		if err != nil {
			return err
		}
		same := bytes.Equal(current, proposed)
		if snapshot.revision != s.revision && !same {
			return ErrStateConflict
		}
		// Retrying an indeterminate, identical commit needs a fresh stream barrier.
		// A follower's same-value read alone cannot prove authoritative success.
		if err := reaperIntentTransition(snapshot.state, &state); err != nil {
			return err
		}
		write := !same || snapshot.recovered
		sequence, err := s.commit(operation, snapshot, &state, write)
		if errors.Is(err, ErrStateConflict) {
			continue
		}
		if err != nil {
			return err
		}
		s.revision = snapshot.revision
		if write {
			s.revision = sequence
		}
		return nil
	}
	return ErrStateConflict
}

func reaperLeaseLive(lease authority.RegionalAuthorityLeaseDocument, at time.Time) bool {
	return lease.Validate() == nil && lease.AuthorityId == "global" && strings.HasPrefix(lease.CandidateId, "global-controller-gru-") && reaperToken(lease.CandidateId) && !at.Before(lease.IssuedAt) && at.Before(lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond))
}
