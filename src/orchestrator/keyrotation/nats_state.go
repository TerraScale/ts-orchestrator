package keyrotation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const (
	rotationStream               = "KV_ORCH_LEADERS"
	rotationLeaseSubject         = "$KV.ORCH_LEADERS.authority.global"
	rotationStateSubject         = "$KV.ORCH_LEADERS.security.rotation.state"
	rotationBarrierSubject       = "$KV.ORCH_LEADERS.security.rotation.barrier"
	maximumRotationStateBytes    = 128 << 10
	maximumRotationDocumentBytes = 300 << 10
)

var (
	ErrStateUnavailable = errors.New("key rotation: authoritative state unavailable")
	ErrStateConflict    = errors.New("key rotation: loaded state revision conflicted")
	ErrStateFenced      = errors.New("key rotation: global authority fenced")
	ErrStateNotLoaded   = errors.New("key rotation: session must load state before saving")
)

// NATSStateStoreConfig binds the actual GRU election identity to its global
// account connection. Recreate the coordinator/store after authority takeover.
// Lease, state and read barriers share one R3 stream so a stream CAS also fences
// an authority change. The caller owns the connection for the session lifetime.
type NATSStateStoreConfig struct {
	Connection     *nats.Conn
	CandidateID    string
	AuthorityEpoch uint64
}

// NATSStateStore is one coordinator's optimistic state session. Never share one
// instance across coordinators: Load establishes this session's expected state
// revision, and Save advances it only after proving the server commit. Production
// construction creates a separate store for each security.Coordinator.
// This fences durable state; provider adapters must independently fence effects.
type NATSStateStore struct {
	connection *nats.Conn
	js         jetstream.JetStream
	candidate  string
	epoch      uint64
	mu         sync.Mutex
	loaded     bool
	revision   uint64
}

var _ security.StateStore = (*NATSStateStore)(nil)

func NewNATSStateStore(config NATSStateStoreConfig) (*NATSStateStore, error) {
	if config.Connection == nil || config.AuthorityEpoch == 0 || config.AuthorityEpoch > math.MaxInt64 || !strings.HasPrefix(config.CandidateID, "global-controller-gru-") || !rotationToken(config.CandidateID) {
		return nil, configurationError("live GRU global state authority is required")
	}
	if err := rotationTransport(config.Connection); err != nil {
		return nil, err
	}
	js, err := jetstream.New(config.Connection)
	if err != nil {
		return nil, ErrStateUnavailable
	}
	return &NATSStateStore{connection: config.Connection, js: js, candidate: config.CandidateID, epoch: config.AuthorityEpoch}, nil
}

func rotationToken(value string) bool {
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

func rotationTransport(connection *nats.Conn) error {
	if connection == nil || !connection.IsConnected() || !connection.AuthRequired() {
		return ErrStateUnavailable
	}
	options := connection.Opts
	if options.Nkey == "" || options.SignatureCB == nil || options.AllowReconnect || options.ReconnectBufSize >= 0 || options.TLSConfig == nil || options.TLSConfig.InsecureSkipVerify || options.TLSConfig.RootCAs == nil || (len(options.TLSConfig.Certificates) == 0 && options.TLSConfig.GetClientCertificate == nil && options.TLSCertCB == nil) {
		return configurationError("authenticated TLS NKey transport without reconnect is required")
	}
	state, err := connection.TLSConnectionState()
	if err != nil || !state.HandshakeComplete || state.Version < tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		return ErrStateUnavailable
	}
	return nil
}

func (s *NATSStateStore) Load(ctx context.Context) (security.PersistedState, error) {
	if s == nil || ctx == nil {
		return security.PersistedState{}, ErrStateUnavailable
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
			return security.PersistedState{}, err
		}
		sequence, err := s.commit(operation, snapshot, snapshot.state, snapshot.recovered)
		if errors.Is(err, ErrStateConflict) {
			continue
		}
		if err != nil {
			return security.PersistedState{}, err
		}
		s.loaded = true
		s.revision = snapshot.revision
		if snapshot.recovered {
			s.revision = sequence
		}
		if snapshot.state == nil {
			return security.PersistedState{}, security.ErrNoState
		}
		return *snapshot.state, nil
	}
	return security.PersistedState{}, ErrStateConflict
}

func (s *NATSStateStore) Save(ctx context.Context, state security.PersistedState) error {
	if s == nil || ctx == nil {
		return ErrStateUnavailable
	}
	proposed, err := rotationStateBytes(&state)
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
		current, err := rotationStateBytes(snapshot.state)
		if err != nil {
			return err
		}
		same := bytes.Equal(current, proposed)
		if snapshot.revision != s.revision && !same {
			return ErrStateConflict
		}
		// Retrying an indeterminate, identical commit needs a fresh stream barrier.
		// A follower's same-value read alone cannot prove authoritative success.
		if err := rotationIntentTransition(snapshot.state, &state); err != nil {
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

func rotationStateBytes(state *security.PersistedState) ([]byte, error) {
	if state != nil {
		if !validOperationKey(state.OperationID) || state.Generation == 0 || state.NewVersion != state.Generation || state.LastVersion < state.Generation || state.LastAt.IsZero() || validateRegions(state.Regions) != nil || !security.ValidCurrentRotationState(*state) {
			return nil, ErrStateUnavailable
		}
		switch state.Phase {
		case security.PhasePrepare, security.PhaseDistribute, security.PhaseVerify, security.PhaseActivate, security.PhaseRetire, security.PhaseActive, security.PhaseFailed:
		default:
			return nil, ErrStateUnavailable
		}
	}
	raw, err := json.Marshal(state)
	if err != nil || len(raw) > maximumRotationStateBytes {
		return nil, ErrStateUnavailable
	}
	return raw, nil
}

func rotationLeaseLive(lease authority.RegionalAuthorityLeaseDocument, at time.Time) bool {
	return lease.Validate() == nil && lease.AuthorityId == "global" && strings.HasPrefix(lease.CandidateId, "global-controller-gru-") && rotationToken(lease.CandidateId) && !at.Before(lease.IssuedAt) && at.Before(lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond))
}

// Issued references and provider receipts are recovery obligations. A resumed
// provider operation cannot replace them while retaining the same intent ID.
func rotationIntentTransition(prior, next *security.PersistedState) error {
	if prior == nil {
		return nil
	}
	if prior.OperationID != next.OperationID {
		if (prior.Phase != security.PhaseActive && prior.Phase != security.PhaseFailed) || next.Phase != security.PhasePrepare || next.Generation <= prior.LastVersion {
			return ErrStateConflict
		}
		return nil
	}
	if prior.Generation != next.Generation || prior.NewVersion != next.NewVersion || prior.NewBucket != next.NewBucket || !prior.NewNotBefore.Equal(next.NewNotBefore) || !prior.NewExpiry.Equal(next.NewExpiry) || !reflect.DeepEqual(prior.Regions, next.Regions) {
		return ErrStateConflict
	}
	for _, pair := range [][2]string{{prior.NewIdentityRef, next.NewIdentityRef}, {prior.NewCapabilityRef, next.NewCapabilityRef}, {prior.NewCapabilityID, next.NewCapabilityID}} {
		if pair[0] != "" && pair[0] != pair[1] {
			return ErrStateConflict
		}
	}
	if prior.PublicationReceipt.ReceiptID != "" && prior.PublicationReceipt != next.PublicationReceipt || prior.PublicationCommitted && !next.PublicationCommitted {
		return ErrStateConflict
	}
	return nil
}
