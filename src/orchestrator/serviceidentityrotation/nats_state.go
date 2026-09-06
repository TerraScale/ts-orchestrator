package serviceidentityrotation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
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
	rotationStream               = "KV_ORCH_LEADERS"
	rotationLeaseSubject         = "$KV.ORCH_LEADERS.authority.global"
	rotationStateSubject         = "$KV.ORCH_LEADERS.security.identity-rotation.state"
	rotationBarrierSubject       = "$KV.ORCH_LEADERS.security.identity-rotation.barrier"
	maximumRotationStateBytes    = 128 << 10
	maximumRotationDocumentBytes = 300 << 10
)

var (
	ErrStateUnavailable = errors.New("identity service rotation: authoritative state unavailable")
	ErrStateConflict    = errors.New("identity service rotation: loaded state revision conflicted")
	ErrStateFenced      = errors.New("identity service rotation: global authority fenced")
	ErrStateNotLoaded   = errors.New("identity service rotation: session must load state before saving")
)

// NATSStateStore fences identity journal updates in the global R3 lease stream.
// Each coordinator owns its own loaded revision cursor.
type NATSStateStore struct {
	connection *nats.Conn
	js         jetstream.JetStream
	candidate  string
	epoch      uint64
	leaseID    string
	authority  func(context.Context) error
	mu         sync.Mutex
	loaded     bool
	revision   uint64
}

var _ Store = (*NATSStateStore)(nil)

func NewNATSStore(connection *nats.Conn, candidate string, epoch uint64, leaseID string, authority func(context.Context) error) (Store, error) {
	if connection == nil || epoch == 0 || epoch > math.MaxInt64 || !rotationToken(leaseID) || !strings.HasPrefix(candidate, "global-controller-gru-") || !rotationToken(candidate) || authority == nil {
		return nil, ErrStateUnavailable
	}
	if err := rotationTransport(connection); err != nil {
		return nil, err
	}
	js, err := jetstream.New(connection)
	if err != nil {
		return nil, ErrStateUnavailable
	}
	return &NATSStateStore{connection: connection, js: js, candidate: candidate, epoch: epoch, leaseID: leaseID, authority: authority}, nil
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
		return ErrStateUnavailable
	}
	state, err := connection.TLSConnectionState()
	if err != nil || !state.HandshakeComplete || state.Version < tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		return ErrStateUnavailable
	}
	return nil
}

func (s *NATSStateStore) Load(ctx context.Context) (Journal, error) {
	if s == nil || ctx == nil {
		return Journal{}, ErrStateUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loaded = false
	operation, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if s.authority(operation) != nil {
		return Journal{}, ErrStateFenced
	}
	for range 8 {
		snapshot, err := s.snapshot(operation)
		if errors.Is(err, ErrStateConflict) {
			continue
		}
		if err != nil {
			return Journal{}, err
		}
		sequence, err := s.commit(operation, snapshot, snapshot.state, snapshot.recovered)
		if errors.Is(err, ErrStateConflict) {
			continue
		}
		if err != nil {
			return Journal{}, err
		}
		s.loaded = true
		s.revision = snapshot.revision
		if snapshot.recovered {
			s.revision = sequence
		}
		if snapshot.state == nil {
			return Journal{}, nil
		}
		return *snapshot.state, nil
	}
	return Journal{}, ErrStateConflict
}

func (s *NATSStateStore) Save(ctx context.Context, state Journal) error {
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
	if s.authority(operation) != nil {
		return ErrStateFenced
	}
	for range 8 {
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
		if !same {
			if err := rotationIntentTransition(snapshot.state, &state); err != nil {
				return err
			}
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

func rotationStateBytes(state *Journal) ([]byte, error) {
	if state != nil && !validJournal(*state) {
		return nil, ErrStateUnavailable
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
