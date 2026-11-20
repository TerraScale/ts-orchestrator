package regionalowner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	streamName    = "TS_REGIONAL_OWNER"
	subjects      = "ts.owner.*"
	maxRecord     = 64 << 10
	leaseDuration = 15 * time.Second
)

var (
	ErrFenced   = errors.New("regional owner is fenced")
	ErrConflict = errors.New("regional owner revision changed")
	ErrQuorum   = errors.New("regional owner quorum is unavailable")
)

type Membership struct {
	Region     string
	Cluster    string
	Epoch      uint64
	Managers   []string
	ValidUntil time.Time
}

type Manager struct {
	Cluster string
	Node    string
}

type AuthenticateManager func(chain [][]byte, message, signature []byte) (Manager, error)

type Operation string

const (
	Acquire Operation = "acquire"
	Renew   Operation = "renew"
	Publish Operation = "publish"
)

type Request struct {
	Operation       Operation
	Region          string
	Cluster         string
	Node            string
	Session         []byte
	MembershipEpoch uint64
	OwnerEpoch      uint64
	Sequence        uint64
	Digest          [32]byte
}

type Proof struct {
	SessionSignature []byte
	ManagerChain     [][]byte
	ManagerSignature []byte
}

type Lease struct {
	OwnerEpoch uint64
	Node       string
	Session    []byte
	Sequence   uint64
	ExpiresAt  time.Time
	Digest     [32]byte
}

type Snapshot struct {
	Membership Membership
	Lease      Lease
	Revision   uint64
}

type record struct {
	Membership   Membership
	Lease        Lease
	CommitBefore time.Time
}

type loaded struct {
	record
	wire     []byte
	revision uint64
	last     uint64
	timely   bool
}

type Store struct {
	js            jetstream.JetStream
	stream        jetstream.Stream
	region        string
	subject       string
	membershipKey ed25519.PublicKey
	authenticate  AuthenticateManager
}

func StreamConfig() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name: streamName, Subjects: []string{subjects}, Replicas: 3, Storage: jetstream.FileStorage,
		MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: 1, MaxMsgSize: maxRecord, DenyDelete: true, DenyPurge: true,
	}
}

func Open(ctx context.Context, js jetstream.JetStream, region string, membershipKey ed25519.PublicKey, authenticate AuthenticateManager) (*Store, error) {
	if _, ok := catalog.LookupName(region); !ok || js == nil || len(membershipKey) != ed25519.PublicKeySize || authenticate == nil {
		return nil, ErrFenced
	}
	stream, err := js.Stream(ctx, streamName)
	if err != nil {
		return nil, errors.Join(ErrQuorum, err)
	}
	store := &Store{js: js, stream: stream, region: region, subject: "ts.owner." + region, membershipKey: slices.Clone(membershipKey), authenticate: authenticate}
	if _, err := store.info(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

func MembershipMessage(view Membership) ([]byte, error) {
	data, err := json.Marshal(view)
	return append([]byte("TS-REGIONAL-OWNER-MEMBERSHIP-V1\x00"), data...), err
}

func RequestMessage(request Request) ([]byte, error) {
	data, err := json.Marshal(request)
	return append([]byte("TS-REGIONAL-OWNER-REQUEST-V1\x00"), data...), err
}

func (s *Store) InstallMembership(ctx context.Context, view Membership, signature []byte) (Snapshot, error) {
	now := time.Now()
	if view.Region != s.region || view.Cluster == "" || view.Epoch == 0 || len(view.Managers) > 64 || !now.Before(view.ValidUntil) ||
		!slices.IsSorted(view.Managers) || len(slices.Compact(slices.Clone(view.Managers))) != len(view.Managers) || slices.Contains(view.Managers, "") {
		return Snapshot{}, ErrFenced
	}
	message, err := MembershipMessage(view)
	if err != nil || !ed25519.Verify(s.membershipKey, message, signature) {
		return Snapshot{}, ErrFenced
	}
	current, err := s.load(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if view.Epoch <= current.Membership.Epoch {
		return Snapshot{}, ErrFenced
	}
	next := record{Membership: view, Lease: Lease{OwnerEpoch: current.Lease.OwnerEpoch}, CommitBefore: view.ValidUntil}
	return s.commit(ctx, current, next)
}

func (s *Store) Apply(ctx context.Context, request Request, proof Proof) (Snapshot, error) {
	if request.Region != s.region || len(request.Session) != ed25519.PublicKeySize || request.Node == "" {
		return Snapshot{}, ErrFenced
	}
	message, err := RequestMessage(request)
	if err != nil || !ed25519.Verify(request.Session, message, proof.SessionSignature) {
		return Snapshot{}, ErrFenced
	}
	current, err := s.load(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	now := time.Now()
	view, lease := current.Membership, current.Lease
	if !current.timely || !now.Before(view.ValidUntil) || request.Cluster != view.Cluster || request.MembershipEpoch != view.Epoch ||
		request.OwnerEpoch != lease.OwnerEpoch || !slices.Contains(view.Managers, request.Node) {
		return Snapshot{}, ErrFenced
	}
	next := current.record
	next.CommitBefore = view.ValidUntil
	switch request.Operation {
	case Acquire:
		if request.Sequence != 1 || request.Digest != ([32]byte{}) || now.Before(lease.ExpiresAt) || lease.OwnerEpoch == math.MaxUint64 {
			return Snapshot{}, ErrFenced
		}
		manager, err := s.authenticate(proof.ManagerChain, message, proof.ManagerSignature)
		if err != nil || manager != (Manager{Cluster: view.Cluster, Node: request.Node}) {
			return Snapshot{}, ErrFenced
		}
		next.Lease = Lease{OwnerEpoch: lease.OwnerEpoch + 1, Node: manager.Node, Session: slices.Clone(request.Session), Sequence: 1,
			ExpiresAt: minTime(view.ValidUntil, now.Add(leaseDuration))}
		next.CommitBefore = next.Lease.ExpiresAt
	case Renew, Publish:
		if lease.Node != request.Node || !bytes.Equal(lease.Session, request.Session) || !now.Before(lease.ExpiresAt) ||
			lease.Sequence == math.MaxUint64 || request.Sequence != lease.Sequence+1 || (request.Digest == ([32]byte{})) != (request.Operation == Renew) {
			return Snapshot{}, ErrFenced
		}
		next.CommitBefore = lease.ExpiresAt
		next.Lease.Sequence = request.Sequence
		if request.Operation == Renew {
			next.Lease.ExpiresAt = minTime(view.ValidUntil, now.Add(leaseDuration))
		} else {
			next.Lease.Digest = request.Digest
		}
	default:
		return Snapshot{}, ErrFenced
	}
	return s.commit(ctx, current, next)
}

func minTime(first, second time.Time) time.Time {
	if first.Before(second) {
		return first
	}
	return second
}

func (s *Store) info(ctx context.Context) (*jetstream.StreamInfo, error) {
	info, err := s.stream.Info(ctx)
	if err != nil {
		return nil, errors.Join(ErrQuorum, err)
	}
	cfg := info.Config
	if cfg.Name != streamName || cfg.Replicas != 3 || cfg.Storage != jetstream.FileStorage || cfg.Retention != jetstream.LimitsPolicy || cfg.AllowDirect ||
		cfg.NoAck || cfg.MaxAge != 0 || cfg.MaxMsgs != -1 || cfg.MaxBytes != -1 || cfg.MaxMsgsPerSubject != 1 || cfg.MaxMsgSize != maxRecord ||
		!cfg.DenyDelete || !cfg.DenyPurge || len(cfg.Sources) != 0 || cfg.Mirror != nil || !slices.Equal(cfg.Subjects, []string{subjects}) {
		return nil, ErrFenced
	}
	if info.Cluster == nil || info.Cluster.Leader == "" || len(info.Cluster.Replicas) != 2 ||
		!slices.ContainsFunc(info.Cluster.Replicas, func(peer *jetstream.PeerInfo) bool { return peer.Current && !peer.Offline }) {
		return nil, ErrQuorum
	}
	return info, nil
}

func (s *Store) load(ctx context.Context) (loaded, error) {
	info, err := s.info(ctx)
	if err != nil {
		return loaded{}, err
	}
	stored, err := s.stream.GetLastMsgForSubject(ctx, s.subject)
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return loaded{last: info.State.LastSeq}, nil
	}
	if err != nil {
		return loaded{}, errors.Join(ErrQuorum, err)
	}
	if stored.Sequence > info.State.LastSeq {
		return loaded{}, ErrConflict
	}
	var record record
	if err := protocol.DecodeStrict(stored.Data, &record, maxRecord); err != nil || stored.Subject != s.subject || stored.Sequence == 0 ||
		stored.Time.IsZero() || record.Membership.Region != s.region || record.Membership.Epoch == 0 || record.CommitBefore.IsZero() {
		return loaded{}, ErrFenced
	}
	return loaded{record: record, wire: stored.Data, revision: stored.Sequence, last: info.State.LastSeq, timely: stored.Time.Before(record.CommitBefore)}, nil
}

func (s *Store) commit(ctx context.Context, before loaded, next record) (Snapshot, error) {
	if !time.Now().Before(next.CommitBefore) {
		return Snapshot{}, ErrFenced
	}
	data, err := protocol.EncodeJSON(next)
	if err != nil {
		return Snapshot{}, err
	}
	write, cancel := context.WithDeadline(ctx, next.CommitBefore)
	defer cancel()
	ack, err := s.js.Publish(write, s.subject, data, jetstream.WithExpectLastSequence(before.last),
		jetstream.WithExpectLastSequencePerSubject(before.revision))
	if err != nil {
		var api *jetstream.APIError
		if errors.As(err, &api) && api.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence {
			return Snapshot{}, errors.Join(ErrConflict, err)
		}
		return Snapshot{}, errors.Join(ErrQuorum, err)
	}
	committed, err := s.load(write)
	if err != nil {
		return Snapshot{}, err
	}
	if ack.Stream != streamName || committed.revision != ack.Sequence || !bytes.Equal(data, committed.wire) {
		return Snapshot{}, ErrConflict
	}
	if !committed.timely || write.Err() != nil {
		return Snapshot{}, ErrFenced
	}
	return Snapshot{Membership: committed.Membership, Lease: committed.Lease, Revision: committed.revision}, nil
}
