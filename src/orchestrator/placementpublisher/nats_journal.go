package placementpublisher

import (
	"bytes"
	"context"
	"crypto/tls"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"google.golang.org/protobuf/proto"
	"math"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
)

const (
	placementJournalStream            = "KV_ORCH_LEADERS"
	placementLeaseSubject             = "$KV.ORCH_LEADERS.authority.global"
	placementStateSubject             = "$KV.ORCH_LEADERS.placement.proposal.state"
	placementBarrierSubject           = "$KV.ORCH_LEADERS.placement.proposal.barrier"
	maximumPlacementJournalBytes      = 1 << 20
	maximumPlacementJournalStateBytes = 480 << 10
)

var (
	ErrPlacementJournalUnavailable = errors.New("placement publisher: authoritative NATS journal unavailable")
	ErrPlacementJournalConflict    = errors.New("placement publisher: authoritative journal CAS conflicted")
)

// NATSJournalConfig binds the GRU global-authority connection and exact live
// election identity. The lease and journal share KV_ORCH_LEADERS so one stream
// CAS fences both; a separately scoped KV store cannot provide this guarantee.
type NATSJournalConfig struct {
	Connection     *nats.Conn
	CandidateID    string
	AuthorityEpoch uint64
	LeaseID        string
}
type NATSJournal struct {
	connection *nats.Conn
	js         jetstream.JetStream
	candidate  string
	epoch      uint64
	leaseID    string
}

func NewNATSJournal(config NATSJournalConfig) (*NATSJournal, error) {
	if config.Connection == nil || !config.Connection.IsConnected() || !config.Connection.AuthRequired() || !validToken(config.LeaseID) || config.AuthorityEpoch == 0 || config.AuthorityEpoch > math.MaxInt64 || !strings.HasPrefix(config.CandidateID, "global-controller-gru-") || !validToken(config.CandidateID) {
		return nil, ErrInvalidConfig
	}
	options := config.Connection.Opts
	if options.Nkey == "" || options.SignatureCB == nil || options.AllowReconnect || options.ReconnectBufSize >= 0 || options.TLSConfig == nil || options.TLSConfig.InsecureSkipVerify || options.TLSConfig.RootCAs == nil || (len(options.TLSConfig.Certificates) == 0 && options.TLSConfig.GetClientCertificate == nil && options.TLSCertCB == nil) {
		return nil, ErrInvalidConfig
	}
	tlsState, err := config.Connection.TLSConnectionState()
	if err != nil || !tlsState.HandshakeComplete || tlsState.Version < tls.VersionTLS13 || len(tlsState.VerifiedChains) == 0 {
		return nil, ErrInvalidConfig
	}
	js, err := jetstream.New(config.Connection)
	if err != nil {
		return nil, ErrPlacementJournalUnavailable
	}
	return &NATSJournal{connection: config.Connection, js: js, candidate: config.CandidateID, epoch: config.AuthorityEpoch, leaseID: config.LeaseID}, nil
}

type placementJournalState struct {
	Hosts map[string]Record
}
type placementJournalEnvelope struct {
	SchemaVersion int
	Lease         authority.RegionalAuthorityLeaseDocument
	LeaseRevision uint64
	State         placementJournalState
	PriorState    jsontext.Value
}
type placementRawMessage struct {
	Subject  string    `json:"subject"`
	Sequence uint64    `json:"seq"`
	Data     []byte    `json:"data"`
	Time     time.Time `json:"time"`
	Headers  []byte    `json:"hdrs"`
}
type placementJournalSnapshot struct {
	sequence      uint64
	leaseRevision uint64
	lease         authority.RegionalAuthorityLeaseDocument
	state         placementJournalState
	recovered     bool
}

func emptyPlacementJournalState() placementJournalState {
	return placementJournalState{Hosts: map[string]Record{}}
}
func (journal *NATSJournal) request(ctx context.Context, subject string, payload []byte, target any) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	if journal == nil || journal.connection == nil || !journal.connection.IsConnected() {
		return ErrPlacementJournalUnavailable
	}
	response, err := journal.connection.RequestWithContext(ctx, subject, payload)
	if err != nil || response == nil || len(response.Data) > maximumPlacementJournalBytes*4/3+8192 {
		return ErrPlacementJournalUnavailable
	}
	if err := json.Unmarshal(response.Data, target, jsonv1.FormatDurationAsNano(true)); err != nil {
		return fmt.Errorf("%w: decode %s: %v", ErrPlacementJournalUnavailable, subject, err)
	}
	return nil
}
func (journal *NATSJournal) rawGet(ctx context.Context, subject string, sequence uint64) (placementRawMessage, bool, error) {
	request := struct {
		LastFor  string `json:"last_by_subj,omitempty"`
		Sequence uint64 `json:"seq,omitzero"`
	}{subject, sequence}
	payload, _ := json.Marshal(request)
	var response struct {
		Message placementRawMessage `json:"message"`
		Error   *jetstream.APIError `json:"error"`
	}
	// STREAM.MSG.GET is leader-routed. Do not use KV.Get / DIRECT.GET, which
	// can read a follower with AllowDirect enabled on the lease bucket.
	if err := journal.request(ctx, "$JS.API.STREAM.MSG.GET."+placementJournalStream, payload, &response); err != nil {
		return placementRawMessage{}, false, err
	}
	if response.Error != nil {
		if response.Error.ErrorCode == 10037 {
			return placementRawMessage{}, false, nil
		}
		return placementRawMessage{}, false, fmt.Errorf("%w: invalid stored message", ErrPlacementJournalUnavailable)
	}
	if response.Message.Sequence == 0 || response.Message.Time.IsZero() || (subject != "" && response.Message.Subject != subject) || (sequence != 0 && response.Message.Sequence != sequence) {
		return placementRawMessage{}, false, fmt.Errorf("%w: invalid stored message", ErrPlacementJournalUnavailable)
	}
	return response.Message, true, nil
}
func (journal *NATSJournal) snapshot(ctx context.Context) (placementJournalSnapshot, error) {
	var info struct {
		jetstream.StreamInfo
		Error *jetstream.APIError `json:"error"`
	}
	if err := journal.request(ctx, "$JS.API.STREAM.INFO."+placementJournalStream, []byte("{}"), &info); err != nil {
		return placementJournalSnapshot{}, err
	}
	if info.Error != nil || info.Config.Name != placementJournalStream || info.Config.Storage != jetstream.FileStorage || info.Config.Replicas != 3 || info.Config.Mirror != nil || len(info.Config.Sources) != 0 || info.Config.MaxAge != 0 {
		return placementJournalSnapshot{}, fmt.Errorf("%w: invalid stream configuration", ErrPlacementJournalUnavailable)
	}
	leaseMessage, found, err := journal.rawGet(ctx, placementLeaseSubject, 0)
	if err != nil {
		return placementJournalSnapshot{}, err
	}
	if !found {
		return placementJournalSnapshot{}, ErrPlacementEpochFenced
	}
	if leaseMessage.Sequence > info.State.LastSeq {
		return placementJournalSnapshot{}, ErrPlacementJournalConflict
	}
	var lease authority.RegionalAuthorityLeaseDocument
	if json.Unmarshal(leaseMessage.Data, &lease) != nil || lease.Validate() != nil || lease.AuthorityId != "global" || lease.CandidateId != journal.candidate || lease.LeaseId != journal.leaseID || lease.Epoch != int64(journal.epoch) || lease.IssuedAt.After(time.Now().UTC()) || !lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond).After(time.Now().UTC()) {
		return placementJournalSnapshot{}, ErrPlacementEpochFenced
	}
	snapshot := placementJournalSnapshot{sequence: info.State.LastSeq, leaseRevision: leaseMessage.Sequence, lease: lease, state: emptyPlacementJournalState()}
	stored, found, err := journal.rawGet(ctx, placementStateSubject, 0)
	if err != nil {
		return snapshot, err
	}
	if !found {
		return snapshot, nil
	}
	if stored.Sequence > snapshot.sequence {
		return snapshot, ErrPlacementJournalConflict
	}
	var envelope placementJournalEnvelope
	if json.Unmarshal(stored.Data, &envelope, json.RejectUnknownMembers(true)) != nil || envelope.SchemaVersion != 1 || envelope.Lease.Validate() != nil || envelope.Lease.AuthorityId != "global" || envelope.LeaseRevision == 0 || envelope.State.Hosts == nil {
		return snapshot, ErrPlacementJournalUnavailable
	}
	if !validLeaseCommit(envelope.Lease, stored.Time) {
		// A server can accept a previously sent message after its lease expires.
		// Preserve the plain prior state in every transition, not recursively
		// nested envelopes, so even history=1 cannot erase valid placement intent history.
		var prior placementJournalState
		if len(envelope.PriorState) == 0 || json.Unmarshal(envelope.PriorState, &prior) != nil || prior.Hosts == nil {
			return snapshot, ErrPlacementJournalUnavailable
		}
		envelope.State = prior
		snapshot.recovered = true
	}
	snapshot.state = envelope.State
	return snapshot, nil
}
func validLeaseCommit(lease authority.RegionalAuthorityLeaseDocument, committed time.Time) bool {
	return !committed.Before(lease.IssuedAt) && committed.Before(lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond))
}
func (journal *NATSJournal) transact(ctx context.Context, write bool, change func(*placementJournalState) error) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	operationCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for attempt := 0; attempt < 8; attempt++ {
		snapshot, err := journal.snapshot(operationCtx)
		if errors.Is(err, ErrPlacementJournalConflict) {
			continue
		}
		if err != nil {
			return err
		}
		priorState, marshalErr := json.Marshal(snapshot.state)
		if marshalErr != nil || len(priorState) > maximumPlacementJournalStateBytes {
			return ErrPlacementJournalUnavailable
		}
		if err := change(&snapshot.state); err != nil {
			return err
		}
		proposedState, marshalErr := json.Marshal(snapshot.state)
		if marshalErr != nil || len(proposedState) > maximumPlacementJournalStateBytes {
			return ErrPlacementJournalUnavailable
		}
		envelope := placementJournalEnvelope{SchemaVersion: 1, Lease: snapshot.lease, LeaseRevision: snapshot.leaseRevision}
		subject := placementBarrierSubject
		if write || snapshot.recovered {
			envelope.PriorState = priorState
			envelope.State = snapshot.state
			subject = placementStateSubject
		}
		payload, err := json.Marshal(envelope)
		if err != nil || len(payload) > maximumPlacementJournalBytes {
			return ErrPlacementJournalUnavailable
		}
		if !snapshot.lease.IssuedAt.Add(time.Duration(snapshot.lease.DurationMilliseconds) * time.Millisecond).After(time.Now().UTC()) {
			return ErrPlacementEpochFenced
		}
		ack, err := journal.js.Publish(operationCtx, subject, payload, jetstream.WithExpectStream(placementJournalStream), jetstream.WithExpectLastSequence(snapshot.sequence))
		if err != nil {
			if apiError, ok := errors.AsType[*jetstream.APIError](err); ok && (apiError.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence || apiError.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant) {
				continue
			}
			return fmt.Errorf("%w: publish: %v", ErrPlacementJournalUnavailable, err)
		}
		if ack.Stream != placementJournalStream || ack.Sequence != snapshot.sequence+1 || ack.Duplicate {
			return ErrPlacementJournalUnavailable
		}
		committed, found, err := journal.rawGet(operationCtx, "", ack.Sequence)
		if err != nil || !found || committed.Subject != subject || !bytes.Equal(committed.Data, payload) {
			return ErrPlacementJournalUnavailable
		}
		// The persisted server timestamp closes the expiry window between local
		// validation and commit. An after-expiry record is never accepted on reads.
		if !validLeaseCommit(snapshot.lease, committed.Time) {
			return ErrPlacementEpochFenced
		}
		return nil
	}
	return ErrPlacementJournalConflict
}

// Accept refuses to replace an unresolved host operation. The next expected
// engine revision comes only from its durable pending receipt.
func (journal *NATSJournal) Accept(ctx context.Context, record Record) error {
	request, err := decodeRecord(record)
	if err != nil || len(record.Receipt) != 0 {
		return ErrInvalidConfig
	}
	return journal.transact(ctx, true, func(state *placementJournalState) error {
		if old, found := state.Hosts[record.ServerIdentity]; found {
			prior, err := decodeRecord(old)
			if err != nil {
				return err
			}
			if sameIntent(old, record) {
				return nil
			}
			if old.OperationID == record.OperationID || len(old.Receipt) == 0 {
				return ErrPlacementJournalConflict
			}
			receipt := new(pb.PlacementProposalResponse)
			if proto.Unmarshal(old.Receipt, receipt) != nil {
				return ErrInvalidConfig
			}
			if request.ExpectedRevision != receipt.Revision || request.Proposal.Generation <= prior.Proposal.Generation || request.Proposal.Epoch <= prior.Proposal.Epoch {
				return ErrPlacementJournalConflict
			}
		} else if request.ExpectedRevision != 0 || len(state.Hosts) >= 128 {
			return ErrPlacementJournalConflict
		}
		state.Hosts[record.ServerIdentity] = record
		return nil
	})
}
func (journal *NATSJournal) Load(ctx context.Context, serverIdentity string) (record Record, err error) {
	if !validIdentity(serverIdentity) {
		return record, ErrInvalidConfig
	}
	err = journal.transact(ctx, false, func(state *placementJournalState) error {
		var found bool
		record, found = state.Hosts[serverIdentity]
		if !found {
			return ErrIntentMissing
		}
		_, err := decodeRecord(record)
		return err
	})
	return
}
func (journal *NATSJournal) Acknowledge(ctx context.Context, record Record, receipt *pb.PlacementProposalResponse) error {
	request, err := decodeRecord(record)
	if err != nil {
		return err
	}
	if err := tbep.ValidatePlacementReceipt(receipt, request.Proposal); err != nil {
		return err
	}
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(receipt)
	if err != nil {
		return err
	}
	return journal.transact(ctx, true, func(state *placementJournalState) error {
		old, found := state.Hosts[record.ServerIdentity]
		if !found || !sameIntent(old, record) {
			return ErrPlacementJournalConflict
		}
		if len(old.Receipt) > 0 && !bytes.Equal(old.Receipt, data) {
			return ErrPlacementJournalConflict
		}
		old.Receipt = data
		state.Hosts[record.ServerIdentity] = old
		return nil
	})
}
