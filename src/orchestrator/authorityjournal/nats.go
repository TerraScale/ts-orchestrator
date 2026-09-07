// Package authorityjournal provides R3 journal transactions fenced by the exact
// live global authority lease in the same JetStream stream.
package authorityjournal

import (
	"bytes"
	"context"
	"crypto/tls"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"math"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"time"
)

const (
	streamName        = "KV_ORCH_LEADERS"
	leaseSubject      = "$KV.ORCH_LEADERS.authority.global"
	maximumBytes      = 1 << 20
	MaximumStateBytes = 480 << 10
)

var (
	ErrInvalidConfig = errors.New("authority journal: invalid configuration")
	ErrUnavailable   = errors.New("authority journal: unavailable")
	ErrConflict      = errors.New("authority journal: CAS conflicted")
	ErrFenced        = errors.New("authority journal: exact live lease required")
)

type Config struct {
	Connection     *nats.Conn
	CandidateID    string
	AuthorityEpoch uint64
	LeaseID        string
	StateKey       string
}
type Journal[S any] struct {
	connection     *nats.Conn
	js             jetstream.JetStream
	candidate      string
	epoch          uint64
	leaseID        string
	stateSubject   string
	barrierSubject string
	empty          func() S
	validate       func(S) error
}

func New[S any](config Config, empty func() S, validate func(S) error) (*Journal[S], error) {
	if !authenticatedConnection(config.Connection) || !validToken(config.LeaseID) || config.AuthorityEpoch == 0 || config.AuthorityEpoch > math.MaxInt64 || !strings.HasPrefix(config.CandidateID, "global-controller-gru-") || !validToken(config.CandidateID) || empty == nil || validate == nil || config.StateKey == "" || strings.ContainsAny(config.StateKey, " *>\t\r\n") || strings.HasPrefix(config.StateKey, "authority.") {
		return nil, ErrInvalidConfig
	}
	js, err := jetstream.New(config.Connection)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Journal[S]{connection: config.Connection, js: js, candidate: config.CandidateID, epoch: config.AuthorityEpoch, leaseID: config.LeaseID, stateSubject: "$KV.ORCH_LEADERS." + config.StateKey + ".state", barrierSubject: "$KV.ORCH_LEADERS." + config.StateKey + ".barrier", empty: empty, validate: validate}, nil
}
func validToken(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func authenticatedConnection(connection *nats.Conn) bool {
	if connection == nil || !connection.IsConnected() || !connection.AuthRequired() {
		return false
	}
	options := connection.Opts
	if options.Nkey == "" || options.SignatureCB == nil || options.AllowReconnect || options.ReconnectBufSize >= 0 || options.TLSConfig == nil || options.TLSConfig.InsecureSkipVerify || options.TLSConfig.RootCAs == nil || (len(options.TLSConfig.Certificates) == 0 && options.TLSConfig.GetClientCertificate == nil && options.TLSCertCB == nil) {
		return false
	}
	state, err := connection.TLSConnectionState()
	return err == nil && state.HandshakeComplete && state.Version >= tls.VersionTLS13 && len(state.VerifiedChains) > 0
}

type envelope[S any] struct {
	SchemaVersion int
	Lease         authority.RegionalAuthorityLeaseDocument
	LeaseRevision uint64
	State         S
	PriorState    jsontext.Value
}
type rawMessage struct {
	Subject  string    `json:"subject"`
	Sequence uint64    `json:"seq"`
	Data     []byte    `json:"data"`
	Time     time.Time `json:"time"`
	Headers  []byte    `json:"hdrs"`
}
type snapshot[S any] struct {
	sequence      uint64
	leaseRevision uint64
	lease         authority.RegionalAuthorityLeaseDocument
	state         S
	recovered     bool
}

func (journal *Journal[S]) request(ctx context.Context, subject string, payload []byte, target any) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	if journal == nil || journal.connection == nil || !journal.connection.IsConnected() {
		return ErrUnavailable
	}
	response, err := journal.connection.RequestWithContext(ctx, subject, payload)
	if err != nil || response == nil || len(response.Data) > maximumBytes*4/3+8192 {
		return ErrUnavailable
	}
	// NATS stream configuration encodes duration fields as nanoseconds.
	if err := json.Unmarshal(response.Data, target, jsonv1.FormatDurationAsNano(true)); err != nil {
		return fmt.Errorf("%w: decode %s: %v", ErrUnavailable, subject, err)
	}
	return nil
}
func (journal *Journal[S]) rawGet(ctx context.Context, subject string, sequence uint64) (rawMessage, bool, error) {
	request := struct {
		LastFor  string `json:"last_by_subj,omitempty"`
		Sequence uint64 `json:"seq,omitzero"`
	}{subject, sequence}
	payload, _ := json.Marshal(request)
	var response struct {
		Message rawMessage          `json:"message"`
		Error   *jetstream.APIError `json:"error"`
	}
	// STREAM.MSG.GET is leader-routed. Do not use KV.Get / DIRECT.GET, which
	// can read a follower with AllowDirect enabled on the lease bucket.
	if err := journal.request(ctx, "$JS.API.STREAM.MSG.GET."+streamName, payload, &response); err != nil {
		return rawMessage{}, false, err
	}
	if response.Error != nil {
		if response.Error.ErrorCode == 10037 {
			return rawMessage{}, false, nil
		}
		return rawMessage{}, false, fmt.Errorf("%w: invalid stored message", ErrUnavailable)
	}
	if response.Message.Sequence == 0 || response.Message.Time.IsZero() || (subject != "" && response.Message.Subject != subject) || (sequence != 0 && response.Message.Sequence != sequence) {
		return rawMessage{}, false, fmt.Errorf("%w: invalid stored message", ErrUnavailable)
	}
	return response.Message, true, nil
}
func (journal *Journal[S]) snapshot(ctx context.Context) (snapshot[S], error) {
	var info struct {
		jetstream.StreamInfo
		Error *jetstream.APIError `json:"error"`
	}
	if err := journal.request(ctx, "$JS.API.STREAM.INFO."+streamName, []byte("{}"), &info); err != nil {
		return snapshot[S]{}, err
	}
	if info.Error != nil || info.Config.Name != streamName || info.Config.Storage != jetstream.FileStorage || info.Config.Replicas != 3 || info.Config.Mirror != nil || len(info.Config.Sources) != 0 || info.Config.MaxAge != 0 {
		return snapshot[S]{}, fmt.Errorf("%w: invalid stream configuration", ErrUnavailable)
	}
	leaseMessage, found, err := journal.rawGet(ctx, leaseSubject, 0)
	if err != nil {
		return snapshot[S]{}, err
	}
	if !found {
		return snapshot[S]{}, ErrFenced
	}
	if leaseMessage.Sequence > info.State.LastSeq {
		return snapshot[S]{}, ErrConflict
	}
	var lease authority.RegionalAuthorityLeaseDocument
	if json.Unmarshal(leaseMessage.Data, &lease) != nil || lease.Validate() != nil || lease.AuthorityId != "global" || lease.CandidateId != journal.candidate || lease.LeaseId != journal.leaseID || lease.Epoch != int64(journal.epoch) || lease.IssuedAt.After(time.Now().UTC()) || !lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond).After(time.Now().UTC()) {
		return snapshot[S]{}, ErrFenced
	}
	snapshot := snapshot[S]{sequence: info.State.LastSeq, leaseRevision: leaseMessage.Sequence, lease: lease, state: journal.empty()}
	stored, found, err := journal.rawGet(ctx, journal.stateSubject, 0)
	if err != nil {
		return snapshot, err
	}
	if !found {
		return snapshot, nil
	}
	if stored.Sequence > snapshot.sequence {
		return snapshot, ErrConflict
	}
	var envelope envelope[S]
	if json.Unmarshal(stored.Data, &envelope, json.RejectUnknownMembers(true)) != nil || envelope.SchemaVersion != 1 || envelope.Lease.Validate() != nil || envelope.Lease.AuthorityId != "global" || envelope.LeaseRevision == 0 || journal.validate(envelope.State) != nil {
		return snapshot, ErrUnavailable
	}
	if !validLeaseCommit(envelope.Lease, stored.Time) {
		// A server can accept a previously sent message after its lease expires.
		// Preserve the plain prior state in every transition, not recursively
		// nested envelopes, so even history=1 cannot erase valid intent history.
		var prior S
		if len(envelope.PriorState) == 0 || json.Unmarshal(envelope.PriorState, &prior) != nil || journal.validate(prior) != nil {
			return snapshot, ErrUnavailable
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

// Transact serializes a bounded state transition with the current live lease.
// The callback may run repeatedly after stream CAS conflicts and must not
// perform external effects or retain pointers to the transaction state.
func (journal *Journal[S]) Transact(ctx context.Context, write bool, change func(*S) error) error {
	return journal.TransactRevision(ctx, write, func(state *S, _ uint64) error { return change(state) })
}

// Read returns the current lease-valid state without mutating the journal.
// Callers use it to rebuild public projections after a process restart.
func (journal *Journal[S]) Read(ctx context.Context) (S, error) {
	snapshot, err := journal.snapshot(ctx)
	if err != nil {
		var zero S
		return zero, err
	}
	return snapshot.state, nil
}

// TransactRevision supplies the proposed commit sequence while the exact lease
// and stream CAS remain fenced together. The callback can run more than once;
// a returned revision is authoritative only after this method succeeds.
func (journal *Journal[S]) TransactRevision(ctx context.Context, write bool, change func(*S, uint64) error) error {
	if ctx == nil || change == nil {
		return ErrInvalidConfig
	}
	operationCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for attempt := 0; attempt < 8; attempt++ {
		snapshot, err := journal.snapshot(operationCtx)
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return err
		}
		priorState, marshalErr := json.Marshal(snapshot.state)
		if marshalErr != nil || len(priorState) > MaximumStateBytes {
			return ErrUnavailable
		}
		if err := change(&snapshot.state, snapshot.sequence+1); err != nil {
			return err
		}
		if journal.validate(snapshot.state) != nil {
			return ErrInvalidConfig
		}
		proposedState, marshalErr := json.Marshal(snapshot.state)
		if marshalErr != nil || len(proposedState) > MaximumStateBytes {
			return ErrUnavailable
		}
		envelope := envelope[S]{SchemaVersion: 1, Lease: snapshot.lease, LeaseRevision: snapshot.leaseRevision}
		subject := journal.barrierSubject
		if write || snapshot.recovered {
			envelope.PriorState = priorState
			envelope.State = snapshot.state
			subject = journal.stateSubject
		}
		payload, err := json.Marshal(envelope)
		if err != nil || len(payload) > maximumBytes {
			return ErrUnavailable
		}
		if !snapshot.lease.IssuedAt.Add(time.Duration(snapshot.lease.DurationMilliseconds) * time.Millisecond).After(time.Now().UTC()) {
			return ErrFenced
		}
		ack, err := journal.js.Publish(operationCtx, subject, payload, jetstream.WithExpectStream(streamName), jetstream.WithExpectLastSequence(snapshot.sequence))
		if err != nil {
			if apiError, ok := errors.AsType[*jetstream.APIError](err); ok && (apiError.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence || apiError.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant) {
				continue
			}
			return fmt.Errorf("%w: publish: %v", ErrUnavailable, err)
		}
		if ack.Stream != streamName || ack.Sequence != snapshot.sequence+1 || ack.Duplicate {
			return ErrUnavailable
		}
		committed, found, err := journal.rawGet(operationCtx, "", ack.Sequence)
		if err != nil || !found || committed.Subject != subject || !bytes.Equal(committed.Data, payload) {
			return ErrUnavailable
		}
		// The persisted server timestamp closes the expiry window between local
		// validation and commit. An after-expiry record is never accepted on reads.
		if !validLeaseCommit(snapshot.lease, committed.Time) {
			return ErrFenced
		}
		return nil
	}
	return ErrConflict
}
