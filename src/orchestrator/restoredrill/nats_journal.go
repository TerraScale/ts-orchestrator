package restoredrill

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
)

const (
	restoreJournalStream            = "KV_ORCH_LEADERS"
	restoreLeaseSubject             = "$KV.ORCH_LEADERS.authority.global"
	restoreStateSubject             = "$KV.ORCH_LEADERS.restore.drill.state"
	restoreBarrierSubject           = "$KV.ORCH_LEADERS.restore.drill.barrier"
	maximumRestoreJournalBytes      = 1 << 20
	maximumRestoreJournalStateBytes = 480 << 10
)

var (
	ErrRestoreJournalUnavailable  = errors.New("restore drill: authoritative NATS journal unavailable")
	ErrRestoreJournalConflict     = errors.New("restore drill: authoritative journal CAS conflicted")
	ErrRestoreJournalFactsMissing = errors.New("restore drill: durable source journal facts are missing")
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

var _ JournalPort = (*NATSJournal)(nil)

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
		return nil, ErrRestoreJournalUnavailable
	}
	return &NATSJournal{connection: config.Connection, js: js, candidate: config.CandidateID, epoch: config.AuthorityEpoch, leaseID: config.LeaseID}, nil
}

type restoreDatabaseEpoch struct {
	Current uint64
	Claims  map[string]uint64
}
type restoreJournalState struct {
	Runs   map[string]RunRecord
	Active map[string]RunRecord
	Items  map[string]ItemRecord
	Epochs map[string]restoreDatabaseEpoch
	Facts  map[string]JournalFacts
}
type restoreJournalEnvelope struct {
	SchemaVersion int
	Lease         authority.RegionalAuthorityLeaseDocument
	LeaseRevision uint64
	State         restoreJournalState
	PriorState    json.RawMessage
}
type restoreRawMessage struct {
	Subject  string    `json:"subject"`
	Sequence uint64    `json:"seq"`
	Data     []byte    `json:"data"`
	Time     time.Time `json:"time"`
	Headers  []byte    `json:"hdrs"`
}
type restoreJournalSnapshot struct {
	sequence      uint64
	leaseRevision uint64
	lease         authority.RegionalAuthorityLeaseDocument
	state         restoreJournalState
	recovered     bool
}

func emptyRestoreJournalState() restoreJournalState {
	return restoreJournalState{Runs: map[string]RunRecord{}, Active: map[string]RunRecord{}, Items: map[string]ItemRecord{}, Epochs: map[string]restoreDatabaseEpoch{}, Facts: map[string]JournalFacts{}}
}
func (journal *NATSJournal) request(ctx context.Context, subject string, payload []byte, target any) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	if journal == nil || journal.connection == nil || !journal.connection.IsConnected() {
		return ErrRestoreJournalUnavailable
	}
	// A restarted JetStream cluster can briefly have no elected stream leader.
	// RequestWithContext reports that convergence window as a timeout/no-responder
	// error. Retry those transport failures while the caller's context remains
	// valid; an actual outage still returns unavailable when its context expires.
	for attempt := 0; ; attempt++ {
		requestCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		response, err := journal.connection.RequestWithContext(requestCtx, subject, payload)
		cancel()
		if err == nil && response != nil && len(response.Data) <= maximumRestoreJournalBytes*4/3+8192 {
			if json.Unmarshal(response.Data, target) == nil {
				return nil
			}
			return ErrRestoreJournalUnavailable
		}
		if ctx.Err() != nil || attempt >= 3 {
			return ErrRestoreJournalUnavailable
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ErrRestoreJournalUnavailable
		case <-timer.C:
		}
	}
}
func (journal *NATSJournal) rawGet(ctx context.Context, subject string, sequence uint64) (restoreRawMessage, bool, error) {
	request := struct {
		LastFor  string `json:"last_by_subj,omitempty"`
		Sequence uint64 `json:"seq,omitempty"`
	}{subject, sequence}
	payload, _ := json.Marshal(request)
	var response struct {
		Message restoreRawMessage   `json:"message"`
		Error   *jetstream.APIError `json:"error"`
	}
	// STREAM.MSG.GET is leader-routed. Do not use KV.Get / DIRECT.GET, which
	// can read a follower with AllowDirect enabled on the lease bucket.
	if err := journal.request(ctx, "$JS.API.STREAM.MSG.GET."+restoreJournalStream, payload, &response); err != nil {
		return restoreRawMessage{}, false, err
	}
	if response.Error != nil {
		if response.Error.ErrorCode == 10037 {
			return restoreRawMessage{}, false, nil
		}
		return restoreRawMessage{}, false, ErrRestoreJournalUnavailable
	}
	if response.Message.Sequence == 0 || response.Message.Time.IsZero() || (subject != "" && response.Message.Subject != subject) || (sequence != 0 && response.Message.Sequence != sequence) {
		return restoreRawMessage{}, false, ErrRestoreJournalUnavailable
	}
	return response.Message, true, nil
}
func (journal *NATSJournal) snapshot(ctx context.Context) (restoreJournalSnapshot, error) {
	var info struct {
		jetstream.StreamInfo
		Error *jetstream.APIError `json:"error"`
	}
	if err := journal.request(ctx, "$JS.API.STREAM.INFO."+restoreJournalStream, []byte("{}"), &info); err != nil {
		return restoreJournalSnapshot{}, err
	}
	if info.Error != nil || info.Config.Name != restoreJournalStream || info.Config.Storage != jetstream.FileStorage || info.Config.Replicas != 3 || info.Config.Mirror != nil || len(info.Config.Sources) != 0 || info.Config.MaxAge != 0 {
		return restoreJournalSnapshot{}, ErrRestoreJournalUnavailable
	}
	leaseMessage, found, err := journal.rawGet(ctx, restoreLeaseSubject, 0)
	if err != nil {
		return restoreJournalSnapshot{}, err
	}
	if !found {
		return restoreJournalSnapshot{}, ErrRestoreEpochFenced
	}
	if leaseMessage.Sequence > info.State.LastSeq {
		return restoreJournalSnapshot{}, ErrRestoreJournalConflict
	}
	var lease authority.RegionalAuthorityLeaseDocument
	if json.Unmarshal(leaseMessage.Data, &lease) != nil || lease.Validate() != nil || lease.AuthorityId != "global" || lease.CandidateId != journal.candidate || lease.LeaseId != journal.leaseID || lease.Epoch != int64(journal.epoch) || lease.IssuedAt.After(time.Now().UTC()) || !lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond).After(time.Now().UTC()) {
		return restoreJournalSnapshot{}, ErrRestoreEpochFenced
	}
	snapshot := restoreJournalSnapshot{sequence: info.State.LastSeq, leaseRevision: leaseMessage.Sequence, lease: lease, state: emptyRestoreJournalState()}
	stored, found, err := journal.rawGet(ctx, restoreStateSubject, 0)
	if err != nil {
		return snapshot, err
	}
	if !found {
		return snapshot, nil
	}
	if stored.Sequence > snapshot.sequence {
		return snapshot, ErrRestoreJournalConflict
	}
	var envelope restoreJournalEnvelope
	decoder := json.NewDecoder(bytes.NewReader(stored.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || envelope.SchemaVersion != 1 || envelope.Lease.Validate() != nil || envelope.Lease.AuthorityId != "global" || envelope.LeaseRevision == 0 || envelope.State.Runs == nil || envelope.State.Items == nil || envelope.State.Epochs == nil || envelope.State.Facts == nil {
		return snapshot, ErrRestoreJournalUnavailable
	}
	if !validLeaseCommit(envelope.Lease, stored.Time) {
		// A server can accept a previously sent message after its lease expires.
		// Preserve the plain prior state in every transition, not recursively
		// nested envelopes, so even history=1 cannot erase valid drill history.
		var prior restoreJournalState
		if len(envelope.PriorState) == 0 || json.Unmarshal(envelope.PriorState, &prior) != nil || prior.Runs == nil || prior.Items == nil || prior.Epochs == nil || prior.Facts == nil {
			return snapshot, ErrRestoreJournalUnavailable
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
func (journal *NATSJournal) transact(ctx context.Context, write bool, change func(*restoreJournalState) error) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	operationCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for attempt := 0; attempt < 8; attempt++ {
		snapshot, err := journal.snapshot(operationCtx)
		if errors.Is(err, ErrRestoreJournalConflict) {
			continue
		}
		if err != nil {
			return err
		}
		priorState, marshalErr := json.Marshal(snapshot.state)
		if marshalErr != nil || len(priorState) > maximumRestoreJournalStateBytes {
			return ErrRestoreJournalUnavailable
		}
		if err := change(&snapshot.state); err != nil {
			return err
		}
		proposedState, marshalErr := json.Marshal(snapshot.state)
		if marshalErr != nil || len(proposedState) > maximumRestoreJournalStateBytes {
			return ErrRestoreJournalUnavailable
		}
		envelope := restoreJournalEnvelope{SchemaVersion: 1, Lease: snapshot.lease, LeaseRevision: snapshot.leaseRevision}
		subject := restoreBarrierSubject
		if write || snapshot.recovered {
			envelope.PriorState = priorState
			envelope.State = snapshot.state
			subject = restoreStateSubject
		}
		payload, err := json.Marshal(envelope)
		if err != nil || len(payload) > maximumRestoreJournalBytes {
			return ErrRestoreJournalUnavailable
		}
		if !snapshot.lease.IssuedAt.Add(time.Duration(snapshot.lease.DurationMilliseconds) * time.Millisecond).After(time.Now().UTC()) {
			return ErrRestoreEpochFenced
		}
		ack, err := journal.js.Publish(operationCtx, subject, payload, jetstream.WithExpectStream(restoreJournalStream), jetstream.WithExpectLastSequence(snapshot.sequence))
		if err != nil {
			var apiError *jetstream.APIError
			if errors.As(err, &apiError) && (apiError.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence || apiError.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant) {
				continue
			}
			return ErrRestoreJournalUnavailable
		}
		if ack.Stream != restoreJournalStream || ack.Sequence != snapshot.sequence+1 || ack.Duplicate {
			return ErrRestoreJournalUnavailable
		}
		committed, found, err := journal.rawGet(operationCtx, "", ack.Sequence)
		if err != nil || !found || committed.Subject != subject || !bytes.Equal(committed.Data, payload) {
			return ErrRestoreJournalUnavailable
		}
		// The persisted server timestamp closes the expiry window between local
		// validation and commit. An after-expiry record is never accepted on reads.
		if !validLeaseCommit(snapshot.lease, committed.Time) {
			return ErrRestoreEpochFenced
		}
		return nil
	}
	return ErrRestoreJournalConflict
}

func (journal *NATSJournal) Facts(ctx context.Context, database, _ string) (facts JournalFacts, err error) {
	if !validID(database) {
		return facts, ErrInvalidConfig
	}
	err = journal.transact(ctx, false, func(state *restoreJournalState) error {
		var found bool
		facts, found = state.Facts[database]
		if !found {
			return ErrRestoreJournalFactsMissing
		}
		return nil
	})
	return
}

// RecordFacts stores only the real source's immutable journal-cut metadata.
// The caller must obtain checksum and count from the database journal; this
// adapter neither samples customer records nor invents empty-database facts.
func (journal *NATSJournal) RecordFacts(ctx context.Context, database string, facts JournalFacts) error {
	if !validID(database) || !validToken(facts.JournalCut) || !validToken(facts.Checksum) || facts.RowCount < 0 {
		return ErrInvalidConfig
	}
	return journal.transact(ctx, true, func(state *restoreJournalState) error {
		if old, found := state.Facts[database]; found && old.JournalCut == facts.JournalCut && old != facts {
			return ErrRestoreJournalConflict
		}
		state.Facts[database] = facts
		return nil
	})
}
func (journal *NATSJournal) LoadRun(ctx context.Context, id string) (run RunRecord, found bool, err error) {
	if !validToken(id) {
		return run, false, ErrInvalidConfig
	}
	err = journal.transact(ctx, false, func(state *restoreJournalState) error { run, found = state.Runs[id]; return nil })
	return
}

func (journal *NATSJournal) ActiveRuns(ctx context.Context) (runs []RunRecord, err error) {
	err = journal.transact(ctx, false, func(state *restoreJournalState) error {
		for _, run := range state.Active {
			runs = append(runs, copyRun(run))
		}
		return nil
	})
	return runs, err
}
func (journal *NATSJournal) SaveRun(ctx context.Context, run RunRecord) error {
	if !validToken(run.ID) || run.StartedAt.IsZero() {
		return ErrInvalidConfig
	}
	return journal.transact(ctx, true, func(state *restoreJournalState) error {
		for _, item := range run.Items {
			if item.RestoreEpoch != 0 && state.Epochs[item.DatabaseID].Current != item.RestoreEpoch {
				return ErrRestoreEpochFenced
			}
		}
		if old, found := state.Runs[run.ID]; found && !old.ScheduledAt.Equal(run.ScheduledAt) {
			return ErrRestoreJournalConflict
		}
		state.Runs[run.ID] = run
		if state.Active == nil {
			state.Active = map[string]RunRecord{}
		}
		if run.Status == RunRunning {
			state.Active[run.ID] = run
		} else {
			delete(state.Active, run.ID)
		}
		return nil
	})
}
func (journal *NATSJournal) LoadItem(ctx context.Context, key string) (item ItemRecord, found bool, err error) {
	if !validToken(key) {
		return item, false, ErrInvalidConfig
	}
	err = journal.transact(ctx, false, func(state *restoreJournalState) error { item, found = state.Items[key]; return nil })
	return
}
func (journal *NATSJournal) SaveItem(ctx context.Context, item ItemRecord) error {
	if !validToken(item.Key) || !validToken(item.RunID) || !validID(item.DatabaseID) || item.StartedAt.IsZero() {
		return ErrInvalidConfig
	}
	return journal.transact(ctx, true, func(state *restoreJournalState) error {
		epochs := state.Epochs[item.DatabaseID]
		claimed := epochs.Claims[item.Key]
		if item.RestoreEpoch == 0 {
			if claimed != 0 || item.Status == ItemRunning || item.Status == ItemSucceeded {
				return ErrRestoreEpochFenced
			}
		} else if item.RestoreEpoch != epochs.Current || claimed != item.RestoreEpoch {
			return ErrRestoreEpochFenced
		}
		if old, found := state.Items[item.Key]; found && (old.DatabaseID != item.DatabaseID || old.RunID != item.RunID) {
			return ErrRestoreJournalConflict
		}
		state.Items[item.Key] = item
		return nil
	})
}
func (journal *NATSJournal) ClaimRestoreEpoch(ctx context.Context, database, key string) (epoch uint64, err error) {
	if !validID(database) || !validToken(key) {
		return 0, ErrInvalidConfig
	}
	err = journal.transact(ctx, true, func(state *restoreJournalState) error {
		epochs := state.Epochs[database]
		if existing := epochs.Claims[key]; existing != 0 {
			epoch = existing
			return nil
		}
		if epochs.Current == math.MaxUint64 {
			return ErrRestoreEpochFenced
		}
		if epochs.Claims == nil {
			epochs.Claims = map[string]uint64{}
		}
		epochs.Current++
		epoch = epochs.Current
		epochs.Claims[key] = epoch
		state.Epochs[database] = epochs
		return nil
	})
	return
}
func (journal *NATSJournal) RestoreEpochCurrent(ctx context.Context, database string, epoch uint64) (current bool, err error) {
	if !validID(database) || epoch == 0 {
		return false, ErrInvalidConfig
	}
	err = journal.transact(ctx, false, func(state *restoreJournalState) error { current = state.Epochs[database].Current == epoch; return nil })
	return
}

func (journal *NATSJournal) String() string {
	return fmt.Sprintf("NATSRestoreJournal{authorityEpoch:%d}", journal.epoch)
}
