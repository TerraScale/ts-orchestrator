package reaper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
)

type reaperEnvelope struct {
	SchemaVersion int
	Lease         authority.RegionalAuthorityLeaseDocument
	LeaseRevision uint64
	State         *State
	PriorState    *State
	PriorRevision uint64
}
type reaperRawMessage struct {
	Subject  string    `json:"subject"`
	Sequence uint64    `json:"seq"`
	Data     []byte    `json:"data"`
	Time     time.Time `json:"time"`
	Headers  []byte    `json:"hdrs"`
}
type reaperSnapshot struct {
	sequence      uint64
	leaseRevision uint64
	lease         authority.RegionalAuthorityLeaseDocument
	state         *State
	revision      uint64
	recovered     bool
}

func (s *NATSStateStore) request(ctx context.Context, subject string, payload []byte, target any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := reaperTransport(s.connection); err != nil {
		return err
	}
	response, err := s.connection.RequestWithContext(ctx, subject, payload)
	if err != nil || response == nil || len(response.Data) > maximumReaperDocumentBytes*4/3+8192 {
		return ErrStateUnavailable
	}
	if json.Unmarshal(response.Data, target) != nil {
		return ErrStateUnavailable
	}
	return nil
}
func (s *NATSStateStore) rawGet(ctx context.Context, subject string, sequence uint64) (reaperRawMessage, bool, error) {
	payload, _ := json.Marshal(struct {
		LastFor  string `json:"last_by_subj,omitempty"`
		Sequence uint64 `json:"seq,omitempty"`
	}{subject, sequence})
	var response struct {
		Message reaperRawMessage    `json:"message"`
		Error   *jetstream.APIError `json:"error"`
	}
	// Ordinary STREAM.MSG.GET routes to the Raft leader. Never use DIRECT.GET.
	if err := s.request(ctx, "$JS.API.STREAM.MSG.GET."+reaperStream, payload, &response); err != nil {
		return reaperRawMessage{}, false, err
	}
	if response.Error != nil {
		if response.Error.ErrorCode == 10037 {
			return reaperRawMessage{}, false, nil
		}
		return reaperRawMessage{}, false, ErrStateUnavailable
	}
	message := response.Message
	if message.Sequence == 0 || message.Time.IsZero() || len(message.Data) > maximumReaperDocumentBytes || len(message.Headers) > 4096 || strings.Contains(string(message.Headers), "KV-Operation:") || subject != "" && message.Subject != subject || sequence != 0 && message.Sequence != sequence {
		return reaperRawMessage{}, false, ErrStateUnavailable
	}
	return message, true, nil
}

func (s *NATSStateStore) snapshot(ctx context.Context) (reaperSnapshot, error) {
	var info struct {
		jetstream.StreamInfo
		Error *jetstream.APIError `json:"error"`
	}
	if err := s.request(ctx, "$JS.API.STREAM.INFO."+reaperStream, []byte("{}"), &info); err != nil {
		return reaperSnapshot{}, err
	}
	config := info.Config
	if info.Error != nil || config.Name != reaperStream || config.Storage != jetstream.FileStorage || config.Replicas != 3 || config.MaxAge != 0 || config.Mirror != nil || len(config.Sources) != 0 || config.Discard != jetstream.DiscardNew || config.MaxMsgs != -1 || config.MaxMsgsPerSubject < 1 || config.MaxMsgsPerSubject > 5 || config.MaxMsgSize > 0 && config.MaxMsgSize < maximumReaperDocumentBytes || config.MaxBytes != 8<<20 || config.AllowMsgTTL || config.SubjectDeleteMarkerTTL != 0 {
		return reaperSnapshot{}, ErrStateUnavailable
	}
	leaseMessage, found, err := s.rawGet(ctx, reaperLeaseSubject, 0)
	if err != nil {
		return reaperSnapshot{}, err
	}
	if !found {
		return reaperSnapshot{}, ErrStateFenced
	}
	if leaseMessage.Sequence > info.State.LastSeq {
		return reaperSnapshot{}, ErrStateConflict
	}
	var lease authority.RegionalAuthorityLeaseDocument
	if strictReaperJSON(leaseMessage.Data, &lease) != nil || !reaperLeaseLive(lease, time.Now().UTC()) || lease.CandidateId != s.candidate || lease.Epoch != int64(s.epoch) || lease.LeaseId != s.leaseID {
		return reaperSnapshot{}, ErrStateFenced
	}
	snapshot := reaperSnapshot{sequence: info.State.LastSeq, leaseRevision: leaseMessage.Sequence, lease: lease}
	stored, found, err := s.rawGet(ctx, reaperStateSubject, 0)
	if err != nil {
		return snapshot, err
	}
	if !found {
		return snapshot, nil
	}
	if stored.Sequence > snapshot.sequence {
		return snapshot, ErrStateConflict
	}
	var envelope reaperEnvelope
	var fields map[string]json.RawMessage
	if json.Unmarshal(stored.Data, &fields) != nil || len(fields) != 6 {
		return snapshot, ErrStateUnavailable
	}
	for _, key := range []string{"SchemaVersion", "Lease", "LeaseRevision", "State", "PriorState", "PriorRevision"} {
		if _, ok := fields[key]; !ok {
			return snapshot, ErrStateUnavailable
		}
	}
	if strictReaperJSON(stored.Data, &envelope) != nil || envelope.SchemaVersion != 1 || envelope.PriorState != nil && envelope.PriorRevision == 0 || envelope.Lease.Epoch > lease.Epoch || envelope.LeaseRevision == 0 || envelope.LeaseRevision >= stored.Sequence || envelope.PriorRevision >= stored.Sequence || envelope.Lease.Validate() != nil || envelope.Lease.AuthorityId != "global" {
		return snapshot, ErrStateUnavailable
	}
	if _, err := reaperStateBytes(envelope.State); err != nil {
		return snapshot, err
	}
	if _, err := reaperStateBytes(envelope.PriorState); err != nil {
		return snapshot, err
	}
	if envelope.State == nil && envelope.PriorState != nil {
		return snapshot, ErrStateUnavailable
	}
	if envelope.State != nil {
		if err := reaperIntentTransition(envelope.PriorState, envelope.State); err != nil {
			return snapshot, ErrStateUnavailable
		}
	}
	snapshot.state = envelope.State
	snapshot.revision = stored.Sequence
	if !reaperLeaseLive(envelope.Lease, stored.Time) {
		// The full prior state stays flat, including when History=1 erased its
		// original record. Late server commits never erase valid retirement work.
		snapshot.state = envelope.PriorState
		snapshot.revision = envelope.PriorRevision
		snapshot.recovered = true
	}
	return snapshot, nil
}

func (s *NATSStateStore) commit(ctx context.Context, snapshot reaperSnapshot, state *State, write bool) (uint64, error) {
	envelope := reaperEnvelope{SchemaVersion: 1, Lease: snapshot.lease, LeaseRevision: snapshot.leaseRevision}
	subject := reaperBarrierSubject
	if write {
		envelope.State = state
		envelope.PriorState = snapshot.state
		envelope.PriorRevision = snapshot.revision
		subject = reaperStateSubject
	}
	payload, err := json.Marshal(envelope)
	if err != nil || len(payload) > maximumReaperDocumentBytes {
		return 0, ErrStateUnavailable
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !reaperLeaseLive(snapshot.lease, time.Now().UTC()) {
		return 0, ErrStateFenced
	}
	ack, err := s.js.Publish(ctx, subject, payload, jetstream.WithExpectStream(reaperStream), jetstream.WithExpectLastSequence(snapshot.sequence))
	if err != nil {
		var apiError *jetstream.APIError
		if errors.As(err, &apiError) && (apiError.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence || apiError.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant) {
			return 0, ErrStateConflict
		}
		return 0, ErrStateUnavailable
	}
	if ack.Stream != reaperStream || ack.Sequence != snapshot.sequence+1 || ack.Duplicate {
		return 0, ErrStateUnavailable
	}
	committed, found, err := s.rawGet(ctx, "", ack.Sequence)
	if err != nil || !found || committed.Subject != subject || !bytes.Equal(committed.Data, payload) {
		return 0, ErrStateUnavailable
	}
	if !reaperLeaseLive(snapshot.lease, committed.Time) {
		return 0, ErrStateFenced
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !reaperLeaseLive(snapshot.lease, time.Now().UTC()) {
		return 0, ErrStateFenced
	}
	return ack.Sequence, nil
}

// Decode exactly one typed object and reject duplicate keys at every depth.
func strictReaperJSON(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maximumReaperDocumentBytes {
		return ErrStateUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var consume func() error
	consume = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for decoder.More() {
				token, err := decoder.Token()
				key, ok := token.(string)
				if err != nil || !ok || seen[key] {
					return ErrStateUnavailable
				}
				seen[key] = true
				if err := consume(); err != nil {
					return err
				}
			}
			token, err = decoder.Token()
			if err != nil || token != json.Delim('}') {
				return ErrStateUnavailable
			}
		case json.Delim('['):
			for decoder.More() {
				if err := consume(); err != nil {
					return err
				}
			}
			token, err = decoder.Token()
			if err != nil || token != json.Delim(']') {
				return ErrStateUnavailable
			}
		}
		return nil
	}
	if consume() != nil {
		return ErrStateUnavailable
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrStateUnavailable
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrStateUnavailable
	}
	return nil
}
