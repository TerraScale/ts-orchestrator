package serviceidentityrotation

import (
	"bytes"
	"context"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
)

type rotationEnvelope struct {
	SchemaVersion int
	Lease         authority.RegionalAuthorityLeaseDocument
	LeaseRevision uint64
	State         *Journal
	PriorState    *Journal
	PriorRevision uint64
}
type rotationRawMessage struct {
	Subject  string    `json:"subject"`
	Sequence uint64    `json:"seq"`
	Data     []byte    `json:"data"`
	Time     time.Time `json:"time"`
	Headers  []byte    `json:"hdrs"`
}
type rotationSnapshot struct {
	sequence      uint64
	leaseRevision uint64
	lease         authority.RegionalAuthorityLeaseDocument
	state         *Journal
	revision      uint64
	recovered     bool
}

func (s *NATSStateStore) request(ctx context.Context, subject string, payload []byte, target any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := rotationTransport(s.connection); err != nil {
		return err
	}
	response, err := s.connection.RequestWithContext(ctx, subject, payload)
	if err != nil || response == nil || len(response.Data) > maximumRotationDocumentBytes*4/3+8192 {
		return ErrStateUnavailable
	}
	// NATS represents StreamConfig duration fields as integer nanoseconds.
	if err := json.Unmarshal(response.Data, target, jsonv1.FormatDurationAsNano(true)); err != nil {
		return ErrStateUnavailable
	}
	return nil
}
func (s *NATSStateStore) rawGet(ctx context.Context, subject string, sequence uint64) (rotationRawMessage, bool, error) {
	payload, _ := json.Marshal(struct {
		LastFor  string `json:"last_by_subj,omitempty"`
		Sequence uint64 `json:"seq,omitzero"`
	}{subject, sequence})
	var response struct {
		Message rotationRawMessage  `json:"message"`
		Error   *jetstream.APIError `json:"error"`
	}
	// Ordinary STREAM.MSG.GET routes to the Raft leader. Never use DIRECT.GET.
	if err := s.request(ctx, "$JS.API.STREAM.MSG.GET."+rotationStream, payload, &response); err != nil {
		return rotationRawMessage{}, false, err
	}
	if response.Error != nil {
		if response.Error.ErrorCode == 10037 {
			return rotationRawMessage{}, false, nil
		}
		return rotationRawMessage{}, false, ErrStateUnavailable
	}
	message := response.Message
	if message.Sequence == 0 || message.Time.IsZero() || len(message.Data) > maximumRotationDocumentBytes || len(message.Headers) > 4096 || strings.Contains(string(message.Headers), "KV-Operation:") || subject != "" && message.Subject != subject || sequence != 0 && message.Sequence != sequence {
		return rotationRawMessage{}, false, ErrStateUnavailable
	}
	return message, true, nil
}

func (s *NATSStateStore) snapshot(ctx context.Context) (rotationSnapshot, error) {
	var info struct {
		jetstream.StreamInfo
		Error *jetstream.APIError `json:"error"`
	}
	if err := s.request(ctx, "$JS.API.STREAM.INFO."+rotationStream, []byte("{}"), &info); err != nil {
		return rotationSnapshot{}, err
	}
	config := info.Config
	if info.Error != nil || config.Name != rotationStream || config.Storage != jetstream.FileStorage || config.Replicas != 3 || config.MaxAge != 0 || config.Mirror != nil || len(config.Sources) != 0 || config.Discard != jetstream.DiscardNew || config.MaxMsgs != -1 || config.MaxMsgsPerSubject < 1 || config.MaxMsgSize > 0 && config.MaxMsgSize < maximumRotationDocumentBytes || config.MaxBytes > 0 && config.MaxBytes < 2*maximumRotationDocumentBytes || config.AllowMsgTTL || config.SubjectDeleteMarkerTTL != 0 {
		return rotationSnapshot{}, ErrStateUnavailable
	}
	leaseMessage, found, err := s.rawGet(ctx, rotationLeaseSubject, 0)
	if err != nil {
		return rotationSnapshot{}, err
	}
	if !found {
		return rotationSnapshot{}, ErrStateFenced
	}
	if leaseMessage.Sequence > info.State.LastSeq {
		return rotationSnapshot{}, ErrStateConflict
	}
	var lease authority.RegionalAuthorityLeaseDocument
	if strictRotationJSON(leaseMessage.Data, &lease) != nil || !rotationLeaseLive(lease, time.Now().UTC()) || lease.CandidateId != s.candidate || lease.Epoch != int64(s.epoch) || lease.LeaseId != s.leaseID {
		return rotationSnapshot{}, ErrStateFenced
	}
	snapshot := rotationSnapshot{sequence: info.State.LastSeq, leaseRevision: leaseMessage.Sequence, lease: lease}
	stored, found, err := s.rawGet(ctx, rotationStateSubject, 0)
	if err != nil {
		return snapshot, err
	}
	if !found {
		return snapshot, nil
	}
	if stored.Sequence > snapshot.sequence {
		return snapshot, ErrStateConflict
	}
	var envelope rotationEnvelope
	var fields map[string]jsontext.Value
	if json.Unmarshal(stored.Data, &fields) != nil || len(fields) != 6 {
		return snapshot, ErrStateUnavailable
	}
	for _, key := range []string{"SchemaVersion", "Lease", "LeaseRevision", "State", "PriorState", "PriorRevision"} {
		if _, ok := fields[key]; !ok {
			return snapshot, ErrStateUnavailable
		}
	}
	if strictRotationJSON(stored.Data, &envelope) != nil || envelope.SchemaVersion != 1 || envelope.PriorState != nil && envelope.PriorRevision == 0 || envelope.Lease.Epoch > lease.Epoch || envelope.LeaseRevision == 0 || envelope.LeaseRevision >= stored.Sequence || envelope.PriorRevision >= stored.Sequence || envelope.Lease.Validate() != nil || envelope.Lease.AuthorityId != "global" {
		return snapshot, ErrStateUnavailable
	}
	// A commit made under the current epoch must carry the exact lease
	// identity observed from the authority stream. Epoch alone is not a
	// sufficient binding: a replacement candidate can otherwise replay a
	// same-term journal record.
	if envelope.Lease.Epoch == lease.Epoch && (envelope.Lease.CandidateId != lease.CandidateId || envelope.Lease.LeaseId != lease.LeaseId) {
		return snapshot, ErrStateUnavailable
	}
	if _, err := rotationStateBytes(envelope.State); err != nil {
		return snapshot, err
	}
	if _, err := rotationStateBytes(envelope.PriorState); err != nil {
		return snapshot, err
	}
	snapshot.state = envelope.State
	snapshot.revision = stored.Sequence
	if !rotationLeaseLive(envelope.Lease, stored.Time) {
		// The full prior state stays flat, including when History=1 erased its
		// original record. Late server commits never erase valid retirement work.
		snapshot.state = envelope.PriorState
		snapshot.revision = envelope.PriorRevision
		snapshot.recovered = true
	}
	return snapshot, nil
}

func (s *NATSStateStore) commit(ctx context.Context, snapshot rotationSnapshot, state *Journal, write bool) (uint64, error) {
	envelope := rotationEnvelope{SchemaVersion: 1, Lease: snapshot.lease, LeaseRevision: snapshot.leaseRevision}
	subject := rotationBarrierSubject
	if write {
		envelope.State = state
		envelope.PriorState = snapshot.state
		envelope.PriorRevision = snapshot.revision
		subject = rotationStateSubject
	}
	payload, err := json.Marshal(envelope)
	if err != nil || len(payload) > maximumRotationDocumentBytes {
		return 0, ErrStateUnavailable
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !rotationLeaseLive(snapshot.lease, time.Now().UTC()) {
		return 0, ErrStateFenced
	}
	ack, err := s.js.Publish(ctx, subject, payload, jetstream.WithExpectStream(rotationStream), jetstream.WithExpectLastSequence(snapshot.sequence))
	if err != nil {
		if apiError, ok := errors.AsType[*jetstream.APIError](err); ok && (apiError.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence || apiError.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant) {
			return 0, ErrStateConflict
		}
		return 0, ErrStateUnavailable
	}
	if ack.Stream != rotationStream || ack.Sequence != snapshot.sequence+1 || ack.Duplicate {
		return 0, ErrStateUnavailable
	}
	committed, found, err := s.rawGet(ctx, "", ack.Sequence)
	if err != nil || !found || committed.Subject != subject || !bytes.Equal(committed.Data, payload) {
		return 0, ErrStateUnavailable
	}
	if !rotationLeaseLive(snapshot.lease, committed.Time) {
		return 0, ErrStateFenced
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !rotationLeaseLive(snapshot.lease, time.Now().UTC()) {
		return 0, ErrStateFenced
	}
	return ack.Sequence, nil
}

// JSON v2 rejects duplicate names and trailing values; typed decoding rejects
// unknown fields, including any attempt to persist credential material.
func strictRotationJSON(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maximumRotationDocumentBytes || json.Unmarshal(raw, target, json.RejectUnknownMembers(true)) != nil {
		return ErrStateUnavailable
	}
	return nil
}
