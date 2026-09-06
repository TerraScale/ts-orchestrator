package reaper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
)

const auditSignatureDomain = "terrascale-reaper-audit-v1\n"

// NATSAuditSink uses immutable per-event subjects in the lease's R3 stream.
// A global stream CAS makes lease replacement and audit append mutually
// exclusive. Capacity exhaustion refuses the append; audit evidence is never
// deleted to make room for a lifecycle effect.
type NATSAuditSink struct{ store *NATSStateStore }
type auditPayload struct {
	Version       int                                      `json:"version"`
	Lease         authority.RegionalAuthorityLeaseDocument `json:"lease"`
	LeaseRevision uint64                                   `json:"leaseRevision"`
	PublicNKey    string                                   `json:"publicNkey"`
	Event         AuditEvent                               `json:"event"`
}
type auditEnvelope struct {
	Payload   auditPayload `json:"payload"`
	Signature []byte       `json:"signature"`
}

var _ AuditSink = (*NATSAuditSink)(nil)

func NewNATSAuditSink(config NATSStateStoreConfig) (*NATSAuditSink, error) {
	store, err := NewNATSStateStore(config)
	if err != nil {
		return nil, err
	}
	return &NATSAuditSink{store: store}, nil
}
func auditSubject(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "$KV.ORCH_LEADERS.reaper.audit." + hex.EncodeToString(sum[:])
}
func validAuditEvent(event AuditEvent) bool {
	if event.ID == "" || event.ID != event.OperationKey || event.DatabaseID == "" || event.Action == "" || event.Outcome == "" || event.At.IsZero() {
		return false
	}
	for _, value := range []string{event.ID, event.DatabaseID, event.Action, event.Outcome, event.OperationKey, event.Error} {
		if len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
	}
	return true
}
func auditSigningBytes(payload auditPayload) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrStateUnavailable
	}
	return append([]byte(auditSignatureDomain), raw...), nil
}
func decodeAudit(message reaperRawMessage) (auditEnvelope, error) {
	var envelope auditEnvelope
	if len(message.Data) > 16<<10 || json.Unmarshal(message.Data, &envelope, json.RejectUnknownMembers(true)) != nil || envelope.Payload.Version != 1 || !validAuditEvent(envelope.Payload.Event) || envelope.Payload.LeaseRevision == 0 || envelope.Payload.LeaseRevision >= message.Sequence || message.Subject != auditSubject(envelope.Payload.Event.ID) {
		return envelope, ErrStateUnavailable
	}
	key, err := nkeys.FromPublicKey(envelope.Payload.PublicNKey)
	if err != nil || !nkeys.IsValidPublicUserKey(envelope.Payload.PublicNKey) {
		return envelope, ErrStateUnavailable
	}
	raw, err := auditSigningBytes(envelope.Payload)
	if err != nil || key.Verify(raw, envelope.Signature) != nil {
		return envelope, ErrStateUnavailable
	}
	if !reaperLeaseLive(envelope.Payload.Lease, message.Time) {
		return envelope, ErrStateFenced
	}
	return envelope, nil
}
func sameAuditEvent(a, b AuditEvent) bool { a.At = b.At; return a == b }
func (a *NATSAuditSink) Record(ctx context.Context, event AuditEvent) error {
	if a == nil || ctx == nil || !validAuditEvent(event) {
		return ErrStateUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	s := a.store
	s.mu.Lock()
	defer s.mu.Unlock()
	for range 8 {
		snapshot, err := s.snapshot(ctx)
		if errors.Is(err, ErrStateConflict) {
			continue
		}
		if err != nil {
			return err
		}
		subject := auditSubject(event.ID)
		previous, found, err := s.rawGet(ctx, subject, 0)
		if err != nil {
			return err
		}
		if found {
			if previous.Sequence > snapshot.sequence {
				continue
			}
			envelope, err := decodeAudit(previous)
			if err == nil {
				if !sameAuditEvent(envelope.Payload.Event, event) {
					return ErrStateConflict
				}
				// Prove an identical retry on the live leader, not a stale read alone.
				_, err = s.commit(ctx, snapshot, nil, false)
				if errors.Is(err, ErrStateConflict) {
					continue
				}
				return err
			}
			if !errors.Is(err, ErrStateFenced) {
				return err
			}
		}
		envelope := auditEnvelope{Payload: auditPayload{Version: 1, Lease: snapshot.lease, LeaseRevision: snapshot.leaseRevision, PublicNKey: s.connection.Opts.Nkey, Event: event}}
		signing, err := auditSigningBytes(envelope.Payload)
		if err != nil {
			return err
		}
		envelope.Signature, err = s.connection.Opts.SignatureCB(signing)
		if err != nil {
			return ErrStateUnavailable
		}
		raw, err := json.Marshal(envelope)
		if err != nil || len(raw) > 16<<10 {
			return ErrStateUnavailable
		}
		if !reaperLeaseLive(snapshot.lease, time.Now().UTC()) {
			return ErrStateFenced
		}
		ack, err := s.js.Publish(ctx, subject, raw, jetstream.WithExpectStream(reaperStream), jetstream.WithExpectLastSequence(snapshot.sequence))
		if err != nil {
			if api, ok := errors.AsType[*jetstream.APIError](err); ok && (api.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence || api.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant) {
				continue
			}
			return ErrStateUnavailable
		}
		if ack.Stream != reaperStream || ack.Sequence != snapshot.sequence+1 || ack.Duplicate {
			return ErrStateUnavailable
		}
		committed, found, err := s.rawGet(ctx, subject, 0)
		if err != nil || !found || committed.Sequence != ack.Sequence || !bytes.Equal(committed.Data, raw) {
			return ErrStateUnavailable
		}
		if _, err := decodeAudit(committed); err != nil {
			return err
		}
		if !reaperLeaseLive(snapshot.lease, time.Now().UTC()) {
			return ErrStateFenced
		}
		return nil
	}
	return ErrStateConflict
}
