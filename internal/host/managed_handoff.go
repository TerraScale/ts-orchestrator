//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

const maxManagedOwnerBytes = 256 << 10

var ErrManagedNativeFenced = errors.New("retained volume is permanently fenced against native execution")
var ErrNativePublicationUnsettled = errors.New("native publication closure has no independently authenticated settlement")

// ManagedNativeProvenance is retained before an Apply can make this artifact a
// possible writer. Current Desired never replaces this historical provenance.
// Unsupported material or host changes require a separately verified transfer.
type ManagedNativeProvenance struct {
	Desired              Desired      `json:"desired"`
	Registration         Registration `json:"registration"`
	DesiredSequence      uint64       `json:"desired_sequence"`
	RegistrationSequence uint64       `json:"registration_sequence"`
	DesiredSHA256        string       `json:"desired_sha256"`
}

// ManagedNativeWriter records the original process independently of any later
// session that observes its stop. Missing observation is not a stopped writer.
type ManagedNativeWriter struct {
	HostPublicKey string               `json:"host_public_key"`
	SessionID     string               `json:"session_id"`
	Epoch         uint64               `json:"epoch"`
	ObservedAt    time.Time            `json:"observed_at"`
	Process       ManagedRuntimeReport `json:"process"`
}

// ManagedNativeStop records a current authenticated observer, not publication
// settlement. Even a genuine local stop cannot complete container ownership.
type ManagedNativeStop struct {
	OwnerSequence uint64            `json:"owner_sequence"`
	Challenge     string            `json:"challenge"`
	WriterSHA256  string            `json:"writer_sha256"`
	ObservedAt    time.Time         `json:"observed_at"`
	SessionID     string            `json:"session_id"`
	Registration  Registration      `json:"registration"`
	Envelope      protocol.Envelope `json:"envelope"`
}

// ManagedRuntimeOwner has no container-completed variant. A later publication
// protocol must independently establish that no old remote Put can still win.
// Keeping this closed is deliberate; a bool or callback cannot confer it.
type ManagedRuntimeOwner struct {
	ObservationOrigin string                  `json:"observation_origin"`
	Version           int                     `json:"version"`
	Cell              string                  `json:"cell"`
	VolumeID          string                  `json:"volume_id"`
	Epoch             uint64                  `json:"epoch"`
	Phase             string                  `json:"phase"`
	Native            ManagedNativeProvenance `json:"native"`
	Writer            *ManagedNativeWriter    `json:"writer,omitempty"`
	OperationID       string                  `json:"operation_id,omitempty"`
	Replacement       string                  `json:"replacement_sha256,omitempty"`
	Drain             *ManagedDrainResult     `json:"drain,omitempty"`
	Challenge         string                  `json:"challenge,omitempty"`
	Stop              *ManagedNativeStop      `json:"stop,omitempty"`
}

func managedOwnerKey(cell, volumeID string) string {
	// Environment/member/incarnation/host attempt cannot select another key for
	// the same physical retained volume. They are pinned inside Native instead.
	return cell + ".volume." + fmt.Sprintf("%x", sha256.Sum256([]byte(volumeID)))
}

func managedOwnerDigest(value any) (string, error) {
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(wire)), nil
}

func ReadManagedRuntimeOwner(ctx context.Context, store authority.HostMutationStore, cell, volumeID string) (ManagedRuntimeOwner, authority.LogEntry, error) {
	if store == nil || validateToken(cell, "cell") != nil || volumeID == "" {
		return ManagedRuntimeOwner{}, authority.LogEntry{}, errors.New("managed ownership scope is incomplete")
	}
	key := managedOwnerKey(cell, volumeID)
	entry, err := store.ReadHostMutation(ctx, authority.MutationManagedRuntimeOwner, key)
	if err != nil {
		return ManagedRuntimeOwner{}, entry, err
	}
	var owner ManagedRuntimeOwner
	if err := protocol.DecodeStrict(entry.Payload, &owner, maxManagedOwnerBytes); err != nil {
		return owner, entry, err
	}
	d, r := owner.Native.Desired, owner.Native.Registration
	digest, err := managedOwnerDigest(d)
	if err != nil || owner.Version != 1 || owner.Cell != cell || owner.VolumeID != volumeID || owner.Epoch != entry.Epoch ||
		entry.Kind != authority.MutationManagedRuntimeOwner || entry.SubjectKey != key || entry.Sequence == 0 || entry.Epoch == 0 ||
		(owner.ObservationOrigin != "retained-before-admission" && owner.ObservationOrigin != "original-unobserved") ||
		owner.Native.DesiredSequence == 0 || owner.Native.RegistrationSequence == 0 || digest != owner.Native.DesiredSHA256 ||
		d.ManagedMember == nil || d.ManagedMember.Runtime == nil || d.ManagedMember.VolumeID != volumeID ||
		d.Cell != cell || d.Role != "terrabase" || validateRegistration(r, cell) != nil || validateDesired(d, cell, r) != nil ||
		owner.Phase != "native" && owner.Phase != "native-fenced" {
		return owner, entry, errors.New("managed owner lacks exact retained native provenance")
	}
	if owner.Phase == "native" && (owner.OperationID != "" || owner.Replacement != "" || owner.Drain != nil || owner.Challenge != "" || owner.Stop != nil) {
		return owner, entry, errors.New("native owner contains a conflicting handoff")
	}
	if owner.Phase == "native-fenced" && (!entityid.Valid(owner.OperationID) || !lowerHex(owner.Replacement, 64) ||
		!lowerHex(owner.Challenge, 32) || owner.Drain == nil || owner.Writer == nil || owner.ObservationOrigin != "retained-before-admission" ||
		!owner.Drain.Command.matchesDesired(d, r) || owner.Drain.Command.VolumeID != volumeID) {
		return owner, entry, errors.New("managed fence lacks its exact replacement and drain")
	}
	if owner.Writer != nil {
		report := Report{Cell: d.Cell, Node: d.Node, Environment: d.Environment, Role: d.Role, Digest: d.Digest,
			Generation: d.Generation, State: "running", Managed: &owner.Writer.Process}
		if owner.Writer.HostPublicKey != r.PublicKey || !entityid.Valid(owner.Writer.SessionID) || owner.Writer.Epoch == 0 ||
			owner.Writer.ObservedAt.IsZero() || owner.Writer.Process.Container != nil || validateManagedReportForDesired(report, d) != nil {
			return owner, entry, errors.New("managed owner original native process is invalid")
		}
	}
	if stop := owner.Stop; stop != nil {
		witness, err := managedOwnerDigest(owner.Writer)
		if err != nil || stop.OwnerSequence == 0 || stop.OwnerSequence >= entry.Sequence || stop.Challenge != owner.Challenge ||
			stop.WriterSHA256 != witness || !entityid.Valid(stop.SessionID) || !sameJSON(stop.Registration, r) || stop.ObservedAt.IsZero() {
			return owner, entry, errors.New("retained native stop differs from its original writer")
		}
		var req request
		if err := protocol.DecodeStrict(stop.Envelope.Payload, &req, 64<<10); err != nil {
			return owner, entry, err
		}
		req.Envelope = stop.Envelope
		key, err := decodePublicKey(r.PublicKey)
		// Verify historical authenticity at the signed issue instant. Current
		// stop admission separately checks freshness on every ordered attempt.
		if err != nil || verifyRequest(req, key, cell, req.IssuedAt) != nil || req.Node != r.Node || req.Operation != "managed-native" ||
			req.SessionID != stop.SessionID || req.NATSUserPublicKey != r.NATSUserPublicKey {
			return owner, entry, errors.New("retained native stop lacks its original signed observer request")
		}
		var query managedNativeQuery
		if err := protocol.DecodeStrict(req.Payload, &query, 64<<10); err != nil {
			return owner, entry, err
		}
		if query.Action != "stop" || query.Role != d.Role || query.Stop == nil {
			return owner, entry, errors.New("retained native stop request has another action")
		}
		signed, retained := *query.Stop, *stop
		signed.Envelope, retained.Envelope = protocol.Envelope{}, protocol.Envelope{}
		if !sameJSON(signed, retained) {
			return owner, entry, errors.New("retained native stop payload was substituted")
		}
	}

	return owner, entry, nil
}

// GuardManagedContainerOwner fails closed for every currently representable
// native lineage. There is no production publication-settlement producer yet.
// DATA close is intentionally not routed through new acquire/renew admission.
func GuardManagedContainerOwner(ctx context.Context, store authority.HostMutationStore, cell, volumeID string) error {
	if _, _, err := ReadManagedRuntimeOwner(ctx, store, cell, volumeID); err != nil {
		return err
	}
	return ErrNativePublicationUnsettled
}

func (c *Controller) currentManagedNative(ctx context.Context, node, role string) (ManagedNativeProvenance, error) {
	r, registrationSequence, found, err := c.readRegistration(ctx, node)
	if err != nil || !found || r.ManagedMember == nil || r.ManagedPlacement == nil || r.ManagedOCI == nil ||
		c.managedVerifier == nil || c.managedDesiredVerifier == nil {
		return ManagedNativeProvenance{}, errors.Join(err, errors.New("native enrollment lacks authenticated managed authority"))
	}
	d, desiredSequence, found, err := c.readDesired(ctx, node, role)
	if err != nil || !found || d.ManagedMember == nil || d.ManagedMember.Runtime == nil || validateDesired(d, c.cell, r) != nil {
		return ManagedNativeProvenance{}, errors.Join(err, errors.New("native enrollment lacks exact retained desired material"))
	}
	if err := c.managedVerifier.VerifyManagedRegistration(ctx, r); err != nil {
		return ManagedNativeProvenance{}, err
	}
	// ApplyDesired already authenticated this ordered record. Its transition
	// verifier is write-only and intentionally rejects later read stages.
	// The original ordered heads, not local inventory or an absent owner, are
	// the enrollment predecessors. A reset/unsupported head loses admission.
	desiredEntry, err := c.mutations.ReadHostMutation(ctx, authority.MutationDesired, desiredSubjectKey(c.cell, node, role))
	if err != nil || desiredEntry.Sequence != desiredSequence || desiredEntry.Epoch != d.AuthorityEpoch {
		return ManagedNativeProvenance{}, errors.Join(err, errors.New("native desired history is discontinuous"))
	}
	registrationEntry, err := c.mutations.ReadHostMutation(ctx, authority.MutationRegistration, registrationSubjectKey(c.cell, node))
	if err != nil || registrationEntry.Sequence != registrationSequence {
		return ManagedNativeProvenance{}, errors.Join(err, errors.New("native registration history is discontinuous"))
	}
	digest, err := managedOwnerDigest(d)
	return ManagedNativeProvenance{Desired: d, Registration: r, DesiredSequence: desiredSequence,
		RegistrationSequence: registrationSequence, DesiredSHA256: digest}, err
}

// Enrollment reads the retained ordered history, never a missing owner or local
// inventory. Unsupported historical changes require a separately verified transfer.
func (c *Controller) verifyManagedEnrollmentHistory(ctx context.Context, native ManagedNativeProvenance) error {
	if c.controlLog == nil {
		return errors.New("native enrollment has no retained ordered history")
	}
	info, err := c.controlLog.Info(ctx)
	if err != nil {
		return err
	}
	cfg, state := info.Config, info.State
	if cfg.Storage != jetstream.FileStorage || cfg.Retention != jetstream.LimitsPolicy ||
		!cfg.DenyDelete || !cfg.DenyPurge || cfg.AllowDirect || cfg.MaxAge != 0 ||
		cfg.MaxMsgs != -1 || cfg.MaxBytes != -1 || cfg.MaxMsgsPerSubject != -1 ||
		state.FirstSeq != 1 || state.NumDeleted != 0 || state.Msgs != state.LastSeq {
		return errors.New("native enrollment ordered history is truncated or mutable")
	}
	desiredSeen, registrationSeen := false, false
	filter := protocol.Control(c.cell, "host") + ".>"
	for next, count := uint64(1), 0; next <= state.LastSeq; count++ {
		if count >= 16384 {
			return errors.New("native enrollment exceeds supported history bound")
		}
		raw, err := c.controlLog.GetMsg(ctx, next, jetstream.WithGetMsgNextBySubject(filter))
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			break
		}
		if err != nil {
			return err
		}
		if raw.Sequence < next || raw.Sequence > state.LastSeq {
			break
		}
		next = raw.Sequence + 1
		var record struct {
			Version     int                        `json:"version"`
			Kind        authority.HostMutationKind `json:"kind"`
			Scope       string                     `json:"scope"`
			SubjectKey  string                     `json:"subject_key"`
			OperationID string                     `json:"operation_id"`
			Epoch       uint64                     `json:"epoch"`
			Payload     []byte                     `json:"payload"`
		}
		if err := protocol.DecodeStrict(raw.Data, &record, 2<<20); err != nil {
			return err
		}
		if record.Version != 1 || record.Scope != c.cell || record.Epoch == 0 || !entityid.Valid(record.OperationID) ||
			raw.Subject != protocol.Control(c.cell, "host")+"."+string(record.Kind)+"."+record.SubjectKey {
			return errors.New("native enrollment historical record identity is invalid")
		}
		switch record.Kind {
		case authority.MutationDesired:
			var d Desired
			if err := protocol.DecodeStrict(record.Payload, &d, 64<<10); err != nil {
				return err
			}
			if d.ManagedMember == nil || d.ManagedMember.VolumeID != native.Desired.ManagedMember.VolumeID {
				continue
			}
			if !sameJSON(d, native.Desired) || record.SubjectKey != desiredSubjectKey(c.cell, d.Node, d.Role) || record.Epoch != d.AuthorityEpoch {
				return errors.New("native volume has unsupported earlier desired lineage")
			}
			desiredSeen = desiredSeen || raw.Sequence == native.DesiredSequence
		case authority.MutationRegistration:
			if record.SubjectKey != registrationSubjectKey(c.cell, native.Registration.Node) {
				continue
			}
			var r Registration
			if err := protocol.DecodeStrict(record.Payload, &r, 64<<10); err != nil {
				return err
			}
			if !sameJSON(r, native.Registration) {
				return errors.New("native host has unsupported earlier registration lineage")
			}
			registrationSeen = registrationSeen || raw.Sequence == native.RegistrationSequence
		case authority.MutationManagedRuntimeOwner:
			if record.SubjectKey != managedOwnerKey(c.cell, native.Desired.ManagedMember.VolumeID) {
				continue
			}
			var owner ManagedRuntimeOwner
			if err := protocol.DecodeStrict(record.Payload, &owner, maxManagedOwnerBytes); err != nil {
				return err
			}
			if owner.Phase != "native" || !sameJSON(owner.Native, native) {
				return ErrManagedNativeFenced
			}
		}
	}
	if !desiredSeen || !registrationSeen {
		return errors.New("native enrollment original ordered heads are missing")
	}
	return nil
}

func (c *Controller) commitManagedOwner(ctx context.Context, owner ManagedRuntimeOwner, prior authority.LogEntry, verify func(context.Context) error) (ManagedRuntimeOwner, authority.LogEntry, error) {
	store, ok := c.mutations.(authority.VerifiedHostMutationStore)
	if !ok || c.readOnly || verify == nil {
		return owner, prior, errors.New("managed ownership requires final ordered verification")
	}
	epoch := c.authorityEpoch()
	owner.Epoch = epoch
	wire, operation, err := mutationPayload(owner)
	if err != nil {
		return owner, prior, err
	}
	check := func(check context.Context) error {
		if err := verify(check); err != nil {
			return err
		}
		return c.guard(check, epoch)
	}
	if err := check(ctx); err != nil {
		return owner, prior, err
	}
	_, err = store.CommitHostMutationVerified(ctx, epoch, authority.MutationManagedRuntimeOwner,
		managedOwnerKey(c.cell, owner.VolumeID), operation, prior.Sequence, wire, check)
	if err != nil {
		return owner, prior, err
	}
	// Idempotent/unknown-ack log returns are history, not new current permission.
	if err := check(ctx); err != nil {
		return owner, prior, err
	}
	current, entry, err := ReadManagedRuntimeOwner(ctx, c.mutations, c.cell, owner.VolumeID)
	if err != nil || !bytes.Equal(entry.Payload, wire) {
		return current, entry, errors.Join(err, errors.New("managed ownership changed before admission readback"))
	}
	return current, entry, nil
}

type managedNativeQuery struct {
	Role   string             `json:"role"`
	Action string             `json:"action"`
	Stop   *ManagedNativeStop `json:"stop,omitempty"`
}

type managedNativeReply struct {
	Owner    ManagedRuntimeOwner `json:"owner"`
	Sequence uint64              `json:"sequence"`
}

func (c *Controller) verifyManagedNativeAdmission(ctx context.Context, native ManagedNativeProvenance) error {
	verifier, ok := c.managedVerifier.(ManagedNativeAdmissionVerifier)
	if !ok {
		return errors.New("managed native admission lacks its independent current-lineage verifier")
	}
	return verifier.VerifyManagedNativeAdmission(ctx, native.Desired, native.Registration)
}

func (c *Controller) serveManagedNative(ctx context.Context, req request, r Registration, s session) (any, error) {
	var query managedNativeQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	if query.Role != "terrabase" || query.Action != "admit" && query.Action != "state" && query.Action != "stop" {
		return nil, errors.New("invalid managed native action")
	}
	native, err := c.currentManagedNative(ctx, req.Node, query.Role)
	if err != nil || !sameJSON(native.Registration, r) || r.Generation != s.RegistrationGeneration {
		return nil, errors.Join(err, errors.New("managed native caller changed"))
	}
	volumeID := native.Desired.ManagedMember.VolumeID
	owner, entry, err := ReadManagedRuntimeOwner(ctx, c.mutations, c.cell, volumeID)
	if errors.Is(err, authority.ErrNotFound) && query.Action == "admit" {
		if err := c.verifyManagedNativeAdmission(ctx, native); err != nil {
			return nil, err
		}
		owner = ManagedRuntimeOwner{Version: 1, Cell: c.cell, VolumeID: volumeID, Phase: "native", Native: native, ObservationOrigin: "original-unobserved"}
		// The prior authenticated report survives Recover dropping local
		// inventory. A later report cannot replace an unknown legacy origin.
		report, _, found, readErr := c.reportSnapshot(ctx, reportKey(c.cell, req.Node, query.Role))
		if readErr != nil {
			return nil, readErr
		}
		if found && report.State == "running" && report.Cell == native.Desired.Cell && report.Node == req.Node &&
			report.Environment == r.Environment && report.Role == query.Role && report.Generation == native.Desired.Generation &&
			report.Digest == native.Desired.Digest && entityid.Valid(report.SessionID) && report.Epoch != 0 && !report.ObservedAt.IsZero() &&
			report.Managed != nil && report.Managed.Container == nil && validateManagedReportForDesired(report, native.Desired) == nil {
			owner.ObservationOrigin = "retained-before-admission"
			owner.Writer = &ManagedNativeWriter{HostPublicKey: r.PublicKey, SessionID: report.SessionID, Epoch: report.Epoch,
				ObservedAt: report.ObservedAt, Process: *report.Managed}
		}
		owner, entry, err = c.commitManagedOwner(ctx, owner, authority.LogEntry{}, func(check context.Context) error {
			current, err := c.currentManagedNative(check, req.Node, query.Role)
			if err != nil || !sameJSON(current, native) {
				return errors.Join(err, errors.New("native enrollment predecessor changed"))
			}
			if err := c.verifyManagedEnrollmentHistory(check, native); err != nil {
				return err
			}
			if err := c.verifyManagedNativeAdmission(check, current); err != nil {
				return err
			}
			authorized, _, err := c.authorize(check, req)
			if err != nil || !sameJSON(authorized, native.Registration) {
				return errors.Join(err, errors.New("native enrollment caller changed during policy verification"))
			}
			return nil
		})
	}
	if err != nil {
		return nil, err
	}
	if !sameJSON(owner.Native, native) {
		return nil, errors.New("retained volume belongs to a different original native lineage")
	}
	if query.Action == "stop" {
		return c.storeManagedNativeStop(ctx, req, r, owner, entry, query.Stop)
	}
	switch owner.Phase {
	case "native":
		if err := c.verifyManagedNativeAdmission(ctx, native); err != nil {
			return nil, err
		}
	case "native-fenced":
		// A negative observation lets the original writer stop, never execute.
	default:
		return nil, ErrManagedNativeFenced
	}
	current, err := c.currentManagedNative(ctx, req.Node, query.Role)
	if err != nil || !sameJSON(current, native) {
		return nil, errors.Join(err, errors.New("managed native target changed before reply"))
	}
	confirmed, retained, err := ReadManagedRuntimeOwner(ctx, c.mutations, c.cell, volumeID)
	if err != nil || retained.Sequence != entry.Sequence || !sameJSON(confirmed, owner) {
		return nil, errors.Join(err, errors.New("managed native owner changed before reply"))
	}
	if _, _, err := c.authorize(ctx, req); err != nil {
		return nil, err
	}
	return managedNativeReply{Owner: owner, Sequence: entry.Sequence}, nil
}

func (c *Controller) retainManagedNativeWriter(ctx context.Context, req request, r Registration, report Report, desired Desired) error {
	if desired.ManagedMember == nil || report.State != "running" || report.Managed == nil || report.Managed.Container != nil {
		return nil
	}
	owner, entry, err := ReadManagedRuntimeOwner(ctx, c.mutations, c.cell, desired.ManagedMember.VolumeID)
	if err != nil {
		return err
	}
	if owner.Phase != "native" || !sameJSON(owner.Native.Desired, desired) || !sameJSON(owner.Native.Registration, r) {
		return ErrManagedNativeFenced
	}
	writer := ManagedNativeWriter{HostPublicKey: r.PublicKey, SessionID: req.SessionID,
		Epoch: req.Epoch, ObservedAt: report.ObservedAt, Process: *report.Managed}
	if owner.Writer != nil {
		old := owner.Writer.Process
		if old.ProcessPID != writer.Process.ProcessPID || old.ProcessStart != writer.Process.ProcessStart ||
			old.ProcessBootID != writer.Process.ProcessBootID || old.ProcessCgroup != writer.Process.ProcessCgroup {
			return errors.New("native process changed without an authenticated lineage transfer")
		}
		if old.ServingProof != nil || writer.Process.ServingProof == nil {
			return nil
		}
		owner.Writer.Process.ServingProof = writer.Process.ServingProof
	} else {
		owner.Writer = &writer
	}
	_, _, err = c.commitManagedOwner(ctx, owner, entry, func(check context.Context) error {
		current, prior, err := ReadManagedRuntimeOwner(check, c.mutations, c.cell, owner.VolumeID)
		if err != nil || current.Phase != "native" || (prior.Sequence != entry.Sequence && !sameJSON(current, owner)) || !sameJSON(current.Native, owner.Native) ||
			time.Since(report.ObservedAt) >= ReportMaxAge {
			return errors.Join(err, errors.New("native observation changed before retention"))
		}
		_, _, err = c.authorize(check, req)
		return err
	})
	return err
}

// FenceManagedNative is irreversible. The caller must verify the signed DATA
// replacement and exact retained-volume provenance on every ordered attempt.
// Drain/root/survivor completion precedes fencing so drain recovery still works.
func (c *Controller) FenceManagedNative(ctx context.Context, node, operation, replacement string, verify func(context.Context) error) error {
	if !entityid.Valid(operation) || !lowerHex(replacement, 64) || verify == nil {
		return errors.New("managed fence lacks authenticated replacement")
	}
	if err := verify(ctx); err != nil {
		return err
	}
	native, err := c.currentManagedNative(ctx, node, "terrabase")
	if err != nil {
		return err
	}
	owner, entry, err := ReadManagedRuntimeOwner(ctx, c.mutations, c.cell, native.Desired.ManagedMember.VolumeID)
	if err != nil || !sameJSON(owner.Native, native) {
		return errors.Join(err, errors.New("managed fence lacks retained original native owner"))
	}
	if owner.Phase == "native-fenced" {
		if owner.OperationID != operation || owner.Replacement != replacement {
			return errors.New("another replacement permanently owns this volume fence")
		}
		return ErrNativePublicationUnsettled
	}
	if owner.ObservationOrigin != "retained-before-admission" || owner.Writer == nil || owner.Writer.Process.ServingProof == nil {
		return errors.New("managed fence lacks original native process/root identity")
	}
	drain, found, err := c.ReadManagedDrainResult(ctx, node, "terrabase")
	if err != nil || !found || drain.Command.OperationID != operation || !drain.Command.matchesDesired(native.Desired, native.Registration) ||
		drain.Command.ExpectedProcess.PID != owner.Writer.Process.ProcessPID ||
		drain.Command.ExpectedProcess.StartNonce != owner.Writer.Process.ProcessBootID {
		return errors.Join(err, errors.New("managed fence awaits completed original native drain"))
	}
	challenge, err := randomID()
	if err != nil {
		return err
	}
	// randomID is a canonical ULID; the challenge is its fixed SHA256 prefix.
	sum := sha256.Sum256([]byte(challenge))
	owner.Phase, owner.OperationID, owner.Replacement = "native-fenced", operation, replacement
	owner.Challenge, owner.Drain = fmt.Sprintf("%x", sum[:16]), &drain
	_, _, err = c.commitManagedOwner(ctx, owner, entry, func(check context.Context) error {
		if err := verify(check); err != nil {
			return err
		}
		current, err := c.currentManagedNative(check, node, "terrabase")
		if err != nil || !sameJSON(current, native) {
			return errors.Join(err, errors.New("native lineage changed before permanent fence"))
		}
		currentDrain, found, err := c.ReadManagedDrainResult(check, node, "terrabase")
		if err != nil || !found || !sameJSON(currentDrain, drain) {
			return errors.Join(err, errors.New("native drain changed before permanent fence"))
		}
		return nil
	})
	if err != nil {
		return err
	}
	return ErrNativePublicationUnsettled
}

func (c *Controller) storeManagedNativeStop(ctx context.Context, req request, r Registration, owner ManagedRuntimeOwner, entry authority.LogEntry, stop *ManagedNativeStop) (any, error) {
	witness, err := managedOwnerDigest(owner.Writer)
	if err != nil || owner.Phase != "native-fenced" || owner.Writer == nil || stop == nil ||
		stop.OwnerSequence != entry.Sequence || stop.Challenge != owner.Challenge || stop.WriterSHA256 != witness ||
		stop.SessionID != req.SessionID || !sameJSON(stop.Registration, r) || stop.ObservedAt.Before(req.IssuedAt.Add(-30*time.Second)) ||
		stop.ObservedAt.After(time.Now().Add(maxClockSkew)) || !time.Now().Before(req.Envelope.ExpiresAt) {
		return nil, errors.Join(err, errors.New("native stop observer lacks exact original writer and fresh challenge"))
	}
	if owner.Stop != nil {
		return managedNativeReply{Owner: owner, Sequence: entry.Sequence}, nil
	}
	stop.Envelope = req.Envelope
	owner.Stop = stop
	updated, next, err := c.commitManagedOwner(ctx, owner, entry, func(check context.Context) error {
		if !time.Now().Before(req.Envelope.ExpiresAt) || time.Since(stop.ObservedAt) >= ReportMaxAge {
			return errors.New("native stop observer expired before ordered retention")
		}
		_, _, err := c.authorize(check, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	return managedNativeReply{Owner: updated, Sequence: next.Sequence}, nil
}

type managedNativePermit struct {
	ctx    context.Context
	parent context.Context
	cancel context.CancelFunc
	done   chan struct{}
	volume string
}

type managedPermitContextKey struct{}

// The local gate closes before canceling or joining permits. A paused permit
// therefore cannot start a late Apply after a stop observer acknowledges it.
type managedNativeGate struct {
	mu      sync.Mutex
	phase   string
	permits map[*managedNativePermit]struct{}
}

func (g *managedNativeGate) acquire(ctx context.Context, volume string) (*managedNativePermit, func(), error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.phase == "native-fenced" {
		return nil, nil, ErrManagedNativeFenced
	}
	if g.permits == nil {
		g.permits = make(map[*managedNativePermit]struct{})
	}
	work, cancel := context.WithCancel(ctx)
	p := &managedNativePermit{ctx: work, parent: ctx, cancel: cancel, done: make(chan struct{}), volume: volume}
	g.permits[p] = struct{}{}
	return p, sync.OnceFunc(func() {
		cancel()
		g.mu.Lock()
		delete(g.permits, p)
		close(p.done)
		g.mu.Unlock()
	}), nil
}

func (g *managedNativeGate) closeAdmission() []*managedNativePermit {
	g.mu.Lock()
	g.phase = "native-fenced"
	permits := make([]*managedNativePermit, 0, len(g.permits))
	for p := range g.permits {
		p.cancel()
		permits = append(permits, p)
	}
	g.mu.Unlock()
	return permits
}

func (g *managedNativeGate) fence(ctx context.Context) error {
	for _, p := range g.closeAdmission() {
		select {
		case <-p.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (a *Agent) managedGate(desired Desired) *managedNativeGate {
	volume := desired.ManagedMember.VolumeID
	a.managedNativeMu.Lock()
	defer a.managedNativeMu.Unlock()
	if a.managedNativeGates == nil {
		a.managedNativeGates = make(map[string]*managedNativeGate)
		a.managedNativeDesired = make(map[string]Desired)
	}
	gate := a.managedNativeGates[volume]
	if gate == nil {
		gate = &managedNativeGate{}
		a.managedNativeGates[volume] = gate
	}
	a.managedNativeDesired[desired.Role] = desired
	return gate
}

func (a *Agent) acquireManagedNative(ctx context.Context, desired Desired) (context.Context, func(), error) {
	if desired.ManagedMember == nil {
		return ctx, func() {}, nil
	}
	if current, ok := ctx.Value(managedPermitContextKey{}).(*managedNativePermit); ok {
		if current.volume != desired.ManagedMember.VolumeID || current.ctx.Err() != nil {
			return nil, nil, ErrManagedNativeFenced
		}
		return ctx, func() {}, nil
	}
	var reply managedNativeReply
	if err := a.request(ctx, "managed-native", managedNativeQuery{Role: desired.Role, Action: "admit"}, &reply); err != nil {
		return nil, nil, err
	}
	if reply.Sequence == 0 || !sameJSON(reply.Owner.Native.Desired, desired) {
		return nil, nil, errors.New("native permit differs from retained desired")
	}
	if reply.Owner.Phase == "native-fenced" {
		// Only the independent observer may join permits held by this caller.
		a.managedGate(desired).closeAdmission()
		return nil, nil, ErrManagedNativeFenced
	}
	if reply.Owner.Phase != "native" {
		return nil, nil, errors.New("native permit lacks authenticated ownership")
	}
	permit, release, err := a.managedGate(desired).acquire(ctx, desired.ManagedMember.VolumeID)
	if err != nil {
		return nil, nil, err
	}
	return context.WithValue(permit.ctx, managedPermitContextKey{}, permit), release, nil
}

// checkManagedNative refreshes the ordered authority for an already serialized
// effect. On a remote fence it cancels this permit; the independent owner poll
// joins it before producing any stop observation.
func (a *Agent) checkManagedNative(ctx context.Context, desired Desired) error {
	if desired.ManagedMember == nil {
		return errors.New("native permit requires a managed volume")
	}
	permit, ok := ctx.Value(managedPermitContextKey{}).(*managedNativePermit)
	if !ok || permit.volume != desired.ManagedMember.VolumeID || ctx.Err() != nil {
		return ErrManagedNativeFenced
	}
	var reply managedNativeReply
	if err := a.request(ctx, "managed-native", managedNativeQuery{Role: desired.Role, Action: "state"}, &reply); err != nil {
		return err
	}
	if reply.Sequence == 0 || reply.Owner.Phase != "native" || !sameJSON(reply.Owner.Native.Desired, desired) {
		permit.cancel()
		return ErrManagedNativeFenced
	}
	return ctx.Err()
}

func (a *Agent) checkManagedNativeRole(role string) error {
	a.managedNativeMu.Lock()
	desired, exists := a.managedNativeDesired[role]
	gate := a.managedNativeGates[desiredVolume(desired)]
	a.managedNativeMu.Unlock()
	if !exists || gate == nil {
		return errors.New("native root has no authenticated volume permit")
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.phase == "native-fenced" {
		return ErrManagedNativeFenced
	}
	return nil
}

func desiredVolume(desired Desired) string {
	if desired.ManagedMember == nil {
		return ""
	}
	return desired.ManagedMember.VolumeID
}

// A root listener outlives one reconcile. Its own permit is retained until all
// IPC workers have joined, so fencing cancels it as well as launch operations.
func (a *Agent) acquireManagedNativeRoot(ctx context.Context, desired Desired) (context.Context, func(), error) {
	if permit, ok := ctx.Value(managedPermitContextKey{}).(*managedNativePermit); ok {
		if desired.ManagedMember == nil || permit.volume != desired.ManagedMember.VolumeID || ctx.Err() != nil {
			return nil, nil, ErrManagedNativeFenced
		}
		ctx = permit.parent
	}
	return a.acquireManagedNative(ctx, desired)
}

func (a *Agent) refreshManagedNativeOwners(ctx context.Context) {
	a.managedNativeMu.Lock()
	desired := make([]Desired, 0, len(a.managedNativeDesired))
	for _, current := range a.managedNativeDesired {
		desired = append(desired, current)
	}
	a.managedNativeMu.Unlock()
	for _, current := range desired {
		var reply managedNativeReply
		if err := a.request(ctx, "managed-native", managedNativeQuery{Role: current.Role, Action: "state"}, &reply); err != nil {
			_ = a.revokeManagedNativeRoot(current.Role)
			_ = a.runner.Stop(ctx, current.Role)
			continue
		}
		if reply.Sequence != 0 && reply.Owner.Phase == "native-fenced" && sameJSON(reply.Owner.Native.Desired, current) {
			_ = a.observeManagedNativeFence(ctx, current, reply)
		}
	}
}

func (a *Agent) observeManagedNativeFence(ctx context.Context, desired Desired, reply managedNativeReply) error {
	if reply.Owner.Phase != "native-fenced" || !sameJSON(reply.Owner.Native.Desired, desired) {
		return errors.New("native stop lacks its permanent ordered fence")
	}
	if err := a.managedGate(desired).fence(ctx); err != nil {
		return err
	}
	if err := a.revokeManagedNativeRoot(desired.Role); err != nil {
		return err
	}
	if err := a.runner.Stop(ctx, desired.Role); err != nil {
		return err
	}
	if err := requireManagedRoleQuiescent(a.runner, desired.Role); err != nil {
		return err
	}
	writer := reply.Owner.Writer
	native, ok := a.runner.(*processRunner)
	if !ok || writer == nil || native.cgroups == "" ||
		filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(writer.Process.ProcessCgroup, "/")) != filepath.Join(native.cgroups, desired.Role) {
		return errors.New("native stop cannot recover the original concrete process/cgroup witness")
	}
	// Missing /proc is positive only after the exact cgroup was stopped. A
	// readable reused PID must have a different kernel start; read errors HOLD.
	originalProc := filepath.Join("/proc", strconv.Itoa(writer.Process.ProcessPID))
	if _, err := os.Stat(originalProc); err == nil {
		start := currentStartTime(writer.Process.ProcessPID)
		if start == "" || start == writer.Process.ProcessStart {
			return errors.New("original native process death is not established")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	paths, err := runtimePaths(a.cfg.ManagedRuntimeRoot, *desired.ManagedMember)
	if err != nil {
		return err
	}
	mount, err := verifyManagedMount(paths, *desired.ManagedMember.Runtime, a.cfg.WorkloadIdentity)
	if err != nil {
		return err
	}
	defer mount.close()
	if mount.id != writer.Process.MountID {
		return errors.New("native stop observer has a different retained mounted volume")
	}
	if err := verifyManagedDeviceWitness(mount); err != nil {
		return err
	}
	digest, err := managedOwnerDigest(writer)
	if err != nil {
		return err
	}
	report := a.reportFor(desired, "stopped", nil)
	stop := ManagedNativeStop{OwnerSequence: reply.Sequence, Challenge: reply.Owner.Challenge, WriterSHA256: digest,
		ObservedAt: time.Now().UTC(), SessionID: report.SessionID, Registration: reply.Owner.Native.Registration}
	var accepted managedNativeReply
	if err := a.request(ctx, "managed-native", managedNativeQuery{Role: desired.Role, Action: "stop", Stop: &stop}, &accepted); err != nil {
		return err
	}
	if accepted.Owner.Phase != "native-fenced" || accepted.Owner.Stop == nil || accepted.Owner.Challenge != stop.Challenge {
		return errors.New("native stop acknowledgment lost its permanent publication HOLD")
	}
	return nil
}
