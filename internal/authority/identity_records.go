package authority

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const rekeyPinsHeader = "TerraScale-Identity-Rekey-Pins"

// VerifyIdentityResetPredecessors checks inventory completeness and exact
// reviewed heads before shared effects. Replacement CAS remains mandatory.
func VerifyIdentityResetPredecessors(ctx context.Context, js jetstream.JetStream, reset IdentityReset, replicas int) error {
	if err := reset.Validate(); err != nil {
		return err
	}
	if err := verifyIdentityResetHostInventory(ctx, js, reset, replicas); err != nil {
		return err
	}
	reader, err := identityRecordReader(js)
	if err != nil {
		return err
	}
	if reset.GlobalLease != nil {
		stream, err := js.Stream(ctx, ControlStreamName)
		if err != nil {
			return err
		}
		if err := verifyIdentityResetGlobalPredecessor(ctx, stream, reset); err != nil {
			return err
		}
	}
	for _, record := range reset.Records {
		stream := ControlStreamName
		if record.Action != IdentityResetAppendHostHead {
			if err := checkIdentityBucket(ctx, js, record.Bucket, replicas); err != nil {
				return err
			}
			stream = "KV_" + record.Bucket
		}
		bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
		previous, err := reader.GetLastMsg(stream, identityRecordSubject(record), nats.Context(bounded))
		cancel()
		if errors.Is(err, nats.ErrMsgNotFound) && record.PreviousRevision == 0 {
			continue
		}
		if err != nil {
			return err
		}
		if !identityRecordPredecessor(record, previous) {
			return fmt.Errorf("%w: identity predecessor %s/%s changed", ErrConflict, record.Bucket, record.Key)
		}
	}
	return nil
}

func verifyIdentityResetHostInventory(ctx context.Context, js jetstream.JetStream, reset IdentityReset, replicas int) error {
	if js == nil {
		return errors.New("identity inventory requires JetStream")
	}
	reviewed := make(map[string]bool, len(reset.Records))
	checked := make(map[string]bool)
	for _, record := range reset.Records {
		if record.Bucket != ControlStreamName && !checked[record.Bucket] {
			if err := checkIdentityBucket(ctx, js, record.Bucket, replicas); err != nil {
				return err
			}
			checked[record.Bucket] = true
		}
		reviewed[identityRecordSubject(record)] = true
	}
	count := 0
	for _, inventory := range [][2]string{
		{ControlStreamName, controlSubjectRoot + "." + reset.Scope + ".host.>"},
		{"KV_TS_HOST_STATE", "$KV.TS_HOST_STATE.>"},
		{"KV_TS_HOST_ENROLLMENT", "$KV.TS_HOST_ENROLLMENT.>"},
	} {
		bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
		stream, err := js.Stream(bounded, inventory[0])
		if errors.Is(err, jetstream.ErrStreamNotFound) && inventory[0] != ControlStreamName {
			cancel()
			continue
		}
		if err != nil {
			cancel()
			return err
		}
		info, err := stream.Info(bounded, jetstream.WithSubjectFilter(inventory[1]))
		cancel()
		if err != nil {
			return err
		}
		if inventory[0] == ControlStreamName {
			if err := verifyControlStreamConfig(info.Config, replicas); err != nil {
				return err
			}
		} else if err := checkIdentityBucket(ctx, js, strings.TrimPrefix(inventory[0], "KV_"), replicas); err != nil {
			return err
		}
		if len(info.State.Subjects) > maxIdentityResetRecords {
			return ErrListTooLarge
		}
		for subject := range info.State.Subjects {
			if inventory[0] == ControlStreamName {
				kind, _, _ := strings.Cut(strings.TrimPrefix(subject, controlSubjectRoot+"."+reset.Scope+".host."), ".")
				if HostMutationKind(kind) != MutationRegistration && HostMutationKind(kind) != MutationDesired && HostMutationKind(kind) != MutationRetirement {
					continue
				}
			}
			if key, ok := strings.CutPrefix(subject, "$KV.TS_HOST_STATE."); ok {
				parts := strings.Split(key, ".")
				// Only named namespaces establish foreign-cell ownership. Opaque
				// keys in these cell-local buckets must have explicit root pins.
				if len(parts) >= 2 && slices.Contains([]string{"session", "retired", "retirement-quarantine", "cycle", "report", "desired", "retirement-cutover", "terrabase-format"}, parts[0]) && parts[1] != reset.Scope && natsToken.MatchString(parts[1]) {
					continue
				}
			}
			count++
			if count > maxIdentityResetRecords {
				return ErrListTooLarge
			}
			if !reviewed[subject] {
				return fmt.Errorf("%w: unreviewed host inventory %s", ErrConflict, subject)
			}
		}
	}
	return nil
}

// ReplaceIdentityRecords executes only signed typed destinations during the
// held lease. Callers must first match the independently verified host plan
// (including real writer shutdown) to this reset; authority cannot import it.
// Exact committed effects resume under the original valid broker timestamp.
func ReplaceIdentityRecords(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope, roots trust.Keyring,
	target IdentityResetTarget, values [][]byte, _ time.Time,
) ([]uint64, error) {
	reset, err := verifyCommittedIdentityReset(ctx, js, envelope, roots, target)
	if err != nil {
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			err = errors.Join(ErrFenced, err)
		}
		return nil, err
	}
	if js == nil || js.Conn() == nil || len(values) != len(reset.Records) {
		return nil, errors.New("identity replacement requires JetStream and every pinned value")
	}
	values = slices.Clone(values)
	for index, record := range reset.Records {
		values[index] = bytes.Clone(values[index])
		if err := validateIdentityRecordValue(reset, record, values[index]); err != nil {
			return nil, err
		}
	}
	if err := holdIdentityResetGlobalLease(ctx, js, reset, resetDigest(envelope.Payload), target.Replicas); err != nil {
		return nil, err
	}
	reader, err := identityRecordReader(js)
	if err != nil {
		return nil, err
	}
	pinID := resetDigest(envelope.Payload)
	revisions := make([]uint64, len(reset.Records))
	for index, record := range reset.Records {
		get := heldIdentityRecordReader(js, reader, reset, record, pinID, target.Replicas)
		previous, err := get(ctx)
		revision := uint64(0)
		if errors.Is(err, nats.ErrMsgNotFound) && record.PreviousRevision == 0 {
			// Even an explicitly absent delete must commit its own positive tombstone.
		} else if err != nil {
			return nil, err
		} else if identityRecordComplete(record, previous, pinID) {
			revisions[index] = previous.Sequence
			continue
		} else if record.Action == IdentityResetReplaceKV && identityRecordPurge(record, previous, pinID) {
			revision = previous.Sequence
		} else if identityRecordPredecessor(record, previous) {
			revision = previous.Sequence
		} else {
			return nil, fmt.Errorf("%w: identity predecessor %s/%s changed", ErrConflict, record.Bucket, record.Key)
		}
		if record.Action != IdentityResetAppendHostHead && (record.Action == IdentityResetDeleteKV || revision == record.PreviousRevision && revision != 0) {
			purge := nats.NewMsg(identityRecordSubject(record))
			purge.Header.Set("KV-Operation", "PURGE")
			purge.Header.Set(nats.MsgRollup, nats.MsgRollupSubject)
			purge.Header.Set(rekeyPinsHeader, pinID)
			purge.Header.Set(nats.MsgIdHdr, reset.OperationID+":"+record.Bucket+":"+record.Key+":purge")
			if revision, err = publishHeldIdentityRecord(ctx, js, reset, record, pinID, target.Replicas, purge, revision, get); err != nil {
				return nil, err
			}
		}
		if record.Action == IdentityResetDeleteKV {
			revisions[index] = revision
			continue
		}
		create := nats.NewMsg(identityRecordSubject(record))
		create.Data = values[index]
		create.Header.Set(rekeyPinsHeader, pinID)
		create.Header.Set(nats.MsgIdHdr, reset.OperationID+":"+record.Bucket+":"+record.Key+":create")
		if record.Action == IdentityResetAppendHostHead {
			head, _ := decodeControlRecord(create.Data) // Every value was validated before effects.
			create.Header.Set("TerraScale-Control-Kind", string(head.Kind))
			create.Header.Set("TerraScale-Operation-ID", head.OperationID)
		}
		if revisions[index], err = publishHeldIdentityRecord(ctx, js, reset, record, pinID, target.Replicas, create, revision, get); err != nil {
			return nil, err
		}
	}
	if err := verifyResetBarrier(ctx, js, reset, pinID, target.Replicas); err != nil {
		return nil, err
	}
	return revisions, nil
}

func validateIdentityRecordValue(reset IdentityReset, record IdentityResetRecord, value []byte) error {
	if record.Action == IdentityResetDeleteKV {
		if len(value) == 0 {
			return nil
		}
	} else if len(value) != 0 && len(value) <= trust.MaxRootChainBytes && resetDigest(value) == record.SHA256 {
		if record.Action != IdentityResetAppendHostHead {
			return nil
		}
		head, err := decodeControlRecord(value)
		if err == nil && head.Scope == reset.Scope && head.Epoch == reset.Epoch &&
			mutationSubject(head.Scope, head.Kind, head.SubjectKey) == record.Key &&
			validateHostMutation(head.Kind, head.SubjectKey, head.OperationID, head.Payload) == nil &&
			head.OperationID == entityid.Derive("host-mutation", resetDigest(head.Payload)) {
			canonical, err := jsonMarshal(head)
			if err == nil && bytes.Equal(value, canonical) {
				return nil
			}
		}
	}
	return fmt.Errorf("identity replacement %s/%s differs from its typed root pin", record.Bucket, record.Key)
}

func identityRecordSubject(record IdentityResetRecord) string {
	if record.Action == IdentityResetAppendHostHead {
		return record.Key
	}
	return "$KV." + record.Bucket + "." + record.Key
}

func identityRecordPredecessor(record IdentityResetRecord, msg *nats.RawStreamMsg) bool {
	return msg != nil && msg.Subject == identityRecordSubject(record) && msg.Sequence == record.PreviousRevision &&
		msg.Header.Get("KV-Operation") == record.PreviousOperation && resetDigest(msg.Data) == record.PreviousSHA256
}

func identityRecordPurge(record IdentityResetRecord, msg *nats.RawStreamMsg, pinID string) bool {
	return msg != nil && msg.Subject == identityRecordSubject(record) && msg.Sequence > record.PreviousRevision &&
		msg.Header.Get(rekeyPinsHeader) == pinID && msg.Header.Get("KV-Operation") == "PURGE" && len(msg.Data) == 0
}

func identityRecordComplete(record IdentityResetRecord, msg *nats.RawStreamMsg, pinID string) bool {
	if record.Action == IdentityResetDeleteKV {
		return identityRecordPurge(record, msg, pinID)
	}
	return msg != nil && msg.Subject == identityRecordSubject(record) && msg.Sequence > record.PreviousRevision &&
		msg.Header.Get(rekeyPinsHeader) == pinID && msg.Header.Get("KV-Operation") == "" && resetDigest(msg.Data) == record.SHA256
}

func heldIdentityRecordReader(js jetstream.JetStream, reader nats.JetStreamContext, reset IdentityReset,
	record IdentityResetRecord, pinID string, replicas int,
) func(context.Context) (*nats.RawStreamMsg, error) {
	return func(ctx context.Context) (*nats.RawStreamMsg, error) {
		if err := verifyResetBarrier(ctx, js, reset, pinID, replicas); err != nil {
			return nil, err
		}
		stream := ControlStreamName
		if record.Action != IdentityResetAppendHostHead {
			if err := checkIdentityBucket(ctx, js, record.Bucket, replicas); err != nil {
				return nil, err
			}
			stream = "KV_" + record.Bucket
		}
		bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
		defer cancel()
		msg, err := reader.GetLastMsg(stream, identityRecordSubject(record), nats.Context(bounded))
		if err == nil && (msg == nil || msg.Subject != identityRecordSubject(record) || msg.Sequence == 0) {
			return nil, errors.New("invalid identity record leader read")
		}
		return msg, err
	}
}

func publishHeldIdentityRecord(ctx context.Context, js jetstream.JetStream, reset IdentityReset,
	record IdentityResetRecord, pinID string, replicas int, msg *nats.Msg, previous uint64,
	get func(context.Context) (*nats.RawStreamMsg, error),
) (uint64, error) {
	var options []jetstream.PublishOpt
	if record.Action == IdentityResetAppendHostHead {
		bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
		defer cancel()
		stream, err := js.Stream(bounded, ControlStreamName)
		if err != nil {
			return 0, err
		}
		info, err := stream.Info(bounded)
		if err != nil {
			return 0, err
		}
		if err := verifyControlStreamConfig(info.Config, replicas); err != nil {
			return 0, err
		}
		// Global CAS atomically orders a host append against completion of the hold.
		options = append(options, jetstream.WithExpectLastSequence(info.State.LastSeq))
	} else if err := checkIdentityBucket(ctx, js, record.Bucket, replicas); err != nil {
		return 0, err
	}
	if err := verifyResetBarrier(ctx, js, reset, pinID, replicas); err != nil {
		return 0, err
	}
	return publishIdentityRecord(ctx, js, msg, previous, get, options...)
}

// CompleteIdentityReset releases the deployment after every typed singleton
// and host record has this operation's exact root pins.
// Its original committed authorization remains valid recovery evidence.
func CompleteIdentityReset(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope, roots trust.Keyring,
	target IdentityResetTarget, _ time.Time,
) (uint64, error) {
	reset, err := verifyCommittedIdentityReset(ctx, js, envelope, roots, target)
	if err != nil {
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			err = errors.Join(ErrFenced, err)
		}
		return 0, err
	}
	if js == nil || js.Conn() == nil {
		return 0, errors.New("identity reset completion requires JetStream")
	}
	pinID := resetDigest(envelope.Payload)
	if sequence, err := identityResetCompletion(ctx, js, reset, pinID, target.Replicas); err != nil || sequence != 0 {
		return sequence, err
	}
	if err := verifyResetBarrier(ctx, js, reset, pinID, target.Replicas); err != nil {
		return 0, err
	}
	reader, err := identityRecordReader(js)
	if err != nil {
		return 0, err
	}
	// Capture the log floor before checking host heads so completion CAS also
	// fences changes between those checks and the release.
	snapshotCtx, snapshotCancel := context.WithTimeout(ctx, authorityAPITimeout)
	stream, err := js.Stream(snapshotCtx, ControlStreamName)
	if err != nil {
		snapshotCancel()
		return 0, err
	}
	info, err := stream.Info(snapshotCtx)
	snapshotCancel()
	if err != nil {
		return 0, err
	}
	if err := verifyControlStreamConfig(info.Config, target.Replicas); err != nil {
		return 0, err
	}
	if err := verifyIdentityResetHostInventory(ctx, js, reset, target.Replicas); err != nil {
		return 0, err
	}
	for _, record := range reset.Records {
		msg, err := heldIdentityRecordReader(js, reader, reset, record, pinID, target.Replicas)(ctx)
		if err != nil {
			return 0, err
		}
		if !identityRecordComplete(record, msg, pinID) {
			return 0, fmt.Errorf("%w: identity replacement %s/%s is incomplete", ErrConflict, record.Bucket, record.Key)
		}
		if record.Action == IdentityResetAppendHostHead {
			if err := validateIdentityRecordValue(reset, record, msg.Data); err != nil {
				return 0, err
			}
		}
	}

	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	subject := fmt.Sprintf("%s.%s.lease", controlSubjectRoot, reset.Scope)
	previous, err := stream.GetLastMsgForSubject(bounded, subject)
	if err != nil {
		return 0, err
	}
	if err := verifyResetBarrier(bounded, js, reset, pinID, target.Replicas); err != nil {
		return 0, err
	}
	if reset.GlobalLease != nil {
		return completeIdentityResetBatch(ctx, js, stream, reset, pinID, info.State.LastSeq, target.Replicas)
	}
	complete, err := identityResetLease(reset, "")
	if err != nil {
		return 0, err
	}
	ack, publishErr := js.PublishMsg(bounded, controlMessage(subject, "lease", reset.OperationID+":complete", complete),
		jetstream.WithExpectLastSequence(info.State.LastSeq),
		jetstream.WithExpectLastSequenceForSubject(previous.Sequence, subject))
	probe, probeCancel := context.WithTimeout(context.WithoutCancel(ctx), authorityAPITimeout)
	defer probeCancel()
	// Immutable log readback still confirms completion if a controller acquired
	// normal authority before the publish reply arrived.
	stored, readErr := stream.GetMsg(probe, info.State.LastSeq+1)
	if readErr == nil && stored.Subject == subject && bytes.Equal(stored.Data, complete) &&
		(publishErr != nil || ack != nil && stored.Sequence == ack.Sequence) {
		return stored.Sequence, nil
	}
	if isSequenceConflict(publishErr) {
		return 0, ErrConflict
	}
	if readErr == nil {
		readErr = ErrConflict
	}
	return 0, fmt.Errorf("%w: identity reset completion: %w", ErrOutcomeUnknown, errors.Join(publishErr, readErr))
}

// IdentityResetCompletion recovers the committed outcome from the immutable
// lease history. Zero means the root-pinned transaction has not completed.
func IdentityResetCompletion(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope, roots trust.Keyring,
	target IdentityResetTarget, now time.Time,
) (uint64, error) {
	reset, err := VerifyIdentityReset(envelope, roots, target, now)
	if err != nil {
		return 0, err
	}
	if js == nil {
		return 0, errors.New("identity reset outcome requires JetStream")
	}
	committed, err := IdentityResetCommitted(ctx, js, envelope, roots, target)
	if err != nil || !committed {
		return 0, err
	}
	return identityResetCompletion(ctx, js, reset, resetDigest(envelope.Payload), target.Replicas)
}

func identityResetCompletion(ctx context.Context, js jetstream.JetStream, reset IdentityReset, pinID string, replicas int) (uint64, error) {
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	stream, err := js.Stream(bounded, ControlStreamName)
	if err != nil {
		return 0, err
	}
	info, err := stream.Info(bounded)
	if err != nil {
		return 0, err
	}
	if err := verifyControlStreamConfig(info.Config, replicas); err != nil {
		return 0, err
	}
	barrier, err := stream.GetMsg(bounded, reset.LastSequence+1)
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	subject := fmt.Sprintf("%s.%s.lease", controlSubjectRoot, reset.Scope)
	wantBarrier, err := identityResetLease(reset, pinID)
	if err != nil {
		return 0, err
	}
	if barrier.Subject != subject || !bytes.Equal(barrier.Data, wantBarrier) {
		return 0, ErrConflict
	}
	// No ordinary lease can follow the hold until completion; other scopes
	// may append between these two records without changing this outcome.
	completed, err := stream.GetMsg(bounded, barrier.Sequence+1, jetstream.WithGetMsgSubject(subject))
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	wantCompleted, err := identityResetLease(reset, "")
	if err != nil {
		return 0, err
	}
	if completed.Subject != subject || !bytes.Equal(completed.Data, wantCompleted) {
		return 0, ErrConflict
	}
	if reset.GlobalLease != nil {
		_, globalComplete, err := globalResetOutcome(bounded, stream, reset, pinID)
		if err != nil || globalComplete == 0 {
			return 0, errors.Join(ErrConflict, err)
		}
	}
	return completed.Sequence, nil
}

func checkIdentityBucket(ctx context.Context, js jetstream.JetStream, bucket string, replicas int) error {
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	stream, err := js.Stream(bounded, "KV_"+bucket)
	if err != nil {
		return err
	}
	info, err := stream.Info(bounded)
	if err != nil {
		return err
	}
	if info.Config.Replicas != replicas || info.Config.Storage != jetstream.FileStorage ||
		!info.Config.AllowRollup || info.Config.MaxAge != 0 || info.Config.Retention != jetstream.LimitsPolicy ||
		(info.Config.MaxMsgs > 0 || info.Config.MaxBytes > 0) && info.Config.Discard != jetstream.DiscardNew ||
		len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != "$KV."+bucket+".>" ||
		info.Config.Mirror != nil || len(info.Config.Sources) != 0 || info.Config.SubjectTransform != nil || info.Config.RePublish != nil ||
		info.Config.Sealed || info.Config.NoAck || info.Config.AllowMsgTTL || info.Config.SubjectDeleteMarkerTTL != 0 {
		return errors.New("identity replacement bucket must preserve the durable replica quorum and permit exact-key purges")
	}
	return nil
}

func identityRecordReader(js jetstream.JetStream) (nats.JetStreamContext, error) {
	options := js.Options()
	var readOptions []nats.JSOpt
	if options.Domain != "" {
		readOptions = append(readOptions, nats.Domain(options.Domain))
	} else if options.APIPrefix != "" {
		readOptions = append(readOptions, nats.APIPrefix(options.APIPrefix))
	}
	return js.Conn().JetStream(readOptions...)
}

func verifyResetBarrier(ctx context.Context, js jetstream.JetStream, reset IdentityReset, pinID string, replicas int) error {
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	stream, err := js.Stream(bounded, ControlStreamName)
	if err != nil {
		return err
	}
	info, err := stream.Info(bounded)
	if err != nil {
		return err
	}
	if err := verifyControlStreamConfig(info.Config, replicas); err != nil {
		return err
	}
	msg, err := stream.GetLastMsgForSubject(bounded, fmt.Sprintf("%s.%s.lease", controlSubjectRoot, reset.Scope))
	if err != nil {
		return err
	}
	want, err := identityResetLease(reset, pinID)
	if err != nil || msg.Sequence != reset.LastSequence+1 || !bytes.Equal(msg.Data, want) {
		return ErrFenced
	}

	return nil
}

func publishIdentityRecord(ctx context.Context, js jetstream.JetStream, msg *nats.Msg, previous uint64,
	get func(context.Context) (*nats.RawStreamMsg, error), options ...jetstream.PublishOpt,
) (uint64, error) {
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	ack, publishErr := js.PublishMsg(bounded, msg, append(options, jetstream.WithExpectLastSequencePerSubject(previous))...)
	cancel()
	if isSequenceConflict(publishErr) {
		return 0, ErrConflict
	}
	stored, err := get(context.WithoutCancel(ctx))
	if err != nil {
		return 0, fmt.Errorf("%w: identity record confirmation: %w", ErrOutcomeUnknown, errors.Join(publishErr, err))
	}
	if bytes.Equal(stored.Data, msg.Data) && stored.Header.Get(rekeyPinsHeader) == msg.Header.Get(rekeyPinsHeader) &&
		stored.Header.Get("KV-Operation") == msg.Header.Get("KV-Operation") &&
		(publishErr != nil || ack != nil && stored.Sequence == ack.Sequence) {
		return stored.Sequence, nil
	}
	if publishErr != nil && stored.Sequence == previous {
		return 0, publishErr
	}
	return 0, ErrConflict
}

// IdentityResetCommitted proves that the exact transaction began while its
// root grant was valid. It never publishes an expired or missing barrier.
func IdentityResetCommitted(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope,
	roots trust.Keyring, target IdentityResetTarget,
) (bool, error) {
	_, err := verifyCommittedIdentityReset(ctx, js, envelope, roots, target)
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return false, nil
	}
	return err == nil, err
}

func verifyCommittedIdentityReset(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope,
	roots trust.Keyring, target IdentityResetTarget,
) (IdentityReset, error) {
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	reset, stream, messages, err := observeIdentityResetCommitment(bounded, js, envelope, roots, target)
	if err != nil {
		return IdentityReset{}, err
	}
	var lifetimeErr error
	for _, msg := range messages {
		if _, err := VerifyIdentityReset(envelope, roots, target, msg.Time); err != nil {
			lifetimeErr = errors.Join(lifetimeErr, err)
		}
	}
	if lifetimeErr == nil {
		return reset, nil
	}
	// A fresh signed authorization is required for an out-of-window commit.
	msg, err := stream.GetLastMsgForSubject(bounded, resetRecoverySubject(reset))
	if err != nil {
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			return IdentityReset{}, lifetimeErr
		}
		return IdentityReset{}, errors.Join(lifetimeErr, err)
	}
	recovery, err := trust.DecodeEnvelope(msg.Data)
	if err != nil {
		return IdentityReset{}, err
	}
	pins, err := resetRecoveryPins(envelope, messages)
	if err != nil {
		return IdentityReset{}, err
	}
	if err := verifyResetRecovery(recovery, roots, reset, pins, msg.Time); err != nil {
		return IdentityReset{}, err
	}
	return reset, nil
}
