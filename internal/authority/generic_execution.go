package authority

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats.go/jetstream"
)

func genericExecutionKey(h drainwire.ExecutionHold) (string, error) {
	key := h.Cell + "." + h.HostNode + "." + h.ExecutionSessionID
	return key, validateMutationKey(MutationGenericExecution, key)
}

// BeginGenericExecution retains a possible process before the worker may create
// it. The immutable record is never removed when a task or host disappears.
func (r *Runtime) BeginGenericExecution(ctx context.Context, epoch uint64, signed drainwire.SignedHold, verify func(context.Context) error) error {
	h := signed.Hold
	if err := h.Validate(); err != nil {
		return err
	}
	key, err := genericExecutionKey(h)
	if err != nil {
		return err
	}
	if h.Cell != r.config.Scope || h.OriginalEpoch != epoch || len(signed.CertificateChain) == 0 || len(signed.Signature) == 0 || verify == nil {
		return errors.New("generic execution requires its original manager and verified host authority")
	}
	wire, err := json.Marshal(signed, json.Deterministic(true))
	if err != nil {
		return err
	}
	digest, err := drainwire.HoldSHA256(h)
	if err != nil {
		return err
	}
	_, err = r.commitMutationVerified(ctx, epoch, MutationGenericExecution, key, entityid.Derive("generic-execution", digest), 0, wire, func(check context.Context) error {
		existing, err := r.ListGenericExecutions(check)
		if err != nil {
			return err
		}
		for _, prior := range existing {
			if prior.Hold.TaskID == h.TaskID {
				return errors.New("generic task already retains a possible original execution")
			}
		}
		return verify(check)
	})
	return err
}

func (r *Runtime) ListGenericExecutions(ctx context.Context) ([]drainwire.SignedHold, error) {
	if r == nil || r.readStream == nil {
		return nil, ErrFenced
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	return listGenericExecutions(ctx, r.readStream, r.config.Scope)
}

func (r *Reader) ListGenericExecutions(ctx context.Context) ([]drainwire.SignedHold, error) {
	if r == nil || r.stream == nil {
		return nil, ErrNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return listGenericExecutions(ctx, r.stream, r.scope)
}

func listGenericExecutions(ctx context.Context, stream jetstream.Stream, scope string) ([]drainwire.SignedHold, error) {
	prefix := fmt.Sprintf("%s.%s.placement.generic-execution.", controlSubjectRoot, scope)
	info, err := stream.Info(ctx, jetstream.WithSubjectFilter(prefix+">"))
	if err != nil {
		return nil, err
	}
	if err := verifyControlStreamConfig(info.Config, info.Config.Replicas); err != nil {
		return nil, err
	}
	if len(info.State.Subjects) > hostHistoryLimit {
		return nil, errors.New("generic execution history exceeds complete observation bound")
	}
	keys := make([]string, 0, len(info.State.Subjects))
	for subject := range info.State.Subjects {
		key, ok := strings.CutPrefix(subject, prefix)
		if !ok || validateMutationKey(MutationGenericExecution, key) != nil {
			return nil, errors.New("generic execution subject is invalid")
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var holds []drainwire.SignedHold
	for _, key := range keys {
		entry, err := readMutation(ctx, stream, scope, MutationGenericExecution, key)
		if err != nil {
			return nil, err
		}
		var signed drainwire.SignedHold
		if err := json.Unmarshal(entry.Payload, &signed, json.RejectUnknownMembers(true)); err != nil {
			return nil, err
		}
		h := signed.Hold
		wire, err := json.Marshal(signed, json.Deterministic(true))
		actual, keyErr := genericExecutionKey(h)
		digest, digestErr := drainwire.HoldSHA256(h)
		if err != nil || keyErr != nil || digestErr != nil || h.Validate() != nil || actual != key || h.Cell != scope || h.OriginalEpoch != entry.Epoch ||
			entry.Kind != MutationGenericExecution || entry.Sequence == 0 || !bytes.Equal(wire, entry.Payload) ||
			entry.OperationID != entityid.Derive("generic-execution", digest) || len(signed.CertificateChain) == 0 || len(signed.Signature) == 0 {
			return nil, errors.New("generic execution history has conflicting retained identity")
		}
		holds = append(holds, signed)
	}
	return holds, ctx.Err()
}
