package placementrelocation

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/v2"
	"slices"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type Operation struct {
	Plan        Plan
	Prepared    placementtransition.Signed
	Accepted    placementtransition.Signed
	Acceptances map[string][]byte
	Ready       bool
}

type transaction interface {
	Transact(context.Context, bool, func(*map[string]Operation) error) error
}
type Journal struct{ state transaction }

func New(config authorityjournal.Config) (*Journal, error) {
	config.StateKey = "placement.relocation"
	state, err := authorityjournal.New(config, func() map[string]Operation { return map[string]Operation{} }, validateState)
	if err != nil {
		return nil, err
	}
	return &Journal{state: state}, nil
}

func (j *Journal) Begin(ctx context.Context, plan Plan) (Operation, error) {
	if ValidatePlan(plan) != nil {
		return Operation{}, ErrInvalid
	}
	return j.change(ctx, plan.OperationID, true, func(old *Operation) error {
		if old.Plan.OperationID != "" {
			a, _ := Digest(old.Plan)
			b, _ := Digest(plan)
			if a != b {
				return ErrConflict
			}
			return nil
		}
		*old = Operation{Plan: clone(plan), Acceptances: map[string][]byte{}}
		return nil
	})
}
func (j *Journal) Load(ctx context.Context, id string) (Operation, error) {
	return j.change(ctx, id, false, func(*Operation) error { return nil })
}
func (j *Journal) List(ctx context.Context) ([]Operation, error) {
	if j == nil || j.state == nil || ctx == nil {
		return nil, ErrInvalid
	}
	var out []Operation
	err := j.state.Transact(ctx, false, func(state *map[string]Operation) error {
		for _, op := range *state {
			out = append(out, clone(op))
		}
		return nil
	})
	slices.SortFunc(out, func(a, b Operation) int {
		if n := cmp.Compare(a.Plan.Request.ScopeID, b.Plan.Request.ScopeID); n != 0 {
			return n
		}
		return cmp.Compare(a.Plan.Request.Epoch, b.Plan.Request.Epoch)
	})
	return out, err
}
func (j *Journal) RecordPrepared(ctx context.Context, id string, signed placementtransition.Signed) (Operation, error) {
	return j.change(ctx, id, true, func(op *Operation) error {
		if len(op.Prepared.Payload) > 0 && !sameSigned(op.Prepared, signed) {
			return ErrConflict
		}
		op.Prepared = clone(signed)
		return nil
	})
}
func (j *Journal) RecordAccepted(ctx context.Context, id string, signed placementtransition.Signed) (Operation, error) {
	return j.change(ctx, id, true, func(op *Operation) error {
		if len(op.Prepared.Payload) == 0 {
			return ErrConflict
		}
		if len(op.Accepted.Payload) > 0 && !sameSigned(op.Accepted, signed) {
			return ErrConflict
		}
		op.Accepted = clone(signed)
		return nil
	})
}
func (j *Journal) RecordAcceptance(ctx context.Context, id, host string, receipt []byte) (Operation, error) {
	return j.change(ctx, id, true, func(op *Operation) error {
		if len(op.Accepted.Payload) == 0 {
			return ErrConflict
		}
		if old := op.Acceptances[host]; len(old) > 0 && !bytes.Equal(old, receipt) {
			return ErrConflict
		}
		op.Acceptances[host] = bytes.Clone(receipt)
		return nil
	})
}

// MarkReady must be called only after authenticated engine catch-up evidence
// for the exact accepted tuple and all usage/key ownership effects complete.
// Readiness evidence is owned and persisted by the existing readiness producer.
func (j *Journal) MarkReady(ctx context.Context, id string) (Operation, error) {
	return j.change(ctx, id, true, func(op *Operation) error { op.Ready = true; return nil })
}
func (j *Journal) change(ctx context.Context, id string, write bool, change func(*Operation) error) (Operation, error) {
	if j == nil || j.state == nil || ctx == nil || id == "" {
		return Operation{}, ErrInvalid
	}
	var out Operation
	err := j.state.Transact(ctx, write, func(state *map[string]Operation) error {
		op, found := (*state)[id]
		if !found && !write {
			return ErrMissing
		}
		op = clone(op)
		if err := change(&op); err != nil {
			return err
		}
		if op.Plan.OperationID != id {
			return ErrMissing
		}
		if err := ValidateOperation(op); err != nil {
			return err
		}
		if write {
			for key, other := range *state {
				if key != id && other.Plan.Request.ScopeID == op.Plan.Request.ScopeID && (!other.Ready || other.Plan.Request.Epoch == op.Plan.Request.Epoch) {
					return ErrConflict
				}
			}
			(*state)[id] = op
		}
		out = clone(op)
		return nil
	})
	return out, err
}
func sameSigned(a, b placementtransition.Signed) bool {
	return a.KeyID == b.KeyID && bytes.Equal(a.Payload, b.Payload) && bytes.Equal(a.Signature, b.Signature)
}
func validateState(state map[string]Operation) error {
	if state == nil {
		return ErrInvalid
	}
	for id, op := range state {
		if id != op.Plan.OperationID || ValidateOperation(op) != nil {
			return ErrInvalid
		}
	}
	// Reserve the largest supported retained receipts before a plan can start
	// draining members. Exhausting journal capacity after fencing would strand
	// an otherwise valid successor operation.
	encoded, err := json.Marshal(state)
	if err != nil {
		return ErrInvalid
	}
	reserved := len(encoded)
	for _, op := range state {
		for _, signed := range []placementtransition.Signed{op.Prepared, op.Accepted} {
			if len(signed.Payload) == 0 {
				reserved += (64<<10)*4/3 + 1024
			}
		}
		reserved += (len(op.Plan.Targets) - len(op.Acceptances)) * (3 << 10)
	}
	if reserved > authorityjournal.MaximumStateBytes {
		return ErrInvalid
	}
	return nil
}

// ValidateOperation checks all retained producer bindings. Callers separately
// authenticate Prepared and Accepted signatures against the admitted issuer key.
func ValidateOperation(op Operation) error {
	if ValidatePlan(op.Plan) != nil || op.Acceptances == nil {
		return ErrInvalid
	}
	for _, signed := range []placementtransition.Signed{op.Prepared, op.Accepted} {
		if len(signed.Payload) > 64<<10 || len(signed.Signature) > 64 || len(signed.KeyID) > 256 {
			return ErrInvalid
		}
	}
	digest, err := placementtransition.RequestDigest(op.Plan.Request)
	if err != nil {
		return ErrInvalid
	}
	if len(op.Prepared.Payload) > 0 {
		var p placementtransition.Prepared
		if json.Unmarshal(op.Prepared.Payload, &p, json.RejectUnknownMembers(true)) != nil || p.Kind != "prepared_epoch" || p.RequestDigest != digest || p.PreviousProofDigest != BytesDigest(op.Plan.PriorProof.Payload) {
			return ErrInvalid
		}
		d, err := placementtransition.RequestDigest(p.Request)
		if err != nil || d != digest {
			return ErrInvalid
		}
	} else if len(op.Accepted.Payload) > 0 || len(op.Acceptances) > 0 || op.Ready {
		return ErrInvalid
	}
	if len(op.Accepted.Payload) > 0 {
		var p placementtransition.Proof
		if json.Unmarshal(op.Accepted.Payload, &p, json.RejectUnknownMembers(true)) != nil || p.Kind != "accepted_epoch" || p.RequestDigest != digest || p.PreviousProofDigest != BytesDigest(op.Plan.PriorProof.Payload) {
			return ErrInvalid
		}
		d, err := placementtransition.RequestDigest(p.Request)
		if err != nil || d != digest {
			return ErrInvalid
		}
	} else if len(op.Acceptances) > 0 || op.Ready {
		return ErrInvalid
	}
	for host, encoded := range op.Acceptances {
		if len(encoded) == 0 || len(encoded) > 2<<10 {
			return ErrInvalid
		}
		i := slices.IndexFunc(op.Plan.Targets, func(t Target) bool { return t.ServerIdentity == host })
		if i < 0 {
			return ErrInvalid
		}
		stage := new(pb.PlacementStageRequest)
		receipt := new(pb.PlacementAcceptanceResponse)
		if proto.Unmarshal(op.Plan.Targets[i].Proposal, stage) != nil || proto.Unmarshal(encoded, receipt) != nil || receipt.ProposalRevision != stage.ExpectedRevision+1 || receipt.Epoch != op.Plan.Request.Epoch || receipt.Generation != op.Plan.Request.Generation || receipt.ProofDigest != BytesDigest(op.Accepted.Payload) || receipt.Status != pb.PlacementAcceptanceStatus_PLACEMENT_ACCEPTANCE_STATUS_ADMITTED_CATCHING_UP {
			return ErrInvalid
		}
	}
	if op.Ready && len(op.Acceptances) != len(op.Plan.Targets) {
		return ErrInvalid
	}
	return nil
}
