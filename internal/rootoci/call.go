package rootoci

import (
	"context"
	"errors"
	"os"
	"reflect"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
)

type Operation string

const (
	OperationInventory                   Operation = "inventory"
	OperationObserveLocalInstance        Operation = "observe_local_instance"
	OperationObserveFleet                Operation = "observe_fleet"
	OperationCosts                       Operation = "costs"
	OperationObserveImage                Operation = "observe_image"
	OperationReleaseChannel              Operation = "release_channel"
	OperationReconcileFoundation         Operation = "reconcile_foundation"
	OperationEnsureSource                Operation = "ensure_source"
	OperationDeliverControllerGeneration Operation = "deliver_controller_generation"
)

// ReadOnly is the complete startup-admission whitelist.
func (operation Operation) ReadOnly() bool {
	switch operation {
	case OperationInventory, OperationObserveLocalInstance, OperationObserveFleet,
		OperationCosts, OperationObserveImage, OperationReleaseChannel:
		return true
	default:
		return false
	}
}

// Expectations narrow root-derived signed authority; they never grant it.
type Expectations struct {
	Cell        string `json:"cell,omitempty"`
	GrantSHA256 string `json:"grant_sha256,omitempty"`
	OperationID string `json:"operation_id,omitempty"`
	Epoch       uint64 `json:"epoch,omitzero"`
}

type Lease struct {
	Context  context.Context
	Deadline time.Time
	Binding  string
}

// Authorize independently checks the exact process, accepted source and role,
// and live session for this operation. Binding must change with any of them.
type Authorize func(context.Context, nativerootoci.Peer, Operation) (Lease, error)

var ErrUnauthorized = errors.New("root OCI authorization rejected")

type Call struct {
	state *callState
}

type callState struct {
	ctx       context.Context
	expected  Expectations
	operation Operation
	witness   *ProcessWitness
	authorize Authorize
	lease     Lease
	root      bool
	deadline  time.Time
}

func (call Call) Expected() Expectations {
	if call.state == nil {
		return Expectations{}
	}
	return call.state.expected
}

func (call Call) Operation() Operation {
	if call.state == nil {
		return ""
	}
	return call.state.operation
}

// Deadline is the original call cap; a renewed session never extends it.
func (call Call) Deadline() time.Time {
	if call.state == nil {
		return time.Time{}
	}
	return call.state.deadline
}

// Guard must run immediately before each provider read, write or installation.
// It never adopts a successor session, even when that session authorizes the peer.
func (call Call) Guard(ctx context.Context) error {
	state := call.state
	if ctx == nil || state == nil || state.ctx == nil || ctx.Err() != nil || state.ctx.Err() != nil ||
		state.deadline.IsZero() || !time.Now().Before(state.deadline) {
		return ErrUnauthorized
	}
	if state.root {
		if os.Geteuid() != 0 {
			return ErrUnauthorized
		}
		return nil
	}
	if state.witness == nil || state.authorize == nil || !validLease(state.lease) || state.witness.Verify() != nil {
		return ErrUnauthorized
	}
	current, err := state.authorize(ctx, state.witness.Peer(), state.operation)
	if err != nil || !validLease(current) || current.Binding != state.lease.Binding ||
		!sameContext(current.Context, state.lease.Context) || current.Deadline.Before(state.lease.Deadline) ||
		state.witness.Verify() != nil || ctx.Err() != nil || state.ctx.Err() != nil {
		return ErrUnauthorized
	}
	return nil
}

func validLease(lease Lease) bool {
	return lease.Context != nil && lease.Context.Err() == nil && lease.Binding != "" && len(lease.Binding) <= 4096 &&
		!lease.Deadline.IsZero() && time.Now().Before(lease.Deadline)
}

func sameContext(left, right context.Context) bool {
	return left != nil && right != nil && reflect.TypeOf(left).Comparable() &&
		reflect.TypeOf(left) == reflect.TypeOf(right) && left == right
}

// RootCall is for the existing root bootstrap process, whose backends still
// independently derive signed domain authority before performing effects.
func RootCall(ctx context.Context) (Call, error) {
	if ctx == nil {
		return Call{}, ErrUnauthorized
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	call := Call{state: &callState{ctx: ctx, root: true, deadline: deadline}}
	if err := call.Guard(ctx); err != nil {
		return Call{}, err
	}
	return call, nil
}
