package mesh

import (
	"bytes"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// Deployment is the signed workflow identity and approved immutable image.
type Deployment = swarmruntime.Deployment

// desiredState retains both authorities: a losing operator must survive a
// signed winner whose authority a later run can permanently invalidate.
type desiredState struct {
	Operator *Entry      `json:"operator,omitempty"`
	Signed   *Entry      `json:"signed,omitempty"`
	Floor    *Deployment `json:"floor,omitempty"`
}

func stateFor(entry Entry) desiredState {
	if entry.Deployment != nil {
		return desiredState{Signed: &entry, Floor: entry.Deployment}
	}
	return desiredState{Operator: &entry}
}

func (state desiredState) entry() Entry {
	if state.Operator != nil && (state.Signed == nil || !state.Signed.supersedes(*state.Operator)) {
		return *state.Operator
	}
	if state.Signed != nil {
		return *state.Signed
	}
	return Entry{}
}

// mergeState is component-wise max: causal order for operators, run order then
// causal order for signed entries. Selection never discards the operator component.
func mergeState(current, next desiredState) (desiredState, error) {
	floor := current.Floor
	if err := floor.Accepts(next.Floor); err == nil {
		if next.Floor != nil {
			floor = next.Floor
		}
	} else if err := next.Floor.Accepts(floor); err != nil {
		return current, err // Same-run equivocation or a different repository.
	}
	operator, err := newestEntry(current.Operator, next.Operator)
	if err != nil {
		return current, err
	}
	var signed *Entry
	for _, candidate := range []*Entry{current.Signed, next.Signed} {
		if candidate != nil && floor != nil && *candidate.Deployment == *floor {
			signed, err = newestEntry(signed, candidate)
			if err != nil {
				return current, err
			}
		}
	}
	return desiredState{Operator: operator, Signed: signed, Floor: floor}, nil
}

func newestEntry(current, next *Entry) (*Entry, error) {
	if current == nil {
		return next, nil
	}
	if next == nil || current.supersedes(*next) {
		return current, nil
	}
	if next.supersedes(*current) {
		return next, nil
	}
	// Equal timestamps still need a total order across independently written specs.
	a, err := protocol.EncodeJSON(current)
	if err != nil {
		return nil, err
	}
	b, err := protocol.EncodeJSON(next)
	if err != nil {
		return nil, err
	}
	if bytes.Compare(b, a) > 0 {
		return next, nil
	}
	return current, nil
}

func validState(name string, state desiredState) error {
	if state.Operator == nil && state.Signed == nil {
		return errors.New("empty desired state")
	}
	if err := state.Floor.Validate(); err != nil {
		return err
	}
	if state.Floor != nil && repository(state.Floor.Image) != "ghcr.io/terrascale/"+name {
		return errors.New("deployment floor image does not belong to the service")
	}
	for _, entry := range []*Entry{state.Operator, state.Signed} {
		if entry != nil {
			if err := validEntry(name, *entry); err != nil {
				return err
			}
		}
	}
	if state.Operator != nil && state.Operator.Deployment != nil {
		return errors.New("operator candidate carries signed authority")
	}
	if state.Signed != nil && (state.Signed.Deployment == nil || state.Floor == nil || *state.Signed.Deployment != *state.Floor) {
		return errors.New("signed candidate does not match the deployment floor")
	}
	return nil
}
