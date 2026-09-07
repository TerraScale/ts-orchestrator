// Package enrollment owns the durable, lease-bound identity reservation used
// by compute and placement declarations. It contains references and public
// metadata only; private identity and NKey bytes never enter State.
package enrollment

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
)

var ErrInvalid = errors.New("enrollment: invalid reservation")

type Record struct {
	MemberID          string    `json:"member_id"`
	Region            string    `json:"region"`
	Slot              int       `json:"slot"`
	Generation        uint64    `json:"generation"`
	OperationID       string    `json:"operation_id"`
	IdentityReference string    `json:"identity_reference,omitempty"`
	IssuedAt          time.Time `json:"issued_at,omitzero"`
	ExpiresAt         time.Time `json:"expires_at,omitzero"`
	ManifestReference string    `json:"manifest_reference,omitempty"`
	Grant             []byte    `json:"grant,omitempty"`
}

type State struct {
	Records map[string]Record `json:"records"`
}

func validate(s State) error {
	if len(s.Records) > 1024 {
		return ErrInvalid
	}
	for key, r := range s.Records {
		if key != keyFor(r.Region, r.Slot) || r.MemberID == "" || r.Region == "" || r.Slot < 1 || r.Generation == 0 || r.OperationID == "" || r.IssuedAt.IsZero() || !r.ExpiresAt.After(r.IssuedAt) || len(r.Grant) > 1<<20 {
			return ErrInvalid
		}
	}
	return nil
}

func keyFor(region string, slot int) string { return region + ":" + fmt.Sprint(slot) }

type Journal struct {
	journal *authorityjournal.Journal[State]
}

func NewJournal(config authorityjournal.Config) (*Journal, error) {
	j, err := authorityjournal.New(config, func() State { return State{Records: map[string]Record{}} }, validate)
	if err != nil {
		return nil, err
	}
	return &Journal{journal: j}, nil
}

// Reserve is idempotent for the exact operation and immutable across retries.
// It executes before any provider effect.
func (j *Journal) Reserve(ctx context.Context, record Record) (Record, error) {
	if j == nil || record.Region == "" || strings.TrimSpace(record.Region) != record.Region || record.Slot < 1 {
		return Record{}, ErrInvalid
	}
	if err := validate(State{Records: map[string]Record{keyFor(record.Region, record.Slot): record}}); err != nil {
		return Record{}, err
	}
	key := keyFor(record.Region, record.Slot)
	err := j.journal.Transact(ctx, true, func(state *State) error {
		if state.Records == nil {
			state.Records = map[string]Record{}
		}
		if prior, ok := state.Records[key]; ok {
			if prior.MemberID != record.MemberID || prior.Generation != record.Generation || prior.OperationID != record.OperationID || !prior.IssuedAt.Equal(record.IssuedAt) || !prior.ExpiresAt.Equal(record.ExpiresAt) {
				return ErrInvalid
			}
			record = prior
			return nil
		}
		state.Records[key] = record
		return nil
	})
	return record, err
}

func (j *Journal) Read(ctx context.Context) (State, error) {
	if j == nil || j.journal == nil {
		return State{}, ErrInvalid
	}
	return j.journal.Read(ctx)
}
