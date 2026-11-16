// Package rollout serializes a cell's NetBird changes across leader failover.
package rollout

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
)

type Target struct {
	Pin        client.Pin     `json:"pin"`
	Enrollment netbird.Config `json:"enrollment"`
}

type Status struct {
	Version           string    `json:"version"`
	AppliedTargetHash string    `json:"applied_target_hash,omitempty"`
	Missing           bool      `json:"missing,omitempty"`
	Connected         bool      `json:"connected"`
	IP                string    `json:"ip,omitempty"`
	DNS               string    `json:"dns,omitempty"`
	Pending           string    `json:"pending,omitempty"`
	ActionID          string    `json:"action_id,omitempty"`
	Error             string    `json:"error,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
}

func (status Status) Validate() error {
	if status.Pending != "" && !entityid.Valid(status.Pending) || status.ActionID != "" && !entityid.Valid(status.ActionID) {
		return errors.New("invalid NetBird status identity")
	}
	return nil
}

type Command struct {
	Generation  uint64 `json:"generation"`
	ID          string `json:"id"`
	Transaction string `json:"transaction"`
	Action      string `json:"action"`
	Target      Target `json:"target"`
}

type Record struct {
	ID                string    `json:"id"`
	Node              string    `json:"node"`
	Previous          string    `json:"previous"`
	Target            Target    `json:"target"`
	PinHash           string    `json:"pin_hash"`
	Phase             string    `json:"phase"`
	RollbackRequired  *bool     `json:"rollback_required,omitempty"`
	RecoveryComplete  bool      `json:"recovery_complete,omitempty"`
	RecoveryReturning bool      `json:"recovery_returning,omitempty"`
	Deadline          time.Time `json:"deadline"`
	StartedAt         time.Time `json:"started_at"`
	Reason            string    `json:"reason,omitempty"`
	// Admission survives pin, grant and fence amendments until recovery.
	Fence      jsontext.Value `json:"fence,omitempty"`
	OCIAddress string         `json:"oci_address,omitempty"`
}

// The store and every effect must be guarded by the same authority epoch.
// A failed rollback holds the cell until an operator repairs its access path.
type Reconciler struct {
	Load      func(context.Context) (Record, error)
	Save      func(context.Context, Record) error
	Status    func(context.Context, string) (Status, error)
	Preflight func(context.Context, string) error
	Drain     func(context.Context, string) error
	Healthy   func(context.Context, string, Status, time.Time) error
	Return    func(context.Context, string) error
	Send      func(context.Context, string, Command) error
	Now       func() time.Time
}
