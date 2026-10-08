// Package rollout serializes a cell's NetBird changes across leader failover.
package rollout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
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

func Hash(target Target) string {
	wire, _ := json.Marshal(target, json.Deterministic(true))
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

// CompareVersions compares exact stable releases, accepting the CLI's v prefix.
func CompareVersions(a, b string) (int, error) {
	parse := func(s string) ([3]uint64, error) {
		var out [3]uint64
		parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(s), "v"), ".")
		if len(parts) != 3 {
			return out, errors.New("NetBird version must have three numeric components")
		}
		for i, part := range parts {
			value, err := strconv.ParseUint(part, 10, 32)
			if err != nil || part == "" || len(part) > 1 && part[0] == '0' {
				return out, errors.New("invalid NetBird version")
			}
			out[i] = value
		}
		return out, nil
	}
	x, err := parse(a)
	if err != nil {
		return 0, err
	}
	y, err := parse(b)
	if err != nil {
		return 0, err
	}
	for i := range x {
		if x[i] < y[i] {
			return -1, nil
		}
		if x[i] > y[i] {
			return 1, nil
		}
	}
	return 0, nil
}

// Tick does one bounded, repeatable step. Persisting intent before every
// effect lets the next leader resume the same node, rather than start another.
func (r *Reconciler) Tick(ctx context.Context, target Target, nodes []string) error {
	currentTime := func() time.Time {
		if r.Now != nil {
			return r.Now().UTC()
		}
		return time.Now().UTC()
	}
	now := currentTime()
	record, err := r.Load(ctx)
	if err != nil {
		return err
	}
	if record.RecoveryReturning && !record.RecoveryComplete {
		// Fence an interrupted return before any status or health gate.
		if err := r.Drain(ctx, record.Node); err != nil {
			return err
		}
		record.RecoveryReturning = false
		if err := r.Save(ctx, record); err != nil {
			return err
		}
	}
	returnNode := func() error {
		record.RecoveryReturning = true
		if err := r.Save(ctx, record); err != nil {
			return err
		}
		if err := r.Return(ctx, record.Node); err != nil {
			// Return may clear backend flags before its health check fails.
			if drainErr := r.Drain(ctx, record.Node); drainErr != nil {
				return errors.Join(err, drainErr)
			}
			record.RecoveryReturning = false
			return errors.Join(err, r.Save(ctx, record))
		}
		record.RecoveryReturning = false
		return nil
	}
	rollbackAcknowledged := func(status Status) bool {
		return status.ActionID == record.ID+".rollback" && status.Error == "" && status.Version == record.Previous && status.Pending == ""
	}
	recovered := func(status Status, since time.Time) error {
		if record.Previous == "" {
			// First-install rollback restores absence, so mesh probes cannot run.
			if !status.Missing || status.Version != "" || status.ObservedAt.IsZero() ||
				now.Sub(status.ObservedAt) > 15*time.Second || status.ObservedAt.Sub(now) > 2*time.Second {
				return errors.New("previous NetBird absence has not been freshly observed")
			}
			return nil
		}
		return r.Healthy(ctx, record.Node, status, since)
	}
	hash := Hash(target)
	if record.Phase == "failed" {
		// Recover the held node even when this pin stays failed or is removed.
		// The completion marker is written only after our fence is released.
		if !record.RecoveryComplete {
			status, err := r.Status(ctx, record.Node)
			// Older journals lack the marker. Require proof of recovery unless
			// this controller explicitly recorded that no agent mutation began.
			if err != nil || status.Pending != "" || status.Error != "" || (record.RollbackRequired == nil || *record.RollbackRequired) && !rollbackAcknowledged(status) {
				return errors.New("previous NetBird rollback is unresolved")
			}
			if err := recovered(status, time.Time{}); err != nil {
				return err
			}
			if err := returnNode(); err != nil {
				return err
			}
			record.RecoveryComplete = true
			if err := r.Save(ctx, record); err != nil {
				return err
			}
		}
		if record.PinHash == hash {
			return fmt.Errorf("NetBird rollout held on %s: %s", record.Node, record.Reason)
		}
	}
	if record.Phase == "" || record.Phase == "done" || record.Phase == "failed" {
		statuses := make(map[string]Status, len(nodes))
		for _, node := range nodes {
			status, err := r.Status(ctx, node)
			if err != nil {
				return err
			}
			if status.Pending != "" {
				return fmt.Errorf("NetBird transaction still pending on %s", node)
			}
			statuses[node] = status
		}
		for _, node := range nodes {
			status := statuses[node]
			if status.Version != "" {
				comparison, err := CompareVersions(status.Version, target.Pin.Version)
				if err != nil {
					return err
				}
				if comparison == 0 && status.AppliedTargetHash == hash {
					continue
				}
			}
			if err := r.Preflight(ctx, node); err != nil {
				return err
			}
			record = Record{ID: fmt.Sprintf("%s-%d", hash[:16], now.UnixNano()), Node: node, Previous: status.Version,
				Target: target, PinHash: hash, Phase: "drain", StartedAt: now, Deadline: now.Add(10 * time.Minute)}
			return r.Save(ctx, record)
		}
		return nil
	}
	transition := func(phase string) error { record.Phase = phase; return r.Save(ctx, record) }
	command := func(action string) error {
		return r.Send(ctx, record.Node, Command{ID: record.ID + "." + action, Generation: uint64(record.StartedAt.UnixNano()), Transaction: record.ID, Action: action, Target: record.Target})
	}
	rollback := func(reason string) error {
		record.RollbackRequired = new(true)
		record.Reason = reason
		record.Deadline = now.Add(6 * time.Minute)
		return transition("rollback")
	}
	switch record.Phase {
	case "drain":
		if now.After(record.Deadline) {
			record.RollbackRequired = new(false)
			record.Reason = "drain timed out"
			return transition("failed")
		}
		if err := r.Preflight(ctx, record.Node); err != nil {
			return err
		}
		if err := r.Drain(ctx, record.Node); err != nil {
			return err
		}
		record.Deadline = currentTime().Add(3 * time.Minute)
		return transition("install")
	case "install":
		if now.After(record.Deadline) {
			return rollback("agent did not acknowledge installation")
		}
		status, err := r.Status(ctx, record.Node)
		if err != nil {
			return err
		}
		if status.ActionID == record.ID+".install" {
			if status.Error != "" {
				return rollback(status.Error)
			}
			record.Deadline = now.Add(2 * time.Minute)
			return transition("check")
		}
		return command("install")
	case "check":
		status, err := r.Status(ctx, record.Node)
		if err == nil && status.Version == record.Target.Pin.Version && status.Pending == record.ID {
			err = r.Healthy(ctx, record.Node, status, record.StartedAt)
			if err == nil {
				record.Deadline = currentTime().Add(2 * time.Minute)
				return transition("confirm")
			}
		}
		if now.After(record.Deadline) {
			return rollback("new NetBird agent failed mesh health checks")
		}
		return err
	case "confirm":
		if now.After(record.Deadline) {
			return rollback("new NetBird agent was not confirmed")
		}
		status, err := r.Status(ctx, record.Node)
		if err != nil {
			return err
		}
		if status.ActionID == record.ID+".confirm" && status.Error == "" && status.Pending == "" && status.Version == record.Target.Pin.Version && status.AppliedTargetHash == record.PinHash {
			record.Deadline = now.Add(2 * time.Minute)
			return transition("return")
		}
		return command("confirm")
	case "return":
		failedReturn := func(err error) error {
			if now.After(record.Deadline) {
				return rollback("confirmed NetBird agent failed return health checks")
			}
			return err
		}
		status, err := r.Status(ctx, record.Node)
		if err != nil {
			return failedReturn(err)
		}
		if status.Pending != "" || status.Version != record.Target.Pin.Version || status.AppliedTargetHash != record.PinHash || status.ActionID != record.ID+".confirm" || status.Error != "" {
			return failedReturn(errors.New("confirmed NetBird transaction changed before return"))
		}
		if err := r.Healthy(ctx, record.Node, status, record.StartedAt); err != nil {
			return failedReturn(err)
		}
		if err := returnNode(); err != nil {
			return failedReturn(err)
		}
		return transition("done")
	case "rollback":
		// Return may have put backends online before an LB health check
		// failed. Re-establish the same fence before restarting the old agent.
		if err := r.Drain(ctx, record.Node); err != nil {
			return err
		}
		if err := command("rollback"); err != nil {
			return err
		}
		// Safe re-draining can wait for repaired quorum across many ticks.
		// Allow a full acknowledgment window once the command is sent.
		record.Deadline = currentTime().Add(6 * time.Minute)
		return transition("rollback-check")
	case "rollback-check":
		status, err := r.Status(ctx, record.Node)
		if err == nil && rollbackAcknowledged(status) && recovered(status, record.StartedAt) == nil {
			if err := returnNode(); err != nil {
				if record.RecoveryReturning {
					return err
				}
				if now.After(record.Deadline) {
					record.Reason += "; previous binary failed return health checks (node remains drained)"
					return transition("failed")
				}
				return err
			}
			record.RecoveryComplete = true
			return transition("failed")
		}
		if now.After(record.Deadline) {
			if err := r.Drain(ctx, record.Node); err != nil {
				return err
			}
			record.Reason += "; previous binary did not recover (node remains drained)"
			return transition("failed")
		}
		return command("rollback")
	default:
		return errors.New("unknown NetBird rollout phase")
	}
}
