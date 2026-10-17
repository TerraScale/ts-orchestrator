package region

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"time"
)

// Every writer of the shared foundation object retains capacity provenance,
// including unrelated foundation reconciliation and generation changes.
func (r FoundationRecord) retainCapacity(previous FoundationRecord) error {
	if r.UpdatedAt.Before(previous.UpdatedAt) {
		return errors.New("protected foundation write cannot regress its evidence timestamp")
	}
	if previous.CapacityLedger != nil {
		if r.CapacityLedger == nil || r.CapacityLedger.Version != previous.CapacityLedger.Version {
			return errors.New("protected capacity liabilities cannot be removed or replaced")
		}
		for _, old := range previous.CapacityLedger.Hosts {
			found := false
			for _, next := range r.CapacityLedger.Hosts {
				if next.Receipt.OperationID != old.Receipt.OperationID {
					continue
				}
				found = sameCapacityValue(next.Receipt, old.Receipt) && retainedString(old.RequestSHA256, next.RequestSHA256) &&
					retainedTime(old.StartedAt, next.StartedAt) && retainedTime(old.BornAt, next.BornAt) &&
					retainedString(old.InstanceID, next.InstanceID) && retainedString(old.BootVolumeID, next.BootVolumeID) &&
					retainedTime(old.InstanceRetiredAt, next.InstanceRetiredAt) && retainedTime(old.BootRetiredAt, next.BootRetiredAt)
				break
			}
			if !found {
				return errors.New("protected capacity liability changed original tariff, identity or evidence")
			}
		}
	}
	for key, old := range previous.CapacityCreates {
		next, exists := r.CapacityCreates[key]
		if !exists || !retainedString(old.ResourceID, next.ResourceID) || !retainPoolWire(&old.Request, &next.Request) {
			return errors.New("protected capacity create lost its original request or result")
		}
		next.ResourceID, next.Request = old.ResourceID, old.Request
		if !sameCapacityValue(old, next) {
			return errors.New("protected capacity create changed original authority or recipe")
		}
	}
	for key, old := range previous.CapacityPools {
		next, exists := r.CapacityPools[key]
		if !exists || !retainPoolWire(&old.Create, &next.Create) || next.Epoch < old.Epoch {
			return errors.New("protected capacity pool lost original provenance or regressed its epoch")
		}
		for id, config := range old.Configurations {
			if !sameCapacityValue(config, next.Configurations[id]) {
				return errors.New("protected capacity configuration cannot be removed or rewritten")
			}
		}
		for id, update := range old.ConfigurationUpdates {
			current, exists := next.ConfigurationUpdates[id]
			if !exists || update.ConfigurationID != current.ConfigurationID || !retainPoolWire(&update.Request, &current.Request) {
				return errors.New("protected pool configuration update lost original conditional request")
			}
		}
		next.Create, next.Configurations = old.Create, old.Configurations
		next.ConfigurationUpdates = old.ConfigurationUpdates
		next.CurrentConfigurationID, next.ActiveOperationID = old.CurrentConfigurationID, old.ActiveOperationID
		next.LeaseID, next.LeaseExpiresAt, next.Epoch = old.LeaseID, old.LeaseExpiresAt, old.Epoch
		if !sameCapacityValue(old, next) {
			return errors.New("protected capacity pool changed its original identity or authority")
		}
	}
	for key, old := range previous.PoolChildren {
		next, exists := r.PoolChildren[key]
		if !exists || poolChildRank(next.Stage) < poolChildRank(old.Stage) ||
			!retainedString(old.InstanceID, next.InstanceID) || !retainedTime(old.BornAt, next.BornAt) ||
			!retainedString(old.BootVolumeID, next.BootVolumeID) || !retainedString(old.BootAttachmentID, next.BootAttachmentID) ||
			!retainedTime(old.ReadyAt, next.ReadyAt) || !retainedString(old.RemovalOperationID, next.RemovalOperationID) ||
			old.DetachTargetFrom != 0 && old.DetachTargetFrom != next.DetachTargetFrom ||
			!retainedString(old.DrainAuthoritySHA256, next.DrainAuthoritySHA256) || !retainedTime(old.DetachedAt, next.DetachedAt) ||
			!retainedTime(old.InstanceRetiredAt, next.InstanceRetiredAt) || !retainedTime(old.BootRetiredAt, next.BootRetiredAt) ||
			old.RetirementDrain != nil && !sameCapacityValue(old.RetirementDrain, next.RetirementDrain) ||
			!retainPoolWire(old.Launch, next.Launch) || !retainPoolWire(old.Attach, next.Attach) || !retainPoolWire(old.Detach, next.Detach) ||
			!retainPoolWire(old.Terminate, next.Terminate) || !retainPoolWire(old.DeleteBoot, next.DeleteBoot) {
			return errors.New("protected pool child lost or rebound original lifecycle evidence")
		}
		next.Stage, next.Launch, next.Attach, next.Detach, next.Terminate, next.DeleteBoot = old.Stage, old.Launch, old.Attach, old.Detach, old.Terminate, old.DeleteBoot
		next.InstanceID, next.BornAt, next.BootVolumeID, next.BootAttachmentID = old.InstanceID, old.BornAt, old.BootVolumeID, old.BootAttachmentID
		next.ReadyAt, next.RemovalOperationID, next.DrainAuthoritySHA256, next.DetachedAt = old.ReadyAt, old.RemovalOperationID, old.DrainAuthoritySHA256, old.DetachedAt
		next.DetachTargetFrom = old.DetachTargetFrom
		next.RetirementDrain = old.RetirementDrain
		next.InstanceRetiredAt, next.BootRetiredAt = old.InstanceRetiredAt, old.BootRetiredAt
		if !sameCapacityValue(old, next) {
			return errors.New("protected pool child changed original recipe, placement or boot identity")
		}
	}
	for key, old := range previous.PoolQuarantines {
		next, exists := r.PoolQuarantines[key]
		if !exists || !retainPoolWire(old.Detach, next.Detach) || !retainedTime(old.DetachedAt, next.DetachedAt) {
			return errors.New("protected quarantine lost its original detach evidence")
		}
		next.Detach, next.DetachedAt = old.Detach, old.DetachedAt
		if !sameCapacityValue(old, next) {
			return errors.New("protected quarantine changed original membership authority")
		}
	}
	return nil
}

func retainPoolWire(old, next *PoolWireRecord) bool {
	if old == nil {
		return true
	}
	if next == nil || old.RequestSHA256 != next.RequestSHA256 || old.RetryToken != next.RetryToken || old.IfMatch != next.IfMatch ||
		!old.FirstAttemptAt.Equal(next.FirstAttemptAt) || next.Attempts < old.Attempts || next.LastAttemptAt.Before(old.LastAttemptAt) ||
		old.EverUnknown && !next.EverUnknown || old.TokenInvalidated && !next.TokenInvalidated ||
		!retainedTime(old.AcceptedAt, next.AcceptedAt) || !retainedString(old.OpcRequestID, next.OpcRequestID) ||
		!retainedString(old.WorkRequestID, next.WorkRequestID) || !retainedTime(old.WorkCompletedAt, next.WorkCompletedAt) {
		return false
	}
	return next.Attempts != old.Attempts || next.PendingAttemptID == "" || next.PendingAttemptID == old.PendingAttemptID
}

func retainedString(old, next string) bool  { return old == "" || old == next }
func retainedTime(old, next time.Time) bool { return old.IsZero() || old.Equal(next) }

func sameCapacityValue(a, b any) bool {
	left, leftErr := json.Marshal(a, json.Deterministic(true))
	right, rightErr := json.Marshal(b, json.Deterministic(true))
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}
