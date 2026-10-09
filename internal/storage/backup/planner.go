package backup

import (
	"fmt"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

// Tag keys written on every controller-created backup.
const (
	tagManagedBy    = "terrascale-managed-by"
	tagOwner        = "terrascale-owner"
	tagRegion       = "terrascale-region"
	tagResource     = "terrascale-resource"
	tagBackupVolume = "terrascale-backup-volume"
	tagBackupKey    = "terrascale-backup-key"

	managedByValue = "ts-orchestrator"
	resourceValue  = "member-data-backup"
)

// Scope binds backups to one controller owner in one region.
type Scope struct {
	Owner  string
	Region oci.Region
}

// Tags returns the exact ownership tags for a backup of volumeID.
func (scope Scope) Tags(volumeID, key string) map[string]string {
	return map[string]string{
		tagManagedBy: managedByValue, tagOwner: scope.Owner, tagRegion: string(scope.Region),
		tagResource: resourceValue, tagBackupVolume: volumeID, tagBackupKey: key,
	}
}

// Owns reports whether backup was created by this scope for volumeID.
func (scope Scope) Owns(backup oci.CloudVolumeBackup, volumeID string) bool {
	tags := backup.FreeformTags
	return backup.ID != "" && backup.VolumeID == volumeID && tags[tagManagedBy] == managedByValue &&
		tags[tagOwner] == scope.Owner && tags[tagRegion] == string(scope.Region) &&
		tags[tagResource] == resourceValue && tags[tagBackupVolume] == volumeID && entityid.Valid(tags[tagBackupKey])
}

// ActionKind is a planned backup effect.
type ActionKind string

const (
	ActionCreate ActionKind = "create"
	ActionDelete ActionKind = "delete"
)

// Action is one planned effect. Key is the idempotency key of a create: it
// is stable within one interval slot, so a retried create replays the same
// OCI retry token instead of creating a second backup.
type Action struct {
	Kind     ActionKind
	VolumeID string
	Type     string
	Key      string
	BackupID string
}

// inProgress reports an OCI backup that is queued (REQUEST_RECEIVED) or
// running (CREATING). OCI runs one backup per volume at a time, so a queued
// request must block a new create exactly like a running one.
func inProgress(state string) bool {
	return state == "CREATING" || state == "REQUEST_RECEIVED"
}

// attemptKey derives the create key for slot. The key stays stable while an
// outcome is ambiguous, so a retry replays the same OCI retry token. Each
// owned backup of this slot observed in a terminal failure (FAULTY) moves the
// key to a new attempt, so a replacement is a new request rather than a
// replay of the failed one.
func attemptKey(slot string, owned []oci.CloudVolumeBackup) string {
	failed := make(map[string]bool)
	for _, backup := range owned {
		if backup.LifecycleState == "FAULTY" {
			failed[backup.FreeformTags[tagBackupKey]] = true
		}
	}
	for attempt := 0; ; attempt++ {
		key := entityid.Derive("backup-attempt", slot, fmt.Sprint(attempt))
		if !failed[key] {
			return key
		}
	}
}

// Plan decides the backup effects for one volume from its listed backups.
// Only owned backups are considered. No create is planned while an owned
// backup is queued or CREATING; prune never touches non-AVAILABLE backups and never
// deletes the newest Retain AVAILABLE ones.
func Plan(policy Policy, scope Scope, volumeID string, backups []oci.CloudVolumeBackup, now time.Time) []Action {
	policy = policy.WithDefaults()
	var owned []oci.CloudVolumeBackup
	for _, backup := range backups {
		if scope.Owns(backup, volumeID) {
			owned = append(owned, backup)
		}
	}
	// Newest first.
	slices.SortFunc(owned, func(a, b oci.CloudVolumeBackup) int { return b.CreatedAt.Compare(a.CreatedAt) })
	var actions []Action
	creating := slices.ContainsFunc(owned, func(backup oci.CloudVolumeBackup) bool { return inProgress(backup.LifecycleState) })
	var latest time.Time
	sinceFull, sawFull := 0, false
	for _, backup := range owned {
		if backup.LifecycleState != "AVAILABLE" && !inProgress(backup.LifecycleState) {
			continue
		}
		if latest.IsZero() {
			latest = backup.CreatedAt
		}
		if !sawFull {
			if backup.Type == TypeFull {
				sawFull = true
			} else {
				sinceFull++
			}
		}
	}
	if !creating && (latest.IsZero() || now.Sub(latest) >= policy.Interval()) {
		kind := TypeIncremental
		if !sawFull || sinceFull+1 >= policy.FullEvery {
			kind = TypeFull
		}
		slot := fmt.Sprintf("%s/%d", volumeID, now.UTC().Truncate(policy.Interval()).Unix())
		actions = append(actions, Action{Kind: ActionCreate, VolumeID: volumeID, Type: kind,
			Key: attemptKey(slot, owned)})
	}
	if !policy.Prune {
		return actions
	}
	kept := 0
	for _, backup := range owned {
		if backup.LifecycleState != "AVAILABLE" {
			continue
		}
		kept++
		if kept > policy.Retain {
			actions = append(actions, Action{Kind: ActionDelete, VolumeID: volumeID, BackupID: backup.ID})
		}
	}
	return actions
}
