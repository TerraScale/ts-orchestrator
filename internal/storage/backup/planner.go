package backup

import (
	"fmt"
	"slices"
	"time"

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
		tags[tagResource] == resourceValue && tags[tagBackupVolume] == volumeID && tags[tagBackupKey] != ""
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

// Plan decides the backup effects for one volume from its listed backups.
// Only owned backups are considered. No create is planned while an owned
// backup is CREATING; prune never touches non-AVAILABLE backups and never
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
	creating := slices.ContainsFunc(owned, func(backup oci.CloudVolumeBackup) bool { return backup.LifecycleState == "CREATING" })
	var latest time.Time
	sinceFull, sawFull := 0, false
	for _, backup := range owned {
		if backup.LifecycleState != "AVAILABLE" && backup.LifecycleState != "CREATING" {
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
		slot := now.UTC().Truncate(policy.Interval()).Unix()
		actions = append(actions, Action{Kind: ActionCreate, VolumeID: volumeID, Type: kind,
			Key: fmt.Sprintf("%s/%d", volumeID, slot)})
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
