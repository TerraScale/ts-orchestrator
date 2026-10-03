package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
)

// Runner applies Policy on the authority leader.
type Runner struct {
	Policy   Policy
	Scope    Scope
	Provider oci.VolumeBackupProvider
	Fencer   authority.Fencer
	// Volumes lists the retained volume IDs to protect. A listing that could
	// not read every source returns the volumes it did read together with an
	// error wrapping ErrPartialVolumes: those volumes are still protected, but
	// orphan retention is skipped because a missing volume may be unread
	// rather than removed.
	Volumes func(context.Context) ([]string, error)
	Now     func() time.Time
}

// ErrPartialVolumes marks a volume listing that skipped unreadable sources.
var ErrPartialVolumes = errors.New("volume listing is partial")

// Report summarizes one evaluation.
type Report struct {
	Created []string
	Deleted []string
	Skipped []string
}

func (runner Runner) validate() error {
	if !runner.Policy.Enabled {
		return storage.ErrDisabled
	}
	if err := runner.Policy.Validate(); err != nil {
		return err
	}
	if runner.Provider == nil || runner.Fencer == nil || runner.Volumes == nil || runner.Scope.Owner == "" || runner.Scope.Region == "" {
		return errors.New("volume backup runner requires a provider, authority fencer, volume source and owner scope")
	}
	return nil
}

// RunOnce evaluates every volume once under the current authority epoch. A
// non-leader returns authority.ErrNotLeader without reading OCI.
func (runner Runner) RunOnce(ctx context.Context) (Report, error) {
	if err := runner.validate(); err != nil {
		return Report{}, err
	}
	snapshot := runner.Fencer.Current()
	if !snapshot.CanMutate() {
		return Report{}, authority.ErrNotLeader
	}
	epoch := snapshot.Epoch
	now := time.Now
	if runner.Now != nil {
		now = runner.Now
	}
	volumes, err := runner.Volumes(ctx)
	partial := errors.Is(err, ErrPartialVolumes)
	if err != nil && !partial {
		return Report{}, fmt.Errorf("list volumes to back up: %w", err)
	}
	var report Report
	var failures []error
	if partial {
		failures = append(failures, fmt.Errorf("list volumes to back up: %w", err))
	}
	for _, volumeID := range volumes {
		backups, err := runner.Provider.ListVolumeBackups(ctx, volumeID)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		for _, action := range Plan(runner.Policy, runner.Scope, volumeID, backups, now()) {
			if err := runner.guard(ctx, epoch); err != nil {
				return report, errors.Join(append(failures, err)...)
			}
			switch action.Kind {
			case ActionCreate:
				created, err := runner.Provider.CreateVolumeBackup(ctx, volumeID,
					"ts-member-data-backup-"+retryToken(runner.Scope, action.Key)[:12], action.Type,
					runner.Scope.Tags(volumeID, action.Key), retryToken(runner.Scope, action.Key))
				if err != nil {
					failures = append(failures, err)
					continue
				}
				report.Created = append(report.Created, created.ID)
				recordBackup(ctx, runner.Scope, epoch, volumeID, action, created.ID)
			case ActionDelete:
				deleted, err := runner.prune(ctx, epoch, volumeID, action.BackupID)
				if err != nil {
					failures = append(failures, err)
					continue
				}
				if deleted {
					report.Deleted = append(report.Deleted, action.BackupID)
				} else {
					report.Skipped = append(report.Skipped, action.BackupID)
				}
			}
		}
	}
	if runner.Policy.Prune && !partial {
		if err := runner.pruneOrphans(ctx, epoch, volumes, now(), &report); err != nil {
			failures = append(failures, err)
		}
	}
	return report, errors.Join(failures...)
}

// pruneOrphans deletes owned AVAILABLE backups whose source volume is no
// longer placed, has been removed from OCI, and whose backup is older than
// the orphan retention. Without it a torn-down partition would strand its
// last Retain backups for ever, since per-volume pruning only visits placed
// volumes. It runs only over a complete placement listing.
func (runner Runner) pruneOrphans(ctx context.Context, epoch uint64, placed []string, now time.Time, report *Report) error {
	backups, err := runner.Provider.ListCompartmentVolumeBackups(ctx)
	if err != nil {
		return fmt.Errorf("list compartment volume backups: %w", err)
	}
	live := make(map[string]bool, len(placed))
	for _, volumeID := range placed {
		live[volumeID] = true
	}
	retention := runner.Policy.OrphanRetention()
	gone := make(map[string]bool)
	var failures []error
	for _, backup := range backups {
		volumeID := backup.VolumeID
		if volumeID == "" || live[volumeID] || !runner.Scope.Owns(backup, volumeID) ||
			backup.LifecycleState != "AVAILABLE" || now.Sub(backup.CreatedAt) < retention {
			continue
		}
		removed, checked := gone[volumeID]
		if !checked {
			removed, err = runner.Provider.VolumeGone(ctx, volumeID)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			gone[volumeID] = removed
		}
		if !removed {
			continue
		}
		deleted, err := runner.prune(ctx, epoch, volumeID, backup.ID)
		if errors.Is(err, authority.ErrFenced) {
			return errors.Join(append(failures, err)...)
		}
		switch {
		case err != nil:
			failures = append(failures, err)
		case deleted:
			report.Deleted = append(report.Deleted, backup.ID)
		default:
			report.Skipped = append(report.Skipped, backup.ID)
		}
	}
	return errors.Join(failures...)
}

// prune re-reads one backup and deletes it with its exact ETag only while it
// is still an AVAILABLE owned backup of volumeID.
func (runner Runner) prune(ctx context.Context, epoch uint64, volumeID, backupID string) (bool, error) {
	current, err := runner.Provider.GetVolumeBackup(ctx, backupID)
	if err != nil {
		return false, err
	}
	if !runner.Scope.Owns(current, volumeID) || current.LifecycleState != "AVAILABLE" || current.ETag == "" {
		return false, nil
	}
	if err := runner.guard(ctx, epoch); err != nil {
		return false, err
	}
	return true, runner.Provider.DeleteVolumeBackup(ctx, backupID, current.ETag)
}

func (runner Runner) guard(ctx context.Context, epoch uint64) error {
	if snapshot := runner.Fencer.Current(); !snapshot.CanMutate() || snapshot.Epoch != epoch {
		return authority.ErrFenced
	}
	if err := runner.Fencer.Guard(ctx, epoch); err != nil {
		return fmt.Errorf("volume backup authority was fenced: %w", err)
	}
	return nil
}

// Run evaluates the policy every RunInterval until ctx ends. Followers skip
// quietly; failures are logged and retried on the next tick.
func (runner Runner) Run(ctx context.Context) error {
	if err := runner.validate(); err != nil {
		return err
	}
	ticker := time.NewTicker(runner.Policy.RunInterval())
	defer ticker.Stop()
	for {
		report, err := runner.RunOnce(ctx)
		switch {
		case errors.Is(err, authority.ErrNotLeader):
		case err != nil && ctx.Err() == nil:
			slog.Warn("volume backup evaluation failed", "error", err)
		case len(report.Created)+len(report.Deleted) > 0:
			slog.Info("volume backup policy applied", "created", report.Created, "deleted", report.Deleted)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// retryToken scopes the OCI retry token to the controller owner and region:
// the same key in another cell must never replay this cell's request.
func retryToken(scope Scope, key string) string {
	sum := sha256.Sum256([]byte(scope.Owner + "\x00" + string(scope.Region) + "\x00" + key))
	return hex.EncodeToString(sum[:])
}

// recordBackup journals one backup OCI accepted. The create replays the same
// retry token within an interval slot, so a retried create returns the same
// backup and the decision is keyed on it.
func recordBackup(ctx context.Context, scope Scope, epoch uint64, volumeID string, action Action, backupID string) {
	key := "backup:" + backupID
	if decisionlog.Correlated(key) != "" {
		return
	}
	id := decisionlog.Record(ctx, decisionlog.Decision{
		Region:  string(scope.Region),
		Actor:   decisionlog.Actor{Slice: "storage"},
		Kind:    decisionlog.KindBackupTaken,
		Subject: decisionlog.Subject{Kind: "volume", ID: volumeID},
		Summary: "Started a " + strings.ToLower(action.Type) + " backup of volume " + volumeID,
		Reason:  "The volume backup policy interval elapsed without a backup.",
		Rule:    "storage.volume_backup",
		Status:  decisionlog.StatusInProgress,
		Epoch:   epoch,
		Attrs:   map[string]string{"backup_id": backupID, "type": action.Type},
	})
	decisionlog.Correlate(key, id)
}
