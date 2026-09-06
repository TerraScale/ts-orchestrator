package tbep

import (
	"errors"
	"strings"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"time"
)

func validateCatchUp(status *pb.MaintenanceServiceCatchUpStatusResponse) error {
	if status == nil || len(status.Databases) > 4096 {
		return errors.New("TBEP catchup status exceeds scope bound")
	}
	if !status.Complete {
		if status.AssignmentRevision != "" || status.ObservedAtUnixMs != 0 || len(status.Databases) != 0 {
			return errors.New("TBEP incomplete catchup must not expose partial host proof")
		}
		return nil
	}
	if !validMetadata(status.AssignmentRevision, 256) || status.ObservedAtUnixMs == 0 || status.ObservedAtUnixMs > uint64(time.Now().Add(time.Second).UnixMilli()) || uint64(time.Now().Add(-30*time.Second).UnixMilli()) > status.ObservedAtUnixMs || len(status.Databases) == 0 {
		return errors.New("TBEP catchup assignment or timestamp unavailable")
	}
	seen := map[string]bool{}
	for _, entry := range status.Databases {
		if entry == nil || !validMetadata(entry.Tenant, 64) || !validMetadata(entry.Project, 255) || !validMetadata(entry.Database, 255) {
			return errors.New("TBEP invalid catchup database scope")
		}
		key := strings.Join([]string{entry.Tenant, entry.Project, entry.Database}, "\x00")
		if seen[key] {
			return errors.New("TBEP duplicate catchup database scope")
		}
		seen[key] = true
		if (!entry.RegionalMeasured && entry.RegionalSequence != 0) || (!entry.CausalMeasured && entry.CausalCaughtUp) || (!entry.BackupMeasured && (entry.BackupCaughtUp || entry.BackupProtectedSequence != 0)) || (entry.BackupCaughtUp && entry.BackupProtectedSequence < entry.BackupSourceSequence) {
			return errors.New("TBEP inconsistent catchup measurements")
		}
	}
	return nil
}
