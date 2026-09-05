package main

import (
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

// The command owns daily scheduling and the already-validated release mirror.
// Callers supply only the domain authorities and durable provider adapters.
type productionRestoreConfig struct {
	Backup          restoredrill.BackupPort
	Branches        restoredrill.BranchPort
	Journal         restoredrill.JournalPort
	Pager           restoredrill.PagerPort
	Drill           restoredrill.Config
	Snapshotter     restoredrill.JetStreamSnapshotter
	SnapshotMirror  restoredrill.JetStreamSnapshotMirror
	SnapshotRegions []string
}

func (config productionRestoreConfig) resolve(mirror *delivery.ArtifactMirror) restoredrill.ProductionConfig {
	return restoredrill.ProductionConfig{
		Backup: config.Backup, Branches: config.Branches, Journal: config.Journal,
		Pager: config.Pager, Drill: config.Drill,
		Scheduler:   restoredrill.TickerScheduler{},
		Snapshotter: config.Snapshotter, SnapshotMirror: config.SnapshotMirror,
		SnapshotRegions: append([]string(nil), config.SnapshotRegions...),
		ArtifactMirror:  mirror,
	}
}
