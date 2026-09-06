package hostagent

import (
	"context"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"time"
)

// EngineFacts preserves unknown lag; the current TBEP health RPC does not
// measure replication lag or expose an overload signal.
type DatabaseCatchUpFacts struct {
	Tenant                  string `json:"tenant"`
	Project                 string `json:"project"`
	Database                string `json:"database"`
	SourceSequence          uint64 `json:"sourceSequence"`
	RegionalSequence        uint64 `json:"regionalSequence"`
	RegionalMeasured        bool   `json:"regionalMeasured"`
	CausalMeasured          bool   `json:"causalMeasured"`
	CausalCaughtUp          bool   `json:"causalCaughtUp"`
	BackupSourceSequence    uint64 `json:"backupSourceSequence"`
	BackupProtectedSequence uint64 `json:"backupProtectedSequence"`
	BackupMeasured          bool   `json:"backupMeasured"`
	BackupCaughtUp          bool   `json:"backupCaughtUp"`
}

type EngineFacts struct {
	CatchUpComplete         bool                   `json:"catchUpComplete"`
	AssignmentRevision      string                 `json:"assignmentRevision"`
	CatchUpObservedAtUnixMS uint64                 `json:"catchUpObservedAtUnixMs"`
	Databases               []DatabaseCatchUpFacts `json:"databases,omitempty"`
	Measured                bool                   `json:"measured"`
	Serving                 bool                   `json:"serving"`
	Draining                bool                   `json:"draining"`
	ObservedAtUnixMS        int64                  `json:"observedAtUnixMs"`
	LagMeasured             bool                   `json:"lagMeasured"`
	LagMS                   int                    `json:"lagMs"`
	// Resource metrics are signed by the host agent and are intentionally
	// absent until the local sampler can provide a bounded measurement.
	ObservationSequence int64   `json:"observationSequence"`
	CPUPercent          float64 `json:"cpuPercent"`
	MemoryPercent       float64 `json:"memoryPercent"`
	QueueDepth          int     `json:"queueDepth"`
	QueueCapacity       int     `json:"queueCapacity"`
}

// SampleEngine opens a short-lived authenticated same-host observation. Failed
// samples are published as unknown, never inferred from a listening port.
func SampleEngine(config tbep.FileConfig) func(context.Context) (EngineFacts, error) {
	return func(ctx context.Context) (EngineFacts, error) {
		client, err := config.Open()
		if err != nil {
			return EngineFacts{}, err
		}
		defer client.Close()
		observation, err := client.Observe(ctx)
		if err != nil {
			return EngineFacts{}, err
		}
		facts := EngineFacts{Measured: true, Serving: observation.Health.State == pb.HealthState_HEALTH_STATE_SERVING, Draining: observation.Health.State == pb.HealthState_HEALTH_STATE_DRAINING, ObservedAtUnixMS: time.Now().UnixMilli(), Databases: []DatabaseCatchUpFacts{}}
		status := observation.CatchUp
		facts.CatchUpComplete = status.Complete
		facts.AssignmentRevision = status.AssignmentRevision
		facts.CatchUpObservedAtUnixMS = status.ObservedAtUnixMs
		for _, entry := range status.Databases {
			facts.Databases = append(facts.Databases, DatabaseCatchUpFacts{Tenant: entry.Tenant, Project: entry.Project, Database: entry.Database, SourceSequence: entry.SourceSequence, RegionalSequence: entry.RegionalSequence, RegionalMeasured: entry.RegionalMeasured, CausalMeasured: entry.CausalMeasured, CausalCaughtUp: entry.CausalCaughtUp, BackupSourceSequence: entry.BackupSourceSequence, BackupProtectedSequence: entry.BackupProtectedSequence, BackupMeasured: entry.BackupMeasured, BackupCaughtUp: entry.BackupCaughtUp})
		}
		return facts, nil
	}
}
