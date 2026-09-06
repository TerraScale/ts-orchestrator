package hostagent

import (
	"context"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"time"
)

// EngineFacts preserves unknown lag; the current TBEP health RPC does not
// measure replication lag or expose an overload signal.
type EngineFacts struct {
	Measured         bool  `json:"measured"`
	Serving          bool  `json:"serving"`
	Draining         bool  `json:"draining"`
	ObservedAtUnixMS int64 `json:"observedAtUnixMs"`
	LagMeasured      bool  `json:"lagMeasured"`
	LagMS            int   `json:"lagMs"`
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
		return EngineFacts{Measured: true, Serving: observation.Health.State == pb.HealthState_HEALTH_STATE_SERVING, Draining: observation.Health.State == pb.HealthState_HEALTH_STATE_DRAINING, ObservedAtUnixMS: time.Now().UnixMilli()}, nil
	}
}
