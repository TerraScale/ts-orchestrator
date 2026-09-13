package autoscale

import (
	"errors"
	"strings"
)

// WorkerTarget is deliberately separate from Target. Member targets carry
// database residency and removal proofs; sharing that state with workers
// could authorize an unsafe member removal. Until worker telemetry and a
// worker termination owner exist, the only admitted worker target is the
// declared fixed floor.
type WorkerTarget struct {
	Region      string
	Workers     int
	MinWorkers  int
	MaxWorkers  int
	OperationID string
}

func (t WorkerTarget) Validate() error {
	if strings.TrimSpace(t.Region) == "" || t.Region != strings.ToLower(t.Region) || t.Workers < 2 || t.MinWorkers < 2 || t.MaxWorkers < t.MinWorkers || t.Workers < t.MinWorkers || t.Workers > t.MaxWorkers {
		return errors.New("autoscale: invalid worker target")
	}
	return nil
}

// FixedWorkerTarget returns the fail-closed target currently supported by the
// runtime: exactly the declared regional floor, with no scale operations.
func FixedWorkerTarget(region string, floor int) (WorkerTarget, error) {
	target := WorkerTarget{Region: region, Workers: floor, MinWorkers: floor, MaxWorkers: floor}
	if err := target.Validate(); err != nil {
		return WorkerTarget{}, err
	}
	return target, nil
}
