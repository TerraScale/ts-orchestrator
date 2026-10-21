package releasechannel

import (
	"testing"
	"time"
)

func TestDeploymentScopeAcceptsFreshInventoryRegardlessOfRolloutProgress(t *testing.T) {
	now := time.Now().UTC()
	for _, state := range []State{StateRolling, StateFailed, StateComplete} {
		for _, environment := range []string{"canary", "production"} {
			status := Status{Schema: StatusSchema, Cell: "SJC", Environment: environment,
				Architectures: []string{"amd64", "arm64"}, State: state, UpdatedAt: now}
			if err := status.ValidateDeploymentScope("SJC", now); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestDeploymentScopeRejectsMissingStaleOrWrongRegionInventory(t *testing.T) {
	now := time.Now().UTC()
	for name, change := range map[string]func(*Status){
		"old schema":               func(s *Status) { s.Schema = "legacy" },
		"wrong cell":               func(s *Status) { s.Cell = "GRU" },
		"missing environment":      func(s *Status) { s.Environment = "" },
		"unsupported environment":  func(s *Status) { s.Environment = "staging" },
		"missing architecture":     func(s *Status) { s.Architectures = nil },
		"unsupported architecture": func(s *Status) { s.Architectures = []string{"386"} },
		"duplicate architecture":   func(s *Status) { s.Architectures = []string{"arm64", "arm64"} },
		"unsorted architecture":    func(s *Status) { s.Architectures = []string{"arm64", "amd64"} },
		"missing clock":            func(s *Status) { s.UpdatedAt = time.Time{} },
		"stale clock":              func(s *Status) { s.UpdatedAt = now.Add(-MaxPinAge - time.Second) },
		"future clock":             func(s *Status) { s.UpdatedAt = now.Add(PinRefreshInterval + time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			status := Status{Schema: StatusSchema, Cell: "SJC", Environment: "canary", Architectures: []string{"arm64"}, UpdatedAt: now}
			change(&status)
			if err := status.ValidateDeploymentScope("SJC", now); err == nil {
				t.Fatal("invalid deployment inventory accepted")
			}
		})
	}
}
