package workload

import (
	"errors"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/autoscale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

func validStateful() ServiceSpec {
	return ServiceSpec{Role: "terrabase", Environment: "prod", Kind: KindStateful, Replicas: ReplicaBounds{Min: 2, Max: 4},
		Stateful: &StatefulPolicy{QuorumFloorPerRegion: 2, MaxConcurrentChanges: 1, DrainTimeoutSeconds: 600,
			MaxLagForScaleDown: 100, VolumeRetention: RetainVolume}}
}

func TestServiceSpecValidate(t *testing.T) {
	scaling := &autoscale.Policy{Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.6}}}
	valid := []ServiceSpec{
		statelessSpec(0, 0),
		{Role: "api", Environment: "prod", Kind: KindStateless, Replicas: ReplicaBounds{Min: 1, Max: 8}, Scaling: scaling,
			Resources: placement.Resources{CPU: 1, MemoryBytes: 1, DiskBytes: 1},
			Placement: Constraints{NodePool: "general", MaxPerFailureDomain: 3}, Rollout: Rollout{MaxSurge: 2, MaxUnavailable: 1}},
		validStateful(),
	}
	for _, spec := range valid {
		if err := spec.Validate(); err != nil {
			t.Errorf("%s: %v", spec.Role, err)
		}
	}
	invalid := map[string]func(*ServiceSpec){
		"bad role":            func(s *ServiceSpec) { s.Role = "API" },
		"bad environment":     func(s *ServiceSpec) { s.Environment = "" },
		"unknown kind":        func(s *ServiceSpec) { s.Kind = "daemon"; s.Stateful = nil },
		"inverted bounds":     func(s *ServiceSpec) { s.Replicas = ReplicaBounds{Min: 3, Max: 2} },
		"partial resources":   func(s *ServiceSpec) { s.Resources = placement.Resources{CPU: 1} },
		"bad node pool":       func(s *ServiceSpec) { s.Placement.NodePool = "Pool" },
		"negative domain cap": func(s *ServiceSpec) { s.Placement.MaxPerFailureDomain = -1 },
		"negative surge":      func(s *ServiceSpec) { s.Rollout.MaxSurge = -1 },
		"invalid scaling":     func(s *ServiceSpec) { s.Scaling = &autoscale.Policy{} },
		"stateful no policy":  func(s *ServiceSpec) { s.Stateful = nil },
		"stateless policy":    func(s *ServiceSpec) { s.Kind = KindStateless },
		"quorum floor of one": func(s *ServiceSpec) { s.Stateful.QuorumFloorPerRegion = 1 },
		"concurrent changes":  func(s *ServiceSpec) { s.Stateful.MaxConcurrentChanges = 2 },
		"no drain timeout":    func(s *ServiceSpec) { s.Stateful.DrainTimeoutSeconds = 0 },
		"volume deletion":     func(s *ServiceSpec) { s.Stateful.VolumeRetention = "delete" },
		"min below floor":     func(s *ServiceSpec) { s.Stateful.QuorumFloorPerRegion = 3 },
	}
	for name, mutate := range invalid {
		spec := validStateful()
		policy := *spec.Stateful
		spec.Stateful = &policy
		mutate(&spec)
		if err := spec.Validate(); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("%s: Validate() = %v", name, err)
		}
	}
	if err := ValidateSpecs([]ServiceSpec{statelessSpec(1, 2), statelessSpec(1, 3)}); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("repeated role accepted: %v", err)
	}
}

func TestNewRejectsResourceMismatch(t *testing.T) {
	spec := statelessSpec(1, 2)
	spec.Resources = placement.Resources{CPU: 1, MemoryBytes: 1, DiskBytes: 1}
	_, err := New(Config{Cell: "gru", Specs: []ServiceSpec{spec}, Profiles: testProfiles, Hosts: newFakeCell(),
		Writer: newFakeCell(), Fencer: &fakeFencer{}})
	if !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("New = %v", err)
	}
	spec.Role = "unprofiled"
	spec.Resources = placement.Resources{}
	if _, err := New(Config{Cell: "gru", Specs: []ServiceSpec{spec}, Profiles: testProfiles, Hosts: newFakeCell(),
		Writer: newFakeCell(), Fencer: &fakeFencer{}}); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("New without profile = %v", err)
	}
}
