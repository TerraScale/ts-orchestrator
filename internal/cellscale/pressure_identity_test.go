package cellscale

import (
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
)

func assertIdentityInvalidated(t *testing.T, c *Controller, old NodeIdentity) {
	t.Helper()
	if _, found := c.lastPressure[old]; found {
		t.Fatalf("retired identity retained operational pressure: %+v", old)
	}
	if _, found := c.pendingRestarts[old]; found {
		t.Fatalf("retired identity retained restart progress: %+v", old)
	}
	if !c.retiredIncarnations[NodeIdentity{Name: old.Name, Incarnation: old.Incarnation}] {
		t.Fatalf("retired incarnation lost its replay tombstone: %+v", old)
	}
}

func TestReplacementPressureCannotAuthorizeActions(t *testing.T) {
	for _, action := range []Action{
		{Kind: KindScaleOut, Node: "gru-1-db-5", To: small},
		{Kind: KindRebalance, Node: "gru-1-db-1", Target: "gru-1-db-2", Tenant: project("org-1-0")},
		{Kind: KindScaleIn, Node: "gru-1-db-4"},
		{Kind: KindResize, To: Shape{OCPUs: 4, MemoryGB: 24}},
	} {
		t.Run(string(action.Kind), func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			original := s.observe()
			cached := *original.Nodes[0].Pressure
			cell.instances[0].ID = "replacement-ocid"
			s.now = s.now.Add(time.Second)
			s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
				if p.Node == cached.Node {
					*p = cached
				}
			}}
			current := s.observe()
			if current.Nodes[0].Pressure != nil || current.Nodes[0].ID != "replacement-ocid" || current.Replicas != nil {
				t.Fatalf("replacement inherited readiness despite fresh placement: %+v", current.Nodes[0])
			}
			assertIdentityInvalidated(t, s.controller, cached.Identity())
			if s.controller.pressureHighWater[cached.Node].Before(cached.SampledAt) ||
				!s.controller.retiredInstances[NodeIdentity{Name: cached.Node, InstanceID: cached.InstanceID}] {
				t.Fatal("replacement discarded predecessor refusal metadata")
			}
			if err := s.controller.apply(t.Context(), current, action); err == nil || !strings.Contains(err.Error(), "not ready") || len(cell.callLog()) != 0 {
				t.Fatalf("cached predecessor authorized %s: err=%v calls=%v", action.Kind, err, cell.callLog())
			}
			got, err := s.controller.Tick(t.Context())
			if err != nil || got.Kind != KindHold || got.Reason != ReasonNotSettled || len(cell.callLog()) != 0 {
				t.Fatalf("replacement cache did not hold decision: %+v err=%v calls=%v", got, err, cell.callLog())
			}
		})
	}
}

func TestReplacementPressureRequiresNewProcessAndPostDiscoverySample(t *testing.T) {
	for _, mode := range []string{"old process", "before discovery", "within skew", "skew boundary", "fresh replacement"} {
		t.Run(mode, func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			original := s.observe()
			candidate := *original.Nodes[0].Pressure
			cell.instances[0].ID = "replacement-ocid"
			candidate.InstanceID = cell.instances[0].ID
			cell.process[candidate.Node]++
			s.now = s.now.Add(time.Second)
			discovered := s.now
			candidate.ProcessID = entityid.Derive("test-process", candidate.Node+"-p2")
			candidate.SampledAt = discovered.Add(MaxPressureClockSkew + time.Second)
			switch mode {
			case "old process":
				candidate.ProcessID = original.Nodes[0].Pressure.ProcessID
			case "before discovery":
				candidate.SampledAt = discovered.Add(-time.Second)
			case "within skew":
				candidate.SampledAt = discovered.Add(MaxPressureClockSkew - time.Second)
			case "skew boundary":
				candidate.SampledAt = discovered.Add(MaxPressureClockSkew)
			}
			// The first report discovers the ID; the second arrives with the
			// selected timestamp after the observer's clock has caught up.
			first := true
			s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
				if p.Node == candidate.Node {
					*p = candidate
					if first {
						first = false
						*p = *original.Nodes[0].Pressure
					}
				}
			}}
			s.observe()
			s.now = discovered.Add(MaxPressureClockSkew + 10*time.Second)
			current := s.observe()
			if mode == "fresh replacement" {
				if current.Nodes[0].Pressure == nil || current.Nodes[0].Pressure.ProcessID != candidate.ProcessID {
					t.Fatal("fresh replacement stayed fenced after repeated discovery")
				}
				if err := s.controller.apply(t.Context(), current, Action{Kind: KindScaleOut, Node: "gru-1-db-5", To: small}); err != nil || len(cell.callLog()) != 2 {
					t.Fatalf("fresh replacement blocked safe launch/join: err=%v calls=%v", err, cell.callLog())
				}
			} else if current.Nodes[0].Pressure != nil || len(cell.callLog()) != 0 {
				t.Fatalf("unsafe replacement report accepted: %s %+v", mode, current.Nodes[0])
			}
		})
	}
}

func TestReplacementPressureIdentitySurvivesAbsence(t *testing.T) {
	for _, mode := range []string{"absent", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			original := s.observe()
			cached := *original.Nodes[0].Pressure
			instance := cell.instances[0]
			s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
				if p.Node == cached.Node {
					*p = cached
				}
			}}
			if mode == "absent" {
				cell.instances = slices.Delete(cell.instances, 0, 1)
			} else {
				cell.instances[0].Foreign = true
			}
			s.now = s.now.Add(time.Second)
			s.observe()
			instance.ID = "replacement-after-absence"
			if mode == "absent" {
				cell.instances = append(cell.instances, instance)
			} else {
				cell.instances[0] = instance
			}
			s.now = s.now.Add(time.Second)
			current := s.observe()
			if current.Nodes[0].Pressure != nil || len(cell.callLog()) != 0 {
				t.Fatal("removal discarded pressure identity history")
			}
		})
	}
}

func TestReplacementPressureDiscoveryDuringEvidenceIsRetained(t *testing.T) {
	for _, read := range []string{"recheck", "readiness", "replicas"} {
		t.Run(read, func(t *testing.T) {
			cell := newFakeCell(4, small, 2, 150)
			s := newSim(t, testPolicy(), cell, time.Minute)
			original := s.observe()
			s.now = s.now.Add(time.Second)
			discovered := s.now
			var err error
			if read == "readiness" {
				s.controller.config.Source = changedLoad{cell, func(*NodePressure) { cell.instances[0].ID = "replacement-ocid" }}
				err = s.controller.waitNode(t.Context(), identities(original.Nodes), "gru-1-db-1", func(NodePressure) bool { return true })
			} else {
				cell.replicas = func() (ReplicaSnapshot, error) {
					cell.instances[0].ID = "replacement-ocid"
					return safeReplicaSnapshot(s.now, cell), nil
				}
				if read == "recheck" {
					_, err = s.controller.recheck(t.Context(), identities(original.Nodes), "", "", original.Nodes)
				} else {
					err = s.controller.waitReplicas(t.Context(), names(original.Nodes), original)
				}
			}
			requireIdentityFailure(t, err)
			candidate := *original.Nodes[0].Pressure
			candidate.InstanceID = cell.instances[0].ID
			cell.process[candidate.Node]++
			candidate.ProcessID = entityid.Derive("test-process", candidate.Node+"-p2")
			candidate.SampledAt = discovered.Add(MaxPressureClockSkew + time.Second)
			s.now = discovered.Add(20 * time.Second)
			cell.replicas = nil
			s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
				if p.Node == candidate.Node {
					*p = candidate
				}
			}}
			// This sample is newer than the first discovery fence but predates
			// this observe. Discovering the ID again must not move its floor.
			current := s.observe()
			if current.Nodes[0].Pressure == nil || len(cell.callLog()) != 0 {
				t.Fatal("final evidence read forgot discovery or advanced its floor again")
			}
		})
	}
}

func TestReplacementPressureRetainsRejectedHighWaterAndConflict(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	original := s.observe()
	candidate := *original.Nodes[0].Pressure
	cell.instances[0].ID = "replacement-ocid"
	s.now = s.now.Add(time.Second)
	s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
		if p.Node == candidate.Node {
			*p = candidate
		}
	}}
	s.observe()
	s.now = s.now.Add(10 * time.Second)
	candidate.SampledAt = s.now // Fresh predecessor evidence is still unknown.
	if current := s.observe(); current.Nodes[0].Pressure != nil {
		t.Fatal("new timestamp from predecessor restored readiness")
	}
	assertIdentityInvalidated(t, s.controller, candidate.Identity())
	if !s.controller.pressureHighWater[candidate.Node].Equal(candidate.SampledAt) {
		t.Fatal("blocked predecessor evidence lost its refusal high-water mark")
	}
	candidate.InstanceID = cell.instances[0].ID
	candidate.ProcessID = entityid.Derive("test-process", "replacement-process")
	candidate.SampledAt = candidate.SampledAt.Add(-time.Second)
	if current := s.observe(); current.Nodes[0].Pressure != nil {
		t.Fatal("new process regressed the retained sample high-water mark")
	}
	candidate.SampledAt = candidate.SampledAt.Add(time.Second)
	if current := s.observe(); current.Nodes[0].Pressure != nil {
		t.Fatal("new process bypassed equal-timestamp refusal floor")
	}
	if _, found := s.controller.lastPressure[candidate.Identity()]; found {
		t.Fatal("refused equal-timestamp successor became operational evidence")
	}
	candidate.SampledAt = s.now.Add(time.Second)
	if current := s.observe(); current.Nodes[0].Pressure == nil {
		t.Fatal("strictly newer replacement report did not restore readiness")
	}
	candidate.ProcessID = original.Nodes[0].Pressure.ProcessID
	candidate.SampledAt = s.now
	if current := s.observe(); current.Nodes[0].Pressure != nil {
		t.Fatal("first valid successor report cleared the predecessor-process guard")
	}
}

// Identity tracking must precede every pressure RPC, even for a later row.
func TestReplacementPressureTrackedBeforeAnyEvidenceRead(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	original := s.observe()
	cell.instances[3].ID = "replacement-ocid"
	s.now = s.now.Add(time.Second)
	s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
		if p.Node == "gru-1-db-1" {
			if s.controller.retainPressure("gru-1-db-4", *original.Nodes[3].Pressure) {
				t.Fatal("earlier pressure RPC could accept a later replacement's predecessor")
			}
		}
	}}
	if _, err := s.controller.observe(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestReplacementPressureFloorSurvivesChainedReplacementsAndClockRegression(t *testing.T) {
	cell := newFakeCell(4, small, 2, 150)
	s := newSim(t, testPolicy(), cell, time.Minute)
	original := s.observe()
	s.controller.config.Members = cell // Inventory must not advance the clock in this pressure-only case.
	candidate := *original.Nodes[0].Pressure
	s.controller.config.Source = changedLoad{cell, func(p *NodePressure) {
		if p.Node == candidate.Node {
			*p = candidate
		}
	}}
	s.now = s.now.Add(10 * time.Second)
	discovered := s.now
	cell.instances[0].ID = "replacement-B"
	s.observe()
	s.now = discovered.Add(-time.Second)
	cell.instances[0].ID = "replacement-C"
	s.observe()
	s.now = discovered.Add(20 * time.Second)
	candidate.InstanceID = cell.instances[0].ID
	candidate.ProcessID = entityid.Derive("test-process", "replacement-C-process")
	candidate.SampledAt = discovered.Add(MaxPressureClockSkew)
	if current := s.observe(); current.Nodes[0].Pressure != nil {
		t.Fatal("backwards clock weakened the prior replacement's skew floor")
	}
	candidate.SampledAt = candidate.SampledAt.Add(time.Second)
	if current := s.observe(); current.Nodes[0].Pressure == nil {
		t.Fatal("chained replacement could not recover past the retained floor")
	}
}
