package vmqual

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

const FourthRegion vmnet.RegionCode = "IAD"

// FourthRegionGuests are member hosts, each running its own orchestrator.
// Neither host joins the permanent GRU/SFO/FRA global control replica set.
func FourthRegionGuests(memoryMiB int64) []Guest {
	if memoryMiB == 0 {
		memoryMiB = DefaultMemoryMiB
	}
	return []Guest{
		{ID: "iad-member-1", Region: FourthRegion, VCPU: 1, MemoryMiB: memoryMiB, Service: true},
		{ID: "iad-member-2", Region: FourthRegion, VCPU: 1, MemoryMiB: memoryMiB, Service: true},
	}
}

// AdmitRegion journals the two declared IAD hosts before creating either VM.
// The caller must first accept the fenced control admission. Network slots
// must already belong to this run; this method cannot create foreign networks
// or expand the permanent global control replica topology.
func (s *Stack) AdmitRegion(ctx context.Context, guests []Guest) error {
	if s == nil || ctx == nil {
		return errors.New("vmqual: region admission requires stack and context")
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.cleanupProbe || s.config.JournalPath == "" {
		return errors.New("vmqual: region admission requires a durable baseline stack")
	}
	if len(guests) != 2 || !reflect.DeepEqual(guests, FourthRegionGuests(guests[0].MemoryMiB)) || guests[0].MemoryMiB < 256 || guests[0].MemoryMiB > MaxGuestMemoryMiB {
		return errors.New("vmqual: region admission requires the two declared IAD member hosts without global replicas")
	}
	snapshot := s.Snapshot()
	if !snapshot.Started || len(snapshot.VMs) != len(snapshot.Guests) {
		return errors.New("vmqual: complete baseline must be ready before region admission")
	}
	if len(snapshot.Guests) == 8 {
		if !reflect.DeepEqual(snapshot.Guests[6:], guests) {
			return errors.New("vmqual: conflicting repeated region admission")
		}
		return s.EnforceBudget(ctx)
	}
	if len(snapshot.Guests) != 6 {
		return errors.New("vmqual: region admission requires exactly six baseline hosts")
	}
	if err := s.EnforceBudget(ctx); err != nil {
		return err
	}
	declared, ok := s.config.Network.(interface{ Plan() vmnet.NetworkPlan })
	if !ok {
		return errors.New("vmqual: region admission requires an owned declared network plan")
	}
	plan := declared.Plan()
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("vmqual: region admission network: %w", err)
	}
	if err := validateFourthRegionSlots(plan, guests); err != nil {
		return err
	}
	s.journalMu.Lock()
	journal := s.journal
	validJournal := journal != nil && journal.NetworkPhase == networkPhaseApplied && reflect.DeepEqual(journal.Network, plan.Journal)
	s.journalMu.Unlock()
	if !validJournal {
		return errors.New("vmqual: region slots differ from the applied durable network journal")
	}
	totalMemory := guests[0].MemoryMiB + guests[1].MemoryMiB
	for _, guest := range snapshot.Guests {
		totalMemory += guest.MemoryMiB
	}
	if totalMemory<<20 > s.config.MaxRSSBytes {
		return errors.New("vmqual: region admission exceeds the configured memory budget")
	}
	runCtx := context.WithValue(ctx, qualificationRunIDKey{}, s.runID)
	planned := make([]JournalVM, 0, 2)
	for _, guest := range guests {
		resources := VMResourceIdentity{RunID: s.runID}
		if planner, ok := s.config.VMFactory.(VMResourcePlanner); ok {
			var err error
			resources, err = planner.PlanResources(runCtx, guest)
			if err != nil {
				return fmt.Errorf("vmqual: plan admitted host %s: %w", guest.ID, err)
			}
			if resources.RunID == "" {
				resources.RunID = s.runID
			}
			if resources.RunID != s.runID {
				return errors.New("vmqual: admitted host resource plan belongs to another run")
			}
		}
		if resources.StateDir != "" && resources.RunMarkerPath == "" {
			resources.RunMarkerPath = filepath.Join(resources.StateDir, RunMarkerName)
		}
		claim := filepath.Join(s.config.StateRoot, ".vmqual-runs", s.runID+".claims", guest.ID+".json")
		planned = append(planned, journalVMFromResources(s.runID, guest, claim, resources))
	}
	if err := s.updateJournal(func(j *Journal) error {
		if len(j.VMs) != 6 {
			return errors.New("vmqual: region admission journal already contains non-baseline resources")
		}
		j.VMs = append(j.VMs, planned...)
		return nil
	}); err != nil {
		return fmt.Errorf("vmqual: persist region admission: %w", err)
	}
	s.mu.Lock()
	s.guests = append(s.guests, guests...)
	s.config.Guests = append(append([]Guest(nil), s.config.Guests...), guests...)
	s.started = false
	s.mu.Unlock()
	if err := s.startSelectedGuests(runCtx, map[vmnet.RegionCode]bool{FourthRegion: true}); err != nil {
		return err
	}
	if err := s.EnforceBudget(runCtx); err != nil {
		return errors.Join(err, s.cleanupAfterFailure())
	}
	snapshot = s.Snapshot()
	for _, guest := range guests {
		observed, err := snapshot.VMs[guest.ID].Inspect(runCtx)
		if err != nil {
			return errors.Join(err, s.cleanupAfterFailure())
		}
		if observed.ID != guest.ID || observed.Region != FourthRegion || !observed.Running || !observed.Ready {
			return errors.Join(errors.New("vmqual: admitted guest did not prove matching live identity and readiness"), s.cleanupAfterFailure())
		}
	}
	s.mu.Lock()
	s.started = len(s.vms) == 8
	s.mu.Unlock()
	return nil
}

func validateFourthRegionSlots(plan vmnet.NetworkPlan, guests []Guest) error {
	for _, region := range plan.Regions {
		if region.Code != FourthRegion {
			continue
		}
		if len(region.Guests) != 2 {
			return errors.New("vmqual: IAD network must declare exactly two guest slots")
		}
		for i, slot := range region.Guests {
			if slot.ID != guests[i].ID {
				return errors.New("vmqual: admitted IAD guest differs from its owned network slot")
			}
		}
		return nil
	}
	return errors.New("vmqual: IAD network slots were not declared before startup")
}

func journalOwnsGuestRegion(journal Journal, resource JournalVM) bool {
	fourthHost := resource.ID == "iad-member-1" || resource.ID == "iad-member-2"
	if !fourthHost && validRegion(resource.Region) {
		return true
	}
	if !fourthHost || resource.Region != string(FourthRegion) || journal.Network.Version == 0 {
		return false
	}
	for _, region := range journal.Network.Cleanup.Regions {
		if region == FourthRegion {
			return true
		}
	}
	return false
}
