package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"slices"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
)

// This producer runs only after the exact enrollment/provider identity join.
// Failed proof reads retain useful pressure telemetry but grant no scale-down.
// The destructive owner rechecks and freezes these authorities before effects.
type productionAutoscaleRemovalProofProducer struct {
	scope   string
	epoch   uint64
	lease   string
	key     ed25519.PublicKey
	head    func(context.Context, string) (placementtransition.Signed, error)
	records func(context.Context) ([]databaseadmission.Record, error)
	check   func(context.Context) error
}

func (p *productionAutoscaleRemovalProofProducer) Produce(ctx context.Context, region string, observations []autoscale.Observation) ([]autoscale.Observation, error) {
	result := slices.Clone(observations)
	for i := range result {
		result[i].Proof.ResidencyVerified = false
		result[i].Proof.QuorumVerified = false
		result[i].Proof.Removal = nil
	}
	if p == nil || p.head == nil || p.records == nil || p.check == nil || len(p.key) != ed25519.PublicKeySize || p.scope == "" || p.epoch == 0 || p.lease == "" {
		return result, nil
	}
	if err := p.check(ctx); err != nil {
		return nil, err
	}
	environment, cluster, validScope := strings.Cut(p.scope, "/")
	if !validScope || environment == "" || cluster == "" || len(result) < 3 {
		return result, nil
	}
	head, err := p.head(ctx, p.scope)
	if err != nil {
		return result, nil
	}
	var accepted placementtransition.Proof
	if !ed25519.Verify(p.key, append([]byte("terrabase-placement-transition-v1\x00"), head.Payload...), head.Signature) || json.Unmarshal(head.Payload, &accepted, json.RejectUnknownMembers(true)) != nil || accepted.Kind != "accepted_epoch" || accepted.SchemaVersion != 1 || accepted.Request.ScopeID != p.scope || accepted.AuthorityEpoch > p.epoch {
		return result, nil
	}
	digest, err := placementtransition.RequestDigest(accepted.Request)
	if err != nil || digest != accepted.RequestDigest {
		return result, nil
	}
	records, err := p.records(ctx)
	if err != nil {
		return result, nil
	}
	expected := map[string]map[string]bool{}
	local := map[string]autoscale.Observation{}
	resources, slots := map[string]bool{}, map[int]bool{}
	for _, observed := range result {
		if !observed.Authenticated || !observed.Healthy || observed.EngineID == "" || observed.HostID == "" || observed.Incarnation == "" || observed.ProviderResourceID == "" || observed.ProviderGeneration == 0 || observed.MemberSlot < 1 || resources[observed.ProviderResourceID] || slots[observed.MemberSlot] {
			return result, nil
		}
		if _, found := local[observed.EngineID]; found {
			return result, nil
		}
		local[observed.EngineID] = observed
		resources[observed.ProviderResourceID] = true
		slots[observed.MemberSlot] = true
		expected[observed.EngineID] = map[string]bool{}
	}
	seats := map[string]bool{}
	for _, member := range accepted.Request.Members {
		if strings.EqualFold(member.Region, region) {
			if _, found := local[member.Identity]; !found {
				return result, nil
			}
			seats[member.Identity] = true
		}
	}
	if len(seats) != 2 {
		return result, nil
	}
	for _, record := range records {
		if record.Request.Environment != environment || record.State != "ready" || record.DatabaseID == "" {
			return result, nil
		}
		key := autoscaleDatabaseKey(record.Request.TenantID, record.Request.ProjectID, record.DatabaseID)
		counts := map[string]int{}
		seen := map[string]bool{}
		for _, target := range record.Targets {
			if seen[target.ServerIdentity] || !slices.Contains(record.Request.Regions, target.Region) || !slices.ContainsFunc(accepted.Request.Members, func(member placementtransition.Member) bool {
				return member.Identity == target.ServerIdentity && member.Region == target.Region
			}) {
				return result, nil
			}
			seen[target.ServerIdentity] = true
			counts[target.Region]++
			if strings.EqualFold(target.Region, region) {
				if _, found := expected[target.ServerIdentity]; !found {
					return result, nil
				}
				expected[target.ServerIdentity][key] = true
			}
		}
		for _, selected := range record.Request.Regions {
			if counts[selected] != 2 {
				return result, nil
			}
		}
		for _, target := range record.PlacementTargets {
			if _, localMember := local[target.ServerIdentity]; localMember && !seats[target.ServerIdentity] {
				return result, nil
			}
		}
	}
	for _, observed := range result {
		assigned := expected[observed.EngineID]
		if len(assigned) != len(observed.Proof.Databases) {
			return result, nil
		}
		for _, database := range observed.Proof.Databases {
			key := autoscaleDatabaseKey(database.Tenant, database.Project, database.Database)
			if !assigned[key] || !database.RegionalCaughtUp || !database.CausalCaughtUp || !database.BackupCaughtUp || database.RegionalSequence < database.SourceSequence || database.BackupProtectedSequence < database.BackupSourceSequence {
				return result, nil
			}
			delete(assigned, key)
		}
	}
	// Fence mixed snapshots and authority changes before emitting proof facts.
	current, err := p.head(ctx, p.scope)
	if err != nil || current.KeyID != head.KeyID || signedDigest(current) != signedDigest(head) {
		return result, nil
	}
	currentRecords, err := p.records(ctx)
	if err != nil || databaseadmission.PlacementInventoryDigest(currentRecords) != databaseadmission.PlacementInventoryDigest(records) {
		return result, nil
	}
	if err := p.check(ctx); err != nil {
		return nil, err
	}
	for i := range result {
		proof := &autoscale.RemovalProof{ScopeID: p.scope, HeadDigest: signedDigest(head), InventoryDigest: databaseadmission.PlacementInventoryDigest(records), LeaseID: p.lease, AuthorityEpoch: p.epoch, Member: autoscaleRemovalMember(result[i]), NoAssignedData: len(result[i].Proof.Databases) == 0}
		for j := range result {
			if i != j {
				proof.Survivors = append(proof.Survivors, autoscaleRemovalMember(result[j]))
			}
		}
		result[i].Proof.Removal = proof
		result[i].Proof.ResidencyVerified = true
		result[i].Proof.QuorumVerified = true
	}
	return result, nil
}
func autoscaleRemovalMember(value autoscale.Observation) autoscale.RemovalMember {
	return autoscale.RemovalMember{HostID: value.HostID, EngineID: value.EngineID, ResourceID: value.ProviderResourceID, Incarnation: value.Incarnation, Generation: value.ProviderGeneration, Slot: value.MemberSlot}
}
func autoscaleDatabaseKey(tenant, project, database string) string {
	return tenant + "\x00" + project + "\x00" + database
}
