package main

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

func TestRuntimeBudgetTargetRequiresAcceptedWriterScope(t *testing.T) {
	for _, mode := range []string{"valid", "follower", "epoch", "proof", "organization", "regions", "deleted", "pending", "stream"} {
		t.Run(mode, func(t *testing.T) {
			config, record := databasePlanFixture()
			plan, err := config.plan(t.Context(), record, &databasePlanJournal{}, databasePlacementJournal{})
			if err != nil {
				t.Fatal(err)
			}
			record.Targets, record.PlacementTargets, record.State = plan.Members, plan.Placements, "ready"
			stage := new(pb.PlacementStageRequest)
			if err := proto.Unmarshal(plan.Members[0].Proposal, stage); err != nil {
				t.Fatal(err)
			}
			for i := range record.Targets {
				record.Targets[i].Installed = true
			}
			for i := range record.PlacementTargets {
				p := &record.PlacementTargets[i]
				p.AcceptedReceipt, p.AcceptedRevision, p.AcceptedEpoch, p.AcceptedGeneration, p.AcceptedProofDigest = []byte("accepted"), 1, stage.Proposal.Epoch, stage.Proposal.Generation, strings.Repeat("a", 64)
			}
			resource := databaselifecycle.Resource{Identity: databaselifecycle.Identity{Environment: record.Request.Environment, OrganizationID: record.Request.TenantID, ProjectID: record.Request.ProjectID, DatabaseID: record.DatabaseID}, Regions: record.Request.Regions, CreatedAt: time.Now(), Streams: []databaselifecycle.Stream{{Region: "GRU", Epoch: stage.Proposal.Epoch, StartedAt: time.Now()}}}
			envelope := writebudget.AllocationEnvelope{Placement: strings.Repeat("a", 64), Grant: writebudget.Grant{OrganizationID: record.Request.TenantID, DatabaseID: record.DatabaseID, HolderID: config.Regions[0].Writer.MemberID, Regions: record.Request.Regions, WriterEpoch: stage.Proposal.Epoch}}
			switch mode {
			case "follower":
				envelope.Grant.HolderID = config.Regions[0].Follower.MemberID
			case "epoch":
				envelope.Grant.WriterEpoch++
			case "proof":
				envelope.Placement = strings.Repeat("b", 64)
			case "organization":
				envelope.Grant.OrganizationID = "other"
			case "regions":
				envelope.Grant.Regions = []string{"FRA", "GRU"}
			case "deleted":
				resource.AccessRevoked = true
			case "stream":
				resource.Streams[0].StoppedAt = time.Now()
			case "pending":
				record.State = "placement_pending"
			}
			target, err := acceptedBudgetTarget(record, []databaselifecycle.Resource{resource}, envelope)
			if mode == "valid" {
				if err != nil || target.MemberID != config.Regions[0].Writer.MemberID {
					t.Fatalf("target=%+v err=%v", target, err)
				}
			} else if err == nil {
				t.Fatal("invalid scope accepted")
			}
		})
	}
}

func TestRuntimeBudgetSnapshotUsesCanonicalBillingFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	policy := map[string]any{"organizationId": "org", "cycleId": "cycle", "policyEpoch": 1, "consentEpoch": 2, "writerEpoch": 3, "writerEpochs": map[string]uint64{"holder": 3}, "includedWriteUnits": "123", "includedAllowanceUnits": 999, "includedAllowanceEndsAt": "2030-01-01T00:00:00Z", "paidExcessEnabled": true, "rateNanoDollar": 1000, "accruedNonWriteNano": "5000", "databaseAccruedNonWriteNano": map[string]string{"db": "5000"}}
	envelope := productionWriteBudgetPolicyFile{SchemaVersion: 1, OrganizationID: "org", CycleID: "cycle", AccountRevision: "revision", PolicyGeneration: 9, Policy: policy, Checksum: "checksum"}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, initial, err := loadProductionWriteBudgetPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.IncludedAllowanceUnits != 123 || got.AccruedNonWriteNano != 5000 || got.DatabaseAccruedNonWriteNano["db"] != 5000 || got.IncludedAllowanceEndsAt.Format(time.RFC3339) != "2030-01-01T00:00:00Z" || initial.PolicyGeneration != 9 || initial.AccountRevision != "revision" {
		t.Fatalf("policy=%+v initial=%+v", got, initial)
	}
	policy["includedWriteUnits"] = "0123"
	data, _ = json.Marshal(envelope)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadProductionWriteBudgetPolicy(path); err == nil {
		t.Fatal("noncanonical allowance accepted")
	}
}
