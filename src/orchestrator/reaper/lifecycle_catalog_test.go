package reaper

import (
	"testing"
	"time"
)

func TestLifecyclePolicyDenialSurvivesReaperTranslation(t *testing.T) {
	now := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	last := now.Add(-100 * 24 * time.Hour)
	facts := LifecyclePolicyFacts{DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Revision: "revision-1", Plan: "free", LastAuthorizedRequestAt: &last, PauseEligible: true, OwnerEmails: []string{"z@example.com", "a@example.com"}}
	database, err := policyDatabase(facts, now)
	if err != nil {
		t.Fatal(err)
	}
	if !database.Exemption.activeAt(now) || database.OwnerEmail != "a@example.com" || database.OwnershipProof != facts.Revision {
		t.Fatalf("policy denial lost: %+v", database)
	}
	facts.DeletionEligible = true
	database, err = policyDatabase(facts, now)
	if err != nil || database.Exemption.Active {
		t.Fatalf("eligible observation rejected: %+v %v", database, err)
	}
	facts.DeletionProtection = true
	database, err = policyDatabase(facts, now)
	if err != nil || !database.Exemption.Active {
		t.Fatalf("protection lost: %+v %v", database, err)
	}
}

func TestLifecyclePolicyUnknownActivityAndPaidPlansStaySafe(t *testing.T) {
	facts := LifecyclePolicyFacts{DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Revision: "revision-1", Plan: "pro", OwnerEmails: []string{"owner@example.com"}}
	database, err := policyDatabase(facts, time.Now())
	if err != nil || database.Plan != PlanPaid || !database.LastRequest.IsZero() {
		t.Fatalf("unknown activity or paid plan changed: %+v %v", database, err)
	}
	facts.OwnerEmails = nil
	if _, err := policyDatabase(facts, time.Now()); err == nil {
		t.Fatal("missing owner accepted")
	}
}

func TestLifecyclePolicyRecentActivityCanReachReactivation(t *testing.T) {
	now := time.Now()
	last := now.Add(-time.Minute)
	facts := LifecyclePolicyFacts{DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Revision: "revision-1", Plan: "free", LastAuthorizedRequestAt: &last, OwnerEmails: []string{"owner@example.com"}, DeletionProtection: true}
	database, err := policyDatabase(facts, now)
	if err != nil || database.Exemption.Active || !database.LastRequest.Equal(last) {
		t.Fatalf("recent activity cannot reach reactivation: %+v %v", database, err)
	}
}

func TestLifecyclePolicyBillingGraceFactsReachReaperDatabase(t *testing.T) {
	now := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	deadline := now.Add(-time.Hour)
	facts := LifecyclePolicyFacts{
		DatabaseID:              "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Revision:                "revision-1",
		Plan:                    "pro",
		OwnerEmails:             []string{"owner@example.com"},
		BillingGraceDeadline:    &deadline,
		BillingDeletionEligible: true,
		DeletionReasons:         []string{"uncovered-storage"},
		Coverage: LifecycleBillingCoverage{UncoveredStorage: &LifecycleBillingGrace{
			StartedAt: deadline.Add(-30 * 24 * time.Hour), Deadline: deadline,
		}},
	}
	database, err := policyDatabase(facts, now)
	if err != nil {
		t.Fatal(err)
	}
	if database.BillingGraceDeadline == nil || !database.BillingGraceDeadline.Equal(deadline) || !database.BillingDeletionEligible || database.SelectedGraceCondition != "uncovered-storage" {
		t.Fatalf("billing grace facts were dropped: %+v", database)
	}
}
