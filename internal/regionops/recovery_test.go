package regionops

import (
	"context"
	"crypto/ed25519"
	"slices"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/identity"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

// TestRecoveredIntentReconcilesBeforeReadmission pins ts-reviewer 13222: a
// journaled spending intent is reconciled by observation before any
// readmission, so an effect that already exists is recorded even when its
// admission expired and a new one would be refused; an absent effect is
// re-run only after a successful readmission.
func TestRecoveredIntentReconcilesBeforeReadmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	t.Cleanup(decisionlog.SetDefault(&recorder{}))
	js := newTestJetStream(t)
	leader := startGlobalAuthority(ctx, t, js)
	store, err := regionlifecycle.OpenStore(ctx, js, 1, leader)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC()
	clock := start
	machine := regionlifecycle.Machine{Policy: regionlifecycle.Policy{MaxRegions: 3, MonthlyCeilingCents: 30_000,
		AdmissionTTL: regionlifecycle.DefaultAdmissionTTL, ProposalTTL: 72 * time.Hour,
		ApprovalMaxLifetime: 7 * 24 * time.Hour, ClockSkew: time.Minute, MinIdle: 14 * 24 * time.Hour,
		Approvers: map[string]ed25519.PublicKey{approver: public}}}
	epoch := leader.Current().Epoch

	// A crash left the subscription intent journaled in Subscribing.
	journaled := func(cell, ociRegion string) {
		t.Helper()
		proposal := regionlifecycle.Proposal{ID: entityid.Derive("test-proposal", cell), Cell: cell, OCIRegion: ociRegion,
			Reason: "planner: capacity", EvidenceDigests: []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
			EstimatedMonthlyCents: 9_000, ProposedAt: start}
		record := mustProposed(t, machine, proposal, start)
		if _, err := store.Create(ctx, epoch, record); err != nil {
			t.Fatal(err)
		}
		payload, err := protocol.EncodeJSON(regionlifecycle.ApprovalPayload{Cell: cell, ProposalDigest: proposal.Digest(),
			MaxMonthlyCents: 10_000})
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: cell,
			Kind: regionlifecycle.ApproveExpansionKind, Actor: approver, OperationID: proposal.ID, Generation: 1},
			start, start.Add(48*time.Hour), private)
		if err != nil {
			t.Fatal(err)
		}
		next, err := machine.Approve(record, envelope, start)
		if err != nil {
			t.Fatal(err)
		}
		if next, err = machine.Admit(next, regionlifecycle.CostAdmission{EstimatedMonthlyCents: 9_000,
			EvidenceDigest: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", AdmittedAt: start},
			regionlifecycle.Fleet{Regions: 1, CommittedMonthlyCents: 9_000}, start); err != nil {
			t.Fatal(err)
		}
		if next, _, err = machine.BeginStep(next, start); err != nil {
			t.Fatal(err)
		}
		next.Pending.Epoch = epoch
		stored, revision, err := store.Get(ctx, cell)
		if err != nil {
			t.Fatal(err)
		}
		next.Generation = stored.Generation + 1
		if _, err := store.Update(ctx, epoch, stored, next, revision); err != nil {
			t.Fatal(err)
		}
	}
	journaled("sfo", "us-sanjose-1")
	journaled("fra", "eu-frankfurt-1")

	// sfo's subscription exists and is READY; fra's does not exist.
	tenancy := &fakeIdentity{status: map[string]identity.RegionSubscriptionStatusEnum{
		"us-sanjose-1": identity.RegionSubscriptionStatusReady}}
	// Both admissions expired, and the price now exceeds the approvals' cap.
	clock = start.Add(20 * time.Minute)
	loop := &Loop{Store: store, Machine: machine, Home: regionlifecycle.Home{Cell: "gru", MonthlyCents: 9_000},
		Leader: leader, Admissions: PriceList{MonthlyCents: map[string]uint64{"sfo": 11_000, "fra": 11_000}},
		Effectors: Effectors{regionlifecycle.StepSubscribe: Subscription{API: tenancy, TenancyID: "ocid1.tenancy.oc1..test"}},
		Now:       func() time.Time { return clock }}
	report := loop.Tick(ctx)
	if !slices.Equal(report.Advanced, []string{"sfo"}) || !slices.Equal(report.Waiting, []string{"fra"}) ||
		len(tenancy.creates) != 0 {
		t.Fatalf("expired-admission tick = %+v (creates %v)", report, tenancy.creates)
	}
	if record, _, err := store.Get(ctx, "sfo"); err != nil || record.Phase != regionlifecycle.Subscribed {
		t.Fatalf("observed sfo = %+v, %v", record, err)
	}
	if record, _, err := store.Get(ctx, "fra"); err != nil || record.Phase != regionlifecycle.Subscribing ||
		!record.Admission.AdmittedAt.Equal(start) {
		t.Fatalf("refused fra = %+v, %v", record, err)
	}

	// With an acceptable price the absent effect is readmitted and re-run
	// with its journaled create key.
	loop.Admissions = PriceList{MonthlyCents: map[string]uint64{"sfo": 9_000, "fra": 9_000}}
	report = loop.Tick(ctx)
	if !slices.Equal(report.Readmitted, []string{"fra"}) || !slices.Equal(tenancy.creates, []string{"FRA"}) {
		t.Fatalf("readmitted tick = %+v (creates %v)", report, tenancy.creates)
	}
	record, _, err := store.Get(ctx, "fra")
	if err != nil || record.Phase != regionlifecycle.Held || record.Pending == nil ||
		tenancy.tokens[0] != record.Pending.CreateKey || !record.Admission.AdmittedAt.Equal(clock) {
		t.Fatalf("re-run fra = %+v, %v", record, err)
	}
}
