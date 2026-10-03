package regionlifecycle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

var testEpoch = time.Date(2026, time.October, 2, 12, 0, 0, 0, time.UTC)

const approver = "operator:mario"

func digest(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

type fixture struct {
	machine Machine
	key     ed25519.PrivateKey
	now     time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{now: testEpoch, key: private, machine: Machine{Policy: Policy{
		MaxRegions: 3, MonthlyCeilingCents: 20_000, AdmissionTTL: DefaultAdmissionTTL,
		ProposalTTL: 72 * time.Hour, ApprovalMaxLifetime: 7 * 24 * time.Hour, ClockSkew: time.Minute,
		MinIdle: 14 * 24 * time.Hour, Approvers: map[string]ed25519.PublicKey{approver: public},
	}}}
}

func (f *fixture) proposal() Proposal {
	return Proposal{ID: "sfo-capacity-1", Cell: "sfo", OCIRegion: "us-sanjose-1",
		Reason: "placement intents name sfo", EvidenceDigests: []string{digest("intent")},
		EstimatedMonthlyCents: 9_000, ProposedAt: f.now}
}

func (f *fixture) sign(t *testing.T, record Record, kind string, maxCents uint64, key ed25519.PrivateKey, lifetime time.Duration) protocol.Envelope {
	t.Helper()
	payload, err := protocol.EncodeJSON(ApprovalPayload{Cell: record.Cell, ProposalDigest: record.Proposal.Digest(), MaxMonthlyCents: maxCents})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: record.Cell, Kind: kind, Actor: approver,
		OperationID: record.Proposal.ID, Generation: record.ProposalGeneration}, f.now, f.now.Add(lifetime), key)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func (f *fixture) approval(t *testing.T, record Record) protocol.Envelope {
	return f.sign(t, record, ApproveExpansionKind, 10_000, f.key, 48*time.Hour)
}

func (f *fixture) admission() CostAdmission {
	return CostAdmission{EstimatedMonthlyCents: 9_000, EvidenceDigest: digest("estimate"), AdmittedAt: f.now}
}

// admitted returns a record in Admitted.
func (f *fixture) admitted(t *testing.T) Record {
	t.Helper()
	record, err := f.machine.Propose(f.proposal(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if record, err = f.machine.Approve(record, f.approval(t, record), f.now); err != nil {
		t.Fatal(err)
	}
	if record, err = f.machine.Admit(record, f.admission(), Fleet{Regions: 1, CommittedMonthlyCents: 5_000}, f.now); err != nil {
		t.Fatal(err)
	}
	return record
}

func (f *fixture) runStep(t *testing.T, record Record) Record {
	t.Helper()
	next, intent, err := f.machine.BeginStep(record, f.now)
	if err != nil {
		t.Fatalf("begin from %s: %v", record.Phase, err)
	}
	if next.Pending == nil || *next.Pending != intent || intent.CreateKey != CreateKey(record.Cell, record.Proposal.ID, record.ProposalGeneration, intent.Step) {
		t.Fatalf("intent was not journaled before the effect: %+v", next.Pending)
	}
	done, err := f.machine.CompleteStep(next, StepResult{Step: intent.Step, CreateKey: intent.CreateKey,
		ResourceID: "ocid1.test." + string(intent.Step), EvidenceDigest: digest(string(intent.Step))}, f.now)
	if err != nil {
		t.Fatalf("complete %s: %v", intent.Step, err)
	}
	if err := done.Validate(); err != nil {
		t.Fatal(err)
	}
	return done
}

func TestLifecycleBringUpAndRetirementFollowTheStepTable(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	record := f.admitted(t)
	phases := []Phase{record.Phase}
	for record.Phase != Active {
		previous := record.Generation
		record = f.runStep(t, record)
		if record.Generation != previous+2 {
			t.Fatalf("generation %d -> %d; every transition must advance once", previous, record.Generation)
		}
		phases = append(phases, record.Phase)
	}
	want := []Phase{Admitted, Subscribed, FoundationReady, ImageReady, Signed, SeedReserved, SeedObserved,
		SeedAdmitted, ClusterFormed, Linked, PublicAPIReady, HandedOff, Active}
	if !slices.Equal(phases, want) {
		t.Fatalf("phases = %v\nwant %v", phases, want)
	}
	if len(record.Completed) != 12 || record.Pending != nil {
		t.Fatalf("completed %d steps, pending %+v", len(record.Completed), record.Pending)
	}

	if _, err := f.machine.ProposeRetire(record, IdleEvidence{IdleSince: f.now.Add(-time.Hour), EvidenceDigest: digest("idle")}, f.now); !errors.Is(err, ErrNotIdle) {
		t.Fatalf("retire after one idle hour = %v", err)
	}
	if _, err := f.machine.ProposeRetire(record, IdleEvidence{IdleSince: f.now.Add(-30 * 24 * time.Hour), PlacementIntents: 1, EvidenceDigest: digest("idle")}, f.now); !errors.Is(err, ErrNotIdle) {
		t.Fatalf("retire with a placement intent = %v", err)
	}
	if _, err := f.machine.ProposeRetire(record, IdleEvidence{IdleSince: f.now.Add(-30 * 24 * time.Hour), ActiveMembers: 2, EvidenceDigest: digest("idle")}, f.now); !errors.Is(err, ErrNotIdle) {
		t.Fatalf("retire with active members = %v", err)
	}
	record, err := f.machine.ProposeRetire(record, IdleEvidence{IdleSince: f.now.Add(-30 * 24 * time.Hour), EvidenceDigest: digest("idle")}, f.now)
	if err != nil || record.Phase != RetireProposed {
		t.Fatalf("propose retire = %s, %v", record.Phase, err)
	}
	if _, _, err := f.machine.BeginStep(record, f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("retirement step ran without approval: %v", err)
	}
	if _, err := f.machine.ApproveRetire(record, f.approval(t, record), f.now); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("expansion approval accepted for retirement: %v", err)
	}
	record, err = f.machine.ApproveRetire(record, f.sign(t, record, ApproveRetirementKind, 0, f.key, time.Hour), f.now)
	if err != nil {
		t.Fatal(err)
	}
	phases = []Phase{record.Phase}
	for record.Phase != Retired {
		record = f.runStep(t, record)
		phases = append(phases, record.Phase)
	}
	if want := []Phase{RetireApproved, Drained, Unlinked, ControllersTerminated, Retired}; !slices.Equal(phases, want) {
		t.Fatalf("retire phases = %v, want %v", phases, want)
	}
	assertTerminal(t, f, record)
}

func TestApprovalAndAdmissionGuards(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	proposed, err := f.machine.Propose(f.proposal(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	_, stranger, _ := ed25519.GenerateKey(nil)
	other := proposed
	other.Proposal.EstimatedMonthlyCents = 1
	approvals := map[string]protocol.Envelope{
		"unknown key":        f.sign(t, proposed, ApproveExpansionKind, 10_000, stranger, time.Hour),
		"retirement kind":    f.sign(t, proposed, ApproveRetirementKind, 10_000, f.key, time.Hour),
		"other proposal":     f.sign(t, other, ApproveExpansionKind, 10_000, f.key, time.Hour),
		"budget below quote": f.sign(t, proposed, ApproveExpansionKind, 8_999, f.key, time.Hour),
		"too long lived":     f.sign(t, proposed, ApproveExpansionKind, 10_000, f.key, 30*24*time.Hour),
	}
	tampered := f.approval(t, proposed)
	tampered.Payload = []byte(`{"cell":"sfo","proposal_digest":"` + proposed.Proposal.Digest() + `","max_monthly_cents":99999999}`)
	approvals["tampered payload"] = tampered
	for name, approval := range approvals {
		if _, err := f.machine.Approve(proposed, approval, f.now); !errors.Is(err, ErrApprovalRequired) {
			t.Errorf("%s: approve = %v", name, err)
		}
	}
	if _, err := f.machine.Approve(proposed, f.approval(t, proposed), f.now.Add(48*time.Hour)); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("expired approval = %v", err)
	}
	if _, err := f.machine.Approve(proposed, f.approval(t, proposed), f.now.Add(73*time.Hour)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("approval of an expired proposal = %v", err)
	}
	approved, err := f.machine.Approve(proposed, f.approval(t, proposed), f.now)
	if err != nil {
		t.Fatal(err)
	}
	admissions := map[string]struct {
		admission CostAdmission
		fleet     Fleet
		want      error
	}{
		"stale":             {CostAdmission{9_000, digest("e"), f.now.Add(-16 * time.Minute)}, Fleet{}, ErrAdmissionStale},
		"future":            {CostAdmission{9_000, digest("e"), f.now.Add(time.Hour)}, Fleet{}, ErrAdmissionStale},
		"no evidence":       {CostAdmission{9_000, "", f.now}, Fleet{}, ErrAdmissionStale},
		"zero estimate":     {CostAdmission{0, digest("e"), f.now}, Fleet{}, ErrAdmissionStale},
		"region limit":      {f.admission(), Fleet{Regions: 3}, ErrRegionLimit},
		"global ceiling":    {f.admission(), Fleet{Regions: 1, CommittedMonthlyCents: 11_001}, ErrBudgetCeiling},
		"over approval cap": {CostAdmission{10_001, digest("e"), f.now}, Fleet{}, ErrBudgetCeiling},
	}
	for name, tc := range admissions {
		if _, err := f.machine.Admit(approved, tc.admission, tc.fleet, f.now); !errors.Is(err, tc.want) {
			t.Errorf("%s: admit = %v, want %v", name, err, tc.want)
		}
	}
	if _, err := f.machine.Admit(proposed, f.admission(), Fleet{}, f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("admit without approval = %v", err)
	}
	unsigned := approved
	unsigned.Approval = nil
	if _, err := f.machine.Admit(unsigned, f.admission(), Fleet{}, f.now); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("admit with a removed approval = %v", err)
	}
}

func TestSpendingStepsNeedFreshAdmissionAndLiveApproval(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	record := f.admitted(t)
	late := f.now.Add(20 * time.Minute)
	if _, _, err := f.machine.BeginStep(record, late); !errors.Is(err, ErrAdmissionStale) {
		t.Fatalf("spending step with a stale admission = %v", err)
	}
	refreshed, err := f.machine.Readmit(record, CostAdmission{9_000, digest("again"), late}, Fleet{Regions: 1}, late)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.machine.BeginStep(refreshed, late); err != nil {
		t.Fatalf("spending step after readmission = %v", err)
	}
	// Non-spending steps do not need a fresh admission, but every step needs
	// a live approval.
	f.now = late
	for record.Phase != ImageReady {
		record = f.runStep(t, refreshedAt(t, f, record))
	}
	if _, _, err := f.machine.BeginStep(record, f.now.Add(time.Hour)); err != nil {
		t.Fatalf("material step with an old admission = %v", err)
	}
	if _, _, err := f.machine.BeginStep(record, testEpoch.Add(49*time.Hour)); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("step after approval expiry = %v", err)
	}
	// A running step may be readmitted (a recovered intent needs a fresh
	// admission to re-execute), but a retirement never is.
	if _, err := f.machine.Readmit(Record{Phase: Draining}, f.admission(), Fleet{}, f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("readmit during retirement = %v", err)
	}
}

func refreshedAt(t *testing.T, f *fixture, record Record) Record {
	t.Helper()
	if def, ok := stepFrom(record.Phase); ok && def.spends {
		next, err := f.machine.Readmit(record, CostAdmission{9_000, digest("fresh"), f.now}, Fleet{Regions: 1}, f.now)
		if err != nil {
			t.Fatal(err)
		}
		return next
	}
	return record
}

func TestCompleteStepRequiresTheJournaledIntent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	running, intent, err := f.machine.BeginStep(f.admitted(t), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.machine.BeginStep(running, f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("second begin while running = %v", err)
	}
	for name, result := range map[string]StepResult{
		"wrong step":     {Step: StepFoundation, CreateKey: intent.CreateKey, EvidenceDigest: digest("x")},
		"wrong key":      {Step: intent.Step, CreateKey: CreateKey("sfo", "other", 1, intent.Step), EvidenceDigest: digest("x")},
		"no evidence":    {Step: intent.Step, CreateKey: intent.CreateKey},
		"non-hex digest": {Step: intent.Step, CreateKey: intent.CreateKey, EvidenceDigest: "evidence"},
	} {
		if _, err := f.machine.CompleteStep(running, result, f.now); !errors.Is(err, ErrStepMismatch) {
			t.Errorf("%s: complete = %v", name, err)
		}
	}
	if _, err := f.machine.CompleteStep(f.admitted(t), StepResult{Step: intent.Step, CreateKey: intent.CreateKey, EvidenceDigest: digest("x")}, f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("complete without a running step = %v", err)
	}
	keys := map[string]bool{}
	for _, def := range steps {
		key := CreateKey("sfo", "sfo-capacity-1", 1, def.step)
		if keys[key] || key != CreateKey("sfo", "sfo-capacity-1", 1, def.step) {
			t.Fatalf("create key for %s is not unique and deterministic", def.step)
		}
		keys[key] = true
	}
}

func TestHeldRegionsResumeOnlyByObservation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	running, intent, err := f.machine.BeginStep(f.admitted(t), f.now)
	if err != nil {
		t.Fatal(err)
	}
	held, err := f.machine.Fail(running, "OCI timeout", digest("timeout"), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if held.Phase != Held || held.Hold.Phase != Subscribing || held.Hold.Step != StepSubscribe || held.Pending == nil {
		t.Fatalf("held record = %+v", held)
	}
	if err := held.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.machine.Fail(held, "again", "", f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("fail while held = %v", err)
	}
	if _, err := f.machine.Fail(running, "bad", "not-a-digest", f.now); err == nil {
		t.Fatal("hold accepted non-digest evidence")
	}
	if _, _, err := f.machine.BeginStep(held, f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("begin while held = %v", err)
	}
	if _, err := f.machine.Resume(held, nil, f.now); !errors.Is(err, ErrStepMismatch) {
		t.Fatalf("resume without observation = %v", err)
	}
	if _, err := f.machine.Resume(held, &Observation{Step: intent.Step, CreateKey: "other", Found: true, EvidenceDigest: digest("x")}, f.now); !errors.Is(err, ErrStepMismatch) {
		t.Fatalf("resume with a foreign observation = %v", err)
	}
	retry, err := f.machine.Resume(held, &Observation{Step: intent.Step, CreateKey: intent.CreateKey}, f.now)
	if err != nil || retry.Phase != Subscribing || retry.Pending == nil || retry.Pending.CreateKey != intent.CreateKey {
		t.Fatalf("resume of an absent effect = %+v, %v; must retry with the same key", retry, err)
	}
	found, err := f.machine.Resume(held, &Observation{Step: intent.Step, CreateKey: intent.CreateKey, Found: true,
		ResourceID: "ocid1.x", EvidenceDigest: digest("found")}, f.now)
	if err != nil || found.Phase != Subscribed || found.Pending != nil {
		t.Fatalf("resume of a found effect = %+v, %v", found, err)
	}
	waiting, err := f.machine.Fail(found, "limits review", "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.machine.Resume(waiting, &Observation{Step: StepFoundation}, f.now); !errors.Is(err, ErrStepMismatch) {
		t.Fatalf("observation for a hold without a pending step = %v", err)
	}
	if back, err := f.machine.Resume(waiting, nil, f.now); err != nil || back.Phase != Subscribed {
		t.Fatalf("resume without a pending step = %+v, %v", back, err)
	}
}

func TestCancelRollsBackOnlyBeforeTheSeedLaunch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	record := f.admitted(t)
	for record.Phase != Signed {
		record = f.runStep(t, record)
	}
	running, intent, err := f.machine.BeginStep(record, f.now)
	if err != nil {
		t.Fatal(err)
	}
	rolling, err := f.machine.Cancel(running, "customer withdrew", f.now)
	if err != nil || rolling.Phase != RollingBack || rolling.RollbackFrom != SeedReserving {
		t.Fatalf("cancel during seed reservation = %+v, %v", rolling, err)
	}
	intents := rolling.RollbackIntents()
	if len(intents) != 5 || intents[0] != intent || intents[1].Step != StepMaterial || intents[4].Step != StepSubscribe {
		t.Fatalf("rollback intents must be newest first including the pending one: %+v", intents)
	}
	if _, err := f.machine.Cancel(rolling, "again", f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("cancel while rolling back = %v", err)
	}
	heldRolling, err := f.machine.Fail(rolling, "delete failed", "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if back, err := f.machine.Resume(heldRolling, nil, f.now); err != nil || back.Phase != RollingBack {
		t.Fatalf("resume held rollback = %+v, %v", back, err)
	}
	if _, err := f.machine.CompleteRollback(rolling, "", f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("rollback completed without evidence = %v", err)
	}
	retired, err := f.machine.CompleteRollback(rolling, digest("deleted"), f.now)
	if err != nil || retired.Phase != Retired || retired.Pending != nil {
		t.Fatalf("complete rollback = %+v, %v", retired, err)
	}
	assertTerminal(t, f, retired)

	seeded := record
	seeded = f.runStep(t, seeded) // SeedReserved
	launching, _, err := f.machine.BeginStep(refreshedAt(t, f, seeded), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.machine.Cancel(launching, "too late", f.now); !errors.Is(err, ErrUseRetire) {
		t.Fatalf("cancel during seed launch = %v", err)
	}
	heldLaunch, err := f.machine.Fail(launching, "unknown launch outcome", "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.machine.Cancel(heldLaunch, "too late", f.now); !errors.Is(err, ErrUseRetire) {
		t.Fatalf("cancel of a region held during seed launch = %v", err)
	}
	proposed, err := f.machine.Propose(f.proposal(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if rejected, err := f.machine.Cancel(proposed, "no", f.now); err != nil || rejected.Phase != Rejected {
		t.Fatalf("cancel of a proposal = %+v, %v", rejected, err)
	}
}

func TestProposalsExpireAndRejectionIsTerminal(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	proposed, err := f.machine.Propose(f.proposal(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.machine.Expire(proposed, f.now.Add(time.Hour)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("early expiry = %v", err)
	}
	expired, err := f.machine.Expire(proposed, f.now.Add(72*time.Hour))
	if err != nil || expired.Phase != Rejected {
		t.Fatalf("expire = %+v, %v", expired, err)
	}
	assertTerminal(t, f, expired)
	oldApproval := f.approval(t, proposed)
	if _, err := f.machine.Repropose(expired, f.proposal(), f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("repropose with the same proposal ID = %v", err)
	}
	if _, err := f.machine.Repropose(proposed, f.proposal(), f.now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("repropose over an open record = %v", err)
	}
	second := f.proposal()
	second.ID = "sfo-capacity-2"
	again, err := f.machine.Repropose(expired, second, f.now)
	if err != nil || again.Phase != Proposed || again.Generation != expired.Generation+1 ||
		again.ProposalGeneration != again.Generation || again.Approval != nil {
		t.Fatalf("repropose = %+v, %v", again, err)
	}
	if err := again.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.machine.Approve(again, oldApproval, f.now); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("approval of the previous proposal replayed: %v", err)
	}
	if _, err := f.machine.Approve(again, f.approval(t, again), f.now); err != nil {
		t.Fatalf("approval of the new proposal = %v", err)
	}
	if CreateKey("sfo", second.ID, 1, StepSubscribe) == CreateKey("sfo", f.proposal().ID, 1, StepSubscribe) {
		t.Fatal("a new proposal reuses the previous attempt's create keys")
	}
	rejected, err := f.machine.Reject(proposed, "", f.now)
	if err != nil || rejected.Outcome != "unspecified" {
		t.Fatalf("reject = %+v, %v", rejected, err)
	}
	invalid := f.proposal()
	invalid.EvidenceDigests = []string{"not-a-digest"}
	if _, err := f.machine.Propose(invalid, f.now); err == nil {
		t.Fatal("proposal without digest evidence accepted")
	}
	broken := f.machine
	broken.Policy.MaxRegions = 0
	if _, err := broken.Propose(f.proposal(), f.now); err == nil {
		t.Fatal("incomplete policy accepted")
	}
}

// TestEveryPhaseHasExactlyItsTableTransitions walks every phase and checks
// which events are accepted, so a new phase cannot silently gain a path.
func TestEveryPhaseHasExactlyItsTableTransitions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	base := f.admitted(t)
	all := []Phase{Proposed, Approved, Rejected, Held, RollingBack, RetireProposed, Active, Retired}
	for _, def := range steps {
		all = append(all, def.from, def.running, def.to)
	}
	slices.Sort(all)
	all = slices.Compact(all)
	for _, phase := range all {
		if !phase.known() {
			t.Fatalf("phase %s is not known", phase)
		}
		record := base
		record.Phase = phase
		record.RetireApproval = &protocol.Envelope{}
		_, canBegin := stepFrom(phase)
		def, isRunning := stepRunning(phase)
		_, _, err := f.machine.BeginStep(record, f.now)
		if canBegin != (err == nil || !errors.Is(err, ErrInvalidTransition)) {
			t.Errorf("%s: BeginStep = %v, table says begin=%v", phase, err, canBegin)
		}
		if isRunning {
			key := CreateKey(record.Cell, record.Proposal.ID, record.ProposalGeneration, def.step)
			record.Pending = &StepIntent{Step: def.step, CreateKey: key}
			if next, err := f.machine.CompleteStep(record, StepResult{Step: def.step, CreateKey: key, EvidenceDigest: digest("x")}, f.now); err != nil || next.Phase != def.to {
				t.Errorf("%s: CompleteStep = %s, %v", phase, next.Phase, err)
			}
		}
		if phase.Terminal() {
			assertTerminal(t, f, record)
		}
	}
	for _, phase := range []Phase{Proposed, Approved, Admitted, Subscribing, ImageReady, Signed, SeedReserving} {
		if seedMayExist(phase) {
			t.Errorf("%s: seed reported as possibly existing", phase)
		}
	}
	for _, phase := range []Phase{SeedLaunching, SeedObserved, ClusterFormed, Active, Draining} {
		if !seedMayExist(phase) {
			t.Errorf("%s: seed reported as absent", phase)
		}
	}
	if Phase("bogus").known() {
		t.Fatal("unknown phase reported known")
	}
}

func TestFleetCountsOnlySlotHoldingOtherRegions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admitted := f.admitted(t)
	gru := admitted
	gru.Cell, gru.Phase = "gru", Active
	fra := admitted
	fra.Cell, fra.Phase, fra.Admission = "fra", Held, nil
	proposed := admitted
	proposed.Cell, proposed.Phase = "iad", Proposed
	retired := admitted
	retired.Cell, retired.Phase = "lhr", Retired
	fleet := FleetOf([]Record{admitted, gru, fra, proposed, retired}, "sfo", Home{})
	if fleet.Regions != 2 || fleet.CommittedMonthlyCents != 18_000 {
		t.Fatalf("fleet = %+v", fleet)
	}
}

func assertTerminal(t *testing.T, f *fixture, record Record) {
	t.Helper()
	if !record.Phase.Terminal() {
		t.Fatalf("%s is not terminal", record.Phase)
	}
	if _, _, err := f.machine.BeginStep(record, f.now); err == nil {
		t.Errorf("%s: BeginStep accepted", record.Phase)
	}
	if _, err := f.machine.Fail(record, "x", "", f.now); err == nil {
		t.Errorf("%s: Fail accepted", record.Phase)
	}
	if _, err := f.machine.Cancel(record, "x", f.now); err == nil {
		t.Errorf("%s: Cancel accepted", record.Phase)
	}
	if _, err := f.machine.Approve(record, protocol.Envelope{}, f.now); err == nil {
		t.Errorf("%s: Approve accepted", record.Phase)
	}
	if _, err := f.machine.Resume(record, nil, f.now); err == nil {
		t.Errorf("%s: Resume accepted", record.Phase)
	}
}

// These pin the fixes for the ts-reviewer findings on PRs #126, #127 and #129.

// An absent effect needs no evidence digest: nothing is journaled for it.
func TestReconcileRetirePendingAcceptsAnAbsentEffectWithoutDigest(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	reserved := f.runTo(t, f.admitted(t), SeedReserved)
	launching, intent, err := f.machine.BeginStep(reserved, f.now)
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := f.machine.ProposeFailedRetire(launching, "seed never booted", digest("boot"), f.now)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := f.machine.ApproveRetire(proposed, f.sign(t, proposed, ApproveRetirementKind, 0, f.key, time.Hour), f.now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := f.machine.ReconcileRetirePending(approved, Observation{Step: intent.Step, CreateKey: intent.CreateKey}, f.now)
	if err != nil || next.Pending != nil {
		t.Fatalf("absent effect without digest = %+v, %v", next.Pending, err)
	}
	if _, err := f.machine.ReconcileRetirePending(approved, Observation{Step: intent.Step, CreateKey: intent.CreateKey,
		Found: true}, f.now); !errors.Is(err, ErrStepMismatch) {
		t.Fatalf("found effect without digest = %v", err)
	}
}

// Reasons are cut on a rune boundary.
func TestBoundReasonKeepsValidUTF8(t *testing.T) {
	t.Parallel()
	if reason := boundReason(strings.Repeat("a", 255) + "é" + strings.Repeat("b", 10)); !utf8.ValidString(reason) ||
		len(reason) > 256 {
		t.Fatalf("bounded reason is invalid UTF-8 or too long: %q", reason)
	}
}

// Cells follow the protocol's region-token rules, so every stored cell can
// be signed into an approval.
func TestCellsFollowProtocolRegionTokens(t *testing.T) {
	t.Parallel()
	for _, cell := range []string{"sfo", "us-east-1", "a1"} {
		if !ValidCell(cell) {
			t.Errorf("valid cell %q refused", cell)
		}
	}
	for _, cell := range []string{"sfo-", "a--b", "-a", "1a", "A", strings.Repeat("a", 32)} {
		if ValidCell(cell) {
			t.Errorf("invalid cell %q accepted", cell)
		}
	}
}

// Step keys belong to one proposal attempt.
func TestCreateKeysDifferPerProposalGeneration(t *testing.T) {
	t.Parallel()
	if CreateKey("sfo", "sfo-a", 1, StepSubscribe) == CreateKey("sfo", "sfo-a", 3, StepSubscribe) {
		t.Fatal("a reused proposal ID reuses the earlier attempt's step keys")
	}
}

// A running phase without its intent, or a stray intent, is corruption.
func TestValidateRejectsPhaseInconsistentIntents(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	reserved := f.runTo(t, f.admitted(t), SeedReserved)
	launching, _, err := f.machine.BeginStep(reserved, f.now)
	if err != nil {
		t.Fatal(err)
	}
	missing := launching
	missing.Pending = nil
	if missing.Validate() == nil {
		t.Fatal("a running phase without its intent validated")
	}
	stray := reserved
	stray.Pending = launching.Pending
	if stray.Validate() == nil {
		t.Fatal("a waiting phase with a stray intent validated")
	}
}
