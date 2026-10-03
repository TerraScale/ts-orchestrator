package regionlifecycle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

var (
	ErrInvalidTransition = errors.New("region lifecycle transition is not allowed from this phase")
	ErrApprovalRequired  = errors.New("region lifecycle needs a valid signed approval")
	ErrAdmissionStale    = errors.New("region cost admission is missing or older than its TTL")
	ErrRegionLimit       = errors.New("region count would exceed the policy maximum")
	ErrBudgetCeiling     = errors.New("region cost would exceed the global monthly ceiling")
	ErrUseRetire         = errors.New("the seed controller may exist; remove the region through retirement")
	ErrStepMismatch      = errors.New("step result does not match the recorded intent")
	ErrNotIdle           = errors.New("region is not idle long enough to retire")
	ErrStaleEpoch        = errors.New("region step intent was journaled by a newer global leader")
)

const (
	recordVersion = 1
	// ApproveExpansionKind and ApproveRetirementKind are the signed envelope
	// kinds of approvals. Envelope Region is the cell, OperationID the
	// proposal ID, and Generation the record generation being approved.
	ApproveExpansionKind  = "region.expansion.approve"
	ApproveRetirementKind = "region.retirement.approve"
	maxEvidence           = 16
)

var (
	cellToken   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	idToken     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	digestToken = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Proposal is why a region should exist. Only the planner or an operator
// creates one; a proposal never authorizes spending by itself.
type Proposal struct {
	ID                    string    `json:"id"`
	Cell                  string    `json:"cell"`
	OCIRegion             string    `json:"oci_region"`
	Reason                string    `json:"reason"`
	EvidenceDigests       []string  `json:"evidence_digests"`
	EstimatedMonthlyCents uint64    `json:"estimated_monthly_cents"`
	ProposedAt            time.Time `json:"proposed_at"`
}

// Validate requires bounded identities, evidence digests and a cost estimate.
func (p Proposal) Validate() error {
	if !idToken.MatchString(p.ID) || !cellToken.MatchString(p.Cell) || p.Cell == protocol.GlobalScope ||
		p.OCIRegion == "" || len(p.OCIRegion) > 63 || p.Reason == "" || len(p.Reason) > 256 ||
		len(p.EvidenceDigests) == 0 || len(p.EvidenceDigests) > maxEvidence ||
		p.EstimatedMonthlyCents == 0 || p.ProposedAt.IsZero() {
		return errors.New("region proposal is incomplete")
	}
	for _, digest := range p.EvidenceDigests {
		if !digestToken.MatchString(digest) {
			return errors.New("region proposal evidence must be SHA-256 hex digests")
		}
	}
	return nil
}

// Digest binds approvals to the exact proposal content.
func (p Proposal) Digest() string {
	digest := sha256.New()
	for _, field := range append([]string{p.ID, p.Cell, p.OCIRegion, p.Reason,
		fmt.Sprint(p.EstimatedMonthlyCents), p.ProposedAt.UTC().Format(time.RFC3339Nano)}, p.EvidenceDigests...) {
		fmt.Fprintf(digest, "%d:%s;", len(field), field)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// ApprovalPayload is the signed body of an expansion or retirement approval.
type ApprovalPayload struct {
	Cell            string `json:"cell"`
	ProposalDigest  string `json:"proposal_digest"`
	MaxMonthlyCents uint64 `json:"max_monthly_cents"`
}

// CostAdmission is a fresh cost estimate admitted under the budget guards.
type CostAdmission struct {
	EstimatedMonthlyCents uint64    `json:"estimated_monthly_cents"`
	EvidenceDigest        string    `json:"evidence_digest"`
	AdmittedAt            time.Time `json:"admitted_at"`
}

// StepIntent is journaled before a step's effect. CreateKey is deterministic
// for (cell, proposal, step), so a retry reuses the OCI retry token and tag.
type StepIntent struct {
	Step       Step      `json:"step"`
	CreateKey  string    `json:"create_key"`
	RecordedAt time.Time `json:"recorded_at"`
	// Epoch is the global leader epoch that last journaled (or re-journaled)
	// the intent before running its effect. A leader with an older epoch
	// never runs it.
	Epoch uint64 `json:"epoch,omitempty"`
	// Attempt counts how often a recovered intent was claimed for re-execution.
	Attempt uint32 `json:"attempt,omitempty"`
}

// StepResult is the observed outcome of a step.
type StepResult struct {
	Step           Step      `json:"step"`
	CreateKey      string    `json:"create_key"`
	ResourceID     string    `json:"resource_id,omitempty"`
	EvidenceDigest string    `json:"evidence_digest"`
	RecordedAt     time.Time `json:"recorded_at"`
}

// Observation reports whether a pending step's effect exists, found by its
// CreateKey tag. It is the only way a Held step resumes.
type Observation struct {
	Step           Step   `json:"step"`
	CreateKey      string `json:"create_key"`
	Found          bool   `json:"found"`
	ResourceID     string `json:"resource_id,omitempty"`
	EvidenceDigest string `json:"evidence_digest"`
}

// Hold records why a region stopped and where it resumes.
type Hold struct {
	Phase          Phase     `json:"phase"`
	Step           Step      `json:"step,omitempty"`
	Reason         string    `json:"reason"`
	EvidenceDigest string    `json:"evidence_digest,omitempty"`
	HeldAt         time.Time `json:"held_at"`
}

// Record is one region's lifecycle state, stored under its cell key.
type Record struct {
	Version    int    `json:"version"`
	Cell       string `json:"cell"`
	Generation uint64 `json:"generation"`
	// ProposalGeneration is the record generation at which the current
	// proposal was made; approvals bind to it so they cannot be replayed
	// against a later proposal for the same cell.
	ProposalGeneration uint64             `json:"proposal_generation"`
	Phase              Phase              `json:"phase"`
	Proposal           Proposal           `json:"proposal"`
	Approval           *protocol.Envelope `json:"approval,omitempty"`
	RetireApproval     *protocol.Envelope `json:"retire_approval,omitempty"`
	Admission          *CostAdmission     `json:"admission,omitempty"`
	Pending            *StepIntent        `json:"pending,omitempty"`
	Completed          []StepResult       `json:"completed,omitempty"`
	Hold               *Hold              `json:"hold,omitempty"`
	// RollbackFrom is the phase a cancel left; rollback removes what the
	// completed steps created, in reverse.
	RollbackFrom Phase `json:"rollback_from,omitempty"`
	// RetireFrom is the bring-up phase a failed, partially launched region
	// left for retirement (see ProposeFailedRetire); empty for an Active one.
	RetireFrom Phase     `json:"retire_from,omitempty"`
	Outcome    string    `json:"outcome,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Policy holds the guard parameters. Approvers maps an approval actor to its
// Ed25519 key; an empty map means nothing can be approved.
type Policy struct {
	MaxRegions          int
	MonthlyCeilingCents uint64
	AdmissionTTL        time.Duration
	ProposalTTL         time.Duration
	ApprovalMaxLifetime time.Duration
	ClockSkew           time.Duration
	MinIdle             time.Duration
	Approvers           map[string]ed25519.PublicKey
}

// DefaultAdmissionTTL matches the region preview's 15-minute cost admission.
const DefaultAdmissionTTL = 15 * time.Minute

func (p Policy) validate() error {
	if p.MaxRegions < 1 || p.MonthlyCeilingCents == 0 || p.AdmissionTTL <= 0 || p.AdmissionTTL > time.Hour ||
		p.ProposalTTL <= 0 || p.ApprovalMaxLifetime <= 0 || p.ClockSkew < 0 || p.MinIdle <= 0 {
		return errors.New("region lifecycle policy is incomplete")
	}
	return nil
}

// Fleet is the guard view of every other region: how many occupy a region
// slot and what they are admitted to spend per month.
type Fleet struct {
	Regions               int
	CommittedMonthlyCents uint64
}

// Home is the global home region. It was bootstrapped by hand and has no
// lifecycle record, but it occupies a region slot and spends like any other.
type Home struct {
	Cell         string
	MonthlyCents uint64
}

// Validate requires a regional cell and a cost; a zero Home is invalid
// because the guards would silently undercount the fleet.
func (h Home) Validate() error {
	if !cellToken.MatchString(h.Cell) || h.Cell == protocol.GlobalScope || h.MonthlyCents == 0 {
		return errors.New("region guards need the home region's cell and monthly cost")
	}
	return nil
}

// FleetOf summarizes the home region and every record except cell's for the
// admission guards. Committed spend counts each slot-holding region's
// admitted estimate, or its proposal estimate before admission. Sums saturate
// at the maximum instead of wrapping, so an absurd estimate can only make the
// fleet look more expensive.
func FleetOf(records []Record, cell string, home Home) Fleet {
	var fleet Fleet
	homeCounted := false
	for _, record := range records {
		if record.Cell == home.Cell && record.OccupiesSlot() {
			homeCounted = true
		}
		if record.Cell == cell || !record.OccupiesSlot() {
			continue
		}
		fleet.Regions++
		cents := record.Proposal.EstimatedMonthlyCents
		if record.Admission != nil {
			cents = record.Admission.EstimatedMonthlyCents
		}
		fleet.CommittedMonthlyCents = SaturatingAdd(fleet.CommittedMonthlyCents, cents)
	}
	if home.Cell != "" && home.Cell != cell && !homeCounted {
		fleet.Regions++
		fleet.CommittedMonthlyCents = SaturatingAdd(fleet.CommittedMonthlyCents, home.MonthlyCents)
	}
	return fleet
}

// SaturatingAdd adds two cent amounts, clamping at the maximum.
func SaturatingAdd(left, right uint64) uint64 {
	if left > math.MaxUint64-right {
		return math.MaxUint64
	}
	return left + right
}

// FitsCeiling reports whether committed plus estimate stays within ceiling,
// without overflowing.
func FitsCeiling(committed, estimate, ceiling uint64) bool {
	return committed <= ceiling && estimate <= ceiling-committed
}

// OccupiesSlot reports whether the record counts toward the region maximum
// and committed spend. A Held record keeps the slot status of the phase it
// was held in, so holding an unapproved proposal does not take a slot.
func (record Record) OccupiesSlot() bool {
	if record.Phase == Held && record.Hold != nil {
		return record.Hold.Phase.OccupiesSlot()
	}
	return record.Phase.OccupiesSlot()
}

// Machine applies transitions. It has no I/O; Store persists its results.
type Machine struct {
	Policy Policy
}

// CreateKey is the deterministic retry token and ownership tag for a step.
func CreateKey(cell, proposalID string, step Step) string {
	digest := sha256.Sum256([]byte("terrascale-region-step-v1\x00" + cell + "\x00" + proposalID + "\x00" + string(step)))
	return hex.EncodeToString(digest[:16])
}

// Propose creates a new Proposed record.
func (m Machine) Propose(proposal Proposal, now time.Time) (Record, error) {
	if err := m.Policy.validate(); err != nil {
		return Record{}, err
	}
	if err := proposal.Validate(); err != nil {
		return Record{}, err
	}
	return Record{Version: recordVersion, Cell: proposal.Cell, Generation: 1, ProposalGeneration: 1,
		Phase: Proposed, Proposal: proposal, UpdatedAt: now.UTC()}, nil
}

// Repropose starts a new proposal for a cell whose previous record is
// terminal. Step keys derive from the new proposal ID, so nothing from the
// previous attempt is reused; approvals and admissions are cleared.
func (m Machine) Repropose(prior Record, proposal Proposal, now time.Time) (Record, error) {
	if !prior.Phase.Terminal() || proposal.Cell != prior.Cell || proposal.ID == prior.Proposal.ID {
		return Record{}, ErrInvalidTransition
	}
	next, err := m.Propose(proposal, now)
	if err != nil {
		return Record{}, err
	}
	next.Generation = prior.Generation + 1
	next.ProposalGeneration = next.Generation
	return next, nil
}

// Approve accepts a signed expansion approval for the exact proposal.
func (m Machine) Approve(record Record, approval protocol.Envelope, now time.Time) (Record, error) {
	if record.Phase != Proposed {
		return Record{}, ErrInvalidTransition
	}
	if m.expired(record, now) {
		return Record{}, fmt.Errorf("%w: proposal expired", ErrInvalidTransition)
	}
	if err := m.verifyApproval(record, approval, ApproveExpansionKind, now); err != nil {
		return Record{}, err
	}
	next := record.advance(Approved, now)
	next.Approval = &approval
	return next, nil
}

// Reject ends a proposal; it is terminal.
func (m Machine) Reject(record Record, reason string, now time.Time) (Record, error) {
	if record.Phase != Proposed && record.Phase != Approved {
		return Record{}, ErrInvalidTransition
	}
	next := record.advance(Rejected, now)
	next.Outcome = boundReason(reason)
	return next, nil
}

// Expire rejects a proposal that waited longer than ProposalTTL.
func (m Machine) Expire(record Record, now time.Time) (Record, error) {
	if record.Phase != Proposed || !m.expired(record, now) {
		return Record{}, ErrInvalidTransition
	}
	next := record.advance(Rejected, now)
	next.Outcome = "proposal expired"
	return next, nil
}

func (m Machine) expired(record Record, now time.Time) bool {
	return !now.Before(record.Proposal.ProposedAt.Add(m.Policy.ProposalTTL))
}

// Admit applies the region count and budget guards to a fresh cost estimate.
func (m Machine) Admit(record Record, admission CostAdmission, fleet Fleet, now time.Time) (Record, error) {
	if record.Phase != Approved {
		return Record{}, ErrInvalidTransition
	}
	if err := m.requireApproval(record, now); err != nil {
		return Record{}, err
	}
	if err := m.admit(record, admission, fleet, now); err != nil {
		return Record{}, err
	}
	next := record.advance(Admitted, now)
	next.Admission = &admission
	return next, nil
}

// Readmit refreshes the cost admission of an in-flight region; spending steps
// need an admission younger than AdmissionTTL when they begin and whenever a
// recovered intent is re-executed, so a running phase can be readmitted too.
func (m Machine) Readmit(record Record, admission CostAdmission, fleet Fleet, now time.Time) (Record, error) {
	_, waiting := stepFrom(record.Phase)
	_, running := stepRunning(record.Phase)
	if !waiting && !running || record.Phase.Terminal() || isRetire(record.Phase) {
		return Record{}, ErrInvalidTransition
	}
	if err := m.requireApproval(record, now); err != nil {
		return Record{}, err
	}
	if err := m.admit(record, admission, fleet, now); err != nil {
		return Record{}, err
	}
	next := record.advance(record.Phase, now)
	next.Admission = &admission
	return next, nil
}

func (m Machine) admit(record Record, admission CostAdmission, fleet Fleet, now time.Time) error {
	if admission.EstimatedMonthlyCents == 0 || !digestToken.MatchString(admission.EvidenceDigest) ||
		admission.AdmittedAt.IsZero() || admission.AdmittedAt.After(now.Add(m.Policy.ClockSkew)) ||
		!now.Before(admission.AdmittedAt.Add(m.Policy.AdmissionTTL)) {
		return ErrAdmissionStale
	}
	if fleet.Regions+1 > m.Policy.MaxRegions {
		return ErrRegionLimit
	}
	payload, err := approvalPayload(*record.Approval)
	if err != nil {
		return err
	}
	if admission.EstimatedMonthlyCents > payload.MaxMonthlyCents ||
		!FitsCeiling(fleet.CommittedMonthlyCents, admission.EstimatedMonthlyCents, m.Policy.MonthlyCeilingCents) {
		return ErrBudgetCeiling
	}
	return nil
}

// BeginStep journals the intent for the step that starts in the current
// phase and moves to its running phase. The caller persists the returned
// record before running the effect.
func (m Machine) BeginStep(record Record, now time.Time) (Record, StepIntent, error) {
	def, ok := stepFrom(record.Phase)
	if !ok || record.Pending != nil {
		return Record{}, StepIntent{}, ErrInvalidTransition
	}
	if err := m.stepGuards(record, def, now); err != nil {
		return Record{}, StepIntent{}, err
	}
	intent := StepIntent{Step: def.step, CreateKey: CreateKey(record.Cell, record.Proposal.ID, def.step), RecordedAt: now.UTC()}
	next := record.advance(def.running, now)
	next.Pending = &intent
	return next, intent, nil
}

// stepGuards are the checks every effect needs when it starts or restarts:
// an unexpired approval of the right kind and, for spending steps, a cost
// admission younger than AdmissionTTL.
func (m Machine) stepGuards(record Record, def stepDef, now time.Time) error {
	if def.retire {
		return m.requireRetireApproval(record, now)
	}
	if err := m.requireApproval(record, now); err != nil {
		return err
	}
	if def.spends && (record.Admission == nil || record.Admission.AdmittedAt.After(now.Add(m.Policy.ClockSkew)) ||
		!now.Before(record.Admission.AdmittedAt.Add(m.Policy.AdmissionTTL))) {
		return ErrAdmissionStale
	}
	return nil
}

// ClaimStep re-journals the pending intent of a running step before its
// effect is re-executed under epoch, for example after a crash left the
// intent journaled but its effect absent. It re-checks the approval and
// admission guards exactly as BeginStep does, refuses an intent that a newer
// leader journaled, and returns the next generation with the intent stamped
// with epoch. The caller must persist the record (a compare-and-set under
// epoch) before running the effect, so two leaders never both run it.
func (m Machine) ClaimStep(record Record, epoch uint64, now time.Time) (Record, StepIntent, error) {
	def, ok := stepRunning(record.Phase)
	if !ok || record.Pending == nil || record.Pending.Step != def.step {
		return Record{}, StepIntent{}, ErrInvalidTransition
	}
	if epoch == 0 || record.Pending.Epoch > epoch {
		return Record{}, StepIntent{}, ErrStaleEpoch
	}
	if err := m.stepGuards(record, def, now); err != nil {
		return Record{}, StepIntent{}, err
	}
	intent := *record.Pending
	intent.Epoch = epoch
	if intent.Attempt < math.MaxUint32 {
		intent.Attempt++
	}
	next := record.advance(record.Phase, now)
	next.Pending = &intent
	return next, intent, nil
}

// CompleteStep records the result of the pending step and advances. Results
// are facts, so no approval or budget guard can block recording them.
func (m Machine) CompleteStep(record Record, result StepResult, now time.Time) (Record, error) {
	def, ok := stepRunning(record.Phase)
	if !ok || record.Pending == nil {
		return Record{}, ErrInvalidTransition
	}
	if result.Step != def.step || record.Pending.Step != def.step || result.CreateKey != record.Pending.CreateKey ||
		!digestToken.MatchString(result.EvidenceDigest) {
		return Record{}, ErrStepMismatch
	}
	result.RecordedAt = now.UTC()
	next := record.advance(def.to, now)
	next.Pending = nil
	next.Completed = append(slices.Clone(record.Completed), result)
	return next, nil
}

// Fail holds the region where it is, keeping any pending intent so that the
// effect is reconciled by observation rather than repeated.
func (m Machine) Fail(record Record, reason, evidenceDigest string, now time.Time) (Record, error) {
	if record.Phase.Terminal() || record.Phase == Held {
		return Record{}, ErrInvalidTransition
	}
	if evidenceDigest != "" && !digestToken.MatchString(evidenceDigest) {
		return Record{}, errors.New("hold evidence must be a SHA-256 hex digest")
	}
	hold := Hold{Phase: record.Phase, Reason: boundReason(reason), EvidenceDigest: evidenceDigest, HeldAt: now.UTC()}
	if record.Pending != nil {
		hold.Step = record.Pending.Step
	}
	next := record.advance(Held, now)
	next.Hold = &hold
	return next, nil
}

// Resume leaves Held. With a pending step it needs an observation of that
// step: a found effect completes it; a missing one returns to the running
// phase to retry with the same CreateKey. Without a pending step it returns
// to the held phase.
func (m Machine) Resume(record Record, observation *Observation, now time.Time) (Record, error) {
	if record.Phase != Held || record.Hold == nil {
		return Record{}, ErrInvalidTransition
	}
	restored := record
	restored.Phase = record.Hold.Phase
	restored.Hold = nil
	if record.Pending == nil || restored.Phase == RollingBack {
		// Rollback reconciles every intent itself before CompleteRollback.
		if observation != nil {
			return Record{}, ErrStepMismatch
		}
		return restored.advance(restored.Phase, now), nil
	}
	if observation == nil || observation.Step != record.Pending.Step || observation.CreateKey != record.Pending.CreateKey {
		return Record{}, ErrStepMismatch
	}
	if observation.Found {
		return m.CompleteStep(restored, StepResult{Step: observation.Step, CreateKey: observation.CreateKey,
			ResourceID: observation.ResourceID, EvidenceDigest: observation.EvidenceDigest}, now)
	}
	return restored.advance(restored.Phase, now), nil
}

// RenewApproval replaces the expansion approval of an in-flight bring-up
// with a fresh signed one for the same proposal, keeping the phase and any
// pending intent. Without it, an approval that expires mid-bring-up would
// leave every later step stuck on ErrApprovalRequired.
func (m Machine) RenewApproval(record Record, approval protocol.Envelope, now time.Time) (Record, error) {
	phase := record.Phase
	if phase == Held && record.Hold != nil {
		phase = record.Hold.Phase
	}
	if _, forward := forwardOrder[phase]; !forward || phase == Proposed || phase == Active || record.Approval == nil {
		return Record{}, ErrInvalidTransition
	}
	if err := m.verifyApproval(record, approval, ApproveExpansionKind, now); err != nil {
		return Record{}, err
	}
	next := record.advance(record.Phase, now)
	next.Approval = &approval
	return next, nil
}

// RenewRetireApproval replaces the retirement approval of an in-flight
// retirement, keeping the phase and any pending intent.
func (m Machine) RenewRetireApproval(record Record, approval protocol.Envelope, now time.Time) (Record, error) {
	phase := record.Phase
	if phase == Held && record.Hold != nil {
		phase = record.Hold.Phase
	}
	if !isRetire(phase) || phase == RetireProposed || record.RetireApproval == nil {
		return Record{}, ErrInvalidTransition
	}
	if err := m.verifyApproval(record, approval, ApproveRetirementKind, now); err != nil {
		return Record{}, err
	}
	next := record.advance(record.Phase, now)
	next.RetireApproval = &approval
	return next, nil
}

// ProposeFailedRetire starts retirement of a region whose bring-up failed
// after the seed launch, when cancel can no longer roll it back. The region
// may own a seed controller and billable resources, so it takes the same
// signed retirement path as an Active region; no idle evidence is needed
// because it never served. A pending intent is kept and reconciled by
// observation (ReconcileRetirePending) before any teardown step begins.
func (m Machine) ProposeFailedRetire(record Record, reason, evidenceDigest string, now time.Time) (Record, error) {
	phase := record.Phase
	if phase == Held && record.Hold != nil {
		phase = record.Hold.Phase
	}
	if _, forward := forwardOrder[phase]; !forward || phase == Active || !seedMayExist(phase) {
		return Record{}, ErrInvalidTransition
	}
	if !digestToken.MatchString(evidenceDigest) {
		return Record{}, errors.New("failed-region retirement needs SHA-256 hex evidence")
	}
	next := record.advance(RetireProposed, now)
	next.Hold = nil
	next.RetireFrom = phase
	next.Outcome = "bring-up failed: " + boundReason(reason)
	return next, nil
}

// ReconcileRetirePending settles the pending bring-up intent of a failed
// region before its teardown, from an observation of that intent: a found
// effect is recorded as completed (teardown must remove it), a missing one
// is dropped. The phase stays RetireApproved.
func (m Machine) ReconcileRetirePending(record Record, observation Observation, now time.Time) (Record, error) {
	if record.Phase != RetireApproved || record.Pending == nil {
		return Record{}, ErrInvalidTransition
	}
	if observation.Step != record.Pending.Step || observation.CreateKey != record.Pending.CreateKey ||
		!digestToken.MatchString(observation.EvidenceDigest) {
		return Record{}, ErrStepMismatch
	}
	next := record.advance(record.Phase, now)
	next.Pending = nil
	if observation.Found {
		next.Completed = append(slices.Clone(record.Completed), StepResult{Step: observation.Step,
			CreateKey: observation.CreateKey, ResourceID: observation.ResourceID,
			EvidenceDigest: observation.EvidenceDigest, RecordedAt: now.UTC()})
	}
	return next, nil
}

// Cancel stops a bring-up. Before the seed launch it rolls back; afterwards
// the region must go through the retire path.
func (m Machine) Cancel(record Record, reason string, now time.Time) (Record, error) {
	phase := record.Phase
	if phase == Held && record.Hold != nil {
		phase = record.Hold.Phase
	}
	switch {
	case phase == Proposed || phase == Approved:
		// Nothing was spent yet; a cancelled proposal is simply rejected.
		next := record.advance(Rejected, now)
		next.Hold = nil
		next.Outcome = boundReason(reason)
		return next, nil
	case phase.Terminal() || phase == RollingBack || isRetire(phase):
		return Record{}, ErrInvalidTransition
	case seedMayExist(phase):
		// ProposeFailedRetire is the removal path from here on.
		return Record{}, ErrUseRetire
	}
	next := record.advance(RollingBack, now)
	next.RollbackFrom = phase
	next.Hold = nil
	next.Outcome = boundReason(reason)
	// The pending intent stays: rollback must observe and remove it too.
	return next, nil
}

// RollbackIntents lists the steps to undo, newest first, including a pending
// step whose effect may exist.
func (record Record) RollbackIntents() []StepIntent {
	var intents []StepIntent
	if record.Pending != nil {
		intents = append(intents, *record.Pending)
	}
	for index := len(record.Completed) - 1; index >= 0; index-- {
		result := record.Completed[index]
		intents = append(intents, StepIntent{Step: result.Step, CreateKey: result.CreateKey})
	}
	return intents
}

// CompleteRollback retires a rolled-back region after every intent was
// observed absent or deleted.
func (m Machine) CompleteRollback(record Record, evidenceDigest string, now time.Time) (Record, error) {
	if record.Phase != RollingBack || !digestToken.MatchString(evidenceDigest) {
		return Record{}, ErrInvalidTransition
	}
	next := record.advance(Retired, now)
	next.Pending = nil
	next.Completed = append(slices.Clone(record.Completed), StepResult{Step: StepRollback,
		CreateKey: CreateKey(record.Cell, record.Proposal.ID, StepRollback), EvidenceDigest: evidenceDigest, RecordedAt: now.UTC()})
	return next, nil
}

// IdleEvidence proves an Active region has no placement intents or members.
type IdleEvidence struct {
	IdleSince        time.Time `json:"idle_since"`
	PlacementIntents int       `json:"placement_intents"`
	ActiveMembers    int       `json:"active_members"`
	EvidenceDigest   string    `json:"evidence_digest"`
}

// ProposeRetire starts retirement of an idle Active region.
func (m Machine) ProposeRetire(record Record, idle IdleEvidence, now time.Time) (Record, error) {
	if record.Phase != Active {
		return Record{}, ErrInvalidTransition
	}
	if idle.PlacementIntents != 0 || idle.ActiveMembers != 0 || idle.IdleSince.IsZero() ||
		now.Sub(idle.IdleSince) < m.Policy.MinIdle || !digestToken.MatchString(idle.EvidenceDigest) {
		return Record{}, ErrNotIdle
	}
	next := record.advance(RetireProposed, now)
	next.Outcome = "idle since " + idle.IdleSince.UTC().Format(time.RFC3339)
	return next, nil
}

// ApproveRetire accepts a signed retirement approval. Retirement always needs
// a human or policy signature, whatever the idle evidence says.
func (m Machine) ApproveRetire(record Record, approval protocol.Envelope, now time.Time) (Record, error) {
	if record.Phase != RetireProposed {
		return Record{}, ErrInvalidTransition
	}
	if err := m.verifyApproval(record, approval, ApproveRetirementKind, now); err != nil {
		return Record{}, err
	}
	next := record.advance(RetireApproved, now)
	next.RetireApproval = &approval
	return next, nil
}

func (m Machine) requireApproval(record Record, now time.Time) error {
	if record.Approval == nil {
		return ErrApprovalRequired
	}
	return m.verifyApproval(record, *record.Approval, ApproveExpansionKind, now)
}

func (m Machine) requireRetireApproval(record Record, now time.Time) error {
	if record.RetireApproval == nil {
		return ErrApprovalRequired
	}
	return m.verifyApproval(record, *record.RetireApproval, ApproveRetirementKind, now)
}

// verifyApproval checks the approver key, exact scope, expiry and that the
// payload binds this proposal. The envelope generation is the record's
// ProposalGeneration, so re-verifying at later transitions stays valid.
func (m Machine) verifyApproval(record Record, approval protocol.Envelope, kind string, now time.Time) error {
	key, ok := m.Policy.Approvers[approval.Actor]
	if !ok {
		return ErrApprovalRequired
	}
	scope := protocol.EnvelopeScope{Region: record.Cell, Kind: kind, Actor: approval.Actor,
		OperationID: record.Proposal.ID, Generation: record.ProposalGeneration, Epoch: 0}
	if err := protocol.VerifyEnvelope(approval, scope, key, now, protocol.VerifyPolicy{
		MaxLifetime: m.Policy.ApprovalMaxLifetime, ClockSkew: m.Policy.ClockSkew,
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrApprovalRequired, err)
	}
	payload, err := approvalPayload(approval)
	if err != nil {
		return err
	}
	if payload.Cell != record.Cell || payload.ProposalDigest != record.Proposal.Digest() {
		return fmt.Errorf("%w: approval binds a different proposal", ErrApprovalRequired)
	}
	if kind == ApproveExpansionKind && payload.MaxMonthlyCents < record.Proposal.EstimatedMonthlyCents {
		return fmt.Errorf("%w: approval budget is below the proposal estimate", ErrApprovalRequired)
	}
	return nil
}

func approvalPayload(approval protocol.Envelope) (ApprovalPayload, error) {
	var payload ApprovalPayload
	if err := protocol.DecodeStrict(approval.Payload, &payload, 4096); err != nil {
		return ApprovalPayload{}, fmt.Errorf("%w: approval payload: %w", ErrApprovalRequired, err)
	}
	return payload, nil
}

func (record Record) advance(phase Phase, now time.Time) Record {
	next := record
	next.Phase = phase
	next.Generation = record.Generation + 1
	next.UpdatedAt = now.UTC()
	return next
}

func isRetire(phase Phase) bool {
	if phase == RetireProposed || phase == RetireApproved {
		return true
	}
	for _, def := range steps {
		if def.retire && (def.running == phase || def.to == phase && phase != Retired) {
			return true
		}
	}
	return false
}

func boundReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > 256 {
		reason = reason[:256]
	}
	if reason == "" {
		reason = "unspecified"
	}
	return reason
}

// Validate checks a stored record's structural invariants.
func (record Record) Validate() error {
	if record.Version != recordVersion || !cellToken.MatchString(record.Cell) || record.Generation == 0 ||
		record.ProposalGeneration == 0 || record.ProposalGeneration > record.Generation ||
		!record.Phase.known() || record.Proposal.Validate() != nil || record.Proposal.Cell != record.Cell {
		return errors.New("region lifecycle record is invalid")
	}
	if (record.Phase == Held) != (record.Hold != nil) {
		return errors.New("region lifecycle hold does not match its phase")
	}
	if record.Pending != nil && record.Pending.CreateKey != CreateKey(record.Cell, record.Proposal.ID, record.Pending.Step) {
		return errors.New("region lifecycle pending intent has a foreign create key")
	}
	if record.RetireFrom != "" {
		if _, forward := forwardOrder[record.RetireFrom]; !forward || !seedMayExist(record.RetireFrom) ||
			record.RetireFrom == Active {
			return errors.New("region lifecycle retire-from phase is invalid")
		}
	}
	return nil
}
