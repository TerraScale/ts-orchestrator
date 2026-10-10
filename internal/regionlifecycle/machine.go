package regionlifecycle

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

var (
	ErrInvalidTransition = errors.New("region lifecycle transition is not allowed from this phase")
	ErrAdmissionStale    = errors.New("region cost admission is missing or older than its TTL")
	ErrRegionLimit       = errors.New("region count would exceed the region maximum")
	ErrBudgetCeiling     = errors.New("region cost would exceed the monthly budget headroom")
	ErrUseRetire         = errors.New("the seed controller may exist; remove the region through retirement")
	ErrStepMismatch      = errors.New("step result does not match the recorded intent")
	ErrNotIdle           = errors.New("region is not idle long enough to retire")
	ErrStaleEpoch        = errors.New("region step intent was journaled by a newer global leader")
)

const (
	recordVersion = 1
	maxEvidence   = 16
)

// The guardrails every region action runs under. They are fixed in code.
const (
	// MaxRegions is the region bound the roster enforces too.
	MaxRegions = catalog.MaxRegions
	// AdmissionTTL is how long a cost admission stays fresh for spending steps.
	AdmissionTTL = 15 * time.Minute
	// ProposalTTL is how long a proposal waits before it expires.
	ProposalTTL = 72 * time.Hour
	// ClockSkew tolerates a writer's clock running ahead of the reader's.
	ClockSkew = time.Minute
	// MinIdle is how long an Active region must be idle before retirement.
	MinIdle = 14 * 24 * time.Hour
)

var (
	cellToken = cellRule{}
	// cellShape matches protocol.CanonicalRegion: no leading, trailing or
	// consecutive hyphens, so every stored cell is a valid canonical region.
	cellShape   = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	idToken     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	digestToken = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// cellRule validates a region cell token: at most 31 characters of
// cellShape.
type cellRule struct{}

func (cellRule) MatchString(cell string) bool { return len(cell) <= 31 && cellShape.MatchString(cell) }

// ValidCell reports whether cell is a valid region cell token.
func ValidCell(cell string) bool { return cellToken.MatchString(cell) }

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
	if !entityid.Valid(p.ID) || !cellToken.MatchString(p.Cell) || p.Cell == protocol.GlobalScope ||
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

// CostAdmission is a fresh cost estimate admitted under the budget guards.
// HeadroomCents is what the monthly budget leaves after every serving region's
// projected spend, computed by the caller.
type CostAdmission struct {
	EstimatedMonthlyCents uint64    `json:"estimated_monthly_cents"`
	HeadroomCents         uint64    `json:"headroom_cents"`
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
	// proposal was made; step keys bind to it so a replaced proposal never
	// reuses an earlier attempt's retry tokens or tags.
	ProposalGeneration uint64         `json:"proposal_generation"`
	Phase              Phase          `json:"phase"`
	Proposal           Proposal       `json:"proposal"`
	Admission          *CostAdmission `json:"admission,omitempty"`
	Pending            *StepIntent    `json:"pending,omitempty"`
	Completed          []StepResult   `json:"completed,omitempty"`
	Hold               *Hold          `json:"hold,omitempty"`
	// RollbackFrom is the phase a cancel left; rollback removes what the
	// completed steps created, in reverse.
	RollbackFrom Phase `json:"rollback_from,omitempty"`
	// RetireFrom is the bring-up phase a failed, partially launched region
	// left for retirement (see ProposeFailedRetire); empty for an Active one.
	RetireFrom Phase     `json:"retire_from,omitempty"`
	Outcome    string    `json:"outcome,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Fleet is the guard view of every other region: how many occupy a region
// slot and what the in-flight ones are admitted to spend per month.
type Fleet struct {
	Regions               int
	CommittedMonthlyCents uint64
}

// Home is the global home region. It was bootstrapped by hand and has no
// lifecycle record, but it occupies a region slot.
type Home struct {
	Cell string
}

// Validate requires a regional cell; a zero Home is invalid because the
// guards would silently undercount the fleet.
func (h Home) Validate() error {
	if !cellToken.MatchString(h.Cell) || h.Cell == protocol.GlobalScope {
		return errors.New("region guards need the home region's cell")
	}
	return nil
}

// FleetOf summarizes the home region and every record except cell's for the
// admission guards. Committed spend counts the admitted estimate, or the
// proposal estimate before admission, of each slot-holding region that is not
// yet Active: an Active region's spend is already in the budget headroom.
// Sums saturate at the maximum instead of wrapping, so an absurd estimate can
// only make the fleet look more expensive.
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
		if record.effectivePhase() == Active {
			continue
		}
		cents := record.Proposal.EstimatedMonthlyCents
		if record.Admission != nil {
			cents = record.Admission.EstimatedMonthlyCents
		}
		fleet.CommittedMonthlyCents = SaturatingAdd(fleet.CommittedMonthlyCents, cents)
	}
	if home.Cell != "" && home.Cell != cell && !homeCounted {
		fleet.Regions++
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

// OccupiesSlot reports whether the record counts toward the region maximum
// and committed spend. A Held record keeps the slot status of the phase it
// was held in, so holding an unapproved proposal does not take a slot.
func (record Record) OccupiesSlot() bool { return record.effectivePhase().OccupiesSlot() }

// effectivePhase is the phase a record is in for the guards: a Held record
// stands for the phase it was held in.
func (record Record) effectivePhase() Phase {
	if record.Phase == Held && record.Hold != nil {
		return record.Hold.Phase
	}
	return record.Phase
}

// Admit applies the region maximum and the budget to one more region that
// costs cents a month: the fleet's committed spend and cents must fit under
// headroomCents. The planner's add guard and the admission both call it.
func (fleet Fleet) Admit(headroomCents, cents uint64) error {
	if fleet.Regions+1 > MaxRegions {
		return ErrRegionLimit
	}
	if SaturatingAdd(fleet.CommittedMonthlyCents, cents) > headroomCents {
		return ErrBudgetCeiling
	}
	return nil
}

// Machine applies transitions. It has no I/O; Store persists its results.
type Machine struct{}

// CreateKey is the deterministic retry token and ownership tag for a step of
// one proposal attempt. The proposal generation is part of it, so a cell
// that later reuses an older proposal ID (only the immediately preceding one
// is refused) never reuses that attempt's OCI retry tokens or tags.
func CreateKey(cell, proposalID string, proposalGeneration uint64, step Step) string {
	return entityid.Derive("region-step", cell, proposalID, strconv.FormatUint(proposalGeneration, 10), string(step))
}

// Propose creates a new Proposed record.
func (m Machine) Propose(proposal Proposal, now time.Time) (Record, error) {
	if err := proposal.Validate(); err != nil {
		return Record{}, err
	}
	return Record{Version: recordVersion, Cell: proposal.Cell, Generation: 1, ProposalGeneration: 1,
		Phase: Proposed, Proposal: proposal, UpdatedAt: now.UTC()}, nil
}

// Repropose starts a new proposal for a cell whose previous record is
// terminal. Step keys derive from the new proposal ID, so nothing from the
// previous attempt is reused; the new record carries no admission.
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

// Approve accepts a proposal inside ProposalTTL. The proposal's Reason is the
// written reason; the region planner calls this only inside its guardrails.
func (m Machine) Approve(record Record, now time.Time) (Record, error) {
	if record.Phase != Proposed {
		return Record{}, ErrInvalidTransition
	}
	if m.expired(record, now) {
		return Record{}, fmt.Errorf("%w: proposal expired", ErrInvalidTransition)
	}
	return record.advance(Approved, now), nil
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
	return !now.Before(record.Proposal.ProposedAt.Add(ProposalTTL))
}

// Admit applies the region count and budget guards to a fresh cost estimate.
func (m Machine) Admit(record Record, admission CostAdmission, fleet Fleet, now time.Time) (Record, error) {
	if record.Phase != Approved {
		return Record{}, ErrInvalidTransition
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
	if err := m.admit(record, admission, fleet, now); err != nil {
		return Record{}, err
	}
	next := record.advance(record.Phase, now)
	next.Admission = &admission
	return next, nil
}

func (m Machine) admit(record Record, admission CostAdmission, fleet Fleet, now time.Time) error {
	if admission.EstimatedMonthlyCents == 0 || !digestToken.MatchString(admission.EvidenceDigest) ||
		admission.AdmittedAt.IsZero() || admission.AdmittedAt.After(now.Add(ClockSkew)) ||
		!now.Before(admission.AdmittedAt.Add(AdmissionTTL)) {
		return ErrAdmissionStale
	}
	return fleet.Admit(admission.HeadroomCents, admission.EstimatedMonthlyCents)
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
	intent := StepIntent{Step: def.step, CreateKey: CreateKey(record.Cell, record.Proposal.ID, record.ProposalGeneration, def.step), RecordedAt: now.UTC()}
	next := record.advance(def.running, now)
	next.Pending = &intent
	return next, intent, nil
}

// stepGuards are the checks an effect needs when it starts or restarts: for
// spending steps, a cost admission younger than AdmissionTTL. Retirement
// steps need nothing more, because they only start from RetireApproved.
func (m Machine) stepGuards(record Record, def stepDef, now time.Time) error {
	if def.spends && (record.Admission == nil || record.Admission.AdmittedAt.After(now.Add(ClockSkew)) ||
		!now.Before(record.Admission.AdmittedAt.Add(AdmissionTTL))) {
		return ErrAdmissionStale
	}
	return nil
}

// ClaimStep re-journals the pending intent of a running step before its
// effect is re-executed under epoch, for example after a crash left the
// intent journaled but its effect absent. It re-checks the admission guard
// exactly as BeginStep does, refuses an intent that a newer
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
// are facts, so no admission guard can block recording them.
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

// ProposeFailedRetire starts retirement of a region whose bring-up failed
// after the seed launch, when cancel can no longer roll it back. The region
// may own a seed controller and billable resources, so it takes the same
// retirement path as an Active region; no idle evidence is needed because it
// never served. A pending intent is kept and reconciled by
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
	// No result is journaled for an absent effect, so only a found one
	// needs evidence, as for every other absent-effect observation.
	if observation.Step != record.Pending.Step || observation.CreateKey != record.Pending.CreateKey ||
		observation.Found && !digestToken.MatchString(observation.EvidenceDigest) {
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
		CreateKey: CreateKey(record.Cell, record.Proposal.ID, record.ProposalGeneration, StepRollback), EvidenceDigest: evidenceDigest, RecordedAt: now.UTC()})
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
		now.Sub(idle.IdleSince) < MinIdle || !digestToken.MatchString(idle.EvidenceDigest) {
		return Record{}, ErrNotIdle
	}
	next := record.advance(RetireProposed, now)
	next.Outcome = "idle since " + idle.IdleSince.UTC().Format(time.RFC3339)
	return next, nil
}

// ApproveRetire accepts a proposed retirement. The proposal's idle evidence
// was checked by ProposeRetire, so nothing else is verified here.
func (m Machine) ApproveRetire(record Record, now time.Time) (Record, error) {
	if record.Phase != RetireProposed {
		return Record{}, ErrInvalidTransition
	}
	return record.advance(RetireApproved, now), nil
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
		// Cut on a rune boundary so the stored reason stays valid UTF-8.
		cut := 256
		for cut > 0 && !utf8.RuneStart(reason[cut]) {
			cut--
		}
		reason = reason[:cut]
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
	if record.Pending != nil && record.Pending.CreateKey != CreateKey(record.Cell, record.Proposal.ID, record.ProposalGeneration, record.Pending.Step) {
		return errors.New("region lifecycle pending intent has a foreign create key")
	}
	// A running phase carries its pending intent; a pending intent outside
	// a running phase is legitimate only while held, rolling back, or
	// awaiting settlement before a failed bring-up retires.
	settling := record.RetireFrom != "" && (record.Phase == RetireProposed || record.Phase == RetireApproved)
	if _, running := stepRunning(record.Phase); running && record.Pending == nil ||
		!running && record.Pending != nil && record.Phase != Held && record.Phase != RollingBack && !settling {
		return errors.New("region lifecycle pending intent does not match its phase")
	}
	if record.RetireFrom != "" {
		if _, forward := forwardOrder[record.RetireFrom]; !forward || !seedMayExist(record.RetireFrom) ||
			record.RetireFrom == Active {
			return errors.New("region lifecycle retire-from phase is invalid")
		}
	}
	return nil
}
