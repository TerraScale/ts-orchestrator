// Package regionlifecycle is the pure state machine for bringing a region
// online and retiring it, plus its compare-and-set store and step driver.
//
// A region moves Proposed -> Approved -> Admitted, then through one journaled
// step per OCI or bootstrap effect to Active. Retirement runs Active ->
// RetireProposed -> RetireApproved and then reverse steps to Retired. Any
// non-terminal phase can become Held; a Held region resumes only through an
// observation of the pending step, never by re-creating a resource. Before
// SeedLaunching a cancel rolls back; from SeedLaunching on, only the retire
// path can remove a region.
//
// Every step writes its StepIntent (with a deterministic CreateKey used as the
// OCI retry token and ownership tag) to the record before the effect runs, so
// a crash between the effect and its result is reconciled by observation.
package regionlifecycle

// Phase is a region lifecycle state.
type Phase string

const (
	Proposed               Phase = "proposed"
	Approved               Phase = "approved"
	Admitted               Phase = "admitted"
	Subscribing            Phase = "subscribing"
	Subscribed             Phase = "subscribed"
	FoundationProvisioning Phase = "foundation-provisioning"
	FoundationReady        Phase = "foundation-ready"
	ImageImporting         Phase = "image-importing"
	ImageReady             Phase = "image-ready"
	MaterialMinting        Phase = "material-minting"
	Signed                 Phase = "signed"
	SeedReserving          Phase = "seed-reserving"
	SeedReserved           Phase = "seed-reserved"
	SeedLaunching          Phase = "seed-launching"
	SeedObserved           Phase = "seed-observed"
	SeedAdmitting          Phase = "seed-admitting"
	SeedAdmitted           Phase = "seed-admitted"
	FounderForming         Phase = "founder-forming"
	ClusterFormed          Phase = "cluster-formed"
	Linking                Phase = "linking"
	Linked                 Phase = "linked"
	PublicAPIProvisioning  Phase = "public-api-provisioning"
	PublicAPIReady         Phase = "public-api-ready"
	HandingOff             Phase = "handing-off"
	HandedOff              Phase = "handed-off"
	Activating             Phase = "activating"
	Active                 Phase = "active"

	RetireProposed         Phase = "retire-proposed"
	RetireApproved         Phase = "retire-approved"
	Draining               Phase = "draining"
	Drained                Phase = "drained"
	Unlinking              Phase = "unlinking"
	Unlinked               Phase = "unlinked"
	ControllersTerminating Phase = "controllers-terminating"
	ControllersTerminated  Phase = "controllers-terminated"
	FoundationDestroying   Phase = "foundation-destroying"
	Retired                Phase = "retired"

	Rejected    Phase = "rejected"
	Held        Phase = "held"
	RollingBack Phase = "rolling-back"
)

// Step names one journaled effect. Each step starts in From, runs in Running
// with its intent recorded, and ends in To once its result is recorded.
type Step string

const (
	StepSubscribe            Step = "subscribe"
	StepFoundation           Step = "foundation"
	StepImage                Step = "image"
	StepMaterial             Step = "material"
	StepSeedReserve          Step = "seed-reserve"
	StepSeedLaunch           Step = "seed-launch"
	StepSeedAdmit            Step = "seed-admit"
	StepFounder              Step = "founder"
	StepLink                 Step = "link"
	StepPublicAPI            Step = "public-api"
	StepHandoff              Step = "handoff"
	StepActivate             Step = "activate"
	StepDrain                Step = "drain"
	StepUnlink               Step = "unlink"
	StepTerminateControllers Step = "terminate-controllers"
	StepDestroyFoundation    Step = "destroy-foundation"
	StepRollback             Step = "rollback"
)

type stepDef struct {
	step    Step
	from    Phase
	running Phase
	to      Phase
	// spends marks steps that create billable resources; they need a fresh
	// cost admission when they begin.
	spends bool
	retire bool
}

// steps is the complete, ordered effect table. Its order is the forward
// order used for cancel and rollback decisions.
var steps = []stepDef{
	{step: StepSubscribe, from: Admitted, running: Subscribing, to: Subscribed, spends: true},
	{step: StepFoundation, from: Subscribed, running: FoundationProvisioning, to: FoundationReady, spends: true},
	{step: StepImage, from: FoundationReady, running: ImageImporting, to: ImageReady, spends: true},
	{step: StepMaterial, from: ImageReady, running: MaterialMinting, to: Signed},
	{step: StepSeedReserve, from: Signed, running: SeedReserving, to: SeedReserved},
	{step: StepSeedLaunch, from: SeedReserved, running: SeedLaunching, to: SeedObserved, spends: true},
	{step: StepSeedAdmit, from: SeedObserved, running: SeedAdmitting, to: SeedAdmitted},
	{step: StepFounder, from: SeedAdmitted, running: FounderForming, to: ClusterFormed, spends: true},
	{step: StepLink, from: ClusterFormed, running: Linking, to: Linked, spends: true},
	{step: StepPublicAPI, from: Linked, running: PublicAPIProvisioning, to: PublicAPIReady, spends: true},
	{step: StepHandoff, from: PublicAPIReady, running: HandingOff, to: HandedOff},
	{step: StepActivate, from: HandedOff, running: Activating, to: Active},
	{step: StepDrain, from: RetireApproved, running: Draining, to: Drained, retire: true},
	{step: StepUnlink, from: Drained, running: Unlinking, to: Unlinked, retire: true},
	{step: StepTerminateControllers, from: Unlinked, running: ControllersTerminating, to: ControllersTerminated, retire: true},
	{step: StepDestroyFoundation, from: ControllersTerminated, running: FoundationDestroying, to: Retired, retire: true},
}

// forwardOrder ranks bring-up phases so cancel can tell whether the seed
// controller may already exist.
var forwardOrder = func() map[Phase]int {
	order := map[Phase]int{Proposed: 0, Approved: 1, Admitted: 2}
	rank := 3
	for _, def := range steps {
		if def.retire {
			continue
		}
		order[def.running] = rank
		order[def.to] = rank + 1
		rank += 2
	}
	return order
}()

func stepFrom(phase Phase) (stepDef, bool) {
	for _, def := range steps {
		if def.from == phase {
			return def, true
		}
	}
	return stepDef{}, false
}

func stepRunning(phase Phase) (stepDef, bool) {
	for _, def := range steps {
		if def.running == phase {
			return def, true
		}
	}
	return stepDef{}, false
}

// Terminal reports whether no further transition is possible.
func (p Phase) Terminal() bool { return p == Retired || p == Rejected }

// known reports whether p is a defined phase.
func (p Phase) known() bool {
	switch p {
	case Proposed, Approved, Rejected, Held, RollingBack, RetireProposed:
		return true
	}
	_, forward := forwardOrder[p]
	if forward {
		return true
	}
	for _, def := range steps {
		if def.running == p || def.to == p || def.from == p {
			return true
		}
	}
	return false
}

// seedMayExist reports whether controller A may already exist in phase p.
// From SeedLaunching on, removal must go through the retire path.
func seedMayExist(p Phase) bool {
	rank, forward := forwardOrder[p]
	return !forward || rank >= forwardOrder[SeedLaunching]
}

// countsTowardMax reports whether a region in phase p occupies a region slot
// for the policy's maximum region count.
func countsTowardMax(p Phase) bool {
	return p != Proposed && p != Rejected && p != Retired
}
