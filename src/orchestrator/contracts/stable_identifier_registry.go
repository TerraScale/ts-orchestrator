// Port of src/TerraScale.Orchestrator/Contracts/StableIdentifiers/StableIdentifierRegistry.cs.
package contracts

// StableIdentifierRegistry mirrors the C# static class of the same name: the
// machine-readable registry of the permanent stable contract identifiers
// defined by the GOAL.md "Stable contract identifiers" tables. The canonical
// text below is copied verbatim from GOAL.md and never changes in place.
// Registry rules encoded here: identifiers are permanent; a replacement
// decision marks the old identifier superseded through Supersessions and adds
// a new identifier; the meaning of a live identifier is never edited.
// SupersessionViolations reports every breach of those rules, so it must stay
// empty. The returned maps must be treated as read-only.
var StableIdentifierRegistry stableIdentifierRegistry

type stableIdentifierRegistry struct{}

// RegistryRevision is the revision of the GOAL.md identifier tables this registry transcribes.
const RegistryRevision = "2026-08-29"

var requirementTexts = map[RequirementId]string{
	RequirementId{Value: "REQ-ORCH-001"}: "GRU runs the permanent global authority.",
	RequirementId{Value: "REQ-ORCH-002"}: "Every global and regional controller group has three replicas and one active leader.",
	RequirementId{Value: "REQ-ORCH-003"}: "Every NATS control domain uses JetStream file storage with three replicas.",
	RequirementId{Value: "REQ-ORCH-004"}: "Every active Region operates safely during GRU or WAN loss from its last accepted policy.",
	RequirementId{Value: "REQ-ORCH-005"}: "GRU receives the complete regional journal after connectivity returns.",
	RequirementId{Value: "REQ-ORCH-006"}: "The Orchestrator bootstraps and owns the greenfield OCI estate without Pulumi or OpenTofu.",
	RequirementId{Value: "REQ-ORCH-007"}: "OCI mutations use typed, region-scoped provider actuators and durable journals.",
	RequirementId{Value: "REQ-ORCH-008"}: "The scheduler places only admitted immutable workloads on eligible hosts.",
	RequirementId{Value: "REQ-ORCH-009"}: "TerraBase placement follows database-selected Regions and RF=2 active Members per Region and Partition.",
	RequirementId{Value: "REQ-ORCH-010"}: "Dashboard and Database API run at least two instances per qualified Region.",
	RequirementId{Value: "REQ-ORCH-011"}: "Orchestrator provisions workload identity, trust bundles, rotation, and bootstrap grants.",
	RequirementId{Value: "REQ-ORCH-012"}: "Orchestrator operates Cloudflare global and strict regional routing for no more than twenty active Regions.",
	RequirementId{Value: "REQ-ORCH-013"}: "Delivery admits exact artifacts, provenance, configuration, migrations, and rollback anchors.",
	RequirementId{Value: "REQ-ORCH-014"}: "Autoscaling uses sustained typed capacity reports and preserves hard safety ceilings.",
	RequirementId{Value: "REQ-ORCH-015"}: "Every long-running action exposes durable exact progress and a terminal receipt.",
	RequirementId{Value: "REQ-ORCH-016"}: "Regional and global control state has backup, restore, corruption, and total-rebuild evidence.",
	RequirementId{Value: "REQ-ORCH-017"}: "Operators receive typed plans, holds, approvals, progress, and redacted evidence.",
	RequirementId{Value: "REQ-ORCH-018"}: "The production release qualifies GRU, SFO, FRA, ARM64 control hosts, ARM64 and x86_64 TerraBase workload hosts, OCI, NATS, systemd, containerd, Block Volume, Vault, Object Storage, and Cloudflare.",
	RequirementId{Value: "REQ-ORCH-019"}: "The architecture supports a deterministic twenty-Region simulation before the fourth Region is published.",
	RequirementId{Value: "REQ-ORCH-020"}: "No customer-serving request requires a live Orchestrator or NATS lookup.",
	RequirementId{Value: "REQ-ORCH-021"}: "The production repository, solution, runtime, and artifact contain no embedded development-host composition or DevHost dependency.",
	RequirementId{Value: "REQ-ORCH-022"}: "Every production upgrade creates and qualifies a parallel regional candidate before cutover.",
	RequirementId{Value: "REQ-ORCH-023"}: "Every host publishes admitted capacity, reserved capacity, allocatable capacity, pressure, shutdown, and reclamation state.",
	RequirementId{Value: "REQ-ORCH-024"}: "Every workload uses a closed execution mode, restart policy, priority class, preemption policy, network lease, and filesystem-reclamation contract.",
	RequirementId{Value: "REQ-ORCH-025"}: "Resource status, list, and watch APIs expose conditions, `observedGeneration`, stable pagination, resumable progress, compaction recovery, and bounded overload behavior.",
	RequirementId{Value: "REQ-ORCH-026"}: "Dependency-aware deletion uses durable typed blockers and verified absence before final removal.",
	RequirementId{Value: "REQ-ORCH-027"}: "Reconcile, reconnect, health, and provider work queues are bounded, fair, coalesced by resource, and safe under retry storms.",
	RequirementId{Value: "REQ-ORCH-028"}: "Rebalancing and consolidation preserve disruption budgets, failure headroom, surge capacity, storage safety, and a measured net benefit.",
}

var invariantTexts = map[InvariantId]string{
	InvariantId{Value: "INV-ORCH-001"}: "One exact authority term may mutate one control scope.",
	InvariantId{Value: "INV-ORCH-002"}: "Global policy has one writer in GRU.",
	InvariantId{Value: "INV-ORCH-003"}: "Regional mutation requires the current local term and local NATS quorum.",
	InvariantId{Value: "INV-ORCH-004"}: "An isolated Region cannot create a new global generation.",
	InvariantId{Value: "INV-ORCH-005"}: "Desired state never erases a provider or TerraBase observation.",
	InvariantId{Value: "INV-ORCH-006"}: "Every external mutation is preceded by durable authorized intent.",
	InvariantId{Value: "INV-ORCH-007"}: "Unknown provider outcome is reconciled before retry or compensation.",
	InvariantId{Value: "INV-ORCH-008"}: "One provider resource has one active lifecycle owner.",
	InvariantId{Value: "INV-ORCH-009"}: "Tags and discovery never grant mutation authority.",
	InvariantId{Value: "INV-ORCH-010"}: "A stale leader cannot complete a new accepted mutation.",
	InvariantId{Value: "INV-ORCH-011"}: "A committed provider target remains fixed across leadership change.",
	InvariantId{Value: "INV-ORCH-012"}: "NATS never carries customer data or TerraBase correctness state.",
	InvariantId{Value: "INV-ORCH-013"}: "TerraBase alone accepts membership and retirement.",
	InvariantId{Value: "INV-ORCH-014"}: "Scale-in cannot reduce required durability or recovery headroom.",
	InvariantId{Value: "INV-ORCH-015"}: "Secrets and private keys never enter desired state, NATS, telemetry, receipts, or Git.",
	InvariantId{Value: "INV-ORCH-016"}: "A release activates only the exact qualified digest and configuration.",
	InvariantId{Value: "INV-ORCH-017"}: "Catalog discovery and catalog publication are separate transitions.",
	InvariantId{Value: "INV-ORCH-018"}: "A retired `RegionCode`, Member identity, replica epoch, volume identity, or bootstrap generation is never reused unsafely.",
	InvariantId{Value: "INV-ORCH-019"}: "Admission and backpressure protect workloads before capacity arrives.",
	InvariantId{Value: "INV-ORCH-020"}: "Telemetry cannot authorize a destructive operation.",
	InvariantId{Value: "INV-ORCH-021"}: "An active allocation is never mutated in place during release.",
	InvariantId{Value: "INV-ORCH-022"}: "Development composition, credentials, trust roots, and authority paths cannot enter a production artifact or state store.",
	InvariantId{Value: "INV-ORCH-023"}: "Production traffic cannot reach a candidate before its exact generation satisfies minimum healthy time and every required gate.",
	InvariantId{Value: "INV-ORCH-024"}: "One active allocation owns one unique, durable IP and port lease for each bound endpoint.",
	InvariantId{Value: "INV-ORCH-025"}: "A resource cannot disappear while a current typed deletion blocker, live dependent, or unverified external resource remains.",
	InvariantId{Value: "INV-ORCH-026"}: "Status cannot claim a desired generation applied until `observedGeneration` equals that generation.",
	InvariantId{Value: "INV-ORCH-027"}: "Host pressure stops new placement before eviction, and planned shutdown drains admitted work before poweroff.",
	InvariantId{Value: "INV-ORCH-028"}: "Queue overload sheds, delays, or coalesces work without dropping durable intent or creating unbounded memory use.",
}

var securityRuleTexts = map[SecurityRuleId]string{
	SecurityRuleId{Value: "SEC-ORCH-001"}: "Every privileged network boundary uses TLS 1.3 and mutual workload identity.",
	SecurityRuleId{Value: "SEC-ORCH-002"}: "NATS servers use mTLS; clients also use scoped NKey and JWT identities.",
	SecurityRuleId{Value: "SEC-ORCH-003"}: "Global, regional, host-agent, CI, monitoring, and infrastructure identities have disjoint permissions.",
	SecurityRuleId{Value: "SEC-ORCH-004"}: "Regional OCI credentials cannot mutate another Region or the tenancy root.",
	SecurityRuleId{Value: "SEC-ORCH-005"}: "GRU global controllers do not hold ordinary regional OCI mutation credentials.",
	SecurityRuleId{Value: "SEC-ORCH-006"}: "Secret configuration contains references and version identities only.",
	SecurityRuleId{Value: "SEC-ORCH-007"}: "Private keys are non-exportable where OCI Vault supports the required operation.",
	SecurityRuleId{Value: "SEC-ORCH-008"}: "Bootstrap credentials expire or are revoked after handoff.",
	SecurityRuleId{Value: "SEC-ORCH-009"}: "Artifacts require immutable digest, signature, provenance, SBOM, and vulnerability disposition.",
	SecurityRuleId{Value: "SEC-ORCH-010"}: "No ordinary operation requires inbound SSH.",
	SecurityRuleId{Value: "SEC-ORCH-011"}: "Break-glass access is time-bound, approved, recorded, and automatically revoked.",
	SecurityRuleId{Value: "SEC-ORCH-012"}: "Logs, traces, metrics, errors, fixtures, and receipts redact secret and customer content before emission.",
	SecurityRuleId{Value: "SEC-ORCH-013"}: "Development trust roots, certificates, credentials, tokens, and secret defaults never enter production state, images, packages, or deployments.",
	SecurityRuleId{Value: "SEC-ORCH-014"}: "A workload receives network, port, filesystem, device, secret, and peer access only through its admitted allocation contract.",
}

var stateMachineTexts = map[StateMachineId]string{
	StateMachineId{Value: "SM-ORCH-BOOTSTRAP"}:          "Empty tenancy to accepted GRU authority",
	StateMachineId{Value: "SM-ORCH-GLOBAL-AUTHORITY"}:   "Global leader election, renewal, fencing, and replacement",
	StateMachineId{Value: "SM-ORCH-REGIONAL-AUTHORITY"}: "Regional leader election, renewal, fencing, and replacement",
	StateMachineId{Value: "SM-ORCH-REGION-ADMISSION"}:   "Planned Region to owner-approved catalog publication",
	StateMachineId{Value: "SM-ORCH-REGION-REMOVAL"}:     "Routing fence through final retention and deletion receipts",
	StateMachineId{Value: "SM-ORCH-PROVIDER-OPERATION"}: "Prepared intent through exact provider terminal outcome",
	StateMachineId{Value: "SM-ORCH-HOST-LIFECYCLE"}:     "Host request, creation, enrollment, admission, drain, and retirement",
	StateMachineId{Value: "SM-ORCH-WORKLOAD-LIFECYCLE"}: "Artifact admission through allocation, minimum health, service, drain, and verified stop",
	StateMachineId{Value: "SM-ORCH-MEMBER-ADD"}:         "TerraBase identity allocation through membership acceptance",
	StateMachineId{Value: "SM-ORCH-MEMBER-REPLACE"}:     "Failed seat through verified replacement and safe retirement",
	StateMachineId{Value: "SM-ORCH-CAPACITY"}:           "Pressure observation through scale, rebalance, or admission refusal",
	StateMachineId{Value: "SM-ORCH-RELEASE"}:            "Immutable blue through parallel green creation, qualification, atomic cutover, rollback window, and blue retirement",
	StateMachineId{Value: "SM-ORCH-RECONNECT"}:          "Regional isolation through journal upload and reconciled generation",
	StateMachineId{Value: "SM-ORCH-TRUST-ROTATION"}:     "New trust generation through overlap and old-generation retirement",
	StateMachineId{Value: "SM-ORCH-CONTROL-RESTORE"}:    "Backup selection through new fenced recovery generation",
	StateMachineId{Value: "SM-ORCH-NODE-PRESSURE"}:      "Pressure detection through cordon, reclaim, drain, recovery, or failed-host replacement",
	StateMachineId{Value: "SM-ORCH-WORKLOAD-RESTART"}:   "Failure through bounded backoff, stable recovery, rollback, or digest quarantine",
	StateMachineId{Value: "SM-ORCH-RESOURCE-DELETION"}:  "Deletion request through dependent drain, blocker release, external absence, and tombstone retention",
}

var stableErrorTexts = map[StableErrorId]string{
	StableErrorId{Value: "ERR-ORCH-AUTHORITY-UNAVAILABLE"}:       "The required authority quorum or current term is unavailable.",
	StableErrorId{Value: "ERR-ORCH-STALE-TERM"}:                  "A command, executor, or observation belongs to an older authority term.",
	StableErrorId{Value: "ERR-ORCH-GENERATION-CONFLICT"}:         "Desired, applied, or observed generations cannot be reconciled automatically.",
	StableErrorId{Value: "ERR-ORCH-REGION-ISOLATED"}:             "The requested action is outside the Region's admitted survival policy.",
	StableErrorId{Value: "ERR-ORCH-OUTCOME-UNKNOWN"}:             "An external mutation may have occurred and needs observation.",
	StableErrorId{Value: "ERR-ORCH-OWNERSHIP-MISMATCH"}:          "Positive resource ownership does not match the requested operation.",
	StableErrorId{Value: "ERR-ORCH-EVIDENCE-INCOMPLETE"}:         "Required current and complete evidence is missing.",
	StableErrorId{Value: "ERR-ORCH-CAPACITY-UNAVAILABLE"}:        "No eligible placement satisfies resources and safety reserves.",
	StableErrorId{Value: "ERR-ORCH-BUDGET-APPROVAL-REQUIRED"}:    "A safe operation exceeds the automatic budget but not the hard ceiling.",
	StableErrorId{Value: "ERR-ORCH-PROVIDER-LIMIT"}:              "A provider quota, capacity, or account ceiling blocks the action.",
	StableErrorId{Value: "ERR-ORCH-TERRABASE-HOLD"}:              "TerraBase has not accepted the required membership, frontier, or retirement state.",
	StableErrorId{Value: "ERR-ORCH-ARTIFACT-DENIED"}:             "Artifact identity, signature, provenance, architecture, or rollback evidence failed.",
	StableErrorId{Value: "ERR-ORCH-REGION-NOT-QUALIFIED"}:        "A Region cannot receive customer traffic or placement.",
	StableErrorId{Value: "ERR-ORCH-RESTORE-GENERATION-CONFLICT"}: "A restore might overlap a live control generation.",
	StableErrorId{Value: "ERR-ORCH-CANDIDATE-NOT-READY"}:         "The exact candidate has not passed minimum health, compatibility, routing, or required tests.",
	StableErrorId{Value: "ERR-ORCH-WORKLOAD-QUARANTINED"}:        "The artifact and configuration pair exceeded its restart or health-failure budget.",
	StableErrorId{Value: "ERR-ORCH-DELETION-BLOCKED"}:            "A current dependent, safety hold, or external resource prevents deletion.",
	StableErrorId{Value: "ERR-ORCH-WATCH-EXPIRED"}:               "The resume point is below retained journal history and the client must relist.",
}

// supersederValues mirrors SupersederValues: a replacement decision maps the
// retired identifier value to its replacement here and adds the replacement to
// its kind's table above. It never edits the retired identifier's canonical
// text. The table starts empty because no identifier has been replaced.
var supersederValues = map[string]string{}

// Requirements mirrors StableIdentifierRegistry.Requirements.
func (stableIdentifierRegistry) Requirements() map[RequirementId]string { return requirementTexts }

// Invariants mirrors StableIdentifierRegistry.Invariants.
func (stableIdentifierRegistry) Invariants() map[InvariantId]string { return invariantTexts }

// SecurityRules mirrors StableIdentifierRegistry.SecurityRules.
func (stableIdentifierRegistry) SecurityRules() map[SecurityRuleId]string { return securityRuleTexts }

// StateMachines mirrors StableIdentifierRegistry.StateMachines.
func (stableIdentifierRegistry) StateMachines() map[StateMachineId]string { return stateMachineTexts }

// StableErrors mirrors StableIdentifierRegistry.StableErrors.
func (stableIdentifierRegistry) StableErrors() map[StableErrorId]string { return stableErrorTexts }

// Supersessions mirrors StableIdentifierRegistry.Supersessions.
func (stableIdentifierRegistry) Supersessions() map[string]string { return supersederValues }

func (stableIdentifierRegistry) tryGetRequirementText(id RequirementId) (string, bool) {
	text, ok := requirementTexts[id]
	return text, ok
}

func (stableIdentifierRegistry) tryGetInvariantText(id InvariantId) (string, bool) {
	text, ok := invariantTexts[id]
	return text, ok
}

func (stableIdentifierRegistry) tryGetSecurityRuleText(id SecurityRuleId) (string, bool) {
	text, ok := securityRuleTexts[id]
	return text, ok
}

func (stableIdentifierRegistry) tryGetStateMachineText(id StateMachineId) (string, bool) {
	text, ok := stateMachineTexts[id]
	return text, ok
}

func (stableIdentifierRegistry) tryGetStableErrorText(id StableErrorId) (string, bool) {
	text, ok := stableErrorTexts[id]
	return text, ok
}

func (stableIdentifierRegistry) supersededRequirement(id RequirementId) (RequirementId, bool) {
	if replacement, ok := supersederValues[id.Value]; ok {
		return RequirementIdTryCreate(replacement)
	}

	return RequirementId{}, false
}

func (stableIdentifierRegistry) supersededInvariant(id InvariantId) (InvariantId, bool) {
	if replacement, ok := supersederValues[id.Value]; ok {
		return InvariantIdTryCreate(replacement)
	}

	return InvariantId{}, false
}

func (stableIdentifierRegistry) supersededSecurityRule(id SecurityRuleId) (SecurityRuleId, bool) {
	if replacement, ok := supersederValues[id.Value]; ok {
		return SecurityRuleIdTryCreate(replacement)
	}

	return SecurityRuleId{}, false
}

func (stableIdentifierRegistry) supersededStateMachine(id StateMachineId) (StateMachineId, bool) {
	if replacement, ok := supersederValues[id.Value]; ok {
		return StateMachineIdTryCreate(replacement)
	}

	return StateMachineId{}, false
}

func (stableIdentifierRegistry) supersededStableError(id StableErrorId) (StableErrorId, bool) {
	if replacement, ok := supersederValues[id.Value]; ok {
		return StableErrorIdTryCreate(replacement)
	}

	return StableErrorId{}, false
}

// SupersessionViolations reports every breach of the supersession rules:
// retired or replacement values that are not registered identifiers of the
// same kind, self-supersession, and supersession cycles. The list must stay
// empty.
func (stableIdentifierRegistry) SupersessionViolations() []string {
	violations := []string{}
	for retired, replacement := range supersederValues {
		retiredKind, retiredOk := tryClassifyIdentifier(retired)
		replacementKind, replacementOk := tryClassifyIdentifier(replacement)
		if !retiredOk {
			violations = append(violations, retired+" is not a registered identifier.")
		}

		if !replacementOk {
			violations = append(violations, replacement+" is not a registered identifier.")
		}

		if retiredOk && replacementOk && retiredKind != replacementKind {
			violations = append(violations, retired+" and "+replacement+" belong to different identifier kinds.")
		}

		if retired == replacement {
			violations = append(violations, retired+" supersedes itself.")
		}
	}

	for retired := range supersederValues {
		visited := map[string]struct{}{}
		current := retired
		for {
			next, ok := supersederValues[current]
			if !ok {
				break
			}

			if _, seen := visited[current]; seen {
				violations = append(violations, retired+" participates in a supersession cycle at "+current+".")
				break
			}

			visited[current] = struct{}{}
			current = next
		}
	}

	return violations
}

func tryClassifyIdentifier(value string) (StableIdentifierKind, bool) {
	if _, ok := requirementTexts[RequirementId{Value: value}]; ok {
		return StableIdentifierKindRequirement, true
	}

	if _, ok := invariantTexts[InvariantId{Value: value}]; ok {
		return StableIdentifierKindInvariant, true
	}

	if _, ok := securityRuleTexts[SecurityRuleId{Value: value}]; ok {
		return StableIdentifierKindSecurityRule, true
	}

	if _, ok := stateMachineTexts[StateMachineId{Value: value}]; ok {
		return StableIdentifierKindStateMachine, true
	}

	if _, ok := stableErrorTexts[StableErrorId{Value: value}]; ok {
		return StableIdentifierKindStableError, true
	}

	return StableIdentifierKindUnspecified, false
}
