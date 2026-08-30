// Port of src/TerraScale.Orchestrator/Protocol/Messaging/DurableWorkInventory.cs.
package protocol

import (
	"errors"
	"strings"
	"time"
)

// DurableWorkDomain mirrors the DurableWorkDomain enum: which JetStream domain
// durably owns a work stream, consumer, or queue group. The regional domain is
// per-cell; the global domain is the single global control plane. No durable
// work item crosses domains: gateways never create a WAN-spanning stream or
// consumer.
type DurableWorkDomain int

const (
	DurableWorkDomainUnspecified DurableWorkDomain = 0
	// DurableWorkDomainRegionalCell: the owning regional cell's JetStream
	// domain (subjects are cell-scoped under ts.orch.v2.<cell>).
	DurableWorkDomainRegionalCell DurableWorkDomain = 1
	// DurableWorkDomainGlobalControl: the single global control domain
	// (subjects under ts.orch.v2.global).
	DurableWorkDomainGlobalControl DurableWorkDomain = 2
)

// DurableStreamRetention mirrors the DurableStreamRetention enum. Retention
// limits is the only adopted shape.
type DurableStreamRetention int

const (
	DurableStreamRetentionUnspecified DurableStreamRetention = 0
	// DurableStreamRetentionLimits: bounded history; messages survive
	// consumption until the age/bytes ceiling discards them.
	DurableStreamRetentionLimits DurableStreamRetention = 1
)

// DurableStreamDiscard mirrors the DurableStreamDiscard enum: what a stream
// does when it reaches its age/bytes ceiling.
type DurableStreamDiscard int

const (
	DurableStreamDiscardUnspecified DurableStreamDiscard = 0
	// DurableStreamDiscardOld: discard the oldest messages; new publishes
	// always succeed.
	DurableStreamDiscardOld DurableStreamDiscard = 1
)

// DurableAcknowledgement mirrors the DurableAcknowledgement enum. Explicit
// acknowledgement is the only adopted shape.
type DurableAcknowledgement int

const (
	DurableAcknowledgementUnspecified DurableAcknowledgement = 0
	// DurableAcknowledgementExplicit: a worker acknowledges only after the
	// durable effect exists or an idempotent replay is proven.
	DurableAcknowledgementExplicit DurableAcknowledgement = 1
)

// DurableWorkOwnership mirrors the DurableWorkOwnership enum: the ownership
// discipline of one durable consumer or queue group.
type DurableWorkOwnership int

const (
	DurableWorkOwnershipUnspecified DurableWorkOwnership = 0
	// DurableWorkOwnershipRegionalEquivalentWorkers: any equivalent regional
	// instance may process the work; the subject and domain keep the group
	// regional.
	DurableWorkOwnershipRegionalEquivalentWorkers DurableWorkOwnership = 1
	// DurableWorkOwnershipRegionalFencedAuthority: only the live fenced
	// regional lease holder (epoch plus KV revision) may process or write.
	DurableWorkOwnershipRegionalFencedAuthority DurableWorkOwnership = 2
	// DurableWorkOwnershipGlobalFencedAuthority: only the live fenced global
	// lease holder (epoch plus KV revision) may process or write.
	DurableWorkOwnershipGlobalFencedAuthority DurableWorkOwnership = 3
	// DurableWorkOwnershipReconciledRunnerIdentity: only the exact reconciled
	// CI runner identity may pull its per-runner fenced inbox.
	DurableWorkOwnershipReconciledRunnerIdentity DurableWorkOwnership = 4
)

// DurableStreamPlan mirrors the sealed record: one durable stream of the work
// inventory — every attribute the delivery contract freezes is declared here
// and drift-bound to the provisioning topology. Regional subjects are
// templates over the cell token; SubjectFor substitutes a validated cell.
type DurableStreamPlan struct {
	Stream                 string
	Subjects               []string
	Domain                 DurableWorkDomain
	SemanticClass          MessagingSemanticClass
	Replicas               int
	Retention              DurableStreamRetention
	MaximumAge             time.Duration
	MaximumBytes           int64
	Discard                DurableStreamDiscard
	DuplicateWindow        DuplicateWindowPolicy
	TerminalEvidenceBehavior string
}

// IsWellFormed mirrors the internal rule.
func (p DurableStreamPlan) IsWellFormed() bool {
	return isDurablePlanToken(p.Stream) &&
		len(p.Subjects) >= 1 && allDurablePlanTokens(p.Subjects) &&
		p.Domain != DurableWorkDomainUnspecified &&
		p.SemanticClass != MessagingSemanticClassUnspecified &&
		p.Replicas >= 1 && p.Replicas <= 5 &&
		p.Retention == DurableStreamRetentionLimits &&
		p.MaximumAge > 0 &&
		p.MaximumBytes > 0 &&
		p.Discard == DurableStreamDiscardOld &&
		p.DuplicateWindow.IsWellFormed() &&
		isBoundedPlanText(p.TerminalEvidenceBehavior, 256)
}

// SubjectFor mirrors SubjectFor: it instantiates the cell-scoped subjects of a
// regional stream template.
func (p DurableStreamPlan) SubjectFor(cell string) ([]string, error) {
	subjects := make([]string, len(p.Subjects))
	for index, template := range p.Subjects {
		substituted, err := durablePlanSubjectFor(template, cell)
		if err != nil {
			return nil, err
		}

		subjects[index] = substituted
	}

	return subjects, nil
}

func durablePlanSubjectFor(template, cell string) (string, error) {
	if !isValidCellToken(cell) {
		return "", errors.New(
			"The regional cell is not a lowercase DNS-style token. (Parameter 'cell')")
	}

	return strings.ReplaceAll(template, "{cell}", cell), nil
}

func isDurablePlanToken(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}

	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '_' || character == '-' || character == '.' ||
			character == '{' || character == '}' || character == '*' || character == '>' {
			continue
		}

		return false
	}

	return true
}

func allDurablePlanTokens(values []string) bool {
	for _, value := range values {
		if !isDurablePlanToken(value) {
			return false
		}
	}

	return true
}

func isBoundedPlanText(value string, maximum int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= maximum
}

// DurableConsumerPlan mirrors the sealed record: one durable consumer profile
// of the work inventory — the closed pull shape every instance must reconcile
// to, including the bounded redelivery contract and how terminal evidence is
// produced when a delivery can make no further progress.
type DurableConsumerPlan struct {
	Stream                   string
	Consumer                 string
	FilterSubject            string
	Domain                   DurableWorkDomain
	Ownership                DurableWorkOwnership
	Acknowledgement          DurableAcknowledgement
	MaximumDeliveries        int
	BackoffLadder            []time.Duration
	MaximumAckPending        int
	MaximumBatch             *int
	MaximumExpires           *time.Duration
	MaximumWaiting           *int
	FlowControlBasis         string
	TerminalEvidenceBehavior string
}

// AckWait mirrors the C# property: the declared ack wait equals the first
// backoff interval (JetStream derives it).
func (p DurableConsumerPlan) AckWait() (time.Duration, error) {
	if len(p.BackoffLadder) > 0 {
		return p.BackoffLadder[0], nil
	}

	return 0, errors.New("The backoff ladder is empty.")
}

// IsWellFormed mirrors the internal rule.
func (p DurableConsumerPlan) IsWellFormed() bool {
	if !isDurablePlanToken(p.Stream) ||
		!isDurablePlanToken(p.Consumer) ||
		!isDurablePlanToken(p.FilterSubject) ||
		p.Domain == DurableWorkDomainUnspecified ||
		p.Ownership == DurableWorkOwnershipUnspecified ||
		p.Acknowledgement != DurableAcknowledgementExplicit ||
		p.MaximumDeliveries < 1 || p.MaximumDeliveries > 100 ||
		len(p.BackoffLadder) < 1 || len(p.BackoffLadder) > 16 {
		return false
	}

	for _, step := range p.BackoffLadder {
		if step <= 0 {
			return false
		}
	}

	if p.MaximumAckPending < 1 {
		return false
	}

	if p.MaximumBatch != nil && *p.MaximumBatch < 1 {
		return false
	}

	if p.MaximumExpires != nil && *p.MaximumExpires <= 0 {
		return false
	}

	if p.MaximumWaiting != nil && *p.MaximumWaiting < 1 {
		return false
	}

	return isBoundedPlanText(p.FlowControlBasis, 256) &&
		isBoundedPlanText(p.TerminalEvidenceBehavior, 256)
}

// FilterSubjectFor mirrors FilterSubjectFor: it instantiates the cell-scoped
// filter subject of a regional consumer template.
func (p DurableConsumerPlan) FilterSubjectFor(cell string) (string, error) {
	return durablePlanSubjectFor(p.FilterSubject, cell)
}

// QueueGroupPlan mirrors the sealed record: one queue group of the work
// inventory. Queue groups distribute only equivalent-worker work; the
// authoritative writer of any journal is always chosen by a fenced lease,
// never by a queue group, and the group's subjects stay cell-scoped so no
// cross-region member can join.
type QueueGroupPlan struct {
	Group           string
	Domain          DurableWorkDomain
	Ownership       DurableWorkOwnership
	DistributionRule string
	FencingBasis    string
}

// IsWellFormed mirrors the internal rule.
func (p QueueGroupPlan) IsWellFormed() bool {
	return isDurablePlanToken(p.Group) &&
		p.Domain != DurableWorkDomainUnspecified &&
		p.Ownership != DurableWorkOwnershipUnspecified &&
		isBoundedPlanText(p.DistributionRule, 256) &&
		isBoundedPlanText(p.FencingBasis, 256)
}

const pullFlowControlBasis =
	"Pull consumers bounded by MaxAckPending, MaxBatch, MaxExpires, and MaxWaiting; no push delivery shape is adopted."

var (
	durableStreamPlans  = createDurableStreams()
	durableConsumerPlans = createDurableConsumers()
	queueGroupPlans     = createQueueGroups()
)

// DurableWorkInventory mirrors the C# static class: the typed inventory of
// every durable command/event/work stream, durable consumer profile, and
// queue group the Orchestrator delivers work through. This table is the
// contract; drift tests pin it against the provisioning topology (NatsTopology,
// GlobalNatsTopology) and against the landed delivery policies
// (BoundedRedeliveryPolicy, DuplicateWindowPolicy). It makes no exactly-once
// claim: transport duplicate windows sit beneath operation-level idempotency
// keys, which remain the authority for durable effects.
var DurableWorkInventory durableWorkInventory

type durableWorkInventory struct{}

// Redelivery mirrors DurableWorkInventory.Redelivery: the landed bounded
// redelivery contract every profile must satisfy.
func (durableWorkInventory) Redelivery() BoundedRedeliveryPolicy { return BoundedRedeliveryPolicyLanded }

// Streams mirrors DurableWorkInventory.Streams; treat the slice as read-only.
func (durableWorkInventory) Streams() []DurableStreamPlan { return durableStreamPlans }

// Consumers mirrors DurableWorkInventory.Consumers; treat the slice as read-only.
func (durableWorkInventory) Consumers() []DurableConsumerPlan { return durableConsumerPlans }

// QueueGroups mirrors DurableWorkInventory.QueueGroups; treat the slice as read-only.
func (durableWorkInventory) QueueGroups() []QueueGroupPlan { return queueGroupPlans }

// IsComplete mirrors DurableWorkInventory.IsComplete: every entry is well
// formed and every consumer names a declared stream.
func (durableWorkInventory) IsComplete() bool {
	return len(DurableWorkInventory.CompletenessViolations()) == 0
}

// CompletenessViolations mirrors DurableWorkInventory.CompletenessViolations.
func (durableWorkInventory) CompletenessViolations() []string {
	violations := []string{}
	streamNames := map[string]struct{}{}
	for _, stream := range durableStreamPlans {
		if !stream.IsWellFormed() {
			violations = append(violations, "The durable stream plan "+stream.Stream+" is not well formed.")
		}

		if _, duplicate := streamNames[stream.Stream]; duplicate {
			violations = append(violations, "The durable stream plan "+stream.Stream+" is declared more than once.")
		}

		streamNames[stream.Stream] = struct{}{}
	}

	consumerNames := map[string]struct{}{}
	for _, consumer := range durableConsumerPlans {
		if !consumer.IsWellFormed() {
			violations = append(violations, "The durable consumer plan "+consumer.Consumer+" is not well formed.")
		}

		if _, duplicate := consumerNames[consumer.Consumer]; duplicate {
			violations = append(violations, "The durable consumer plan "+consumer.Consumer+" is declared more than once.")
		}

		consumerNames[consumer.Consumer] = struct{}{}
		if _, declared := streamNames[consumer.Stream]; !declared {
			violations = append(violations, "The durable consumer plan "+consumer.Consumer+" names an undeclared stream.")
		}

		if consumer.Domain == DurableWorkDomainGlobalControl &&
			!BoundedRedeliveryContract.BoundedBy(DurableWorkInventory.Redelivery(), consumer) {
			violations = append(violations,
				"The durable consumer plan "+consumer.Consumer+" violates the bounded redelivery contract.")
		}
	}

	groups := map[string]struct{}{}
	for _, group := range queueGroupPlans {
		if !group.IsWellFormed() {
			violations = append(violations, "The queue group plan "+group.Group+" is not well formed.")
		}

		if _, duplicate := groups[group.Group]; duplicate {
			violations = append(violations, "The queue group plan "+group.Group+" is declared more than once.")
		}

		groups[group.Group] = struct{}{}
	}

	return violations
}

func createDurableStreams() []DurableStreamPlan {
	cell := DuplicateWindowPolicyCellStreams
	global := DuplicateWindowPolicyGlobalCiStream
	return []DurableStreamPlan{
		{
			Stream: "CELL_SPEC",
			Subjects: []string{
				NatsSubjectTaxonomy.RegionalDesiredFamilyTemplate(),
			},
			Domain:        DurableWorkDomainRegionalCell,
			SemanticClass: MessagingSemanticClassAuthoritativeJournal,
			Replicas:      3,
			Retention:     DurableStreamRetentionLimits,
			MaximumAge:    30 * 24 * time.Hour,
			MaximumBytes:  256 * 1024 * 1024,
			Discard:       DurableStreamDiscardOld,
			DuplicateWindow: cell,
			TerminalEvidenceBehavior: "Accepted CellSpec history; deterministic conflicts terminate with terminal evidence, exhaustion warns on the final delivery.",
		},
		{
			Stream: "CELL_OPERATIONS",
			Subjects: []string{
				NatsSubjectTaxonomy.RegionalOperationFamilyTemplate(),
			},
			Domain:        DurableWorkDomainRegionalCell,
			SemanticClass: MessagingSemanticClassAuthoritativeJournal,
			Replicas:      3,
			Retention:     DurableStreamRetentionLimits,
			MaximumAge:    30 * 24 * time.Hour,
			MaximumBytes:  1024 * 1024 * 1024,
			Discard:       DurableStreamDiscardOld,
			DuplicateWindow: cell,
			TerminalEvidenceBehavior: "Authoritative regional operation history; KV CAS plus operation proofs fence every append.",
		},
		{
			Stream: "CELL_EVENTS",
			Subjects: []string{
				NatsSubjectTaxonomy.RegionalObservationFamilyTemplate(),
			},
			Domain:        DurableWorkDomainRegionalCell,
			SemanticClass: MessagingSemanticClassReplayable,
			Replicas:      3,
			Retention:     DurableStreamRetentionLimits,
			MaximumAge:    30 * 24 * time.Hour,
			MaximumBytes:  256 * 1024 * 1024,
			Discard:       DurableStreamDiscardOld,
			DuplicateWindow: cell,
			TerminalEvidenceBehavior: "Bounded replayable runtime events; consumers reconcile from journals, so loss or replay is safe.",
		},
		{
			Stream: "GLOBAL_SPEC",
			Subjects: []string{
				NatsSubjectTaxonomy.GlobalRoot() + ".desired.>",
			},
			Domain:        DurableWorkDomainGlobalControl,
			SemanticClass: MessagingSemanticClassAuthoritativeJournal,
			Replicas:      3,
			Retention:     DurableStreamRetentionLimits,
			MaximumAge:    30 * 24 * time.Hour,
			MaximumBytes:  256 * 1024 * 1024,
			Discard:       DurableStreamDiscardOld,
			DuplicateWindow: cell,
			TerminalEvidenceBehavior: "Accepted global revisions; deterministic conflicts terminate with terminal evidence.",
		},
		{
			Stream: "GLOBAL_CI",
			Subjects: []string{
				NatsSubjectTaxonomy.GlobalCiFamilyPattern(),
			},
			Domain:        DurableWorkDomainGlobalControl,
			SemanticClass: MessagingSemanticClassWorkQueue,
			Replicas:      3,
			Retention:     DurableStreamRetentionLimits,
			MaximumAge:    30 * 24 * time.Hour,
			MaximumBytes:  1024 * 1024 * 1024,
			Discard:       DurableStreamDiscardOld,
			DuplicateWindow: global,
			TerminalEvidenceBehavior: "Normalized CI events and fenced runner commands; trigger conflicts terminate, runner identity conflicts terminate, exhaustion warns on the final delivery.",
		},
	}
}

func createDurableConsumers() []DurableConsumerPlan {
	ladder := BoundedRedeliveryPolicyLanded.BackoffLadder
	triggerTerminal :=
		"Deterministic conflicts AckTerminate loudly; retry exhaustion warns on the final delivery before its nak."
	cellspecTerminal :=
		"Deterministic conflicts and identity conflicts AckTerminate loudly; authority loss withholds the acknowledgement."
	batchOne := 1
	expiresThirty := 30 * time.Second
	waitingEight := 8
	waitingSixteen := 16
	waitingFour := 4
	return []DurableConsumerPlan{
		{
			Stream:        "CELL_EVENTS",
			Consumer:      "runtime_startup",
			FilterSubject: NatsSubjectTaxonomy.RegionalRuntimeStartupTemplate(),
			Domain:        DurableWorkDomainRegionalCell,
			Ownership:     DurableWorkOwnershipRegionalEquivalentWorkers,
			Acknowledgement: DurableAcknowledgementExplicit,
			MaximumDeliveries: BoundedRedeliveryPolicyLanded.MaximumDeliveries,
			BackoffLadder:  ladder,
			MaximumAckPending: 32,
			MaximumBatch:  nil,
			MaximumExpires: nil,
			MaximumWaiting: &waitingSixteen,
			FlowControlBasis: pullFlowControlBasis,
			TerminalEvidenceBehavior: "Acknowledged startup events; a lost acknowledgement redelivers and the idempotent event id converges.",
		},
		{
			Stream:        "CELL_SPEC",
			Consumer:      "gitops_cell_spec_{instance}",
			FilterSubject: NatsSubjectTaxonomy.RegionalCellSpecTemplate(),
			Domain:        DurableWorkDomainRegionalCell,
			Ownership:     DurableWorkOwnershipRegionalFencedAuthority,
			Acknowledgement: DurableAcknowledgementExplicit,
			MaximumDeliveries: BoundedRedeliveryPolicyLanded.MaximumDeliveries,
			BackoffLadder:  ladder,
			MaximumAckPending: 8,
			MaximumBatch:  &batchOne,
			MaximumExpires: &expiresThirty,
			MaximumWaiting: &waitingEight,
			FlowControlBasis: pullFlowControlBasis,
			TerminalEvidenceBehavior: cellspecTerminal,
		},
		{
			Stream:        "GLOBAL_SPEC",
			Consumer:      "gitops_global_cell_spec_{cell}",
			FilterSubject: NatsSubjectTaxonomy.GlobalCellSpecPrefix() + ".{cell}",
			Domain:        DurableWorkDomainGlobalControl,
			Ownership:     DurableWorkOwnershipGlobalFencedAuthority,
			Acknowledgement: DurableAcknowledgementExplicit,
			MaximumDeliveries: BoundedRedeliveryPolicyLanded.MaximumDeliveries,
			BackoffLadder:  ladder,
			MaximumAckPending: 8,
			MaximumBatch:  &batchOne,
			MaximumExpires: &expiresThirty,
			MaximumWaiting: &waitingEight,
			FlowControlBasis: pullFlowControlBasis,
			TerminalEvidenceBehavior: cellspecTerminal,
		},
		{
			Stream:        "GLOBAL_CI",
			Consumer:      "global_ci_trigger",
			FilterSubject: NatsSubjectTaxonomy.CiForgejoTriggerSubject(),
			Domain:        DurableWorkDomainGlobalControl,
			Ownership:     DurableWorkOwnershipGlobalFencedAuthority,
			Acknowledgement: DurableAcknowledgementExplicit,
			MaximumDeliveries: BoundedRedeliveryPolicyLanded.MaximumDeliveries,
			BackoffLadder:  ladder,
			MaximumAckPending: 32,
			MaximumBatch:  nil,
			MaximumExpires: nil,
			MaximumWaiting: &waitingSixteen,
			FlowControlBasis: pullFlowControlBasis,
			TerminalEvidenceBehavior: triggerTerminal,
		},
		{
			Stream:        "GLOBAL_CI",
			Consumer:      "global_ci_runtime_proof",
			FilterSubject: NatsSubjectTaxonomy.CiRuntimeProofSubject(),
			Domain:        DurableWorkDomainGlobalControl,
			Ownership:     DurableWorkOwnershipGlobalFencedAuthority,
			Acknowledgement: DurableAcknowledgementExplicit,
			MaximumDeliveries: BoundedRedeliveryPolicyLanded.MaximumDeliveries,
			BackoffLadder:  ladder,
			MaximumAckPending: 32,
			MaximumBatch:  &batchOne,
			MaximumExpires: &expiresThirty,
			MaximumWaiting: &waitingSixteen,
			FlowControlBasis: pullFlowControlBasis,
			TerminalEvidenceBehavior: "Leader-verified observations double-ack after the durable pointer wins; deterministic failures terminate loudly.",
		},
		{
			Stream:        "GLOBAL_CI",
			Consumer:      "ci_runner_{zone}_{runner}",
			FilterSubject: NatsSubjectTaxonomy.CiJobSubjectPrefix() + ".{zone}.{runner}",
			Domain:        DurableWorkDomainGlobalControl,
			Ownership:     DurableWorkOwnershipReconciledRunnerIdentity,
			Acknowledgement: DurableAcknowledgementExplicit,
			MaximumDeliveries: BoundedRedeliveryPolicyLanded.MaximumDeliveries,
			BackoffLadder:  ladder,
			MaximumAckPending: 1,
			MaximumBatch:  &batchOne,
			MaximumExpires: &expiresThirty,
			MaximumWaiting: &waitingFour,
			FlowControlBasis: pullFlowControlBasis,
			TerminalEvidenceBehavior: "Fenced per-runner inbox (MaxAckPending 1); a message-id/payload identity conflict AckTerminates loudly; progress acks keep long executions leased.",
		},
	}
}

func createQueueGroups() []QueueGroupPlan {
	return []QueueGroupPlan{
		{
			Group:  "orchestrator_{cell}",
			Domain: DurableWorkDomainRegionalCell,
			Ownership: DurableWorkOwnershipRegionalEquivalentWorkers,
			DistributionRule: "Equivalent-worker regional service endpoints; any member may answer a health, status, or members query.",
			FencingBasis: "No authoritative write rides the group; answers are equivalent and cell-scoped subjects keep membership regional.",
		},
		{
			Group:  "terrascale_orchestrator_journal_writer_{cell}",
			Domain: DurableWorkDomainRegionalCell,
			Ownership: DurableWorkOwnershipRegionalEquivalentWorkers,
			DistributionRule: "Equivalent-worker journal writer fan-in for one regional cell only.",
			FencingBasis: "Every authoritative journal append is fenced by the regional lease epoch and single-use operation proofs before and after the write.",
		},
	}
}

// BoundedRedeliveryContract mirrors the C# static class: the extension seam
// binding a consumer plan to the landed bounded redelivery contract.
var BoundedRedeliveryContract boundedRedeliveryContract

type boundedRedeliveryContract struct{}

// BoundedBy mirrors BoundedRedeliveryPolicy.BoundedBy: true when the consumer
// profile satisfies the landed bounded redelivery contract — the delivery cap,
// the backoff ladder, and the derived ack wait must equal the policy. The
// ack-pending bound is per-consumer flow control — a profile may tighten it
// (the fenced runner inbox pins 1) or widen it within its own declared pull
// shape.
func (boundedRedeliveryContract) BoundedBy(policy BoundedRedeliveryPolicy, consumer DurableConsumerPlan) bool {
	if consumer.MaximumDeliveries != policy.MaximumDeliveries {
		return false
	}

	if len(consumer.BackoffLadder) != len(policy.BackoffLadder) {
		return false
	}

	for index, step := range consumer.BackoffLadder {
		if step != policy.BackoffLadder[index] {
			return false
		}
	}

	consumerAckWait, err := consumer.AckWait()
	if err != nil {
		return false
	}

	policyAckWait, err := policy.AckWait()
	if err != nil {
		return false
	}

	return consumerAckWait == policyAckWait
}
