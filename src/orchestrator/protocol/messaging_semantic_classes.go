package protocol

import "terrascale.tech/orchestrator/src/orchestrator/natspolicy"

import "strconv"

// MessagingSemanticClass is the set of five message semantic classes of the
// messaging contract. Every control subject maps to exactly one class; the
// class fixes what loss, replay, and duplication mean for it.
type MessagingSemanticClass int

const (
	MessagingSemanticClassUnspecified MessagingSemanticClass = 0
	// MessagingSemanticClassLossy: loss is safe; senders/consumers retry; no
	// durability is owed.
	MessagingSemanticClassLossy MessagingSemanticClass = 1
	// MessagingSemanticClassReplayable: durable bounded history; consumers may
	// replay from the beginning.
	MessagingSemanticClassReplayable MessagingSemanticClass = 2
	// MessagingSemanticClassWorkQueue: durably queued unit of work; at most one
	// active handler; terminal disposition required.
	MessagingSemanticClassWorkQueue MessagingSemanticClass = 3
	// MessagingSemanticClassSnapshot: content-addressed state snapshot;
	// consumed by position/digest, not by subscription order.
	MessagingSemanticClassSnapshot MessagingSemanticClass = 4
	// MessagingSemanticClassAuthoritativeJournal: authoritative append-only
	// history; one fenced writer per aggregate; the source of truth.
	MessagingSemanticClassAuthoritativeJournal MessagingSemanticClass = 5
)

func (c MessagingSemanticClass) String() string {
	switch c {
	case MessagingSemanticClassLossy:
		return "Lossy"
	case MessagingSemanticClassReplayable:
		return "Replayable"
	case MessagingSemanticClassWorkQueue:
		return "WorkQueue"
	case MessagingSemanticClassSnapshot:
		return "Snapshot"
	case MessagingSemanticClassAuthoritativeJournal:
		return "AuthoritativeJournal"
	default:
		return strconv.Itoa(int(c))
	}
}

// SemanticClassRule is one declarative subject-to-semantic-class mapping.
type SemanticClassRule struct {
	SubjectPattern string
	Namespace      natspolicy.NatsSubjectNamespace
	SemanticClass  MessagingSemanticClass
	LossMeaning    string

	compiled *natspolicy.SubjectPermissionPattern
}

// Matches reports whether the concrete subject matches the rule's pattern.
func (r *SemanticClassRule) Matches(subject *natspolicy.ConcreteSubject) bool {
	return r.compiled != nil && r.compiled.Matches(subject)
}

// StoreClassRule classifies one JetStream KV bucket or Object Store record by
// bucket identity.
type StoreClassRule struct {
	StoreIdentity string
	SemanticClass MessagingSemanticClass
	LossMeaning   string
}

// MessagingSemanticClasses is the declarative mapping of landed subjects and
// stores to semantic classes. This table is the contract; the drift tests pin
// it against the landed topology definitions.
var MessagingSemanticClasses messagingSemanticClasses

type messagingSemanticClasses struct{}

// SubjectRules returns the subject classification rules; the patterns are
// compiled once at package initialization and an invalid pattern panics.
func (messagingSemanticClasses) SubjectRules() []SemanticClassRule { return semanticClassSubjectRules }

// StoreRules returns the store classification rules.
func (messagingSemanticClasses) StoreRules() []StoreClassRule { return semanticClassStoreRules }

// TryClassifySubject classifies one concrete subject; unknown shapes fail
// closed with false.
func (messagingSemanticClasses) TryClassifySubject(subject string) (MessagingSemanticClass, natspolicy.NatsSubjectNamespace, bool) {
	semanticClass := MessagingSemanticClassUnspecified
	ns := natspolicy.NatsSubjectTaxonomy.Classify(subject)
	concrete, err := natspolicy.ConcreteSubjectTryParse(subject, natspolicy.NatsSubjectTaxonomy.GrammarLimits())
	if err != natspolicy.SubjectGrammarErrorNone || concrete == nil {
		return semanticClass, ns, false
	}

	for index := range semanticClassSubjectRules {
		if semanticClassSubjectRules[index].Matches(concrete) {
			return semanticClassSubjectRules[index].SemanticClass, ns, true
		}
	}

	return semanticClass, ns, false
}

// Matches reports whether one subject matches one pattern; patterns use the
// closed NATS permission grammar: * is one token and a terminal > is a
// multi-token prefix.
func (messagingSemanticClasses) Matches(pattern, subject string) bool {
	compiled, patternErr := natspolicy.SubjectPermissionPatternTryParse(pattern, natspolicy.NatsSubjectTaxonomy.GrammarLimits())
	concrete, subjectErr := natspolicy.ConcreteSubjectTryParse(subject, natspolicy.NatsSubjectTaxonomy.GrammarLimits())
	if patternErr != natspolicy.SubjectGrammarErrorNone || subjectErr != natspolicy.SubjectGrammarErrorNone ||
		compiled == nil || concrete == nil {
		return false
	}

	return compiled.Matches(concrete)
}

var semanticClassSubjectRules = compileSemanticClassRules([]SemanticClassRule{
	{SubjectPattern: natspolicy.NatsSubjectTaxonomy.GlobalDeliverySubject(), Namespace: natspolicy.NatsSubjectNamespaceGlobalAuthority, SemanticClass: MessagingSemanticClassLossy, LossMeaning: "Signed request/reply admission; GLOBAL_DELIVERIES journals durable intent and retries preserve lineage."},
	{SubjectPattern: natspolicy.NatsSubjectTaxonomy.GlobalDirectoryQuerySubject(), Namespace: natspolicy.NatsSubjectNamespaceGlobalDirectory,
		SemanticClass: MessagingSemanticClassLossy,
		LossMeaning:   "Request/reply over the durable directory snapshot; callers retry."},
	{SubjectPattern: natspolicy.NatsSubjectTaxonomy.GlobalCellSpecPrefix() + ".>", Namespace: natspolicy.NatsSubjectNamespaceGlobalAuthority,
		SemanticClass: MessagingSemanticClassAuthoritativeJournal,
		LossMeaning:   "GLOBAL_SPEC is the authority for accepted global revisions; never lost by policy."},
	{SubjectPattern: natspolicy.NatsSubjectTaxonomy.Root() + ".*.query.>", Namespace: natspolicy.NatsSubjectNamespaceRegionalControl,
		SemanticClass: MessagingSemanticClassLossy,
		LossMeaning:   "Typed control queries; no-responder is caller-visible."},
	{SubjectPattern: natspolicy.NatsSubjectTaxonomy.Root() + ".*.command.>", Namespace: natspolicy.NatsSubjectNamespaceRegionalControl,
		SemanticClass: MessagingSemanticClassLossy,
		LossMeaning:   "Signed admission requests; the durable effect is journaled separately and retries use the idempotency key."},
	{SubjectPattern: natspolicy.NatsSubjectTaxonomy.Root() + ".*.observation.>", Namespace: natspolicy.NatsSubjectNamespaceRegionalControl,
		SemanticClass: MessagingSemanticClassReplayable,
		LossMeaning:   "CELL_EVENTS bounded durable history; replayable."},
	{SubjectPattern: natspolicy.NatsSubjectTaxonomy.Root() + ".*.desired.>", Namespace: natspolicy.NatsSubjectNamespaceRegionalControl,
		SemanticClass: MessagingSemanticClassAuthoritativeJournal,
		LossMeaning:   "The cell's accepted CellSpec history (CELL_SPEC)."},
	{SubjectPattern: natspolicy.NatsSubjectTaxonomy.Root() + ".*.operation.>", Namespace: natspolicy.NatsSubjectNamespaceOperations,
		SemanticClass: MessagingSemanticClassAuthoritativeJournal,
		LossMeaning:   "CELL_OPERATIONS authoritative regional history."},
	{SubjectPattern: natspolicy.NatsSubjectTaxonomy.Root() + ".*.agent.>", Namespace: natspolicy.NatsSubjectNamespaceAgent,
		SemanticClass: MessagingSemanticClassWorkQueue,
		LossMeaning:   "Reserved: host-agent command/ack channels will be work queues."},
	{SubjectPattern: natspolicy.NatsSubjectTaxonomy.Root() + ".*.audit.>", Namespace: natspolicy.NatsSubjectNamespaceAudit,
		SemanticClass: MessagingSemanticClassAuthoritativeJournal,
		LossMeaning:   "Reserved: audit history is authoritative and export-only."},
})

var semanticClassStoreRules = []StoreClassRule{
	// Coordination buckets are classified Lossy in the contract sense: losing
	// or replaying a record is safe because CAS plus fencing epochs — not the
	// record — carry correctness.
	{"ORCH_LEADERS", MessagingSemanticClassLossy,
		"A lost lease record is recoverable: the next epoch winner re-acquires via CAS; history lives in the operation stream."},
	{"GLOBAL_CELLS", MessagingSemanticClassSnapshot,
		"A lost advertisement re-converges when the cell renews it; regional state stays authoritative."},
	{"ORCH_RUNTIME", MessagingSemanticClassLossy,
		"Membership heartbeats are hints; the directory degrades to stale, never to wrong."},
	{"ORCH_DELIVERY", MessagingSemanticClassLossy,
		"Coordination records rebuild from journals; effects remain journaled."},
	{"ORCH_OPERATIONS", MessagingSemanticClassAuthoritativeJournal,
		"The authoritative encrypted regional operation journal; never rebuilt from hints."},
	{"ORCH_OPERATION_PROOFS", MessagingSemanticClassLossy,
		"Expiry-bounded single-use proofs; a lost un-consumed proof simply expires."},
	{"GLOBAL_DELIVERIES", MessagingSemanticClassAuthoritativeJournal, "Original signed delivery intents, saved release signatures, and regional acceptance survive master replacement."},
	{"CELL_BUNDLES", MessagingSemanticClassSnapshot,
		"Signed regional control bundles; content-addressed and re-fetchable."},
	{"ORCH_PROTOCOL_PACKAGE", MessagingSemanticClassSnapshot,
		"Immutable canonical protocol package; byte-exact verified at startup."},
}

func compileSemanticClassRules(rules []SemanticClassRule) []SemanticClassRule {
	for index := range rules {
		compiled, err := natspolicy.SubjectPermissionPatternTryParse(rules[index].SubjectPattern, natspolicy.NatsSubjectTaxonomy.GrammarLimits())
		if err != natspolicy.SubjectGrammarErrorNone || compiled == nil {
			panic("The semantic-class subject pattern is invalid: " + rules[index].SubjectPattern)
		}

		rules[index].compiled = compiled
	}

	return rules
}
