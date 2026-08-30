// Port of src/TerraScale.Orchestrator/Protocol/Messaging/MessagingCompatibility.cs.
package protocol

// SchemaNegotiationOutcome mirrors the SchemaNegotiationOutcome enum.
type SchemaNegotiationOutcome int

const (
	SchemaNegotiationOutcomeUnspecified SchemaNegotiationOutcome = 0
	// SchemaNegotiationOutcomeAcceptExact: same major and minor; consume directly.
	SchemaNegotiationOutcomeAcceptExact SchemaNegotiationOutcome = 1
	// SchemaNegotiationOutcomeMigrateForward: known older schema in the same
	// major; consume after the forward-only migration step runs.
	SchemaNegotiationOutcomeMigrateForward SchemaNegotiationOutcome = 2
	// SchemaNegotiationOutcomeRejectMajorMismatch: the offered major is not the
	// current one; fail closed.
	SchemaNegotiationOutcomeRejectMajorMismatch SchemaNegotiationOutcome = 3
	// SchemaNegotiationOutcomeRejectNewerVersion: a newer version than this
	// node knows; fail closed — an N-1 node never guesses at N documents.
	SchemaNegotiationOutcomeRejectNewerVersion SchemaNegotiationOutcome = 4
	// SchemaNegotiationOutcomeRejectUnmigratableOlderVersion: an older version
	// with no registered forward migration path; fail closed.
	SchemaNegotiationOutcomeRejectUnmigratableOlderVersion SchemaNegotiationOutcome = 5
	// SchemaNegotiationOutcomeRejectMalformed: the offered or current version
	// is malformed (for example a non-positive major); fail closed without
	// claiming a major mismatch.
	SchemaNegotiationOutcomeRejectMalformed SchemaNegotiationOutcome = 6
)

// MessagingSchemaNegotiation mirrors the C# static class: schema negotiation
// for N/N-1 rolling compatibility. The discipline matches the landed journal
// migration core: forward-only, stepwise, each step validated, unknown members
// fail closed (JSON unmapped-member handling is Disallow), so a node accepts
// exactly its known versions or an older one it can migrate.
var MessagingSchemaNegotiation messagingSchemaNegotiation

type messagingSchemaNegotiation struct{}

// Decide mirrors MessagingSchemaNegotiation.Decide: whether this node, at
// current, may consume a document offered at offered. MigratableFrom lists
// the older schemas this node carries a registered forward migration for.
func (messagingSchemaNegotiation) Decide(
	offered MessagingSchemaVersion,
	current MessagingSchemaVersion,
	migratableFrom map[MessagingSchemaVersion]struct{},
) SchemaNegotiationOutcome {
	if !offered.IsWellFormed() || !current.IsWellFormed() {
		return SchemaNegotiationOutcomeRejectMalformed
	}

	if offered.Major != current.Major {
		return SchemaNegotiationOutcomeRejectMajorMismatch
	}

	if offered.Minor == current.Minor {
		return SchemaNegotiationOutcomeAcceptExact
	}

	if offered.Minor > current.Minor {
		return SchemaNegotiationOutcomeRejectNewerVersion
	}

	if _, migratable := migratableFrom[offered]; migratable {
		return SchemaNegotiationOutcomeMigrateForward
	}

	return SchemaNegotiationOutcomeRejectUnmigratableOlderVersion
}

// MessagingCompatibilityRulesArea mirrors the nested
// MessagingCompatibilityRules.Area enum.
type MessagingCompatibilityRulesArea int

const (
	MessagingCompatibilityRulesAreaUnspecified MessagingCompatibilityRulesArea = 0
	MessagingCompatibilityRulesAreaClients MessagingCompatibilityRulesArea = 1
	MessagingCompatibilityRulesAreaServers MessagingCompatibilityRulesArea = 2
	MessagingCompatibilityRulesAreaStreams MessagingCompatibilityRulesArea = 3
	MessagingCompatibilityRulesAreaConsumers MessagingCompatibilityRulesArea = 4
	MessagingCompatibilityRulesAreaKeyValueValues MessagingCompatibilityRulesArea = 5
	MessagingCompatibilityRulesAreaObjectStoreMetadata MessagingCompatibilityRulesArea = 6
	MessagingCompatibilityRulesAreaRollingUpgrades MessagingCompatibilityRulesArea = 7
)

// CompatibilityRule mirrors the nested CompatibilityRule record.
type CompatibilityRule struct {
	RuleArea MessagingCompatibilityRulesArea
	RuleId   string
	Rule     string
}

// MessagingCompatibilityRules mirrors the C# static class: the N/N-1
// compatibility rule set — clients, servers, streams, consumers, KV values,
// Object Store metadata, and rolling upgrades. Rules are declarative; the
// drift tests pin the set so no area can silently lose coverage.
var MessagingCompatibilityRules messagingCompatibilityRules

type messagingCompatibilityRules struct{}

var messagingCompatibilityRuleSet = []CompatibilityRule{
	{MessagingCompatibilityRulesAreaClients, "compat-client-1",
		"A client of version N may talk to a server of N or N-1; an N-1 client never receives an N-major document — endpoints fail closed instead."},
	{MessagingCompatibilityRulesAreaClients, "compat-client-2",
		"Client schema negotiation uses the closed major/minor rule: accept exact, migrate registered older minors, reject everything else."},
	{MessagingCompatibilityRulesAreaServers, "compat-server-1",
		"N and N-1 servers interoperate for commands, snapshots, schema reads, and leadership transfer within one plane."},
	{MessagingCompatibilityRulesAreaServers, "compat-server-2",
		"An upgrade cannot remove the last controller candidate or reduce either NATS plane below its disruption budget; it proceeds one failure domain at a time."},
	{MessagingCompatibilityRulesAreaStreams, "compat-stream-1",
		"Stream configuration changes are additive-only across a rolling upgrade; retention, duplicate windows, and replica counts never regress mid-rollout."},
	{MessagingCompatibilityRulesAreaStreams, "compat-stream-2",
		"No stream spans regions, so no upgrade path ever requires a cross-region stream migration."},
	{MessagingCompatibilityRulesAreaConsumers, "compat-consumer-1",
		"Durable consumer profiles are forward-compatible: new optional fields default safely and N-1 controllers still validate their closed profile."},
	{MessagingCompatibilityRulesAreaConsumers, "compat-consumer-2",
		"A consumer name, filter subject, ack policy, and deliver policy are immutable across versions; changes require a new consumer name."},
	{MessagingCompatibilityRulesAreaKeyValueValues, "compat-kv-1",
		"KV value schema versions are per-bucket and additive within a major; unknown members fail closed rather than being ignored."},
	{MessagingCompatibilityRulesAreaKeyValueValues, "compat-kv-2",
		"KV lease/epoch records of N-1 writers remain valid for N readers; an epoch written by an N writer is rejected by N-1 readers as a major mismatch."},
	{MessagingCompatibilityRulesAreaObjectStoreMetadata, "compat-obj-1",
		"Object metadata carries its schema version; readers accept exact or registered older metadata and reject newer metadata closed."},
	{MessagingCompatibilityRulesAreaObjectStoreMetadata, "compat-obj-2",
		"Object digests are content addresses independent of metadata version; integrity checks never depend on schema negotiation."},
	{MessagingCompatibilityRulesAreaRollingUpgrades, "compat-roll-1",
		"A release is not accepted by a cell until both its forward and rollback artifacts/secrets are locally available in the regional survival bundle."},
	{MessagingCompatibilityRulesAreaRollingUpgrades, "compat-roll-2",
		"Rollback restores the N-1 artifact and its schema unchanged; no rollback path upgrades data forward."},
}

// Rules mirrors MessagingCompatibilityRules.Rules.
func (messagingCompatibilityRules) Rules() []CompatibilityRule {
	return messagingCompatibilityRuleSet
}

// IsComplete mirrors MessagingCompatibilityRules.IsComplete: every
// compatibility area named by the contract has at least one rule.
func (messagingCompatibilityRules) IsComplete() bool {
	areas := map[MessagingCompatibilityRulesArea]struct{}{}
	for _, rule := range messagingCompatibilityRuleSet {
		if rule.RuleArea != MessagingCompatibilityRulesAreaUnspecified {
			areas[rule.RuleArea] = struct{}{}
		}
	}

	for _, area := range []MessagingCompatibilityRulesArea{
		MessagingCompatibilityRulesAreaClients,
		MessagingCompatibilityRulesAreaServers,
		MessagingCompatibilityRulesAreaStreams,
		MessagingCompatibilityRulesAreaConsumers,
		MessagingCompatibilityRulesAreaKeyValueValues,
		MessagingCompatibilityRulesAreaObjectStoreMetadata,
		MessagingCompatibilityRulesAreaRollingUpgrades,
	} {
		if _, present := areas[area]; !present {
			return false
		}
	}

	return true
}
