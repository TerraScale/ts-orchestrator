namespace TerraScale.Orchestrator.Protocol.Messaging;

public enum SchemaNegotiationOutcome
{
    Unspecified = 0,
    /// <summary>Same major and minor: consume directly.</summary>
    AcceptExact,
    /// <summary>Known older schema in the same major: consume after the forward-only migration step runs.</summary>
    MigrateForward,
    /// <summary>The offered major is not the current one: fail closed.</summary>
    RejectMajorMismatch,
    /// <summary>A newer version than this node knows: fail closed — an N-1 node never guesses at N documents.</summary>
    RejectNewerVersion,
    /// <summary>An older version with no registered forward migration path: fail closed.</summary>
    RejectUnmigratableOlderVersion,
    /// <summary>The offered or current version is malformed (for example a non-positive major): fail closed without claiming a major mismatch.</summary>
    RejectMalformed,
}

/// <summary>
/// Schema negotiation for N/N-1 rolling compatibility. The discipline matches the landed
/// journal migration core: forward-only, stepwise, each step validated, unknown members
/// fail closed (JSON unmapped-member handling is Disallow), so a node accepts exactly its
/// known versions or an older one it can migrate.
/// </summary>
public static class MessagingSchemaNegotiation
{
    /// <summary>
    /// Decides whether this node, at <paramref name="current"/>, may consume a document
    /// offered at <paramref name="offered"/>. <paramref name="migratableFrom"/> lists the
    /// older schemas this node carries a registered forward migration for.
    /// </summary>
    public static SchemaNegotiationOutcome Decide(
        MessagingSchemaVersion offered,
        MessagingSchemaVersion current,
        IReadOnlySet<MessagingSchemaVersion> migratableFrom)
    {
        if (!offered.IsWellFormed || !current.IsWellFormed)
        {
            return SchemaNegotiationOutcome.RejectMalformed;
        }

        if (offered.Major != current.Major)
        {
            return SchemaNegotiationOutcome.RejectMajorMismatch;
        }

        if (offered.Minor == current.Minor)
        {
            return SchemaNegotiationOutcome.AcceptExact;
        }

        if (offered.Minor > current.Minor)
        {
            return SchemaNegotiationOutcome.RejectNewerVersion;
        }

        return migratableFrom.Contains(offered)
            ? SchemaNegotiationOutcome.MigrateForward
            : SchemaNegotiationOutcome.RejectUnmigratableOlderVersion;
    }
}

/// <summary>
/// The N/N-1 compatibility rule set: clients, servers, streams, consumers, KV values, Object
/// Store metadata, and rolling upgrades. Rules are declarative; the drift tests pin the set
/// so no area can silently lose coverage.
/// </summary>
public static class MessagingCompatibilityRules
{
    public enum Area
    {
        Unspecified = 0,
        Clients,
        Servers,
        Streams,
        Consumers,
        KeyValueValues,
        ObjectStoreMetadata,
        RollingUpgrades,
    }

    public sealed record CompatibilityRule(Area RuleArea, string RuleId, string Rule);

    public static readonly IReadOnlyList<CompatibilityRule> Rules = CreateRules();

    /// <summary>Every compatibility area named by the contract has at least one rule.</summary>
    public static bool IsComplete =>
        Enum.GetValues<Area>()
            .Where(static area => area != Area.Unspecified)
            .All(static area => Rules.Any(rule => rule.RuleArea == area));

    private static CompatibilityRule[] CreateRules() =>
    [
        new(Area.Clients, "compat-client-1", "A client of version N may talk to a server of N or N-1; an N-1 client never receives an N-major document — endpoints fail closed instead."),
        new(Area.Clients, "compat-client-2", "Client schema negotiation uses the closed major/minor rule: accept exact, migrate registered older minors, reject everything else."),
        new(Area.Servers, "compat-server-1", "N and N-1 servers interoperate for commands, snapshots, schema reads, and leadership transfer within one plane."),
        new(Area.Servers, "compat-server-2", "An upgrade cannot remove the last controller candidate or reduce either NATS plane below its disruption budget; it proceeds one failure domain at a time."),
        new(Area.Streams, "compat-stream-1", "Stream configuration changes are additive-only across a rolling upgrade; retention, duplicate windows, and replica counts never regress mid-rollout."),
        new(Area.Streams, "compat-stream-2", "No stream spans regions, so no upgrade path ever requires a cross-region stream migration."),
        new(Area.Consumers, "compat-consumer-1", "Durable consumer profiles are forward-compatible: new optional fields default safely and N-1 controllers still validate their closed profile."),
        new(Area.Consumers, "compat-consumer-2", "A consumer name, filter subject, ack policy, and deliver policy are immutable across versions; changes require a new consumer name."),
        new(Area.KeyValueValues, "compat-kv-1", "KV value schema versions are per-bucket and additive within a major; unknown members fail closed rather than being ignored."),
        new(Area.KeyValueValues, "compat-kv-2", "KV lease/epoch records of N-1 writers remain valid for N readers; an epoch written by an N writer is rejected by N-1 readers as a major mismatch."),
        new(Area.ObjectStoreMetadata, "compat-obj-1", "Object metadata carries its schema version; readers accept exact or registered older metadata and reject newer metadata closed."),
        new(Area.ObjectStoreMetadata, "compat-obj-2", "Object digests are content addresses independent of metadata version; integrity checks never depend on schema negotiation."),
        new(Area.RollingUpgrades, "compat-roll-1", "A release is not accepted by a cell until both its forward and rollback artifacts/secrets are locally available in the regional survival bundle."),
        new(Area.RollingUpgrades, "compat-roll-2", "Rollback restores the N-1 artifact and its schema unchanged; no rollback path upgrades data forward."),
    ];
}
