using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Messaging;

/// <summary>
/// Which JetStream domain durably owns a work stream, consumer, or queue group. The regional
/// domain is per-cell; the global domain is the single global control plane. No durable work
/// item crosses domains: gateways never create a WAN-spanning stream or consumer.
/// </summary>
public enum DurableWorkDomain
{
    Unspecified = 0,
    /// <summary>The owning regional cell's JetStream domain (subjects are cell-scoped under <c>ts.orch.v2.&lt;cell&gt;</c>).</summary>
    RegionalCell,
    /// <summary>The single global control domain (subjects under <c>ts.orch.v2.global</c>).</summary>
    GlobalControl,
}

/// <summary>Retention class declared for a durable stream. Limits retention is the only adopted shape.</summary>
public enum DurableStreamRetention
{
    Unspecified = 0,
    /// <summary>Bounded history: messages survive consumption until the age/bytes ceiling discards them.</summary>
    Limits,
}

/// <summary>What a stream does when it reaches its age/bytes ceiling.</summary>
public enum DurableStreamDiscard
{
    Unspecified = 0,
    /// <summary>Discard the oldest messages; new publishes always succeed.</summary>
    Old,
}

/// <summary>Acknowledgement mode of a durable consumer. Explicit acknowledgement is the only adopted shape.</summary>
public enum DurableAcknowledgement
{
    Unspecified = 0,
    /// <summary>A worker acknowledges only after the durable effect exists or an idempotent replay is proven.</summary>
    Explicit,
}

/// <summary>The ownership discipline of one durable consumer or queue group.</summary>
public enum DurableWorkOwnership
{
    Unspecified = 0,
    /// <summary>Any equivalent regional instance may process the work; the subject and domain keep the group regional.</summary>
    RegionalEquivalentWorkers,
    /// <summary>Only the live fenced regional lease holder (epoch plus KV revision) may process or write.</summary>
    RegionalFencedAuthority,
    /// <summary>Only the live fenced global lease holder (epoch plus KV revision) may process or write.</summary>
    GlobalFencedAuthority,
    /// <summary>Only the exact reconciled CI runner identity may pull its per-runner fenced inbox.</summary>
    ReconciledRunnerIdentity,
}

/// <summary>
/// One durable stream of the work inventory: every attribute the delivery contract freezes is
/// declared here and drift-bound to the provisioning topology. Regional subjects are templates
/// over the cell token; <see cref="SubjectFor"/> substitutes a validated cell.
/// </summary>
public sealed record DurableStreamPlan(
    string Stream,
    IReadOnlyList<string> Subjects,
    DurableWorkDomain Domain,
    MessagingSemanticClass SemanticClass,
    int Replicas,
    DurableStreamRetention Retention,
    TimeSpan MaximumAge,
    long MaximumBytes,
    DurableStreamDiscard Discard,
    DuplicateWindowPolicy DuplicateWindow,
    string TerminalEvidenceBehavior)
{
    internal bool IsWellFormed =>
        IsToken(Stream) &&
        Subjects is { Count: >= 1 } && Subjects.All(IsToken) &&
        Domain != DurableWorkDomain.Unspecified &&
        SemanticClass != MessagingSemanticClass.Unspecified &&
        Replicas is >= 1 and <= 5 &&
        Retention == DurableStreamRetention.Limits &&
        MaximumAge > TimeSpan.Zero &&
        MaximumBytes > 0 &&
        Discard == DurableStreamDiscard.Old &&
        DuplicateWindow.IsWellFormed &&
        IsBounded(TerminalEvidenceBehavior, 256);

    /// <summary>Instantiates the cell-scoped subjects of a regional stream template.</summary>
    public IReadOnlyList<string> SubjectFor(string cell) =>
        [.. Subjects.Select(template => SubjectFor(template, cell))];

    internal static string SubjectFor(string template, string cell)
    {
        if (!CellTokenRule.IsValid(cell))
            throw new ArgumentException("The regional cell is not a lowercase DNS-style token.", nameof(cell));
        return template.Replace("{cell}", cell, StringComparison.Ordinal);
    }

    internal static bool IsToken(string? value) =>
        value is { Length: >= 1 and <= 128 } &&
        value.All(static character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.' or '{' or '}' or '*' or '>');

    internal static bool IsBounded(string? value, int maximum) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximum;
}

/// <summary>
/// One durable consumer profile of the work inventory: the closed pull shape every instance
/// must reconcile to, including the bounded redelivery contract and how terminal evidence is
/// produced when a delivery can make no further progress.
/// </summary>
public sealed record DurableConsumerPlan(
    string Stream,
    string Consumer,
    string FilterSubject,
    DurableWorkDomain Domain,
    DurableWorkOwnership Ownership,
    DurableAcknowledgement Acknowledgement,
    int MaximumDeliveries,
    IReadOnlyList<TimeSpan> BackoffLadder,
    int MaximumAckPending,
    int? MaximumBatch,
    TimeSpan? MaximumExpires,
    int? MaximumWaiting,
    string FlowControlBasis,
    string TerminalEvidenceBehavior)
{
    /// <summary>The declared ack wait equals the first backoff interval (JetStream derives it).</summary>
    public TimeSpan AckWait => BackoffLadder.Count > 0
        ? BackoffLadder[0]
        : throw new InvalidOperationException("The backoff ladder is empty.");

    internal bool IsWellFormed =>
        DurableStreamPlan.IsToken(Stream) &&
        DurableStreamPlan.IsToken(Consumer) &&
        DurableStreamPlan.IsToken(FilterSubject) &&
        Domain != DurableWorkDomain.Unspecified &&
        Ownership != DurableWorkOwnership.Unspecified &&
        Acknowledgement == DurableAcknowledgement.Explicit &&
        MaximumDeliveries is >= 1 and <= 100 &&
        BackoffLadder is { Count: >= 1 and <= 16 } &&
        BackoffLadder.All(static step => step > TimeSpan.Zero) &&
        MaximumAckPending >= 1 &&
        (MaximumBatch is null or >= 1) &&
        (MaximumExpires is null || MaximumExpires > TimeSpan.Zero) &&
        (MaximumWaiting is null or >= 1) &&
        DurableStreamPlan.IsBounded(FlowControlBasis, 256) &&
        DurableStreamPlan.IsBounded(TerminalEvidenceBehavior, 256);

    /// <summary>Instantiates the cell-scoped filter subject of a regional consumer template.</summary>
    public string FilterSubjectFor(string cell) =>
        DurableStreamPlan.SubjectFor(FilterSubject, cell);
}

/// <summary>
/// One queue group of the work inventory. Queue groups distribute only equivalent-worker work;
/// the authoritative writer of any journal is always chosen by a fenced lease, never by a queue
/// group, and the group's subjects stay cell-scoped so no cross-region member can join.
/// </summary>
public sealed record QueueGroupPlan(
    string Group,
    DurableWorkDomain Domain,
    DurableWorkOwnership Ownership,
    string DistributionRule,
    string FencingBasis)
{
    internal bool IsWellFormed =>
        DurableStreamPlan.IsToken(Group) &&
        Domain != DurableWorkDomain.Unspecified &&
        Ownership != DurableWorkOwnership.Unspecified &&
        DurableStreamPlan.IsBounded(DistributionRule, 256) &&
        DurableStreamPlan.IsBounded(FencingBasis, 256);
}

/// <summary>
/// The typed inventory of every durable command/event/work stream, durable consumer profile,
/// and queue group the Orchestrator delivers work through. This table is the contract; drift
/// tests pin it against the provisioning topology (NatsTopology, GlobalNatsTopology) and
/// against the landed delivery policies (BoundedRedeliveryPolicy, DuplicateWindowPolicy).
/// It makes no exactly-once claim: transport duplicate windows sit beneath operation-level
/// idempotency keys, which remain the authority for durable effects.
/// </summary>
public static class DurableWorkInventory
{
    /// <summary>The landed bounded redelivery contract every profile below must satisfy.</summary>
    public static BoundedRedeliveryPolicy Redelivery => BoundedRedeliveryPolicy.Landed;

    private const string PullFlowControlBasis =
        "Pull consumers bounded by MaxAckPending, MaxBatch, MaxExpires, and MaxWaiting; no push delivery shape is adopted.";

    public static readonly IReadOnlyList<DurableStreamPlan> Streams = CreateStreams();

    public static readonly IReadOnlyList<DurableConsumerPlan> Consumers = CreateConsumers();

    public static readonly IReadOnlyList<QueueGroupPlan> QueueGroups = CreateQueueGroups();

    /// <summary>Completeness proof: every entry is well formed and every consumer names a declared stream.</summary>
    public static bool IsComplete => !CompletenessViolations().Any();

    public static IReadOnlyList<string> CompletenessViolations()
    {
        var violations = new List<string>();
        var streamNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var stream in Streams)
        {
            if (!stream.IsWellFormed)
                violations.Add($"The durable stream plan {stream.Stream} is not well formed.");
            if (!streamNames.Add(stream.Stream))
                violations.Add($"The durable stream plan {stream.Stream} is declared more than once.");
        }

        var consumerNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var consumer in Consumers)
        {
            if (!consumer.IsWellFormed)
                violations.Add($"The durable consumer plan {consumer.Consumer} is not well formed.");
            if (!consumerNames.Add(consumer.Consumer))
                violations.Add($"The durable consumer plan {consumer.Consumer} is declared more than once.");
            if (!streamNames.Contains(consumer.Stream))
                violations.Add($"The durable consumer plan {consumer.Consumer} names an undeclared stream.");
            if (consumer.Domain == DurableWorkDomain.GlobalControl && Redelivery.BoundedBy(consumer) is false)
                violations.Add($"The durable consumer plan {consumer.Consumer} violates the bounded redelivery contract.");
        }

        var groups = new HashSet<string>(StringComparer.Ordinal);
        foreach (var group in QueueGroups)
        {
            if (!group.IsWellFormed)
                violations.Add($"The queue group plan {group.Group} is not well formed.");
            if (!groups.Add(group.Group))
                violations.Add($"The queue group plan {group.Group} is declared more than once.");
        }

        return violations;
    }

    private static DurableStreamPlan[] CreateStreams()
    {
        var cell = DuplicateWindowPolicy.CellStreams;
        var global = DuplicateWindowPolicy.GlobalCiStream;
        return
        [
            new("CELL_SPEC",
                [NatsSubjectTaxonomy.RegionalDesiredFamilyTemplate],
                DurableWorkDomain.RegionalCell,
                MessagingSemanticClass.AuthoritativeJournal,
                3,
                DurableStreamRetention.Limits,
                TimeSpan.FromDays(30),
                256L * 1024 * 1024,
                DurableStreamDiscard.Old,
                cell,
                "Accepted CellSpec history; deterministic conflicts terminate with terminal evidence, exhaustion warns on the final delivery."),
            new("CELL_OPERATIONS",
                [NatsSubjectTaxonomy.RegionalOperationFamilyTemplate],
                DurableWorkDomain.RegionalCell,
                MessagingSemanticClass.AuthoritativeJournal,
                3,
                DurableStreamRetention.Limits,
                TimeSpan.FromDays(30),
                1024L * 1024 * 1024,
                DurableStreamDiscard.Old,
                cell,
                "Authoritative regional operation history; KV CAS plus operation proofs fence every append."),
            new("CELL_EVENTS",
                [NatsSubjectTaxonomy.RegionalObservationFamilyTemplate],
                DurableWorkDomain.RegionalCell,
                MessagingSemanticClass.Replayable,
                3,
                DurableStreamRetention.Limits,
                TimeSpan.FromDays(30),
                256L * 1024 * 1024,
                DurableStreamDiscard.Old,
                cell,
                "Bounded replayable runtime events; consumers reconcile from journals, so loss or replay is safe."),
            new("GLOBAL_SPEC",
                [NatsSubjectTaxonomy.GlobalRoot + ".desired.>"],
                DurableWorkDomain.GlobalControl,
                MessagingSemanticClass.AuthoritativeJournal,
                3,
                DurableStreamRetention.Limits,
                TimeSpan.FromDays(30),
                256L * 1024 * 1024,
                DurableStreamDiscard.Old,
                cell,
                "Accepted global revisions; deterministic conflicts terminate with terminal evidence."),
            new("GLOBAL_CI",
                [NatsSubjectTaxonomy.GlobalCiFamilyPattern],
                DurableWorkDomain.GlobalControl,
                MessagingSemanticClass.WorkQueue,
                3,
                DurableStreamRetention.Limits,
                TimeSpan.FromDays(30),
                1024L * 1024 * 1024,
                DurableStreamDiscard.Old,
                global,
                "Normalized CI events and fenced runner commands; trigger conflicts terminate, runner identity conflicts terminate, exhaustion warns on the final delivery."),
        ];
    }

    private static DurableConsumerPlan[] CreateConsumers()
    {
        var ladder = Redelivery.BackoffLadder;
        var triggerTerminal =
            "Deterministic conflicts AckTerminate loudly; retry exhaustion warns on the final delivery before its nak.";
        var cellspecTerminal =
            "Deterministic conflicts and identity conflicts AckTerminate loudly; authority loss withholds the acknowledgement.";
        return
        [
            new("CELL_EVENTS",
                "runtime_startup",
                NatsSubjectTaxonomy.RegionalRuntimeStartupTemplate,
                DurableWorkDomain.RegionalCell,
                DurableWorkOwnership.RegionalEquivalentWorkers,
                DurableAcknowledgement.Explicit,
                Redelivery.MaximumDeliveries,
                ladder,
                32,
                MaximumBatch: null,
                MaximumExpires: null,
                MaximumWaiting: 16,
                PullFlowControlBasis,
                "Acknowledged startup events; a lost acknowledgement redelivers and the idempotent event id converges."),
            new("CELL_SPEC",
                "gitops_cell_spec_{instance}",
                NatsSubjectTaxonomy.RegionalCellSpecTemplate,
                DurableWorkDomain.RegionalCell,
                DurableWorkOwnership.RegionalFencedAuthority,
                DurableAcknowledgement.Explicit,
                Redelivery.MaximumDeliveries,
                ladder,
                8,
                MaximumBatch: 1,
                MaximumExpires: TimeSpan.FromSeconds(30),
                MaximumWaiting: 8,
                PullFlowControlBasis,
                cellspecTerminal),
            new("GLOBAL_SPEC",
                "gitops_global_cell_spec_{cell}",
                NatsSubjectTaxonomy.GlobalCellSpecPrefix + ".{cell}",
                DurableWorkDomain.GlobalControl,
                DurableWorkOwnership.GlobalFencedAuthority,
                DurableAcknowledgement.Explicit,
                Redelivery.MaximumDeliveries,
                ladder,
                8,
                MaximumBatch: 1,
                MaximumExpires: TimeSpan.FromSeconds(30),
                MaximumWaiting: 8,
                PullFlowControlBasis,
                cellspecTerminal),
            new("GLOBAL_CI",
                "global_ci_trigger",
                NatsSubjectTaxonomy.CiForgejoTriggerSubject,
                DurableWorkDomain.GlobalControl,
                DurableWorkOwnership.GlobalFencedAuthority,
                DurableAcknowledgement.Explicit,
                Redelivery.MaximumDeliveries,
                ladder,
                32,
                MaximumBatch: null,
                MaximumExpires: null,
                MaximumWaiting: 16,
                PullFlowControlBasis,
                triggerTerminal),
            new("GLOBAL_CI",
                "global_ci_runtime_proof",
                NatsSubjectTaxonomy.CiRuntimeProofSubject,
                DurableWorkDomain.GlobalControl,
                DurableWorkOwnership.GlobalFencedAuthority,
                DurableAcknowledgement.Explicit,
                Redelivery.MaximumDeliveries,
                ladder,
                32,
                MaximumBatch: 1,
                MaximumExpires: TimeSpan.FromSeconds(30),
                MaximumWaiting: 16,
                PullFlowControlBasis,
                "Leader-verified observations double-ack after the durable pointer wins; deterministic failures terminate loudly."),
            new("GLOBAL_CI",
                "ci_runner_{zone}_{runner}",
                NatsSubjectTaxonomy.CiJobSubjectPrefix + ".{zone}.{runner}",
                DurableWorkDomain.GlobalControl,
                DurableWorkOwnership.ReconciledRunnerIdentity,
                DurableAcknowledgement.Explicit,
                Redelivery.MaximumDeliveries,
                ladder,
                1,
                MaximumBatch: 1,
                MaximumExpires: TimeSpan.FromSeconds(30),
                MaximumWaiting: 4,
                PullFlowControlBasis,
                "Fenced per-runner inbox (MaxAckPending 1); a message-id/payload identity conflict AckTerminates loudly; progress acks keep long executions leased."),
        ];
    }

    private static QueueGroupPlan[] CreateQueueGroups() =>
    [
        new("orchestrator_{cell}",
            DurableWorkDomain.RegionalCell,
            DurableWorkOwnership.RegionalEquivalentWorkers,
            "Equivalent-worker regional service endpoints; any member may answer a health, status, or members query.",
            "No authoritative write rides the group; answers are equivalent and cell-scoped subjects keep membership regional."),
        new("terrascale_orchestrator_journal_writer_{cell}",
            DurableWorkDomain.RegionalCell,
            DurableWorkOwnership.RegionalEquivalentWorkers,
            "Equivalent-worker journal writer fan-in for one regional cell only.",
            "Every authoritative journal append is fenced by the regional lease epoch and single-use operation proofs before and after the write."),
    ];
}

/// <summary>Extension seam binding a consumer plan to the landed bounded redelivery contract.</summary>
public static class BoundedRedeliveryContract
{
    /// <summary>
    /// True when the consumer profile satisfies the landed bounded redelivery contract: the
    /// delivery cap, the backoff ladder, and the derived ack wait must equal the policy. The
    /// ack-pending bound is per-consumer flow control — a profile may tighten it (the fenced
    /// runner inbox pins 1) or widen it within its own declared pull shape.
    /// </summary>
    public static bool BoundedBy(this BoundedRedeliveryPolicy policy, DurableConsumerPlan consumer) =>
        consumer.MaximumDeliveries == policy.MaximumDeliveries &&
        consumer.BackoffLadder.SequenceEqual(policy.BackoffLadder) &&
        consumer.AckWait == policy.AckWait;
}

