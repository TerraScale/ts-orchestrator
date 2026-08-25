using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Messaging;

/// <summary>
/// The five message semantic classes of the messaging contract. Every control subject maps
/// to exactly one class; the class fixes what loss, replay, and duplication mean for it.
/// </summary>
public enum MessagingSemanticClass
{
    Unspecified = 0,
    /// <summary>Loss is safe; senders/consumers retry; no durability is owed.</summary>
    Lossy,
    /// <summary>Durable bounded history; consumers may replay from the beginning.</summary>
    Replayable,
    /// <summary>Durably queued unit of work; at-most-one active handler; terminal disposition required.</summary>
    WorkQueue,
    /// <summary>Content-addressed state snapshot; consumed by position/digest, not by subscription order.</summary>
    Snapshot,
    /// <summary>Authoritative append-only history; one fenced writer per aggregate; the source of truth.</summary>
    AuthoritativeJournal,
}

/// <summary>
/// Declarative mapping of landed subjects and stores to semantic classes. This table is the
/// contract; the drift tests pin it against the landed topology definitions.
/// </summary>
public static class MessagingSemanticClasses
{
    public sealed record SemanticClassRule(
        string SubjectPattern,
        NatsSubjectNamespace Namespace,
        MessagingSemanticClass SemanticClass,
        string LossMeaning)
    {
        internal SubjectPermissionPattern? Compiled { get; set; }

        internal bool Matches(ConcreteSubject? subject) =>
            Compiled is not null && Compiled.Matches(subject);
    }

    public static readonly IReadOnlyList<SemanticClassRule> SubjectRules = CreateSubjectRules();

    /// <summary>JetStream KV buckets and Object Store records classified by bucket identity.</summary>
    public sealed record StoreClassRule(string StoreIdentity, MessagingSemanticClass SemanticClass, string LossMeaning);

    public static readonly IReadOnlyList<StoreClassRule> StoreRules =
    [
        // Coordination buckets are classified Lossy in the contract sense: losing or replaying a
        // record is safe because CAS plus fencing epochs — not the record — carry correctness.
        new("ORCH_LEADERS", MessagingSemanticClass.Lossy, "A lost lease record is recoverable: the next epoch winner re-acquires via CAS; history lives in the operation stream."),
        new("GLOBAL_CELLS", MessagingSemanticClass.Snapshot, "A lost advertisement re-converges when the cell renews it; regional state stays authoritative."),
        new("ORCH_RUNTIME", MessagingSemanticClass.Lossy, "Membership heartbeats are hints; the directory degrades to stale, never to wrong."),
        new("ORCH_DELIVERY", MessagingSemanticClass.Lossy, "Coordination records rebuild from journals; effects remain journaled."),
        new("ORCH_OPERATIONS", MessagingSemanticClass.AuthoritativeJournal, "The authoritative encrypted regional operation journal; never rebuilt from hints."),
        new("ORCH_OPERATION_PROOFS", MessagingSemanticClass.Lossy, "Expiry-bounded single-use proofs; a lost un-consumed proof simply expires."),
        new("GLOBAL_RELEASES", MessagingSemanticClass.AuthoritativeJournal, "Durable delivery and CI journal ledger; authoritative history."),
        new("CI_RUNNER_JOBS", MessagingSemanticClass.Lossy, "Fenced command acceptance pointers; idempotency keys keep replays safe."),
        new("CELL_BUNDLES", MessagingSemanticClass.Snapshot, "Signed regional control bundles; content-addressed and re-fetchable."),
        new("GLOBAL_BUNDLES", MessagingSemanticClass.Snapshot, "Content-addressed global CI pipeline and GitOps handoff records."),
        new("CI_RUNNER_BUNDLES", MessagingSemanticClass.Snapshot, "Content-addressed runner source, log, evidence, and artifact records."),
        new("ORCH_PROTOCOL_PACKAGE", MessagingSemanticClass.Snapshot, "Immutable canonical protocol package; byte-exact verified at startup."),
    ];

    /// <summary>Classifies one concrete subject; unknown shapes fail closed with <c>false</c>.</summary>
    public static bool TryClassifySubject(string? subject, out MessagingSemanticClass semanticClass, out NatsSubjectNamespace ns)
    {
        semanticClass = MessagingSemanticClass.Unspecified;
        ns = NatsSubjectTaxonomy.Classify(subject);
        if (!ConcreteSubject.TryParse(subject, NatsSubjectTaxonomy.GrammarLimits, out var concrete, out _))
        {
            return false;
        }

        var matched = SubjectRules.FirstOrDefault(rule => rule.Matches(concrete));
        if (matched is null)
        {
            return false;
        }

        semanticClass = matched.SemanticClass;
        return true;
    }

    /// <summary>Subject patterns use the closed NATS permission grammar: <c>*</c> is one token and a terminal <c>&gt;</c> is a multi-token prefix.</summary>
    public static bool Matches(string pattern, string subject)
    {
        if (!SubjectPermissionPattern.TryParse(pattern, NatsSubjectTaxonomy.GrammarLimits, out var compiled, out _) ||
            !ConcreteSubject.TryParse(subject, NatsSubjectTaxonomy.GrammarLimits, out var concrete, out _))
        {
            return false;
        }

        return compiled!.Matches(concrete);
    }

    private static SemanticClassRule[] CreateSubjectRules() =>
        Compile(
    [
        new(NatsSubjectTaxonomy.GlobalDirectoryQuerySubject, NatsSubjectNamespace.GlobalDirectory, MessagingSemanticClass.Lossy, "Request/reply over the durable directory snapshot; callers retry."),
        new(NatsSubjectTaxonomy.GlobalCellSpecPrefix + ".>", NatsSubjectNamespace.GlobalAuthority, MessagingSemanticClass.AuthoritativeJournal, "GLOBAL_SPEC is the authority for accepted global revisions; never lost by policy."),
        new(NatsSubjectTaxonomy.CiForgejoTriggerSubject, NatsSubjectNamespace.ContinuousIntegration, MessagingSemanticClass.WorkQueue, "Leader-only trigger decisions; exhaustion requires terminal evidence."),
        new(NatsSubjectTaxonomy.CiJobSubjectPrefix + ".>", NatsSubjectNamespace.ContinuousIntegration, MessagingSemanticClass.WorkQueue, "Per-runner fenced inbox; one active job per runner (MaxAckPending 1)."),
        new(NatsSubjectTaxonomy.CiRuntimeProofSubject, NatsSubjectNamespace.ContinuousIntegration, MessagingSemanticClass.Replayable, "Bounded durable observations; replayable from the beginning."),
        new(NatsSubjectTaxonomy.Root + ".*.query.>", NatsSubjectNamespace.RegionalControl, MessagingSemanticClass.Lossy, "Typed control queries; no-responder is caller-visible."),
        new(NatsSubjectTaxonomy.Root + ".*.command.>", NatsSubjectNamespace.RegionalControl, MessagingSemanticClass.Lossy, "Signed admission requests; the durable effect is journaled separately and retries use the idempotency key."),
        new(NatsSubjectTaxonomy.Root + ".*.event.>", NatsSubjectNamespace.RegionalControl, MessagingSemanticClass.Replayable, "CELL_EVENTS bounded durable history; replayable."),
        new(NatsSubjectTaxonomy.Root + ".*.desired.>", NatsSubjectNamespace.RegionalControl, MessagingSemanticClass.AuthoritativeJournal, "The cell's accepted CellSpec history (CELL_SPEC)."),
        new(NatsSubjectTaxonomy.Root + ".*.internal.reply.>", NatsSubjectNamespace.RegionalControl, MessagingSemanticClass.Lossy, "Ephemeral controller inboxes."),
        new(NatsSubjectTaxonomy.Root + ".*.internal.operation-journal.reply.>", NatsSubjectNamespace.Operations, MessagingSemanticClass.Lossy, "Ephemeral journal request replies; the durable effect lives in the journal."),
        new(NatsSubjectTaxonomy.Root + ".*.internal.runtime-lifecycle-journal.reply.>", NatsSubjectNamespace.Operations, MessagingSemanticClass.Lossy, "Ephemeral journal request replies; the durable effect lives in the journal."),
        new(NatsSubjectTaxonomy.Root + ".*.internal.operation-journal.>", NatsSubjectNamespace.Operations, MessagingSemanticClass.AuthoritativeJournal, "Private authoritative operation journal bridge."),
        new(NatsSubjectTaxonomy.Root + ".*.internal.runtime-lifecycle-journal.>", NatsSubjectNamespace.Operations, MessagingSemanticClass.AuthoritativeJournal, "Private authoritative runtime lifecycle journal bridge."),
        new(NatsSubjectTaxonomy.Root + ".*.operation.>", NatsSubjectNamespace.Operations, MessagingSemanticClass.AuthoritativeJournal, "CELL_OPERATIONS authoritative regional history."),
        new(NatsSubjectTaxonomy.Root + ".*.agent.>", NatsSubjectNamespace.Agent, MessagingSemanticClass.WorkQueue, "Reserved: host-agent command/ack channels will be work queues."),
        new(NatsSubjectTaxonomy.Root + ".*.audit.>", NatsSubjectNamespace.Audit, MessagingSemanticClass.AuthoritativeJournal, "Reserved: audit history is authoritative and export-only."),
    ]);

    private static SemanticClassRule[] Compile(SemanticClassRule[] rules)
    {
        foreach (var rule in rules)
        {
            if (!SubjectPermissionPattern.TryParse(
                    rule.SubjectPattern, NatsSubjectTaxonomy.GrammarLimits, out var compiled, out _) ||
                compiled is null)
            {
                throw new InvalidOperationException(
                    $"The semantic-class subject pattern is invalid: {rule.SubjectPattern}");
            }

            rule.Compiled = compiled;
        }

        return rules;
    }
}
