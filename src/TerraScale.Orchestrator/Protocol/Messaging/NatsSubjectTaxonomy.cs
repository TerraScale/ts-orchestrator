using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Messaging;

/// <summary>
/// The closed NATS subject taxonomy for TerraScale.Orchestrator control messaging.
/// This is the single canonical definition of every subject namespace root and every
/// concrete subject shape the production adapters may use; adapters compose subjects
/// exclusively through these definitions. The taxonomy is infrastructure-free: it
/// knows subject grammar, not NATS clients.
/// </summary>
public static class NatsSubjectTaxonomy
{
    /// <summary>The one versioned control-plane subject root. The product plane is NOT rooted here.</summary>
    public const string Root = "ts.orch.v1";

    /// <summary>Global-authority namespace root (GRU-owned global journals, CI, and directory).</summary>
    public const string GlobalRoot = Root + ".global";

    /// <summary>Directory query service subject served by the GRU directory-service identity.</summary>
    public const string GlobalDirectoryQuerySubject = GlobalRoot + ".query.cells";

    /// <summary>Prefix for durable globally signed native GitOps CellSpecs, one subject per cell.</summary>
    public const string GlobalCellSpecPrefix = GlobalRoot + ".desired.gitops";

    /// <summary>Normalized Forgejo trigger decisions consumed by the leader-only global CI consumer.</summary>
    public const string CiForgejoTriggerSubject = GlobalRoot + ".ci.forgejo";

    /// <summary>Native CI runtime observations verified by the global authority.</summary>
    public const string CiRuntimeProofSubject = GlobalRoot + ".ci.runtime-proof";

    /// <summary>Prefix for fenced per-runner CI command inboxes (zone + identity hash).</summary>
    public const string CiJobSubjectPrefix = GlobalRoot + ".ci.job";

    /// <summary>Reserved regional audit namespace; no production subject is landed under it yet.</summary>
    public const string RegionalAuditPrefixSegment = "audit";

    /// <summary>Reserved regional host-agent namespace; no production subject is landed under it yet.</summary>
    public const string RegionalAgentPrefixSegment = "agent";

    internal static readonly SubjectGrammarLimits GrammarLimits = CreateGrammarLimits();

    /// <summary>Regional control namespace root for one cell (<c>ts.orch.v1.&lt;cell&gt;</c>).</summary>
    public static string RegionalRoot(string cell) =>
        IsValidCellToken(cell)
            ? Root + "." + cell
            : throw new ArgumentException("The cell is not a lowercase DNS-style token.", nameof(cell));

    /// <summary>Durable signed regional CellSpec subject (<c>ts.orch.v1.&lt;cell&gt;.desired.gitops</c>).</summary>
    public static string CellSpecSubject(string cell) => RegionalRoot(cell) + ".desired.gitops";

    public static string ControllerHealthSubject(string cell) => RegionalRoot(cell) + ".query.health";

    public static string ControllerInstanceHealthSubject(string cell, string instance) =>
        RegionalRoot(cell) + ".query.health." + RequireToken(instance, "instance");

    public static string ControllerStatusSubject(string cell) => RegionalRoot(cell) + ".query.status";

    public static string ControllerMembersSubject(string cell) => RegionalRoot(cell) + ".query.members";

    /// <summary>Signed direct-delivery mutation admission subject (request/reply, lossy transport).</summary>
    public static string DirectDeliverySubject(string cell) => RegionalRoot(cell) + ".command.delivery";

    public static string OperationJournalCreateSubject(string cell) =>
        RegionalRoot(cell) + ".internal.operation-journal.create";

    public static string OperationJournalUpdateSubject(string cell) =>
        RegionalRoot(cell) + ".internal.operation-journal.update";

    public static string OperationJournalReplySubject(string cell, string callerIdentity, string nonce) =>
        RegionalRoot(cell) + ".internal.operation-journal.reply."
            + RequireToken(callerIdentity, "callerIdentity") + "." + RequireNonce(nonce);

    /// <summary>Ephemeral controller inbox prefix; the NATS client appends its unique suffix.</summary>
    public static string ControllerInboxPrefix(string cell, string publicKey) =>
        RegionalRoot(cell) + ".internal.reply." + RequireToken(publicKey, "publicKey");

    public static string RuntimeStartupSubject(string cell, string instance) =>
        RegionalRoot(cell) + ".event.runtime.started." + RequireToken(instance, "instance");

    public static string RuntimeLifecycleJournalSubject(string cell, string operation) =>
        RegionalRoot(cell) + ".internal.runtime-lifecycle-journal." + RequireToken(operation, "operation");

    public static string RuntimeLifecycleJournalReplySubject(string cell, string callerIdentity, string nonce) =>
        RegionalRoot(cell) + ".internal.runtime-lifecycle-journal.reply."
            + RequireToken(callerIdentity, "callerIdentity") + "." + RequireNonce(nonce);

    /// <summary>Durable globally signed CellSpec subject for one cell.</summary>
    public static string GlobalCellSpecSubject(string cell) =>
        IsValidCellToken(cell)
            ? GlobalCellSpecPrefix + "." + cell
            : throw new ArgumentException("The cell is not a lowercase DNS-style token.", nameof(cell));

    /// <summary>
    /// Classifies one concrete subject into the closed namespace taxonomy. Returns
    /// <see cref="NatsSubjectNamespace.Unknown"/> for anything outside the closed set —
    /// classification fails closed; callers must reject unknown subjects.
    /// </summary>
    public static NatsSubjectNamespace Classify(string? subject)
    {
        if (string.IsNullOrEmpty(subject))
        {
            return NatsSubjectNamespace.Unknown;
        }

        var tokens = subject.Split('.');
        if (tokens.Length > 0 && IsPlatformReservedRoot(tokens[0]))
        {
            return NatsSubjectNamespace.PlatformReserved;
        }

        if (tokens.Length < 4)
        {
            return NatsSubjectNamespace.Unknown;
        }

        if (!string.Equals(tokens[0], "ts", StringComparison.Ordinal))
        {
            return NatsSubjectNamespace.Unknown;
        }

        if (!string.Equals(tokens[1], "orch", StringComparison.Ordinal) ||
            !string.Equals(tokens[2], "v1", StringComparison.Ordinal))
        {
            return string.Equals(tokens[1], "product", StringComparison.Ordinal)
                ? NatsSubjectNamespace.ProductPlane
                : NatsSubjectNamespace.Unknown;
        }

        if (string.Equals(tokens[3], "global", StringComparison.Ordinal))
        {
            if (tokens.Length == 6 &&
                string.Equals(tokens[4], "query", StringComparison.Ordinal) &&
                string.Equals(tokens[5], "cells", StringComparison.Ordinal))
            {
                return NatsSubjectNamespace.GlobalDirectory;
            }

            if (tokens.Length > 4 && string.Equals(tokens[4], "ci", StringComparison.Ordinal))
            {
                return NatsSubjectNamespace.ContinuousIntegration;
            }

            if (tokens.Length > 4 && string.Equals(tokens[4], RegionalAuditPrefixSegment, StringComparison.Ordinal))
            {
                return NatsSubjectNamespace.Audit;
            }

            return NatsSubjectNamespace.GlobalAuthority;
        }

        if (!IsValidCellToken(tokens[3]))
        {
            return NatsSubjectNamespace.Unknown;
        }

        if (tokens.Length < 6)
        {
            return NatsSubjectNamespace.Unknown;
        }

        if (string.Equals(tokens[4], RegionalAgentPrefixSegment, StringComparison.Ordinal))
        {
            return NatsSubjectNamespace.Agent;
        }

        if (string.Equals(tokens[4], RegionalAuditPrefixSegment, StringComparison.Ordinal))
        {
            return NatsSubjectNamespace.Audit;
        }

        if (string.Equals(tokens[4], "operation", StringComparison.Ordinal))
        {
            return NatsSubjectNamespace.Operations;
        }

        if (string.Equals(tokens[4], "internal", StringComparison.Ordinal))
        {
            if (string.Equals(tokens[5], "operation-journal", StringComparison.Ordinal) ||
                string.Equals(tokens[5], "runtime-lifecycle-journal", StringComparison.Ordinal))
            {
                return NatsSubjectNamespace.Operations;
            }

            return NatsSubjectNamespace.RegionalControl;
        }

        if (tokens[4] is "query" or "command" or "event" or "desired")
        {
            return NatsSubjectNamespace.RegionalControl;
        }

        return NatsSubjectNamespace.Unknown;
    }

    /// <summary>Exactly the seven control namespaces of the closed taxonomy; the product-plane business namespace is excluded.</summary>
    public static bool IsControlNamespace(NatsSubjectNamespace ns) =>
        ns is NatsSubjectNamespace.GlobalAuthority
            or NatsSubjectNamespace.GlobalDirectory
            or NatsSubjectNamespace.RegionalControl
            or NatsSubjectNamespace.Agent
            or NatsSubjectNamespace.ContinuousIntegration
            or NatsSubjectNamespace.Operations
            or NatsSubjectNamespace.Audit;

    internal static bool IsValidCellToken(string? cell) =>
        cell is { Length: >= 1 and <= 63 } &&
        cell[0] != '-' && cell[^1] != '-' &&
        cell.All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

    private static bool IsPlatformReservedRoot(string token) =>
        token.Length > 0 && (token[0] == '$' || token[0] == '_' || token[0] == '#');

    private static string RequireToken(string value, string name) =>
        value is { Length: >= 1 and <= 128 } &&
            value.All(static character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.')
            ? value
            : throw new ArgumentException($"The {name} is not a bounded subject token.", name);

    private static string RequireNonce(string value, string name = "nonce") =>
        value is { Length: 32 } && value.All(char.IsAsciiHexDigit)
            ? value
            : throw new ArgumentException($"The {name} is not a 32-character hex nonce.", name);

    private static SubjectGrammarLimits CreateGrammarLimits()
    {
        if (!SubjectGrammarLimits.TryCreate(512, 16, 128, 256, out var limits) || limits is null)
        {
            throw new InvalidOperationException("The canonical NATS subject grammar limits are invalid.");
        }

        return limits;
    }
}

/// <summary>
/// The closed set of subject namespaces. Seven of the eight business namespaces are
/// control subjects; the eighth — <see cref="ProductPlane"/> — names the separate product
/// trust plane, which the control taxonomy never defines subjects for, and
/// <see cref="PlatformReserved"/> covers NATS-reserved API subjects.
/// </summary>
public enum NatsSubjectNamespace
{
    Unspecified = 0,
    GlobalAuthority,
    GlobalDirectory,
    RegionalControl,
    Agent,
    ContinuousIntegration,
    Operations,
    Audit,
    ProductPlane,
    PlatformReserved,
    Unknown,
}
