using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Messaging;

/// <summary>
/// The closed NATS subject taxonomy for TerraScale.Orchestrator v2 control messaging.
/// This is the single canonical definition of every subject namespace root and every
/// concrete subject shape the production adapters may use; adapters compose subjects
/// exclusively through these definitions. The closed family set is generated from the
/// checked-in protocol manifest (<c>Protocol/protocol-manifest.json</c>) and validated
/// against it: the taxonomy and the manifest cannot drift apart silently. The taxonomy
/// is infrastructure-free: it knows subject grammar, not NATS clients.
/// </summary>
public static class NatsSubjectTaxonomy
{
    /// <summary>The one versioned control-plane subject root. The product plane is NOT rooted here.</summary>
    public const string Root = "ts.orch.v2";

    /// <summary>
    /// The superseded v1 control root. It must never share authority, subjects, permissions,
    /// or consumers with <see cref="Root"/>; every v1-prefixed subject fails closed.
    /// </summary>
    public const string SupersededRoot = "ts.orch.v1";

    /// <summary>The reserved scope token that names the global authority namespace.</summary>
    public const string GlobalScopeToken = "global";

    /// <summary>The placeholder a manifest template carries at the Region position.</summary>
    public const string RegionPlaceholderToken = "<region>";

    /// <summary>The placeholder a manifest template carries at the host-agent hash position.</summary>
    public const string AgentHashPlaceholderToken = "<agent-hash>";

    /// <summary>Global-authority namespace root (GRU-owned global journals, releases, and directory).</summary>
    public const string GlobalRoot = Root + "." + GlobalScopeToken;

    /// <summary>Directory query service subject served by the GRU directory-service identity.</summary>
    public const string GlobalDirectoryQuerySubject = GlobalRoot + ".query.cells";

    /// <summary>Prefix for durable globally signed native CellSpecs, one subject per Region.</summary>
    public const string GlobalCellSpecPrefix = GlobalRoot + ".desired.gitops";

    /// <summary>Prefix of the accepted global release journal under the closed release family.</summary>
    public const string GlobalAcceptedReleasePrefix = GlobalRoot + ".release.accepted";

    /// <summary>Normalized Forgejo trigger decisions consumed by the leader-only global CI consumer.</summary>
    public const string CiForgejoTriggerSubject = GlobalRoot + ".release.ci.forgejo";

    /// <summary>Native CI runtime observations verified by the global authority.</summary>
    public const string CiRuntimeProofSubject = GlobalRoot + ".release.ci.runtime-proof";

    /// <summary>Prefix for fenced per-runner CI command inboxes (zone + identity hash).</summary>
    public const string CiJobSubjectPrefix = GlobalRoot + ".release.ci.job";

    /// <summary>The desired-state family segment, shared by the global and regional scopes.</summary>
    public const string DesiredFamilySegment = "desired";

    /// <summary>The global release and delivery family segment.</summary>
    public const string ReleaseFamilySegment = "release";

    /// <summary>The query family segment, shared by the global and regional scopes.</summary>
    public const string QueryFamilySegment = "query";

    /// <summary>The regional command family segment.</summary>
    public const string CommandFamilySegment = "command";

    /// <summary>The regional observation family segment.</summary>
    public const string ObservationFamilySegment = "observation";

    /// <summary>The regional operation family segment.</summary>
    public const string OperationFamilySegment = "operation";

    /// <summary>Regional audit family segment.</summary>
    public const string RegionalAuditPrefixSegment = "audit";

    /// <summary>Regional host-agent family segment; deeper tokens pin the admitted agent hash.</summary>
    public const string RegionalAgentPrefixSegment = "agent";

    /// <summary>Cell-substitution template for the durable regional desired-state family.</summary>
    public const string RegionalDesiredFamilyTemplate = Root + ".{cell}." + DesiredFamilySegment + ".>";

    /// <summary>Cell-substitution template for the durable regional operation family.</summary>
    public const string RegionalOperationFamilyTemplate = Root + ".{cell}." + OperationFamilySegment + ".>";

    /// <summary>Cell-substitution template for the durable regional observation family.</summary>
    public const string RegionalObservationFamilyTemplate = Root + ".{cell}." + ObservationFamilySegment + ".>";

    /// <summary>Cell-substitution template for one durable signed regional CellSpec.</summary>
    public const string RegionalCellSpecTemplate = Root + ".{cell}.desired.gitops";

    /// <summary>Cell-substitution template for all regional runtime-startup observations.</summary>
    public const string RegionalRuntimeStartupTemplate = Root + ".{cell}.observation.runtime.started.>";

    /// <summary>The complete global CI family under the closed release namespace.</summary>
    public const string GlobalCiFamilyPattern = GlobalRoot + ".release.ci.>";

    /// <summary>Length of the truncated SHA-256 host-agent hash token used in subjects.</summary>
    public const int AgentHashTokenLength = 24;

    internal static readonly SubjectGrammarLimits GrammarLimits = CreateGrammarLimits();

    /// <summary>
    /// The closed subject families, generated from the checked-in protocol manifest and
    /// validated against the compiled taxonomy. Any disagreement throws
    /// <see cref="InvalidOperationException"/>: the manifest is the single source of truth.
    /// </summary>
    public static IReadOnlyList<ProtocolSubjectFamily> Families => ManifestFamilies.Value;

    private static readonly Lazy<IReadOnlyList<ProtocolSubjectFamily>> ManifestFamilies = new(LoadValidatedFamilies);

    /// <summary>Regional control namespace root for one Region (<c>ts.orch.v2.&lt;region&gt;</c>).</summary>
    public static string RegionalRoot(string cell) =>
        IsValidCellToken(cell) && !string.Equals(cell, GlobalScopeToken, StringComparison.Ordinal)
            ? Root + "." + cell
            : throw new ArgumentException(
                "The region subject token is not a lowercase DNS-style token and must not name the reserved global scope.",
                nameof(cell));

    /// <summary>Regional control namespace root for one canonical uppercase <c>RegionCode</c>.</summary>
    public static string RegionalRootForRegionCode(string regionCode) =>
        RegionalRoot(SubjectTokenForRegion(regionCode));

    /// <summary>Durable signed regional CellSpec subject (<c>ts.orch.v2.&lt;region&gt;.desired.gitops</c>).</summary>
    public static string CellSpecSubject(string cell) => RegionalRoot(cell) + ".desired.gitops";

    /// <summary>The terminal permission pattern of one closed regional family.</summary>
    public static string RegionalFamilyPattern(string cell, string familySegment) =>
        RegionalRoot(cell) + "." + familySegment + ".>";

    /// <summary>The terminal permission pattern of one closed global family.</summary>
    public static string GlobalFamilyPattern(string familySegment) =>
        GlobalRoot + "." + familySegment + ".>";

    public static string ControllerHealthSubject(string cell) => RegionalRoot(cell) + ".query.health";

    public static string ControllerInstanceHealthSubject(string cell, string instance) =>
        RegionalRoot(cell) + ".query.health." + RequireToken(instance, "instance");

    public static string ControllerStatusSubject(string cell) => RegionalRoot(cell) + ".query.status";

    public static string ControllerMembersSubject(string cell) => RegionalRoot(cell) + ".query.members";

    /// <summary>Read-only service statistics endpoint subject (no mutation surface).</summary>
    public static string ControllerStatsSubject(string cell) => RegionalRoot(cell) + ".query.stats";

    /// <summary>Signed direct-delivery mutation admission subject (request/reply, lossy transport).</summary>
    public static string DirectDeliverySubject(string cell) => RegionalRoot(cell) + ".command.delivery";

    /// <summary>Ephemeral controller inbox prefix under the command family; the NATS client appends its unique suffix.</summary>
    public static string ControllerInboxPrefix(string cell, string publicKey) =>
        RegionalRoot(cell) + ".command.reply." + RequireToken(publicKey, "publicKey");

    /// <summary>Ephemeral regional operation-journal append RPC under the non-streamed command family.</summary>
    public static string OperationJournalCreateSubject(string cell) =>
        RegionalRoot(cell) + ".command.journal.create";

    /// <summary>Ephemeral regional operation-journal update RPC under the non-streamed command family.</summary>
    public static string OperationJournalUpdateSubject(string cell) =>
        RegionalRoot(cell) + ".command.journal.update";

    public static string OperationJournalReplySubject(string cell, string callerIdentity, string nonce) =>
        RegionalRoot(cell) + ".command.journal.reply."
            + RequireToken(callerIdentity, "callerIdentity") + "." + RequireNonce(nonce);

    /// <summary>Runtime startup observation of the closed observation family.</summary>
    public static string RuntimeStartupSubject(string cell, string instance) =>
        RegionalRoot(cell) + ".observation.runtime.started." + RequireToken(instance, "instance");

    /// <summary>All runtime-startup observations for one Region.</summary>
    public static string RuntimeStartupPattern(string cell) =>
        RegionalRoot(cell) + ".observation.runtime.started.>";

    /// <summary>Private runtime-lifecycle journal RPC under the non-streamed command family.</summary>
    public static string RuntimeLifecycleJournalSubject(string cell, string operation) =>
        RegionalRoot(cell) + ".command.runtime-lifecycle." + RequireToken(operation, "operation");

    public static string RuntimeLifecycleJournalReplySubject(string cell, string callerIdentity, string nonce) =>
        RegionalRoot(cell) + ".command.runtime-lifecycle.reply."
            + RequireToken(callerIdentity, "callerIdentity") + "." + RequireNonce(nonce);

    /// <summary>The fixed SHA-256 subject token of one admitted host-agent identity (lowercase hex).</summary>
    public static string HostAgentSubjectToken(string agentIdentity) =>
        HostAgentIdentityHash(agentIdentity)[..AgentHashTokenLength];

    /// <summary>The host-agent subject root of one admitted agent: the fixed hash, never the raw identity.</summary>
    public static string HostAgentSubjectRoot(string cell, string agentIdentity) =>
        RegionalRoot(cell) + "." + RegionalAgentPrefixSegment + "." + HostAgentSubjectToken(agentIdentity);

    /// <summary>Fenced command leaf addressed to exactly one admitted host agent.</summary>
    public static string HostAgentCommandSubject(string cell, string agentIdentity, string command) =>
        HostAgentSubjectRoot(cell, agentIdentity) + ".command." + RequireToken(command, "command");

    /// <summary>Observation leaf published by exactly one admitted host agent.</summary>
    public static string HostAgentObservationSubject(string cell, string agentIdentity, string observation) =>
        HostAgentSubjectRoot(cell, agentIdentity) + "." + ObservationFamilySegment + "."
            + RequireToken(observation, "observation");

    /// <summary>Acknowledgement leaf published by exactly one admitted host agent.</summary>
    public static string HostAgentAcknowledgementSubject(string cell, string agentIdentity, string acknowledgement) =>
        HostAgentSubjectRoot(cell, agentIdentity) + ".ack." + RequireToken(acknowledgement, "acknowledgement");

    /// <summary>
    /// The fixed SHA-256 hash of an admitted host-agent identity. The raw identity — which may
    /// carry operator-controlled text — never becomes a subject token.
    /// </summary>
    public static string HostAgentIdentityHash(string agentIdentity)
    {
        if (agentIdentity is not { Length: >= 1 and <= 512 } ||
            agentIdentity.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character)))
        {
            throw new ArgumentException("The admitted host-agent identity is not bounded text.", nameof(agentIdentity));
        }

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(agentIdentity)));
    }

    /// <summary>
    /// Maps one registered canonical uppercase <c>RegionCode</c> to its strict lowercase subject
    /// token. The mapping is bijective: payloads keep the uppercase code while subjects use the
    /// token.
    /// </summary>
    public static bool TryMapRegionCodeToSubjectToken(string? regionCode, out string subjectToken)
    {
        subjectToken = regionCode switch
        {
            "GRU" => "gru",
            "SFO" => "sfo",
            "FRA" => "fra",
            _ => "",
        };

        return subjectToken.Length > 0;
    }

    /// <summary>Maps one registered strict lowercase subject token back to its canonical uppercase <c>RegionCode</c>.</summary>
    public static bool TryMapSubjectTokenToRegionCode(string? subjectToken, out string regionCode)
    {
        regionCode = subjectToken switch
        {
            "gru" => "GRU",
            "sfo" => "SFO",
            "fra" => "FRA",
            _ => "",
        };

        return regionCode.Length > 0;
    }

    /// <summary>The strict lowercase subject token of one canonical uppercase <c>RegionCode</c>.</summary>
    public static string SubjectTokenForRegion(string regionCode) =>
        TryMapRegionCodeToSubjectToken(regionCode, out var token)
            ? token
            : throw new ArgumentException(
                "The RegionCode is not a registered canonical uppercase Region.",
                nameof(regionCode));

    /// <summary>The canonical uppercase <c>RegionCode</c> of one strict lowercase subject token.</summary>
    public static string RegionCodeFromSubjectToken(string subjectToken) =>
        TryMapSubjectTokenToRegionCode(subjectToken, out var code)
            ? code
            : throw new ArgumentException(
                "The subject token does not map to a registered canonical Region.", nameof(subjectToken));

    /// <summary>Durable globally signed CellSpec subject for one Region.</summary>
    public static string GlobalCellSpecSubject(string cell) =>
        IsValidCellToken(cell) && !string.Equals(cell, GlobalScopeToken, StringComparison.Ordinal)
            ? GlobalCellSpecPrefix + "." + cell
            : throw new ArgumentException(
                "The region subject token is not a lowercase DNS-style token and must not name the reserved global scope.",
                nameof(cell));

    /// <summary>
    /// Classifies one concrete subject into the closed namespace taxonomy. Returns
    /// <see cref="NatsSubjectNamespace.Unknown"/> for anything outside the closed set —
    /// including every <see cref="SupersededRoot"/>-prefixed subject: classification fails
    /// closed; callers must reject unknown subjects.
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
            !string.Equals(tokens[2], "v2", StringComparison.Ordinal))
        {
            return string.Equals(tokens[1], "product", StringComparison.Ordinal)
                ? NatsSubjectNamespace.ProductPlane
                : NatsSubjectNamespace.Unknown;
        }

        if (string.Equals(tokens[3], GlobalScopeToken, StringComparison.Ordinal))
        {
            if (tokens.Length < 5)
            {
                return NatsSubjectNamespace.Unknown;
            }

            if (tokens.Length == 6 &&
                string.Equals(tokens[4], QueryFamilySegment, StringComparison.Ordinal) &&
                string.Equals(tokens[5], "cells", StringComparison.Ordinal))
            {
                return NatsSubjectNamespace.GlobalDirectory;
            }

            if (string.Equals(tokens[4], ReleaseFamilySegment, StringComparison.Ordinal) &&
                tokens.Length > 5 &&
                string.Equals(tokens[5], "ci", StringComparison.Ordinal))
            {
                return NatsSubjectNamespace.ContinuousIntegration;
            }

            return tokens[4] is DesiredFamilySegment or ReleaseFamilySegment or QueryFamilySegment
                ? NatsSubjectNamespace.GlobalAuthority
                : NatsSubjectNamespace.Unknown;
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

        if (string.Equals(tokens[4], OperationFamilySegment, StringComparison.Ordinal))
        {
            return NatsSubjectNamespace.Operations;
        }

        return tokens[4] is DesiredFamilySegment
            or CommandFamilySegment
            or QueryFamilySegment
            or ObservationFamilySegment
            ? NatsSubjectNamespace.RegionalControl
            : NatsSubjectNamespace.Unknown;
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

    /// <summary>
    /// Validates one permission pattern against the closed v2 family set. A wildcard may never
    /// sit at — or span — the scope or family position, so no permission can cross a Region
    /// boundary; superseded-root patterns are rejected outright.
    /// </summary>
    public static bool TryValidatePermissionPattern(string? pattern, out NatsSubjectPermissionError error)
    {
        if (!SubjectPermissionPattern.TryParse(pattern, GrammarLimits, out var compiled, out _) ||
            compiled is null ||
            pattern is null)
        {
            error = NatsSubjectPermissionError.MalformedPattern;
            return false;
        }

        if (pattern.StartsWith(SupersededRoot + ".", StringComparison.Ordinal))
        {
            error = NatsSubjectPermissionError.SupersededRoot;
            return false;
        }

        var tokens = pattern.Split('.');
        if (tokens.Length < 3 ||
            tokens[0] != "ts" || tokens[1] != "orch" || tokens[2] != "v2")
        {
            error = IsPlatformReservedRoot(tokens[0])
                ? NatsSubjectPermissionError.PlatformReserved
                : NatsSubjectPermissionError.OutsideControlRoot;
            return false;
        }

        if (tokens.Length < 5)
        {
            error = NatsSubjectPermissionError.WildcardInScopeToken;
            return false;
        }

        var scope = tokens[3];
        if (scope is "*" or ">")
        {
            error = NatsSubjectPermissionError.WildcardInScopeToken;
            return false;
        }

        var isGlobal = string.Equals(scope, GlobalScopeToken, StringComparison.Ordinal);
        if (!isGlobal && !IsValidCellToken(scope))
        {
            error = NatsSubjectPermissionError.InvalidRegionToken;
            return false;
        }

        var family = tokens[4];
        if (family is "*" or ">")
        {
            error = NatsSubjectPermissionError.WildcardInFamilyToken;
            return false;
        }

        if (!IsClosedFamilySegment(isGlobal, family))
        {
            error = NatsSubjectPermissionError.UnknownFamily;
            return false;
        }

        if (!isGlobal && string.Equals(family, RegionalAgentPrefixSegment, StringComparison.Ordinal) &&
            tokens.Length > 5)
        {
            if (tokens[5] is "*" or ">" || !IsAgentHashToken(tokens[5]))
            {
                error = NatsSubjectPermissionError.InvalidAgentHashToken;
                return false;
            }
        }

        error = NatsSubjectPermissionError.None;
        return true;
    }

    /// <summary>
    /// Validates one concrete subject for admission into the closed v2 taxonomy: bounded
    /// grammar, control namespace, strict ASCII tokens (customer-provided text never becomes a
    /// subject token), and a fixed agent-hash token inside the host-agent family.
    /// </summary>
    public static bool TryAdmitSubject(string? subject, out NatsSubjectAdmissionError error)
    {
        if (!ConcreteSubject.TryParse(subject, GrammarLimits, out _, out _) || subject is null)
        {
            error = NatsSubjectAdmissionError.MalformedSubject;
            return false;
        }

        if (subject.StartsWith(SupersededRoot + ".", StringComparison.Ordinal))
        {
            error = NatsSubjectAdmissionError.SupersededRoot;
            return false;
        }

        var tokens = subject.Split('.');
        if (tokens.Length < 3 ||
            tokens[0] != "ts" || tokens[1] != "orch" || tokens[2] != "v2")
        {
            error = IsPlatformReservedRoot(tokens[0])
                ? NatsSubjectAdmissionError.PlatformReserved
                : NatsSubjectAdmissionError.OutsideControlRoot;
            return false;
        }

        if (!IsControlNamespace(Classify(subject)))
        {
            error = NatsSubjectAdmissionError.UnknownNamespace;
            return false;
        }

        if (tokens.Any(static token => token is { Length: > 128 } ||
                !token.All(static character =>
                    char.IsAsciiLetterOrDigit(character) || character is '-' or '_')))
        {
            error = NatsSubjectAdmissionError.CustomerTextInSubject;
            return false;
        }

        if (tokens.Length > 4 &&
            !string.Equals(tokens[3], GlobalScopeToken, StringComparison.Ordinal) &&
            string.Equals(tokens[4], RegionalAgentPrefixSegment, StringComparison.Ordinal) &&
            tokens.Length > 5 &&
            !IsAgentHashToken(tokens[5]))
        {
            error = NatsSubjectAdmissionError.InvalidAgentHashToken;
            return false;
        }

        error = NatsSubjectAdmissionError.None;
        return true;
    }

    /// <summary>
    /// Every disagreement between the checked-in protocol manifest and the compiled taxonomy.
    /// An empty list is the contract: the closed family set is identical in both directions.
    /// </summary>
    public static IReadOnlyList<string> ManifestValidationViolations()
    {
        var manifest = ProtocolManifest.Loaded;
        var violations = new List<string>();

        if (!string.Equals(manifest.Root, Root, StringComparison.Ordinal))
        {
            violations.Add($"The manifest root '{manifest.Root}' is not the canonical root '{Root}'.");
        }

        if (manifest.ReservedRegionTokens.Count != 1 ||
            !string.Equals(manifest.ReservedRegionTokens[0], GlobalScopeToken, StringComparison.Ordinal))
        {
            violations.Add("The manifest region-token reservations are not exactly the reserved global scope token.");
        }

        var declared = DeclaredFamilies.Select(static family => family.Pattern).ToHashSet(StringComparer.Ordinal);
        var manifestPatterns = manifest.SubjectFamilies.Select(static family => family.Pattern)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var pattern in declared.Where(pattern => !manifestPatterns.Contains(pattern)))
        {
            violations.Add($"The manifest is missing the closed subject family '{pattern}'.");
        }

        foreach (var family in manifest.SubjectFamilies.Where(family => !declared.Contains(family.Pattern)))
        {
            violations.Add($"The manifest declares the unknown subject family '{family.Pattern}'.");
        }

        foreach (var family in manifest.SubjectFamilies.Where(family =>
                     family.Pattern.StartsWith(SupersededRoot + ".", StringComparison.Ordinal)))
        {
            violations.Add($"The manifest family '{family.Pattern}' lives under the superseded v1 root.");
        }

        foreach (var family in manifest.SubjectFamilies.Where(family =>
                     !family.Pattern.StartsWith(Root + ".", StringComparison.Ordinal)))
        {
            violations.Add($"The manifest family '{family.Pattern}' does not live under the v2 root.");
        }

        var agentFamily = manifest.SubjectFamilies.SingleOrDefault(static family =>
            family.Scope == ProtocolSubjectFamilyScope.Regional &&
            string.Equals(family.Family, RegionalAgentPrefixSegment, StringComparison.Ordinal));
        if (agentFamily is null || !agentFamily.AgentHashToken ||
            !agentFamily.Pattern.Contains("." + AgentHashPlaceholderToken + ".>", StringComparison.Ordinal))
        {
            violations.Add("The manifest agent family does not pin the admitted-agent hash token.");
        }

        return violations;
    }

    internal static bool IsValidCellToken(string? cell) => CellTokenRule.IsValid(cell);

    internal static bool IsAgentHashToken(string? token) =>
        token is { Length: AgentHashTokenLength } &&
        token.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    internal static bool IsPlatformReservedRoot(string token) =>
        token.Length > 0 && (token[0] == '$' || token[0] == '_' || token[0] == '#');

    private static readonly (ProtocolSubjectFamilyScope Scope, string Family, string Pattern)[] DeclaredFamilies =
    [
        (ProtocolSubjectFamilyScope.Global, DesiredFamilySegment, GlobalRoot + "." + DesiredFamilySegment + ".>"),
        (ProtocolSubjectFamilyScope.Global, ReleaseFamilySegment, GlobalRoot + "." + ReleaseFamilySegment + ".>"),
        (ProtocolSubjectFamilyScope.Global, QueryFamilySegment, GlobalRoot + "." + QueryFamilySegment + ".>"),
        (ProtocolSubjectFamilyScope.Regional, DesiredFamilySegment,
            Root + "." + RegionPlaceholderToken + "." + DesiredFamilySegment + ".>"),
        (ProtocolSubjectFamilyScope.Regional, CommandFamilySegment,
            Root + "." + RegionPlaceholderToken + "." + CommandFamilySegment + ".>"),
        (ProtocolSubjectFamilyScope.Regional, ObservationFamilySegment,
            Root + "." + RegionPlaceholderToken + "." + ObservationFamilySegment + ".>"),
        (ProtocolSubjectFamilyScope.Regional, OperationFamilySegment,
            Root + "." + RegionPlaceholderToken + "." + OperationFamilySegment + ".>"),
        (ProtocolSubjectFamilyScope.Regional, QueryFamilySegment,
            Root + "." + RegionPlaceholderToken + "." + QueryFamilySegment + ".>"),
        (ProtocolSubjectFamilyScope.Regional, RegionalAuditPrefixSegment,
            Root + "." + RegionPlaceholderToken + "." + RegionalAuditPrefixSegment + ".>"),
        (ProtocolSubjectFamilyScope.Regional, RegionalAgentPrefixSegment,
            Root + "." + RegionPlaceholderToken + "." + RegionalAgentPrefixSegment + "."
                + AgentHashPlaceholderToken + ".>"),
    ];

    private static bool IsClosedFamilySegment(bool isGlobal, string family) => isGlobal
        ? family is DesiredFamilySegment or ReleaseFamilySegment or QueryFamilySegment
        : family is DesiredFamilySegment
            or CommandFamilySegment
            or ObservationFamilySegment
            or OperationFamilySegment
            or QueryFamilySegment
            or RegionalAuditPrefixSegment
            or RegionalAgentPrefixSegment;

    private static IReadOnlyList<ProtocolSubjectFamily> LoadValidatedFamilies()
    {
        var violations = ManifestValidationViolations();
        if (violations.Count > 0)
        {
            throw new InvalidOperationException(
                "The checked-in protocol manifest disagrees with the NATS subject taxonomy: "
                + string.Join("; ", violations));
        }

        return ProtocolManifest.Loaded.SubjectFamilies;
    }

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

/// <summary>Why one permission pattern is not a closed v2 control-family permission.</summary>
public enum NatsSubjectPermissionError
{
    None = 0,
    /// <summary>The pattern is not bounded subject-permission grammar.</summary>
    MalformedPattern,
    /// <summary>The pattern does not live under the v2 control root.</summary>
    OutsideControlRoot,
    /// <summary>The pattern lives under the superseded v1 root.</summary>
    SupersededRoot,
    /// <summary>A wildcard sits at — or spans — the Region scope position, so it could cross a Region boundary.</summary>
    WildcardInScopeToken,
    /// <summary>A wildcard sits at the family position, so it spans the closed family set.</summary>
    WildcardInFamilyToken,
    /// <summary>The Region scope token is not a strict lowercase Region token.</summary>
    InvalidRegionToken,
    /// <summary>The family segment is not one of the closed manifest families.</summary>
    UnknownFamily,
    /// <summary>The host-agent family token is not the fixed hash of an admitted agent identity.</summary>
    InvalidAgentHashToken,
    /// <summary>The pattern is platform-reserved NATS API surface, not control-family surface.</summary>
    PlatformReserved,
}

/// <summary>Why one concrete subject is not admissible into the closed v2 taxonomy.</summary>
public enum NatsSubjectAdmissionError
{
    None = 0,
    /// <summary>The subject is not bounded subject grammar.</summary>
    MalformedSubject,
    /// <summary>The subject does not live under the v2 control root.</summary>
    OutsideControlRoot,
    /// <summary>The subject lives under the superseded v1 root.</summary>
    SupersededRoot,
    /// <summary>The subject does not classify into a control namespace.</summary>
    UnknownNamespace,
    /// <summary>The subject carries non-token text (for example customer-provided text) in a token position.</summary>
    CustomerTextInSubject,
    /// <summary>The host-agent family token is not the fixed hash of an admitted agent identity.</summary>
    InvalidAgentHashToken,
    /// <summary>The subject is platform-reserved NATS API surface, not control-family surface.</summary>
    PlatformReserved,
}

