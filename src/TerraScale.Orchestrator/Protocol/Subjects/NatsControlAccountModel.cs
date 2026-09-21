using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Protocol.Subjects;

/// <summary>
/// The closed account kinds of the NATS control network. The kinds separate infrastructure
/// administration, global authority, the global directory read service, one regional
/// controller scope per Region, per-host-agent scopes, CI coordinators, isolated CI runners,
/// read-only monitoring, and break-glass recovery. Standing write permissions are disjoint:
/// no control subject may be published by two different account kinds.
/// </summary>
public enum NatsControlAccountKind
{
    Unspecified = 0,
    /// <summary>Operates the NATS servers themselves; platform-reserved subjects only, never control subjects.</summary>
    InfrastructureAdministration,
    /// <summary>The GRU global authority: global desired state, accepted releases, and fenced CI job commands.</summary>
    GlobalAuthority,
    /// <summary>Serves the global cell directory query; read-only.</summary>
    GlobalDirectoryReadService,
    /// <summary>One regional controller scope per Region; writes exactly its Region's families.</summary>
    RegionalController,
    /// <summary>One regional operator scope per Region; requests only read-only query endpoints.</summary>
    OperatorQuery,
    /// <summary>One admitted host agent; writes only its own hashed agent subjects.</summary>
    HostAgent,
    /// <summary>Publishes normalized CI trigger decisions; no control-state writes.</summary>
    CiCoordinator,
    /// <summary>One isolated CI runner; consumes its fenced job inbox and publishes runtime proofs.</summary>
    CiIsolatedRunner,
    /// <summary>Read-only monitoring of one Region's observations and audit history.</summary>
    ReadOnlyMonitoring,
    /// <summary>Break-glass recovery holds no standing permissions; every grant is time-bound and approved.</summary>
    BreakGlassRecovery,
}

/// <summary>
/// One instantiated account scope. Grant patterns are generated from the checked-in protocol
/// manifest: the <c>&lt;region&gt;</c> placeholder is replaced with one strict lowercase Region
/// token and the <c>&lt;agent-hash&gt;</c> placeholder with the fixed hash of the admitted
/// agent identity. Regional controllers address all agents in their fixed Region; host
/// agents remain pinned to exactly one identity.
/// </summary>
public sealed class NatsControlAccountScope
{
    private NatsControlAccountScope(
        NatsControlAccountKind kind,
        string? regionToken,
        string? agentHash,
        IReadOnlyList<string> publish,
        IReadOnlyList<string> subscribe)
    {
        Kind = kind;
        RegionToken = regionToken;
        AgentHash = agentHash;
        Publish = publish;
        Subscribe = subscribe;
    }

    public NatsControlAccountKind Kind { get; }

    /// <summary>The strict lowercase Region token this scope is pinned to, when the kind is Region-scoped.</summary>
    public string? RegionToken { get; }

    /// <summary>The fixed hash token of the admitted agent identity, when the kind is agent-hash scoped.</summary>
    public string? AgentHash { get; }

    public IReadOnlyList<string> Publish { get; }

    public IReadOnlyList<string> Subscribe { get; }

    /// <summary>
    /// Instantiates one account scope. Region-scoped kinds require one strict lowercase Region
    /// token; every kind whose grants carry the agent-hash placeholder additionally requires the
    /// admitted agent identity, which is reduced to its fixed hash before any subject is
    /// composed. No other combination of scope inputs is accepted.
    /// </summary>
    public static NatsControlAccountScope Create(
        NatsControlAccountKind kind,
        string? regionToken = null,
        string? agentIdentity = null)
    {
        var grants = NatsControlAccountModel.GrantTemplateFor(kind);

        if (grants.RegionScoped)
        {
            if (regionToken is null ||
                !NatsSubjectTaxonomy.TryMapSubjectTokenToRegionCode(regionToken, out _))
            {
                throw new ArgumentException(
                    "The Region-scoped account kind requires one strict lowercase Region subject token.",
                    nameof(regionToken));
            }
        }
        else if (regionToken is not null)
        {
            throw new ArgumentException(
                "The account kind is not Region-scoped and must not pin a Region token.", nameof(regionToken));
        }

        var needsAgentHash = grants.Publish.Concat(grants.Subscribe)
            .Any(template => template.Contains(NatsSubjectTaxonomy.AgentHashPlaceholderToken, StringComparison.Ordinal));
        string? agentHash = null;
        if (needsAgentHash)
        {
            if (agentIdentity is null)
            {
                throw new ArgumentException(
                    "The account kind grants agent-hash scoped subjects and requires the admitted agent identity.",
                    nameof(agentIdentity));
            }

            agentHash = NatsSubjectTaxonomy.HostAgentSubjectToken(agentIdentity);
        }
        else if (agentIdentity is not null)
        {
            throw new ArgumentException(
                "The account kind holds no agent-hash scoped grant and must not pin an agent identity.",
                nameof(agentIdentity));
        }

        return new NatsControlAccountScope(
            kind,
            regionToken,
            agentHash,
            Instantiate(grants.Publish, regionToken, agentHash),
            Instantiate(grants.Subscribe, regionToken, agentHash));
    }

    private static IReadOnlyList<string> Instantiate(
        IReadOnlyList<string> templates,
        string? regionToken,
        string? agentHash) =>
        templates.Select(template => NatsControlAccountModel.Materialize(template, regionToken ?? "", agentHash ?? ""))
            .ToArray();
}

/// <summary>
/// The closed account model, generated from and validated against the checked-in protocol
/// manifest. Completeness proves: every manifest kind maps to one account kind in both
/// directions, every standing grant is a closed control-family permission (or, for the
/// infrastructure kind, platform-reserved surface), write grants are pairwise disjoint across
/// kinds, read-only kinds hold no write grants, and break-glass recovery holds no standing
/// grants at all.
/// </summary>
public static class NatsControlAccountModel
{
    private static readonly Lazy<IReadOnlyList<NatsControlAccountKind>> ManifestKinds = new(LoadValidatedKinds);

    /// <summary>The closed account kinds, generated from the checked-in protocol manifest.</summary>
    public static IReadOnlyList<NatsControlAccountKind> Kinds => ManifestKinds.Value;

    public static bool IsComplete => CompletenessViolations().Count == 0;

    /// <summary>Every disagreement between the protocol manifest, the account kinds, and the disjointness contract.</summary>
    public static IReadOnlyList<string> CompletenessViolations()
    {
        var manifest = ProtocolManifest.Loaded;
        var violations = new List<string>();

        var manifestKinds = manifest.AccountKinds.Select(static grants => grants.Kind)
            .ToHashSet(StringComparer.Ordinal);
        foreach (var kind in EnumerateKinds().Where(kind => !manifestKinds.Contains(KindName(kind))))
        {
            violations.Add($"The manifest is missing the account kind '{KindName(kind)}'.");
        }

        foreach (var grants in manifest.AccountKinds.Where(grants => !TryMapKindName(grants.Kind, out _)))
        {
            violations.Add($"The manifest declares the unknown account kind '{grants.Kind}'.");
        }

        var publishOwners = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var grants in manifest.AccountKinds)
        {
            var kindName = grants.Kind;
            if (grants.ReadOnly && grants.Publish.Count > 0)
            {
                violations.Add($"The read-only account kind '{kindName}' holds write grants.");
            }

            if (grants.BreakGlass && (grants.Publish.Count > 0 || grants.Subscribe.Count > 0))
            {
                violations.Add($"The break-glass account kind '{kindName}' holds standing grants.");
            }

            if (grants.AgentHashScoped && !grants.RegionScoped)
            {
                violations.Add($"The account kind '{kindName}' is agent-hash scoped without a Region scope.");
            }

            foreach (var template in grants.Publish.Concat(grants.Subscribe))
            {
                var carriesRegion = template.Contains(NatsSubjectTaxonomy.RegionPlaceholderToken, StringComparison.Ordinal);
                var carriesAgentHash = template.Contains(NatsSubjectTaxonomy.AgentHashPlaceholderToken, StringComparison.Ordinal);
                var materialized = Materialize(template, SampleRegionToken, SampleAgentHashToken);

                if (grants.PlatformOnly)
                {
                    if (!IsPlatformPattern(materialized))
                    {
                        violations.Add($"The infrastructure account kind '{kindName}' grants '{template}' outside the platform-reserved surface.");
                    }
                }
                else if (materialized != "_INBOX.>" && (IsPlatformPattern(materialized) ||
                         !NatsSubjectTaxonomy.TryValidatePermissionPattern(materialized, out var error) ||
                         error != NatsSubjectPermissionError.None))
                {
                    violations.Add($"The account kind '{kindName}' grants the non-closed permission '{template}'.");
                }

                if (grants.RegionScoped && !carriesRegion && carriesAgentHash)
                {
                    violations.Add($"The Region-scoped account kind '{kindName}' grants '{template}' without a Region pin.");
                }

                if (grants.AgentHashScoped && !carriesAgentHash)
                {
                    violations.Add($"The agent-hash scoped account kind '{kindName}' grants '{template}' without an agent-hash pin.");
                }
            }

            foreach (var pattern in grants.Publish.Where(pattern => !publishOwners.TryAdd(pattern, kindName)))
            {
                violations.Add(
                    $"The write permission '{pattern}' is granted to both '{publishOwners[pattern]}' and '{kindName}'.");
            }
        }

        return violations;
    }

    internal const string SampleRegionToken = "gru";

    internal static string SampleAgentHashToken { get; } =
        NatsSubjectTaxonomy.HostAgentSubjectToken("completeness-sample-host-agent");

    internal static string Materialize(string template, string regionToken, string agentHashToken) =>
        template
            .Replace(NatsSubjectTaxonomy.RegionPlaceholderToken, regionToken, StringComparison.Ordinal)
            .Replace(NatsSubjectTaxonomy.AgentHashPlaceholderToken, agentHashToken, StringComparison.Ordinal);

    internal static ProtocolAccountKindGrants GrantTemplateFor(NatsControlAccountKind kind)
    {
        if (kind == NatsControlAccountKind.Unspecified)
        {
            throw new ArgumentOutOfRangeException(nameof(kind), "The account kind is unspecified.");
        }

        var name = KindName(kind);
        var grants = ProtocolManifest.Loaded.AccountKinds.SingleOrDefault(
            candidate => string.Equals(candidate.Kind, name, StringComparison.Ordinal));
        if (grants is null)
        {
            throw new InvalidOperationException(
                $"The checked-in protocol manifest does not declare the account kind '{name}'.");
        }

        return grants;
    }

    private static IReadOnlyList<NatsControlAccountKind> LoadValidatedKinds()
    {
        var violations = CompletenessViolations();
        if (violations.Count > 0)
        {
            throw new InvalidOperationException(
                "The checked-in protocol manifest disagrees with the NATS control account model: "
                + string.Join("; ", violations));
        }

        return ProtocolManifest.Loaded.AccountKinds
            .Select(grants => TryMapKindName(grants.Kind, out var kind) ? kind : NatsControlAccountKind.Unspecified)
            .ToArray();
    }

    private static IEnumerable<NatsControlAccountKind> EnumerateKinds() =>
        Enum.GetValues<NatsControlAccountKind>().Where(static kind => kind != NatsControlAccountKind.Unspecified);

    private static bool TryMapKindName(string? kindName, out NatsControlAccountKind kind)
    {
        kind = kindName switch
        {
            "infrastructure-administration" => NatsControlAccountKind.InfrastructureAdministration,
            "global-authority" => NatsControlAccountKind.GlobalAuthority,
            "global-directory-read-service" => NatsControlAccountKind.GlobalDirectoryReadService,
            "regional-controller" => NatsControlAccountKind.RegionalController,
            "operator-query" => NatsControlAccountKind.OperatorQuery,
            "host-agent" => NatsControlAccountKind.HostAgent,
            "ci-coordinator" => NatsControlAccountKind.CiCoordinator,
            "ci-isolated-runner" => NatsControlAccountKind.CiIsolatedRunner,
            "read-only-monitoring" => NatsControlAccountKind.ReadOnlyMonitoring,
            "break-glass-recovery" => NatsControlAccountKind.BreakGlassRecovery,
            _ => NatsControlAccountKind.Unspecified,
        };
        return kind != NatsControlAccountKind.Unspecified;
    }

    private static string KindName(NatsControlAccountKind kind) => kind switch
    {
        NatsControlAccountKind.InfrastructureAdministration => "infrastructure-administration",
        NatsControlAccountKind.GlobalAuthority => "global-authority",
        NatsControlAccountKind.GlobalDirectoryReadService => "global-directory-read-service",
        NatsControlAccountKind.RegionalController => "regional-controller",
        NatsControlAccountKind.OperatorQuery => "operator-query",
        NatsControlAccountKind.HostAgent => "host-agent",
        NatsControlAccountKind.CiCoordinator => "ci-coordinator",
        NatsControlAccountKind.CiIsolatedRunner => "ci-isolated-runner",
        NatsControlAccountKind.ReadOnlyMonitoring => "read-only-monitoring",
        NatsControlAccountKind.BreakGlassRecovery => "break-glass-recovery",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), "The account kind is unspecified."),
    };

    private static bool IsPlatformPattern(string pattern)
    {
        var firstToken = pattern.Split('.')[0];
        return NatsSubjectTaxonomy.IsPlatformReservedRoot(firstToken);
    }
}
