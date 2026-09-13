using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Runtime.Mcp;

/// <summary>Why a new desired state exists. Recorded on every instance action so an upgrade,
/// a rollback, and a plain restart are distinguishable in the operator view.</summary>
public enum McpChangeKind
{
    InitialCreation = 0,
    Upgrade = 1,
    Rollback = 2,
    Restart = 3,
}

/// <summary>
/// The desired MCP workload state: one generation, one admitted manifest, and the exact
/// failure-domain placement. Two distinct failure domains are the admission floor; the
/// workload is stateless, so instances share no session state and any instance may serve any
/// request.
/// </summary>
public sealed partial record McpDesiredWorkload
{
    public McpDesiredWorkload(
        long generation,
        McpWorkloadManifest manifest,
        IReadOnlyList<string> failureDomains,
        McpChangeKind changeKind)
    {
        if (generation < 1)
            throw new ArgumentOutOfRangeException(nameof(generation), "The desired generation must be positive.");
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(failureDomains);
        if (failureDomains.Count != McpPlacementContract.MinimumInstances)
            throw new ArgumentException(
                $"The MCP workload requires exactly {McpPlacementContract.MinimumInstances} failure domains.",
                nameof(failureDomains));
        foreach (var domain in failureDomains)
        {
            if (domain is null || !DomainToken().IsMatch(domain))
                throw new ArgumentException("A failure domain must be a bounded lowercase token.", nameof(failureDomains));
        }
        if (failureDomains.Distinct(StringComparer.Ordinal).Count() != failureDomains.Count)
            throw new ArgumentException(
                "The two MCP instances must run in independent failure domains.", nameof(failureDomains));
        if (!Enum.IsDefined(changeKind))
            throw new ArgumentOutOfRangeException(nameof(changeKind));
        Generation = generation;
        Manifest = manifest;
        FailureDomains = failureDomains;
        ChangeKind = changeKind;
    }

    public long Generation { get; }
    public McpWorkloadManifest Manifest { get; }
    public IReadOnlyList<string> FailureDomains { get; }
    public McpChangeKind ChangeKind { get; }

    public string ArtifactDigest => Manifest.ArtifactDigest;

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{0,31}$", RegexOptions.CultureInvariant)]
    private static partial Regex DomainToken();
}

/// <summary>The observed condition of one MCP instance in one failure domain.</summary>
public enum McpInstanceCondition
{
    /// <summary>The domain holds no instance observation at all (crash removal or first deployment).</summary>
    Absent = 0,
    Starting = 1,
    Ready = 2,
    Failed = 3,
}

/// <summary>What one MCP instance actually runs, as last observed.</summary>
public sealed record McpInstanceObservation(
    string FailureDomain,
    long Generation,
    string ArtifactDigest,
    McpInstanceCondition Condition);

/// <summary>The reconciler's instance action kinds.</summary>
public enum McpInstanceActionKind
{
    /// <summary>The failure domain has never run an instance of this workload.</summary>
    Create = 0,
    /// <summary>The domain already holds the right artifact; start it again after loss or crash.</summary>
    Restart = 1,
    /// <summary>The observed instance failed; replace it with the desired artifact.</summary>
    Replace = 2,
    /// <summary>Move the domain onto the desired artifact (upgrade, rollback, or drift repair).</summary>
    Converge = 3,
    /// <summary>The right artifact is starting; wait for its health evidence.</summary>
    AwaitHealth = 4,
}

/// <summary>One typed instance action the reconciler emits for one failure domain.</summary>
public sealed record McpInstanceAction(
    string FailureDomain,
    McpInstanceActionKind Kind,
    string ArtifactDigest,
    McpChangeKind ChangeKind,
    string Reason);

/// <summary>The route decision for the MCP public route after one reconciliation pass.</summary>
public enum McpRouteDecisionCode
{
    Open = 0,
    /// <summary>At least one healthy backend serves stateless traffic, but fewer than the placement floor.</summary>
    OpenDegraded = 1,
    ClosedNoHealthyBackend = 2,
    /// <summary>Live Authentication, scope-denial, isolation, health, and rollback evidence has not passed.</summary>
    ClosedIngressNotProven = 3,
    ClosedByEmergencyWithdrawal = 4,
    /// <summary>The desired generation is behind an observed generation; a fenced writer must not regress it.</summary>
    ClosedDesiredStale = 5,
}

/// <summary>The backend selected for one stateless request.</summary>
public sealed record McpBackendSelection(long RequestSequence, string FailureDomain);

/// <summary>
/// The typed reconciliation plan for the MCP workload. Pure: it decides instance actions, the
/// route decision, and stateless backend selection from desired state, observations, the route
/// table, and the ingress evidence gate. It performs no I/O and mutates nothing.
/// </summary>
public sealed record McpReconciliationPlan(
    McpRouteDecisionCode Route,
    IReadOnlyList<McpInstanceAction> InstanceActions,
    IReadOnlyList<string> HealthyFailureDomains,
    IReadOnlyList<string> Holds)
{
    /// <summary>Stateless contract: no session affinity ever exists (issue #9, ADR 0032).</summary>
    public bool StickySessions => McpPlacementContract.StickySessions;

    /// <summary>
    /// Selects the backend for one request deterministically from the request sequence alone:
    /// selection carries no session, cookie, or affinity state, so consecutive requests may be
    /// served by different failure domains and any healthy backend may replace a lost one.
    /// </summary>
    public McpBackendSelection SelectBackend(long requestSequence)
    {
        if (requestSequence < 0)
            throw new ArgumentOutOfRangeException(
                nameof(requestSequence), "The request sequence must be non-negative.");
        if (HealthyFailureDomains.Count == 0)
            throw new InvalidOperationException("No healthy MCP backend is available for routing.");
        var remainder = (int)(uint)(requestSequence % HealthyFailureDomains.Count);
        return new(requestSequence, HealthyFailureDomains[remainder]);
    }
}

/// <summary>The MCP workload reconciler: create, restart, converge, route, and withdraw decisions.</summary>
public static class McpWorkloadReconciler
{
    public static McpReconciliationPlan Plan(
        McpDesiredWorkload desired,
        IReadOnlyList<McpInstanceObservation>? observations,
        McpProductRouteTable routeTable,
        McpIngressEvidence? ingressEvidence)
    {
        ArgumentNullException.ThrowIfNull(desired);
        ArgumentNullException.ThrowIfNull(routeTable);

        var observed = (observations ?? [])
            .Where(static observation => observation is not null)
            .GroupBy(static observation => observation.FailureDomain, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.Last(), StringComparer.Ordinal);

        var actions = new List<McpInstanceAction>(desired.FailureDomains.Count);
        var healthy = new List<string>(desired.FailureDomains.Count);
        var holds = new List<string>();

        foreach (var domain in desired.FailureDomains)
        {
            if (!observed.TryGetValue(domain, out var observation))
            {
                actions.Add(new(domain, McpInstanceActionKind.Create, desired.ArtifactDigest,
                    desired.ChangeKind, "the failure domain holds no observation"));
                continue;
            }

            // The generation fence runs before every condition branch — including crash-removed
            // (Absent) observations — so a stale writer's older generation can never restart,
            // regress, or act on a domain a newer fenced writer already advanced.
            if (observation.Generation > desired.Generation)
            {
                holds.Add($"{domain}:observed-generation-{observation.Generation}-exceeds-desired-{desired.Generation}");
                continue;
            }

            if (observation.Condition == McpInstanceCondition.Absent)
            {
                // The domain ran an instance of this workload and lost it (crash removal):
                // restart, which is idempotent at the same generation and digest.
                actions.Add(new(domain, McpInstanceActionKind.Restart, desired.ArtifactDigest,
                    McpChangeKind.Restart, "the domain lost its instance and restarts the same artifact"));
                continue;
            }

            var runsDesiredArtifact =
                string.Equals(observation.ArtifactDigest, desired.ArtifactDigest, StringComparison.Ordinal);
            if (observation.Generation == desired.Generation)
            {
                if (!runsDesiredArtifact)
                {
                    actions.Add(new(domain, McpInstanceActionKind.Converge, desired.ArtifactDigest,
                        desired.ChangeKind, "the observed artifact drifted from the desired digest"));
                    continue;
                }
                switch (observation.Condition)
                {
                    case McpInstanceCondition.Ready:
                        healthy.Add(domain);
                        break;
                    case McpInstanceCondition.Starting:
                        actions.Add(new(domain, McpInstanceActionKind.AwaitHealth, desired.ArtifactDigest,
                            desired.ChangeKind, "the desired artifact is starting"));
                        break;
                    case McpInstanceCondition.Failed:
                        actions.Add(new(domain, McpInstanceActionKind.Replace, desired.ArtifactDigest,
                            McpChangeKind.Restart, "the instance failed and is replaced on the same artifact"));
                        break;
                }
                continue;
            }

            // The observation trails the desired generation.
            actions.Add(new(domain, runsDesiredArtifact ? McpInstanceActionKind.Restart : McpInstanceActionKind.Converge,
                desired.ArtifactDigest, desired.ChangeKind,
                runsDesiredArtifact
                    ? "the generation advanced without an artifact change"
                    : "the desired artifact differs from the observed one"));
        }

        var route = DecideRoute(desired, routeTable, ingressEvidence, healthy, holds);
        return new McpReconciliationPlan(route, actions, healthy, holds);
    }

    private static McpRouteDecisionCode DecideRoute(
        McpDesiredWorkload desired,
        McpProductRouteTable routeTable,
        McpIngressEvidence? ingressEvidence,
        List<string> healthy,
        List<string> holds)
    {
        if (!routeTable.IsOpen(McpProductRouteTable.McpRouteName))
            return McpRouteDecisionCode.ClosedByEmergencyWithdrawal;
        if (McpIngressGate.Evaluate(ingressEvidence) != McpIngressState.Open)
            return McpRouteDecisionCode.ClosedIngressNotProven;
        if (holds.Count > 0)
            return McpRouteDecisionCode.ClosedDesiredStale;
        if (healthy.Count == 0)
            return McpRouteDecisionCode.ClosedNoHealthyBackend;
        return healthy.Count < McpPlacementContract.MinimumInstances
            ? McpRouteDecisionCode.OpenDegraded
            : McpRouteDecisionCode.Open;
    }
}

