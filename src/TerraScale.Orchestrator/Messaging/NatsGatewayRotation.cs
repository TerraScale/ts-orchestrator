namespace TerraScale.Orchestrator.Messaging;

/// <summary>What a rotation rolls: the server configuration, the trust root, or both.</summary>
internal enum NatsGatewayRotationKind
{
    Configuration = 0,
    Trust = 1,
    TrustAndConfiguration = 2,
}

/// <summary>
/// One rolling step: the observed pre-state and target post-state of one
/// server's trust and configuration generations, plus the recorded digest of
/// the configuration it must return to if the step fails. Digests are opaque
/// values computed by the rendering adapter; the decision itself never
/// renders.
/// </summary>
internal sealed record NatsGatewayRotationStep
{
    internal NatsGatewayRotationStep(
        NatsGatewayPlane plane,
        string cell,
        string serverName,
        string failureDomain,
        int fromTrustGeneration,
        int toTrustGeneration,
        int fromConfigurationGeneration,
        int toConfigurationGeneration,
        string beforeDigest,
        string afterDigest)
    {
        if (fromTrustGeneration < 1 || toTrustGeneration < 1 ||
            fromConfigurationGeneration < 1 || toConfigurationGeneration < 1)
            throw new ArgumentException("The rotation generations must be positive.");
        if (string.IsNullOrWhiteSpace(beforeDigest) || string.IsNullOrWhiteSpace(afterDigest))
            throw new ArgumentException("The rotation step must record the pre- and post-configuration digests.");
        if (toTrustGeneration == fromTrustGeneration && toConfigurationGeneration == fromConfigurationGeneration)
            throw new ArgumentException("A rotation step must change at least one generation.");
        Plane = plane;
        Cell = cell;
        ServerName = serverName;
        FailureDomain = failureDomain;
        FromTrustGeneration = fromTrustGeneration;
        ToTrustGeneration = toTrustGeneration;
        FromConfigurationGeneration = fromConfigurationGeneration;
        ToConfigurationGeneration = toConfigurationGeneration;
        BeforeDigest = beforeDigest;
        AfterDigest = afterDigest;
    }

    internal NatsGatewayPlane Plane { get; }
    internal string Cell { get; }
    internal string ServerName { get; }
    internal string FailureDomain { get; }
    internal int FromTrustGeneration { get; }
    internal int ToTrustGeneration { get; }
    internal int FromConfigurationGeneration { get; }
    internal int ToConfigurationGeneration { get; }
    internal string BeforeDigest { get; }
    internal string AfterDigest { get; }

    /// <summary>The recorded pre-state this step restores on rollback.</summary>
    internal (int TrustGeneration, int ConfigurationGeneration, string Digest) RollbackTarget =>
        (FromTrustGeneration, FromConfigurationGeneration, BeforeDigest);
}

/// <summary>
/// Pure rotation decision for one plane: turns a current and next plan into a
/// one-plane, one-failure-domain-at-a-time rolling sequence with pre/post
/// state and explicit rollback, and fails closed on any rotation that would
/// touch two planes, skip a server of a changed cluster, or move a generation
/// backwards.
/// </summary>
internal static class NatsGatewayRotation
{
    /// <summary>
    /// Builds the ordered rolling steps from <paramref name="current"/> to
    /// <paramref name="next"/>. Digests are supplied by the caller per server:
    /// current configuration digest and next configuration digest.
    /// </summary>
    internal static IReadOnlyList<NatsGatewayRotationStep> Plan(
        NatsGatewayPlan current,
        NatsGatewayPlan next,
        IReadOnlyDictionary<string, (string Before, string After)> configurationDigests)
    {
        var errors = ValidateTransition(current, next, configurationDigests);
        if (errors.Count > 0)
            throw new InvalidOperationException(
                "The gateway rotation transition is invalid: " + string.Join(" ", errors));

        var steps = new List<NatsGatewayRotationStep>();
        foreach (var fromCluster in current.Clusters.OrderBy(static cluster => cluster.Cell, StringComparer.Ordinal))
        {
            var toCluster = next.Cluster(fromCluster.Cell)!;
            if (fromCluster.TrustGeneration == toCluster.TrustGeneration &&
                fromCluster.ConfigurationGeneration == toCluster.ConfigurationGeneration)
                continue;
            foreach (var server in fromCluster.Servers.OrderBy(static server => server.ServerName, StringComparer.Ordinal))
            {
                var (before, after) = configurationDigests[server.ServerName];
                steps.Add(new NatsGatewayRotationStep(
                    current.Plane,
                    fromCluster.Cell,
                    server.ServerName,
                    server.FailureDomain,
                    fromCluster.TrustGeneration,
                    toCluster.TrustGeneration,
                    fromCluster.ConfigurationGeneration,
                    toCluster.ConfigurationGeneration,
                    before,
                    after));
            }
        }
        return steps;
    }

    /// <summary>
    /// The explicit rollback of one step: the inverse transition restoring the
    /// recorded pre-state generations and digest. Rollback steps are inverse
    /// steps; rolling them back again restores the forward target.
    /// </summary>
    internal static NatsGatewayRotationStep Rollback(NatsGatewayRotationStep step) => new(
        step.Plane,
        step.Cell,
        step.ServerName,
        step.FailureDomain,
        step.ToTrustGeneration,
        step.FromTrustGeneration,
        step.ToConfigurationGeneration,
        step.FromConfigurationGeneration,
        step.AfterDigest,
        step.BeforeDigest);

    /// <summary>The rollback sequence of a whole plan: the inverse steps in reverse order.</summary>
    internal static IReadOnlyList<NatsGatewayRotationStep> Rollback(
        IReadOnlyList<NatsGatewayRotationStep> steps) =>
        [.. steps.AsEnumerable().Reverse().Select(Rollback)];

    /// <summary>Every reason the current-to-next transition is not rollable as declared.</summary>
    internal static IReadOnlyList<string> ValidateTransition(
        NatsGatewayPlan current,
        NatsGatewayPlan next,
        IReadOnlyDictionary<string, (string Before, string After)> configurationDigests)
    {
        var errors = new List<string>();
        if (current.Plane != next.Plane)
            errors.Add("A rotation touches exactly one plane.");
        if (current.OperatorName != next.OperatorName)
            errors.Add("A rotation never changes the plane operator trust root name.");
        if (current.Plane == NatsGatewayPlane.Product && next.GatewayRelationships.Count > 0)
            errors.Add("A product-plane rotation cannot introduce gateway relationships.");

        var currentCells = current.Clusters.Select(static cluster => cluster.Cell).Order(StringComparer.Ordinal).ToArray();
        var nextCells = next.Clusters.Select(static cluster => cluster.Cell).Order(StringComparer.Ordinal).ToArray();
        if (!currentCells.SequenceEqual(nextCells))
            errors.Add("A rotation never adds or removes a cluster; membership changes are a separate replacement operation.");

        var trustGenerations = next.Clusters.Select(static cluster => cluster.TrustGeneration).Distinct().ToArray();
        var currentTrust = current.Clusters.Select(static cluster => cluster.TrustGeneration).Distinct().ToArray();
        if (currentTrust.Length > 1 || trustGenerations.Length > 1)
            errors.Add("The trust generation is one value for the whole supercluster, before and after a rotation.");
        var changedTrust = current.Clusters.Any(cluster =>
            next.Cluster(cluster.Cell) is { } to && to.TrustGeneration != cluster.TrustGeneration);
        var unchangedTrustClusters = current.Clusters
            .Where(cluster => next.Cluster(cluster.Cell) is { } to && to.TrustGeneration == cluster.TrustGeneration)
            .Select(static cluster => cluster.Cell)
            .ToArray();
        if (changedTrust && unchangedTrustClusters.Length > 0)
            errors.Add(
                $"A trust rotation must advance every cluster; {string.Join(", ", unchangedTrustClusters.Order(StringComparer.Ordinal))} were left behind.");

        foreach (var from in current.Clusters)
        {
            var to = next.Cluster(from.Cell);
            if (to is null)
                continue;
            var currentServers = from.Servers.Select(static server => server.ServerName).Order(StringComparer.Ordinal).ToArray();
            var nextServers = to.Servers.Select(static server => server.ServerName).Order(StringComparer.Ordinal).ToArray();
            if (!currentServers.SequenceEqual(nextServers))
                errors.Add($"The cluster '{from.ClusterName}' changed its server set during a rotation.");
            if (to.ConfigurationGeneration < from.ConfigurationGeneration || to.TrustGeneration < from.TrustGeneration)
                errors.Add($"The cluster '{from.ClusterName}' rolls a generation backwards.");
            var changed = to.ConfigurationGeneration != from.ConfigurationGeneration || to.TrustGeneration != from.TrustGeneration;
            if (!changed)
            {
                // A cluster whose generations did not advance must be bit-for-bit
                // the same content; otherwise the rotation would silently
                // rewrite servers without steps, digests, or rollback.
                if (!string.Equals(ClusterContentFingerprint(from), ClusterContentFingerprint(to), StringComparison.Ordinal))
                    errors.Add(
                        $"The cluster '{from.ClusterName}' changed its content without advancing a generation; bump the configuration generation or keep the cluster unchanged.");
                continue;
            }
            foreach (var server in from.Servers)
            {
                if (!configurationDigests.TryGetValue(server.ServerName, out var digests) ||
                    string.IsNullOrWhiteSpace(digests.Before) || string.IsNullOrWhiteSpace(digests.After))
                    errors.Add($"The rotation has no pre/post configuration digest for server '{server.ServerName}'.");
                else if (digests.Before == digests.After && to.ConfigurationGeneration != from.ConfigurationGeneration)
                    errors.Add(
                        $"The rotation for server '{server.ServerName}' claims a configuration change but the configuration digest is unchanged.");
            }
        }

        return errors;
    }

    /// <summary>Every reason an executed step sequence is not a safe serial rollout.</summary>
    internal static IReadOnlyList<string> ValidateSteps(
        NatsGatewayPlan current,
        IReadOnlyList<NatsGatewayRotationStep> steps)
    {
        var errors = new List<string>();
        var planes = steps.Select(static step => step.Plane).Distinct().ToArray();
        if (planes.Length > 1)
            errors.Add("A rotation sequence touches more than one plane.");

        foreach (var duplicate in steps
                     .GroupBy(static step => (step.Cell, step.ServerName))
                     .Where(group => group.Count() > 1))
            errors.Add($"The server '{duplicate.Key.ServerName}' is rolled more than once in one sequence.");

        var ordered = steps
            .OrderBy(static step => step.Cell, StringComparer.Ordinal)
            .ThenBy(static step => step.ServerName, StringComparer.Ordinal)
            .ToArray();
        if (!steps.SequenceEqual(ordered))
            errors.Add("The rotation sequence is not ordered by cell then server ordinal.");

        foreach (var step in steps)
        {
            var cluster = current.Cluster(step.Cell);
            if (cluster is null)
            {
                errors.Add($"The rotation step references the undeclared cell '{step.Cell}'.");
                continue;
            }
            var server = cluster.Servers.SingleOrDefault(candidate => candidate.ServerName == step.ServerName);
            if (server is null)
            {
                errors.Add($"The rotation step references the undeclared server '{step.ServerName}'.");
                continue;
            }
            if (server.FailureDomain != step.FailureDomain)
                errors.Add(
                    $"The rotation step for '{step.ServerName}' records the wrong failure domain '{step.FailureDomain}'.");
            // The recorded pre-state must be exactly the current plan's state:
            // a step cannot claim to start from generations the deployment
            // never had.
            if (step.FromTrustGeneration != cluster.TrustGeneration ||
                step.FromConfigurationGeneration != cluster.ConfigurationGeneration)
                errors.Add(
                    $"The rotation step for '{step.ServerName}' does not record the current plan's generations as its pre-state.");
        }

        // One failure domain at a time: the serialized sequence never holds two
        // servers of the same cluster in flight, which keeps an R3 cluster at
        // quorum throughout the rollout. A host-spread production cluster rolls
        // each host at most once per rotation; the loopback conformance lane
        // co-locates a region's servers on one host, so its shared failure
        // domain is by design and exempt from the once-per-domain rule.
        foreach (var pair in steps
                     .GroupBy(static step => (step.Cell, step.FailureDomain))
                     .Where(group => group.Count() > 1))
        {
            var cluster = current.Cluster(pair.Key.Cell);
            var hostSpread = cluster is null ||
                             cluster.Servers.Select(static server => server.FailureDomain).Distinct().Count() ==
                             cluster.Servers.Count;
            if (hostSpread)
                errors.Add(
                    $"The rotation sequence rolls the failure domain '{pair.Key.FailureDomain}' of cell '{pair.Key.Cell}' more than once.");
        }

        return errors;
    }

    /// <summary>
    /// A canonical, order-independent projection of everything a rotation must
    /// not change without a generation bump: names, domains, endpoints, store
    /// directories, process identity, certificate file references and expected
    /// peers, accounts, and JetStream assets.
    /// </summary>
    private static string ClusterContentFingerprint(NatsGatewayCluster cluster) => string.Join(
        "|",
        cluster.ClusterName,
        cluster.JetStreamDomain,
        cluster.OperatorName,
        cluster.CgroupSlice,
        string.Join(",", cluster.Accounts.Order(StringComparer.Ordinal)),
        string.Join(",", cluster.JetStreamAssets.Order(StringComparer.Ordinal)),
        string.Join(";", cluster.Servers
            .OrderBy(static server => server.ServerName, StringComparer.Ordinal)
            .Select(static server => string.Join(
                ",",
                server.ServerName,
                server.FailureDomain,
                server.Client.Qualified,
                server.Route.Qualified,
                server.Gateway?.Qualified ?? "-",
                server.StoreDirectory,
                server.Process.UnitName,
                server.Process.Cgroup,
                string.Join(
                    ",",
                    server.CertificateProfiles
                        .OrderBy(static profile => profile.Transport)
                        .Select(static profile => string.Join(
                            ":",
                            profile.Transport,
                            profile.CertificateFile,
                            profile.KeyFile,
                            profile.CaFile,
                            string.Join(",", profile.ExpectedPeerIdentities.Order(StringComparer.Ordinal)))))))));
}
