namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Options for plan admission. Production plans reject loopback endpoints;
/// the pinned-NATS local conformance lane — which deliberately binds every
/// listener to loopback — is the only caller that opts in.
/// </summary>
internal sealed record NatsGatewayValidationOptions
{
    internal static NatsGatewayValidationOptions Production { get; } = new();

    internal static NatsGatewayValidationOptions LocalConformance { get; } = new() { AllowLoopbackEndpoints = true };

    internal bool AllowLoopbackEndpoints { get; init; }
}

/// <summary>
/// The fail-closed admission gate every gateway plan passes before any
/// configuration is rendered or any server starts. It aggregates the mesh,
/// service-catalog, and isolation decisions with identity, endpoint, store,
/// credential, and naming checks. <see cref="EnsureValid"/> is the single
/// entry point used by rendering and startup composition.
/// </summary>
internal static class NatsGatewayPlanValidation
{
    /// <summary>Every reason the plan cannot be rendered or started.</summary>
    internal static IReadOnlyList<string> Validate(
        NatsGatewayPlan plan,
        NatsGatewayValidationOptions? options = null)
    {
        options ??= NatsGatewayValidationOptions.Production;
        var errors = new List<string>();

        // The product plane never exchanges subjects across accounts, not even
        // the one control-plane service that is approved there. This ban is
        // part of single-plan admission, so a product plan cannot pass Validate
        // alone and only fail later in dual-plane composition.
        if (plan.Plane == NatsGatewayPlane.Product)
        {
            foreach (var export in plan.Exports)
                errors.Add(
                    $"The product plane must not declare any cross-account export; '{export.AccountName}' exports '{export.Subject}'.");
            foreach (var import in plan.Imports)
                errors.Add(
                    $"The product plane must not declare any cross-account import; '{import.AccountName}' imports '{import.Subject}'.");
        }

        errors.AddRange(NatsGatewayMesh.Validate(plan));
        errors.AddRange(NatsGatewayIsolation.ValidateRegionalDomainIsolation(plan));
        foreach (var export in plan.Exports)
            errors.AddRange(NatsGatewayServiceCatalog.ValidateExport(plan, export));
        foreach (var import in plan.Imports)
            errors.AddRange(NatsGatewayServiceCatalog.ValidateImport(plan, import));

        var cells = plan.Clusters.Select(static cluster => cluster.Cell).ToArray();
        foreach (var duplicate in cells
                     .GroupBy(static cell => cell)
                     .Where(group => group.Count() > 1))
            errors.Add($"The cell '{duplicate.Key}' declares more than one cluster.");

        var accountScopes = plan.Accounts.Select(static scope => scope.AccountName).ToArray();
        var duplicateAccounts = accountScopes
            .GroupBy(static account => account, StringComparer.Ordinal)
            .Where(group => group.Count() > 1);
        foreach (var duplicate in duplicateAccounts)
            errors.Add($"The account '{duplicate.Key}' is scoped more than once.");
        foreach (var scope in plan.Accounts.Where(scope => !cells.Contains(scope.Cell)))
            errors.Add($"The account '{scope.AccountName}' is scoped to the undeclared cell '{scope.Cell}'.");
        foreach (var cluster in plan.Clusters)
        {
            foreach (var missing in cluster.Accounts.Where(account => !accountScopes.Contains(account)))
                errors.Add(
                    $"The cluster '{cluster.ClusterName}' lists the account '{missing}' without an account scope.");
            var canonicalName = plan.Plane == NatsGatewayPlane.Control
                ? NatsGatewayPlaneTopology.ControlClusterName(cluster.Cell)
                : NatsGatewayPlaneTopology.ProductClusterName(cluster.Cell);
            if (cluster.ClusterName != canonicalName)
                errors.Add(
                    $"The cluster name '{cluster.ClusterName}' is not the canonical '{canonicalName}'.");
            var canonicalDomain = plan.Plane == NatsGatewayPlane.Control
                ? NatsGatewayPlaneTopology.ControlJetStreamDomain(cluster.Cell)
                : NatsGatewayPlaneTopology.ProductJetStreamDomain(cluster.Cell);
            if (cluster.JetStreamDomain != canonicalDomain)
                errors.Add(
                    $"The JetStream domain '{cluster.JetStreamDomain}' is not the canonical '{canonicalDomain}'.");
            if (cluster.OperatorName != plan.OperatorName)
                errors.Add($"The cluster '{cluster.ClusterName}' does not carry the plan operator.");
        }

        var servers = plan.Clusters
            .SelectMany(static cluster => cluster.Servers.Select(server => (cluster, server)))
            .ToArray();
        foreach (var duplicate in servers
                     .GroupBy(entry => entry.server.ServerName, StringComparer.Ordinal)
                     .Where(group => group.Count() > 1))
            errors.Add($"The server identity '{duplicate.Key}' is shared by more than one cluster.");
        foreach (var entry in servers.Where(entry =>
                     !entry.server.ServerName.StartsWith(entry.cluster.Cell + "-", StringComparison.Ordinal)))
            errors.Add(
                $"The server identity '{entry.server.ServerName}' is not namespaced by its cell '{entry.cluster.Cell}'.");
        foreach (var duplicate in servers
                     .SelectMany(entry => entry.server.Listeners.Select(endpoint => (entry.server.ServerName, endpoint)))
                     .GroupBy(entry => entry.endpoint.Qualified, StringComparer.Ordinal)
                     .Where(group => group.Count() > 1))
            errors.Add(
                $"The listener endpoint '{duplicate.Key}' is shared by: {string.Join(", ", duplicate.Select(entry => entry.ServerName).Order(StringComparer.Ordinal))}.");

        foreach (var entry in servers)
        {
            if (entry.server.Client.Qualified == entry.server.Route.Qualified)
                errors.Add($"The server '{entry.server.ServerName}' shares one endpoint for client and route transport.");
            if (entry.server.Gateway is { } gateway &&
                (gateway.Qualified == entry.server.Client.Qualified || gateway.Qualified == entry.server.Route.Qualified))
                errors.Add($"The server '{entry.server.ServerName}' shares one endpoint across two transports.");
            if (!options.AllowLoopbackEndpoints && entry.server.Listeners.Any(endpoint => endpoint.IsLoopback))
                errors.Add(
                    $"The server '{entry.server.ServerName}' binds a loopback endpoint; production listeners need qualified hosts.");
            if (plan.Plane == NatsGatewayPlane.Control && entry.server.Gateway is null)
                errors.Add($"The control server '{entry.server.ServerName}' has no gateway listener.");
        }

        foreach (var cluster in plan.Clusters)
        {
            // Production admission requires each regional cluster to spread its
            // servers across failure domains; the loopback conformance lane
            // co-locates a region's servers on one host and is not host-spread
            // evidence.
            if (options.AllowLoopbackEndpoints)
                continue;
            var duplicateFailureDomains = cluster.Servers
                .GroupBy(static server => server.FailureDomain, StringComparer.Ordinal)
                .Where(group => group.Count() > 1);
            foreach (var duplicate in duplicateFailureDomains)
                errors.Add(
                    $"The cluster '{cluster.ClusterName}' places servers '{string.Join(", ", duplicate.Select(static server => server.ServerName).Order(StringComparer.Ordinal))}' in one failure domain.");
        }

        foreach (var duplicate in plan.Clusters
                     .SelectMany(static cluster => cluster.Servers)
                     .GroupBy(static server => server.StoreDirectory, StringComparer.Ordinal)
                     .Where(group => group.Count() > 1))
            errors.Add($"The store directory '{duplicate.Key}' is shared by more than one server.");
        // The cgroup slice is plane-scoped by design: every cluster of one plane
        // lives in that plane's slice, and per-server cgroups are unique above.
        // Cross-plane slice separation is enforced by the dual-plane isolation.
        foreach (var duplicate in plan.Clusters
                     .SelectMany(static cluster => cluster.Servers)
                     .GroupBy(static server => server.Process.UnitName, StringComparer.Ordinal)
                     .Where(group => group.Count() > 1))
            errors.Add($"The process unit '{duplicate.Key}' is shared by more than one server.");
        foreach (var duplicate in plan.Clusters
                     .SelectMany(static cluster => cluster.Servers)
                     .GroupBy(static server => server.Process.Cgroup, StringComparer.Ordinal)
                     .Where(group => group.Count() > 1))
            errors.Add($"The server cgroup '{duplicate.Key}' is shared by more than one server.");

        var planeCertificateAuthorities = plan.Clusters
            .SelectMany(static cluster => cluster.Servers)
            .SelectMany(static server => server.CertificateProfiles)
            .Select(static profile => profile.CaFile)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (planeCertificateAuthorities.Length > 1)
            errors.Add(
                "The plane references more than one certificate authority; one plane has exactly one trust root.");
        foreach (var duplicate in plan.Clusters
                     .SelectMany(static cluster => cluster.Servers)
                     .SelectMany(static server => server.CertificateProfiles.Select(profile => (server.ServerName, profile)))
                     .GroupBy(entry => entry.profile.CertificateFile, StringComparer.Ordinal)
                     .Where(group => group.Count() > 1))
            errors.Add(
                $"The certificate '{duplicate.Key}' is shared by more than one profile; each transport and server uses its own certificate.");
        foreach (var duplicate in plan.Clusters
                     .SelectMany(static cluster => cluster.Servers)
                     .SelectMany(static server => server.CertificateProfiles.Select(profile => (server.ServerName, profile)))
                     .GroupBy(entry => entry.profile.KeyFile, StringComparer.Ordinal)
                     .Where(group => group.Count() > 1))
            errors.Add(
                $"The private key file '{duplicate.Key}' is shared by more than one profile; each transport and server uses its own key.");

        if (plan.Plane == NatsGatewayPlane.Control)
        {
            foreach (var cluster in plan.Clusters)
            {
                foreach (var server in cluster.Servers)
                {
                    var routePeers = server.Profile(NatsGatewayTransport.Route).ExpectedPeerIdentities;
                    foreach (var missing in cluster.Servers
                                 .Where(peer => peer.ServerName != server.ServerName)
                                 .Select(peer => NatsGatewayPlaneTopology.ControlServerSpiffeId(peer.ServerName))
                                 .Where(sibling => !routePeers.Contains(sibling)))
                        errors.Add(
                            $"The route certificate profile of '{server.ServerName}' does not expect the sibling peer identity '{missing}'.");
                    if (server.Gateway is null)
                        continue;
                    var gatewayPeers = server.Profile(NatsGatewayTransport.Gateway).ExpectedPeerIdentities;
                    foreach (var missing in plan.Clusters
                                 .Where(other => other.Cell != cluster.Cell)
                                 .SelectMany(static other => other.Servers)
                                 .Select(peer => NatsGatewayPlaneTopology.ControlServerSpiffeId(peer.ServerName))
                                 .Where(peer => !gatewayPeers.Contains(peer)))
                        errors.Add(
                            $"The gateway certificate profile of '{server.ServerName}' does not expect the remote peer identity '{missing}'.");
                }
            }
        }

        return errors;
    }

    /// <summary>
    /// Validates the dual-plane pair — the control supercluster and the
    /// product plane — as one deployment. An empty list is the only passing
    /// result.
    /// </summary>
    internal static IReadOnlyList<string> ValidateDualPlane(
        NatsGatewayPlan control,
        NatsGatewayPlan product,
        NatsGatewayValidationOptions? options = null)
    {
        var errors = new List<string>();
        errors.AddRange(Validate(control, options));
        errors.AddRange(Validate(product, options));
        errors.AddRange(NatsGatewayIsolation.ValidatePlaneSeparation(control, product));
        return errors;
    }

    /// <summary>Throws with every admission failure; the only gate rendering and startup may call.</summary>
    internal static void EnsureValid(
        NatsGatewayPlan plan,
        NatsGatewayValidationOptions? options = null)
    {
        var errors = Validate(plan, options);
        if (errors.Count > 0)
            throw new InvalidOperationException(
                $"The {plan.Plane}-plane NATS gateway plan is not admissible ({errors.Count} failures): " +
                string.Join(" ", errors));
    }

    /// <summary>
    /// Throws with every dual-plane admission failure. This is the gate
    /// startup composition calls: neither plane may render or start unless the
    /// pair passes single-plan admission and dual-plane separation together.
    /// </summary>
    internal static void EnsureValidDualPlane(
        NatsGatewayPlan control,
        NatsGatewayPlan product,
        NatsGatewayValidationOptions? options = null)
    {
        var errors = ValidateDualPlane(control, product, options);
        if (errors.Count > 0)
            throw new InvalidOperationException(
                $"The dual-plane NATS gateway deployment is not admissible ({errors.Count} failures): " +
                string.Join(" ", errors));
    }
}
