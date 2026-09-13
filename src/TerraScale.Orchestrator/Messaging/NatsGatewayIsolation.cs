namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Pure isolation decisions for the dual-plane and regional-domain invariants:
/// the control and product planes never share an operator, process, account,
/// port, subject, cgroup, store path, or credential file; every region keeps
/// its own JetStream domain and no JetStream asset spans regions. An empty
/// error list is the only passing result.
/// </summary>
internal static class NatsGatewayIsolation
{
    /// <summary>
    /// The account name both planes use for their operator-scoped system
    /// account. It is scoped by its operator, so it is the one name allowed in
    /// both planes; every other account must be disjoint.
    /// </summary>
    internal const string SharedSystemAccountName = "system";

    internal static IReadOnlyList<string> ValidatePlaneSeparation(
        NatsGatewayPlan control,
        NatsGatewayPlan product)
    {
        var errors = new List<string>();
        if (control.Plane != NatsGatewayPlane.Control)
            errors.Add("The control isolation argument is not a control-plane plan.");
        if (product.Plane != NatsGatewayPlane.Product)
            errors.Add("The product isolation argument is not a product-plane plan.");
        if (errors.Count > 0)
            return errors;

        if (control.OperatorName == product.OperatorName)
            errors.Add("The control and product planes share one operator trust root.");

        var sharedAccounts = control.Accounts
            .Select(static scope => scope.AccountName)
            .Intersect(product.Accounts.Select(static scope => scope.AccountName), StringComparer.Ordinal)
            .Where(account => account != SharedSystemAccountName)
            .ToArray();
        foreach (var account in sharedAccounts)
            errors.Add($"The account '{account}' is declared in both planes.");

        var sharedListenerPorts = control.Clusters
            .SelectMany(static cluster => cluster.Servers)
            .SelectMany(static server => server.Listeners)
            .Select(static endpoint => endpoint.Port)
            .Intersect(product.Clusters
                .SelectMany(static cluster => cluster.Servers)
                .SelectMany(static server => server.Listeners)
                .Select(static endpoint => endpoint.Port))
            .Distinct()
            .ToArray();
        foreach (var port in sharedListenerPorts)
            errors.Add($"The planes share listener port {port}.");

        var sharedStores = control.Clusters
            .SelectMany(static cluster => cluster.Servers)
            .Select(static server => server.StoreDirectory)
            .Intersect(product.Clusters
                .SelectMany(static cluster => cluster.Servers)
                .Select(static server => server.StoreDirectory), StringComparer.Ordinal)
            .ToArray();
        foreach (var store in sharedStores)
            errors.Add($"The planes share the store directory '{store}'.");
        foreach (var pair in control.Clusters
                     .SelectMany(static cluster => cluster.Servers.Select(static server => server.StoreDirectory))
                     .SelectMany(controlStore => product.Clusters
                         .SelectMany(static cluster => cluster.Servers.Select(static server => server.StoreDirectory))
                         .Select(productStore => (Control: controlStore, Product: productStore)))
                     .Where(pair =>
                         pair.Control.StartsWith(pair.Product + "/", StringComparison.Ordinal) ||
                         pair.Product.StartsWith(pair.Control + "/", StringComparison.Ordinal)))
            errors.Add(
                $"The store directories '{pair.Control}' and '{pair.Product}' overlap; each plane needs its own store root.");

        var sharedUnits = control.Clusters
            .SelectMany(static cluster => cluster.Servers)
            .Select(static server => server.Process.UnitName)
            .Intersect(product.Clusters
                .SelectMany(static cluster => cluster.Servers)
                .Select(static server => server.Process.UnitName), StringComparer.Ordinal)
            .ToArray();
        foreach (var unit in sharedUnits)
            errors.Add($"The planes share the process unit '{unit}'.");
        var sharedCgroups = control.Clusters
            .SelectMany(static cluster => cluster.Servers)
            .Select(static server => server.Process.Cgroup)
            .Concat(control.Clusters.Select(static cluster => cluster.CgroupSlice))
            .Intersect(product.Clusters
                .SelectMany(static cluster => cluster.Servers)
                .Select(static server => server.Process.Cgroup)
                .Concat(product.Clusters.Select(static cluster => cluster.CgroupSlice)), StringComparer.Ordinal)
            .ToArray();
        foreach (var cgroup in sharedCgroups)
            errors.Add($"The planes share the cgroup '{cgroup}'.");

        var controlCredentialFiles = CredentialFiles(control);
        foreach (var productFile in CredentialFiles(product))
        {
            if (controlCredentialFiles.Contains(productFile))
                errors.Add(
                    $"The credential file '{productFile}' is referenced by both planes; a certificate or key never crosses planes.");
        }

        if (product.GatewayRelationships.Count > 0)
            errors.Add("The product plane declares an inter-region gateway relationship.");
        if (product.Exports.Count > 0 || product.Imports.Count > 0)
            errors.Add("The product plane declares a cross-account import or export.");
        foreach (var cluster in product.Clusters.Where(cluster => cluster.Servers.Any(static server => server.Gateway is not null)))
            errors.Add($"The product cluster '{cluster.ClusterName}' opens a gateway listener.");

        return errors;
    }

    /// <summary>
    /// Regional JetStream domain isolation inside one plane: every cluster owns
    /// a unique domain, every asset is bound to exactly one cluster's domain,
    /// and global-authority assets exist only in their single owning cluster.
    /// JetStream Raft groups are per domain and asset, so domain uniqueness is
    /// what keeps them regional.
    /// </summary>
    internal static IReadOnlyList<string> ValidateRegionalDomainIsolation(NatsGatewayPlan plan)
    {
        var errors = new List<string>();
        foreach (var duplicate in plan.Clusters
                     .GroupBy(static cluster => cluster.JetStreamDomain)
                     .Where(group => group.Count() > 1))
        {
            errors.Add($"The JetStream domain '{duplicate.Key}' is declared by more than one cluster.");
        }

        foreach (var prefix in NatsGatewayServiceCatalog.GlobalAuthorityAssetPrefixes)
        {
            var owners = plan.Clusters
                .Where(cluster => cluster.JetStreamAssets.Any(asset => asset.StartsWith(prefix, StringComparison.Ordinal)))
                .Select(static cluster => cluster.Cell)
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (owners.Length > 1)
                errors.Add(
                    $"The global-authority asset prefix '{prefix}' spans the regions {string.Join(", ", owners.Order(StringComparer.Ordinal))}; global assets live in exactly one region.");
        }

        if (plan.Plane == NatsGatewayPlane.Control)
        {
            foreach (var cluster in plan.Clusters.Where(cluster => cluster.JetStreamAssets.Count == 0))
                errors.Add($"The control cluster '{cluster.ClusterName}' declares no JetStream assets.");
        }

        return errors;
    }

    private static HashSet<string> CredentialFiles(NatsGatewayPlan plan) =>
        [.. plan.Clusters
            .SelectMany(static cluster => cluster.Servers)
            .SelectMany(static server => server.CertificateProfiles)
            .SelectMany(static profile => new[] { profile.CertificateFile, profile.KeyFile, profile.CaFile })];
}

