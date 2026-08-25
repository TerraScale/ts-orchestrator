namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Pure decision for the directed gateway mesh of one plane. The launch
/// control plane is a full mesh — every ordered pair of distinct clusters has
/// exactly one directed relationship — never hub-and-spoke. Missing,
/// duplicate, self, hub-only, or product-plane edges fail closed.
/// </summary>
internal static class NatsGatewayMesh
{
    /// <summary>
    /// Every ordered pair of distinct cells, in stable ordinal order. A full
    /// mesh has n*(n-1) directed relationships for n clusters.
    /// </summary>
    internal static IReadOnlyList<NatsGatewayRelationship> FullMesh(IReadOnlyList<string> cells)
    {
        if (cells.Count < 2)
            throw new ArgumentException("A gateway supercluster requires at least two clusters.", nameof(cells));
        if (cells.Any(cell => !CellTokenRule.IsValid(cell)))
            throw new ArgumentException("A mesh cell is not a lowercase DNS-style token.", nameof(cells));
        var distinct = cells.Distinct(StringComparer.Ordinal).ToArray();
        if (distinct.Length != cells.Count)
            throw new ArgumentException("A mesh cell appears twice.", nameof(cells));
        return
        [
            .. distinct
                .OrderBy(static cell => cell, StringComparer.Ordinal)
                .SelectMany(from => distinct
                    .OrderBy(static cell => cell, StringComparer.Ordinal)
                    .Where(to => to != from)
                    .Select(to => new NatsGatewayRelationship(from, to))),
        ];
    }

    /// <summary>
    /// Every reason the plan's mesh is not a valid full mesh. An empty list is
    /// the only passing result. Cells are validated — and duplicate-cell
    /// failures aggregated — before any mesh is derived, so a malformed plan
    /// yields the complete failure list instead of a raw generator exception.
    /// </summary>
    internal static IReadOnlyList<string> Validate(NatsGatewayPlan plan)
    {
        var errors = new List<string>();
        var cells = plan.Clusters.Select(static cluster => cluster.Cell).OrderBy(static cell => cell, StringComparer.Ordinal).ToArray();

        foreach (var duplicate in cells
                     .GroupBy(static cell => cell, StringComparer.Ordinal)
                     .Where(group => group.Count() > 1))
            errors.Add($"The cell '{duplicate.Key}' declares more than one cluster.");
        foreach (var invalid in cells.Where(cell => !CellTokenRule.IsValid(cell)))
            errors.Add($"The mesh cell '{invalid}' is not a lowercase DNS-style token.");

        if (plan.Plane == NatsGatewayPlane.Product)
        {
            if (plan.GatewayRelationships.Count > 0)
                errors.Add("The product plane must not declare any gateway relationship.");
            return errors;
        }

        var distinct = cells.Distinct(StringComparer.Ordinal).ToArray();
        if (distinct.Length < 2)
        {
            errors.Add("A control-plane gateway supercluster requires at least two clusters.");
            return errors;
        }

        var expected = FullMesh(distinct);
        var declared = plan.GatewayRelationships;
        foreach (var duplicate in declared
                     .GroupBy(relationship => (relationship.FromCell, relationship.ToCell))
                     .Where(group => group.Count() > 1))
            errors.Add($"The gateway relationship {duplicate.Key.FromCell}->{duplicate.Key.ToCell} is declared more than once.");
        foreach (var self in declared.Where(relationship => relationship.FromCell == relationship.ToCell))
            errors.Add($"The gateway relationship {self.FromCell}->{self.ToCell} is a self edge.");
        foreach (var unknown in declared.Where(relationship =>
                     !cells.Contains(relationship.FromCell) || !cells.Contains(relationship.ToCell)))
            errors.Add($"The gateway relationship {unknown.FromCell}->{unknown.ToCell} references an undeclared cell.");
        foreach (var missing in expected.Where(relationship => !declared.Contains(relationship)))
            errors.Add($"The full mesh is missing the gateway relationship {missing.FromCell}->{missing.ToCell}.");
        foreach (var cluster in plan.Clusters.Where(cluster => cluster.Servers.All(static server => server.Gateway is null)))
            errors.Add($"The control cluster '{cluster.ClusterName}' has no gateway listener.");

        return errors;
    }
}
