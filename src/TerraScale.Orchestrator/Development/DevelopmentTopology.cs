namespace TerraScale.Orchestrator.Development;

public enum DevelopmentResourceKind
{
    ControllerAgent,
    ControlNats,
    ProductNats,
    TerraBase,
    Authentication,
    Platform,
    Dashboard
}

public sealed record DevelopmentResourcePlan(
    string Name,
    string Cell,
    DevelopmentResourceKind Kind,
    int Replica,
    int Port,
    int? ClusterPort = null,
    int? SecondaryPort = null);

public sealed record DevelopmentCellPlan(
    string Cell,
    int Ordinal,
    IReadOnlyList<DevelopmentResourcePlan> Resources)
{
    public IReadOnlyList<DevelopmentResourcePlan> OfKind(DevelopmentResourceKind kind) =>
        Resources.Where(resource => resource.Kind == kind).ToArray();
}

public sealed record DevelopmentTopology(
    string Profile,
    IReadOnlyList<DevelopmentCellPlan> Cells)
{
    private const int CellStride = 200;
    private const int BasePort = 18600;

    public static DevelopmentTopology CreateRegional() => new("regional", CreateCells());

    private static DevelopmentCellPlan[] CreateCells() =>
    [
        CreateCell("gru", 0),
        CreateCell("sfo", 1),
        CreateCell("fra", 2)
    ];

    public DevelopmentResourcePlan GetRequired(
        string cell,
        DevelopmentResourceKind kind,
        int replica = 1) =>
        Cells.Single(candidate => candidate.Cell == cell)
            .Resources.Single(resource => resource.Kind == kind && resource.Replica == replica);

    private static DevelopmentCellPlan CreateCell(string cell, int ordinal)
    {
        var start = BasePort + (ordinal * CellStride);
        var resources = new List<DevelopmentResourcePlan>();
        const int replica = 1;
        resources.Add(new(
            $"{cell}-control-nats-{replica}",
            cell,
            DevelopmentResourceKind.ControlNats,
            replica,
            start,
            start + 10));
        resources.Add(new(
            $"{cell}-product-nats-{replica}",
            cell,
            DevelopmentResourceKind.ProductNats,
            replica,
            start + 20,
            start + 30));
        resources.Add(new(
            $"{cell}-controller-{replica}",
            cell,
            DevelopmentResourceKind.ControllerAgent,
            replica,
            start + 40));
        resources.Add(new(
            $"{cell}-terrabase-{replica}",
            cell,
            DevelopmentResourceKind.TerraBase,
            replica,
            start + 50,
            SecondaryPort: start + 60));

        // Public HTTP listeners occupy +70..+72. Authentication's private
        // MagicOnion HTTP/2 listener uses +73 (SecondaryPort); the full-stack
        // Vinext Dashboard has no private listener. These ports keep DevHost's
        // endpoint projection separate from TerraBase TCP (+60) and NATS ports.
        resources.Add(new(
            $"{cell}-authentication",
            cell,
            DevelopmentResourceKind.Authentication,
            1,
            start + 70,
            SecondaryPort: start + 73));
        // Dashboard is one Vinext full-stack workload. Its existing +72 listener
        // is a compatibility contract for DevHost (GRU remains 18672); there is
        // no separate Dashboard.Api process or +71 endpoint.
        resources.Add(new(
            $"{cell}-dashboard",
            cell,
            DevelopmentResourceKind.Dashboard,
            1,
            start + 72));
        return new(cell, ordinal, resources);
    }
}
