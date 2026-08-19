namespace TerraScale.Orchestrator.Development;

public enum DevelopmentResourceKind
{
    ControllerAgent,
    ControlNats,
    ProductNats,
    TerraBase,
    Authentication,
    Platform,
    Dashboard,
    EmailEmulator
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
    IReadOnlyList<DevelopmentCellPlan> Cells,
    IReadOnlyList<DevelopmentResourcePlan> GlobalResources)
{
    private const int CellStride = 200;
    private const int BasePort = 18600;

    public static DevelopmentTopology CreateRegional()
    {
        var cells = CreateCells();
        return new("regional", cells, CreateGlobalResources(cells.Length));
    }

    private static DevelopmentCellPlan[] CreateCells() =>
    [
        CreateCell("gru", 0),
        CreateCell("sfo", 1),
        CreateCell("fra", 2)
    ];

    private static DevelopmentResourcePlan[] CreateGlobalResources(int cellCount)
    {
        var globalBase = BasePort + (cellCount * CellStride);
        return
        [
            new(
                "email-emulator",
                "gru",
                DevelopmentResourceKind.EmailEmulator,
                1,
                globalBase)
        ];
    }

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

        // Public HTTP listeners occupy +70..+72. Private MagicOnion HTTP/2
        // listeners for Authentication and Platform use +73/+74 (SecondaryPort)
        // so DevHost can publish them and inject InternalRpc endpoints without
        // colliding with TerraBase TCP (+60) or NATS cluster ports.
        resources.Add(new(
            $"{cell}-authentication",
            cell,
            DevelopmentResourceKind.Authentication,
            1,
            start + 70,
            SecondaryPort: start + 73));
        resources.Add(new(
            $"{cell}-platform",
            cell,
            DevelopmentResourceKind.Platform,
            1,
            start + 71,
            SecondaryPort: start + 74));
        resources.Add(new(
            $"{cell}-dashboard",
            cell,
            DevelopmentResourceKind.Dashboard,
            1,
            start + 72));
        return new(cell, ordinal, resources);
    }
}
