namespace TerraScale.Orchestrator.Development;

public enum DevelopmentResourceKind
{
    ControllerAgent,
    ControlNats,
    ProductNats,
    TerraBase,
    Authentication,
    Api,
    Dashboard,
    EmailEmulator,
    StripeEmulator
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

    public static DevelopmentTopology CreateThreeCellLean()
    {
        var cells = CreateCells(controlOnly: false);
        var globalBase = BasePort + (cells.Length * CellStride);
        var global = new[]
        {
            new DevelopmentResourcePlan(
                "email-emulator",
                "gru",
                DevelopmentResourceKind.EmailEmulator,
                1,
                globalBase),
            new DevelopmentResourcePlan(
                "stripe-emulator",
                "gru",
                DevelopmentResourceKind.StripeEmulator,
                1,
                globalBase + 1)
        };
        return new("dev-containers-three-cell-lean", cells, global);
    }

    public static DevelopmentTopology CreateThreeCellControlPlane()
    {
        var cells = CreateCells(controlOnly: true);
        return new("dev-containers-control-three-cell-lean", cells, []);
    }

    private static DevelopmentCellPlan[] CreateCells(bool controlOnly) =>
    [
        CreateCell("gru", 0, controlOnly),
        CreateCell("sfo", 1, controlOnly),
        CreateCell("fra", 2, controlOnly)
    ];

    public DevelopmentResourcePlan GetRequired(
        string cell,
        DevelopmentResourceKind kind,
        int replica = 1) =>
        Cells.Single(candidate => candidate.Cell == cell)
            .Resources.Single(resource => resource.Kind == kind && resource.Replica == replica);

    private static DevelopmentCellPlan CreateCell(
        string cell,
        int ordinal,
        bool controlOnly = false)
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
        if (!controlOnly)
        {
            resources.Add(new(
                $"{cell}-product-nats-{replica}",
                cell,
                DevelopmentResourceKind.ProductNats,
                replica,
                start + 20,
                start + 30));
        }
        resources.Add(new(
            $"{cell}-controller-{replica}",
            cell,
            DevelopmentResourceKind.ControllerAgent,
            replica,
            start + 40));
        if (controlOnly)
        {
            return new(cell, ordinal, resources);
        }
        resources.Add(new(
            $"{cell}-terrabase-{replica}",
            cell,
            DevelopmentResourceKind.TerraBase,
            replica,
            start + 50,
            SecondaryPort: start + 60));

        resources.Add(new(
            $"{cell}-authentication",
            cell,
            DevelopmentResourceKind.Authentication,
            1,
            start + 70));
        resources.Add(new(
            $"{cell}-api",
            cell,
            DevelopmentResourceKind.Api,
            1,
            start + 71));
        resources.Add(new(
            $"{cell}-dashboard",
            cell,
            DevelopmentResourceKind.Dashboard,
            1,
            start + 72));
        return new(cell, ordinal, resources);
    }
}
