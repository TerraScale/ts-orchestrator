using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.Messaging;

internal enum GlobalNatsRole
{
    CellDirectoryPublisher,
    CellDirectoryReader,
    CellDirectoryService
}

internal sealed record GlobalNatsPermissionPlan
{
    internal GlobalNatsPermissionPlan(IEnumerable<string> publish, IEnumerable<string> subscribe)
    {
        Publish = Array.AsReadOnly(publish.Order(StringComparer.Ordinal).ToArray());
        Subscribe = Array.AsReadOnly(subscribe.Order(StringComparer.Ordinal).ToArray());
    }

    internal ReadOnlyCollection<string> Publish { get; }
    internal ReadOnlyCollection<string> Subscribe { get; }
}

/// <summary>
/// Produces the complete NATS subject permissions for one global-control role.
/// Callers grant the returned subjects as an allowlist with no implicit defaults.
/// </summary>
internal static class GlobalNatsPermissions
{
    internal static GlobalNatsPermissionPlan Create(string cell, GlobalNatsRole role)
    {
        if (!GlobalNatsTopology.IsCellToken(cell))
            throw new ArgumentException("The global NATS permission cell is not a lowercase DNS-style token.", nameof(cell));

        return role switch
        {
            GlobalNatsRole.CellDirectoryPublisher => new(
                [
                    "$JS.API.CONSUMER.CREATE.KV_GLOBAL_CELLS.>",
                    "$JS.API.DIRECT.GET.KV_GLOBAL_CELLS",
                    "$JS.API.DIRECT.GET.KV_GLOBAL_CELLS.>",
                    "$JS.API.STREAM.INFO.KV_GLOBAL_CELLS",
                    "$JS.FC.KV_GLOBAL_CELLS.>",
                    $"$KV.GLOBAL_CELLS.{GlobalNatsTopology.CellAdvertisementKey(cell)}",
                    GlobalNatsTopology.CellDirectorySubject,
                ],
                ["$KV.GLOBAL_CELLS.>", "_INBOX.>"]),
            GlobalNatsRole.CellDirectoryReader => new(
                [GlobalNatsTopology.CellDirectorySubject],
                ["_INBOX.>"]),
            GlobalNatsRole.CellDirectoryService => new(
                ["_INBOX.>"],
                ["$SRV.>", GlobalNatsTopology.CellDirectorySubject]),
            _ => throw new ArgumentOutOfRangeException(nameof(role))
        };
    }
}
