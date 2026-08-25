using System.Collections.ObjectModel;
using TerraScale.Orchestrator;

namespace TerraScale.Orchestrator.Messaging;

internal enum GlobalNatsRole
{
    CellDirectoryPublisher,
    CellDirectoryReader,
    CellDirectoryService,
    GlobalAuthority
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
        if (!CellTokenRule.IsValid(cell))
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
                ["_INBOX.>", "_R_.>"],
                ["$SRV.>", GlobalNatsTopology.CellDirectorySubject]),
            GlobalNatsRole.GlobalAuthority => Authority(cell),
            _ => throw new ArgumentOutOfRangeException(nameof(role))
        };
    }

    private static GlobalNatsPermissionPlan Authority(string cell)
    {
        var topology = new GlobalNatsTopology(3);
        var publish = topology.Streams.SelectMany(stream => StreamManagement(stream.Name!))
            .Concat(new[]
            {
                $"$KV.{topology.Leaders.Bucket}.authority.global",
                $"$KV.{topology.Releases.Bucket}.>",
                $"$KV.{topology.RunnerJobs.Bucket}.{GlobalNatsTopology.CiRunnerJournalKeyPrefix}.*.job.>",
                GlobalNatsTopology.CiSubject,
                $"{GlobalNatsTopology.CiJobSubjectPrefix}.untrusted-product.*",
                $"{GlobalNatsTopology.CiJobSubjectPrefix}.trusted-build.*",
                $"{GlobalNatsTopology.CellSpecSubjectPrefix}.*",
            })
            .Concat(KeyValueManagement(topology.Leaders.Bucket))
            .Concat(KeyValueManagement(topology.Releases.Bucket))
            .Concat(KeyValueManagement(topology.RunnerJobs.Bucket))
            .Concat(ObjectStorePermissions(topology.Bundles.Bucket))
            .Concat(ObjectStorePermissions(topology.RunnerBundles.Bucket))
            .Concat(ConsumerPermissions(
                GlobalNatsTopology.CiStream,
                topology.CiConsumer.Name!,
                topology.CiConsumer.FilterSubject!))
            .Concat(ConsumerPermissions(
                GlobalNatsTopology.CiStream,
                topology.CiRuntimeProofConsumer.Name!,
                topology.CiRuntimeProofConsumer.FilterSubject!))
            .Concat(ConsumerPermissions(
                GlobalNatsTopology.CellSpecStream,
                topology.CellSpecConsumer(cell).Name!,
                topology.CellSpecConsumer(cell).FilterSubject!))
            .Concat(KeyValueWatchPermissions(topology.Releases.Bucket))
            .Concat(CiRunnerConsumerPermissions());

        return new(publish, ["_INBOX.>"]);
    }

    private static IEnumerable<string> StreamManagement(string stream) =>
    [
        $"$JS.API.STREAM.CREATE.{stream}",
        $"$JS.API.STREAM.UPDATE.{stream}",
        $"$JS.API.STREAM.INFO.{stream}",
    ];

    private static IEnumerable<string> KeyValueManagement(string bucket) =>
    [
        $"$JS.API.STREAM.CREATE.KV_{bucket}",
        $"$JS.API.STREAM.UPDATE.KV_{bucket}",
        $"$JS.API.STREAM.INFO.KV_{bucket}",
        $"$JS.API.DIRECT.GET.KV_{bucket}",
    ];

    private static IEnumerable<string> ObjectStorePermissions(string bucket)
    {
        var stream = $"OBJ_{bucket}";
        return
        [
            $"$JS.API.STREAM.CREATE.{stream}",
            $"$JS.API.STREAM.UPDATE.{stream}",
            $"$JS.API.STREAM.INFO.{stream}",
            $"$JS.API.STREAM.PURGE.{stream}",
            $"$JS.API.STREAM.MSG.GET.{stream}",
            $"$JS.API.DIRECT.GET.{stream}",
            $"$JS.API.CONSUMER.CREATE.{stream}.*.$O.{bucket}.C.*",
            $"$JS.API.CONSUMER.DELETE.{stream}.*",
            $"$JS.FC.{stream}.>",
            $"$O.{bucket}.C.>",
            $"$O.{bucket}.M.>",
        ];
    }

    private static IEnumerable<string> KeyValueWatchPermissions(string bucket) =>
    [
        $"$JS.API.CONSUMER.CREATE.KV_{bucket}",
        $"$JS.API.CONSUMER.CREATE.KV_{bucket}.>",
        $"$JS.API.CONSUMER.DURABLE.CREATE.KV_{bucket}.>",
        $"$JS.API.CONSUMER.INFO.KV_{bucket}.>",
        $"$JS.API.CONSUMER.MSG.NEXT.KV_{bucket}.>",
        $"$JS.ACK.KV_{bucket}.>",
        $"$JS.FC.KV_{bucket}.>",
    ];

    private static IEnumerable<string> ConsumerPermissions(
        string stream,
        string consumer,
        string filterSubject) =>
    [
        $"$JS.API.CONSUMER.CREATE.{stream}.{consumer}",
        $"$JS.API.CONSUMER.CREATE.{stream}.{consumer}.{filterSubject}",
        $"$JS.API.CONSUMER.DURABLE.CREATE.{stream}.{consumer}",
        $"$JS.API.CONSUMER.DURABLE.CREATE.{stream}.{consumer}.{filterSubject}",
        $"$JS.API.CONSUMER.INFO.{stream}.{consumer}",
        $"$JS.API.CONSUMER.MSG.NEXT.{stream}.{consumer}",
        $"$JS.ACK.{stream}.{consumer}.>",
        $"$JS.FC.{stream}.{consumer}.>",
    ];

    private static IEnumerable<string> CiRunnerConsumerPermissions()
    {
        var filter = $"{GlobalNatsTopology.CiJobSubjectPrefix}.*.*";
        return
        [
            $"$JS.API.CONSUMER.CREATE.{GlobalNatsTopology.CiStream}.*.{filter}",
            $"$JS.API.CONSUMER.DURABLE.CREATE.{GlobalNatsTopology.CiStream}.*.{filter}",
            $"$JS.API.CONSUMER.INFO.{GlobalNatsTopology.CiStream}.*",
            $"$JS.API.CONSUMER.MSG.NEXT.{GlobalNatsTopology.CiStream}.*",
            $"$JS.ACK.{GlobalNatsTopology.CiStream}.*.>",
            $"$JS.FC.{GlobalNatsTopology.CiStream}.*.>",
        ];
    }
}
