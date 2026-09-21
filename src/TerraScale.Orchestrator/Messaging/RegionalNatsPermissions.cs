using System.Collections.ObjectModel;
using TerraScale.Orchestrator.Protocol.Messaging;
using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Messaging;

internal sealed record RegionalNatsPermissionPlan(
    ReadOnlyCollection<string> Publish,
    ReadOnlyCollection<string> Subscribe);

/// <summary>
/// Runtime grants for a controller on an infrastructure-provisioned regional account.
/// This identity cannot provision topology or open the isolated operation/proof journals.
/// Server/account isolation pins the unqualified JetStream buckets to this region.
/// </summary>
internal static class RegionalNatsPermissions
{
    internal static RegionalNatsPermissionPlan Create(string cell, string instance, string publicKey)
    {
        var scope = NatsControlAccountScope.Create(NatsControlAccountKind.RegionalController, cell);
        var topology = new NatsTopology(cell, 3, instance);
        _ = topology.InstanceHealthSubject; // Validate before forming API/consumer subjects.
        var inbox = NatsSubjectTaxonomy.ControllerInboxPrefix(cell, publicKey);
        var root = NatsSubjectTaxonomy.RegionalRoot(cell);
        var publish = scope.Publish.Where(pattern => pattern != root + ".command.>")
            .Concat(new[]
            {
                topology.DirectDeliverySubject,
                topology.OperationJournalCreateSubject,
                topology.OperationJournalUpdateSubject,
                NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject(cell, "read"),
                NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject(cell, "write"),
                root + ".command.reply.*.>",
                $"$SRV.INFO.{topology.ServiceName}",
            })
            .Concat(topology.Streams.Select(stream => $"$JS.API.STREAM.INFO.{stream.Name}"))
            .Concat(KeyValue(topology.Leaders.Bucket, watch: false))
            .Concat(KeyValue(topology.Runtime.Bucket, watch: true))
            .Concat(KeyValue(topology.NodeEnrollments.Bucket, watch: false))
            .Concat(KeyValue(topology.Delivery.Bucket, watch: true))
            .Concat(Objects(topology.ProtocolPackage.Bucket, writable: false))
            .Concat(Objects(topology.Artifacts.Bucket, writable: true))
            .Concat(Objects(topology.Bundles.Bucket, writable: true))
            .Concat(Consumer("CELL_EVENTS", topology.StartupConsumer.Name!))
            .Concat(Consumer("CELL_SPEC", topology.CellSpecConsumer.Name!));
        var subscribe = scope.Subscribe.Where(pattern => pattern != root + ".command.>")
            .Concat(new[]
            {
                topology.DirectDeliverySubject,
                inbox + ".>",
                root + $".command.journal.reply.{publicKey}.>",
                root + $".command.runtime-lifecycle.reply.{publicKey}.>",
                "_INBOX.>",
            })
            .Concat(ServiceDiscovery(topology.ServiceName))
            .Concat(ServiceDiscovery(topology.ServiceName + "_direct_delivery"));
        return new(Sorted(publish), Sorted(subscribe));
    }

    private static ReadOnlyCollection<string> Sorted(IEnumerable<string> subjects) =>
        Array.AsReadOnly(subjects.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray());

    private static IEnumerable<string> KeyValue(string bucket, bool watch)
    {
        yield return $"$JS.API.STREAM.INFO.KV_{bucket}";
        yield return $"$JS.API.DIRECT.GET.KV_{bucket}";
        yield return $"$JS.API.DIRECT.GET.KV_{bucket}.>";
        yield return $"$KV.{bucket}.>";
        if (watch)
        {
            yield return $"$JS.API.CONSUMER.CREATE.KV_{bucket}.>";
            yield return $"$JS.FC.KV_{bucket}.>";
        }
    }

    private static IEnumerable<string> Objects(string bucket, bool writable)
    {
        yield return $"$JS.API.STREAM.INFO.OBJ_{bucket}";
        yield return $"$JS.API.STREAM.MSG.GET.OBJ_{bucket}";
        yield return $"$JS.API.CONSUMER.CREATE.OBJ_{bucket}.*.$O.{bucket}.C.*";
        yield return $"$JS.API.CONSUMER.DELETE.OBJ_{bucket}.*";
        yield return $"$JS.FC.OBJ_{bucket}.>";
        if (writable)
        {
            yield return $"$O.{bucket}.C.>";
            yield return $"$O.{bucket}.M.>";
        }
    }

    private static IEnumerable<string> Consumer(string stream, string consumer) =>
    [
        $"$JS.API.CONSUMER.INFO.{stream}.{consumer}",
        $"$JS.API.CONSUMER.MSG.NEXT.{stream}.{consumer}",
        $"$JS.ACK.{stream}.{consumer}.>",
    ];

    private static IEnumerable<string> ServiceDiscovery(string service) =>
        new[] { "PING", "INFO", "STATS" }.SelectMany(verb => new[]
        {
            $"$SRV.{verb}", $"$SRV.{verb}.{service}", $"$SRV.{verb}.{service}.*",
        });
}
