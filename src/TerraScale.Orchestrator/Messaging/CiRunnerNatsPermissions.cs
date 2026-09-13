using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.Messaging;

internal sealed record CiRunnerNatsPermissionPlan
{
    internal CiRunnerNatsPermissionPlan(
        string consumer,
        string filterSubject,
        IEnumerable<string> publish,
        IEnumerable<string> subscribe)
    {
        Consumer = consumer;
        FilterSubject = filterSubject;
        Publish = Array.AsReadOnly(publish.Order(StringComparer.Ordinal).ToArray());
        Subscribe = Array.AsReadOnly(subscribe.Order(StringComparer.Ordinal).ToArray());
    }

    internal string Consumer { get; }
    internal string FilterSubject { get; }
    internal ReadOnlyCollection<string> Publish { get; }
    internal ReadOnlyCollection<string> Subscribe { get; }
}

/// <summary>
/// Exact NATS.Net 2.7.2 subjects required by a runner agent after a controller has
/// provisioned its durable consumer. Job containers never receive this identity.
/// </summary>
internal static class CiRunnerNatsPermissions
{
    internal static CiRunnerNatsPermissionPlan Create(
        GlobalNatsTopology topology,
        string zone,
        string runner)
    {
        ArgumentNullException.ThrowIfNull(topology);
        var consumer = topology.CiJobConsumer(zone, runner);
        if (consumer.Name is not { Length: > 0 } consumerName)
            throw new InvalidOperationException("The CI runner consumer must have a name.");
        if (consumer.FilterSubject is not { Length: > 0 } filterSubject)
            throw new InvalidOperationException("The CI runner consumer must have a filter subject.");
        var journalPrefix = GlobalNatsTopology.CiRunnerJournalPrefix(runner);
        var runnerObjects = $"OBJ_{GlobalNatsTopology.RunnerBundlesBucket}";
        return new(
            consumerName,
            filterSubject,
            [
                $"$JS.ACK.{GlobalNatsTopology.CiStream}.{consumerName}.>",
                $"$JS.API.CONSUMER.INFO.{GlobalNatsTopology.CiStream}.{consumerName}",
                $"$JS.API.CONSUMER.MSG.NEXT.{GlobalNatsTopology.CiStream}.{consumerName}",
                $"$JS.API.CONSUMER.CREATE.{runnerObjects}.*.$O.{GlobalNatsTopology.RunnerBundlesBucket}.C.*",
                $"$JS.API.CONSUMER.DELETE.{runnerObjects}.*",
                $"$JS.API.DIRECT.GET.KV_{GlobalNatsTopology.RunnerJobsBucket}.$KV.{GlobalNatsTopology.RunnerJobsBucket}.{journalPrefix}.*",
                $"$JS.API.STREAM.INFO.KV_{GlobalNatsTopology.RunnerJobsBucket}",
                $"$JS.API.STREAM.INFO.{runnerObjects}",
                $"$JS.API.STREAM.MSG.GET.{runnerObjects}",
                $"$JS.FC.{runnerObjects}.>",
                $"$KV.{GlobalNatsTopology.RunnerJobsBucket}.{journalPrefix}.*",
                $"$O.{GlobalNatsTopology.RunnerBundlesBucket}.C.*",
                $"$O.{GlobalNatsTopology.RunnerBundlesBucket}.M.*",
            ],
            ["_INBOX.>"]);
    }
}
