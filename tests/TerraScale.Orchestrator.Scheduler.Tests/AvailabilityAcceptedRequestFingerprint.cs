using System.Globalization;
using System.Text;
using TerraScale.Orchestrator.Scheduler.Availability;

namespace TerraScale.Orchestrator.Scheduler.Tests;

internal static class AvailabilityAcceptedRequestFingerprint
{
    internal static string Create(AvailabilityDecision decision)
    {
        if (decision.AcceptedRequest is null)
        {
            return "denied";
        }

        var request = decision.AcceptedRequest;
        var policy = request.Policy;
        var builder = new StringBuilder("availability-accepted-request/v1|");
        Text(builder, policy.ServiceId.Value);
        Number(builder, policy.Desired.Value);
        Number(builder, policy.MinimumAvailable.Value);
        Number(builder, policy.Quorum.Value);
        Number(builder, policy.MaximumConcurrentDisruptions.Value);
        Number(builder, (ulong)policy.Criticality);
        Number(builder, policy.OnePerHost ? 1UL : 0UL);
        Number(builder, policy.RequiredDistinctFailureDomains.Value);
        Resources(builder, policy.Reserve);
        Number(builder, (ulong)policy.ReserveDisposition);
        Change(builder, request.Change);
        Number(builder, (ulong)request.ObservationCompleteness);
        Number(builder, request.ObservationGeneration.Value);
        Number(builder, request.CurrentAcceptedObservationGeneration.Value);
        var observations = request.Observations.OrderBy(static observation => observation.ReplicaId.Value, StringComparer.Ordinal)
            .ThenBy(static observation => observation.ServiceId.Value, StringComparer.Ordinal)
            .ThenBy(static observation => observation.NodeId?.Value, StringComparer.Ordinal)
            .ThenBy(static observation => observation.FailureDomainId?.Value, StringComparer.Ordinal)
            .ThenBy(static observation => observation.State)
            .ToArray();
        Number(builder, checked((ulong)observations.Length));
        foreach (var observation in observations)
        {
            Text(builder, observation.ReplicaId.Value);
            Text(builder, observation.ServiceId.Value);
            Text(builder, observation.NodeId?.Value ?? "-");
            Text(builder, observation.FailureDomainId?.Value ?? "-");
            Number(builder, (ulong)observation.State);
        }
        return builder.ToString();
    }

    private static void Change(StringBuilder builder, AvailabilityChange change)
    {
        switch (change)
        {
            case PlaceReplicaChange placement:
                Text(builder, "place");
                Text(builder, placement.ReplicaId.Value);
                Text(builder, placement.TargetNodeId.Value);
                Text(builder, placement.TargetFailureDomainId.Value);
                Resources(builder, placement.RequestedResources);
                Resources(builder, placement.AvailableResources);
                break;
            case MaintainReplicaChange maintenance:
                Text(builder, "maintain");
                Text(builder, maintenance.ReplicaId.Value);
                break;
            case DrainNodeChange drain:
                Text(builder, "drain");
                Text(builder, drain.NodeId.Value);
                break;
            default:
                throw new InvalidOperationException("The availability change vocabulary is closed.");
        }
    }

    private static void Resources(StringBuilder builder, ResourceVector resources)
    {
        Number(builder, checked((ulong)resources.Cpu));
        Number(builder, checked((ulong)resources.Memory));
        Number(builder, checked((ulong)resources.BlockIo));
        Number(builder, checked((ulong)resources.EphemeralDisk));
        Number(builder, checked((ulong)resources.Bandwidth));
        Number(builder, checked((ulong)resources.Pids));
        Number(builder, checked((ulong)resources.FileDescriptors));
        Number(builder, checked((ulong)resources.HugePages));
    }

    private static void Text(StringBuilder builder, string value) => builder
        .Append(value.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(value).Append('|');

    private static void Number(StringBuilder builder, ulong value) => builder
        .Append(value.ToString(CultureInfo.InvariantCulture)).Append('|');
}
