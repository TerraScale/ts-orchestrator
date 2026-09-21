using System.Text.Json;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using TerraScale.Orchestrator.Runtime;
using TerraScale.Orchestrator.Nodes;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>Reads one workload's replica count and exact artifact from the accepted CellSpec objects.</summary>
internal sealed class NatsWorkloadDesiredStateReader
{
    private const int MaximumPointerKeys = 512;
    private readonly INatsKVStore delivery;
    private readonly INatsObjStore bundles;
    private readonly string cell;

    internal NatsWorkloadDesiredStateReader(INatsKVStore delivery, INatsObjStore bundles, string cell)
    {
        this.delivery = delivery ?? throw new ArgumentNullException(nameof(delivery));
        this.bundles = bundles ?? throw new ArgumentNullException(nameof(bundles));
        this.cell = cell is { Length: > 0 } ? cell : throw new ArgumentException("The cell is required.", nameof(cell));
    }

    internal async Task<WorkloadReplicaIntent> ReadAsync(string workload, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(workload))
            throw new ArgumentException("The workload is required.", nameof(workload));
        var desired = 0;
        string? digest = null;
        var keys = new List<string>(MaximumPointerKeys);
        await foreach (var key in delivery.GetKeysAsync(
                           ["gitops.cell.>"],
                           new NatsKVWatchOpts { IgnoreDeletes = true },
                           cancellationToken).ConfigureAwait(false))
        {
            keys.Add(key);
            if (keys.Count > MaximumPointerKeys)
                throw new InvalidDataException("The accepted workload pointer set exceeds its bound.");
        }

        foreach (var key in keys)
        {
            var entry = await delivery.GetEntryAsync<string>(key, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            entry.EnsureSuccess();
            using var pointer = JsonDocument.Parse(entry.Value ?? string.Empty);
            var root = pointer.RootElement;
            if (!root.TryGetProperty("cell", out var pointerCell) || pointerCell.GetString() != cell ||
                !root.TryGetProperty("payloadObject", out var payloadObject))
                continue;
            var payloadName = payloadObject.GetString();
            if (string.IsNullOrWhiteSpace(payloadName))
                continue;
            var payload = await bundles.GetBytesAsync(payloadName, cancellationToken).ConfigureAwait(false);
            using var document = JsonDocument.Parse(payload);
            if (!document.RootElement.TryGetProperty("desiredWorkloads", out var workloads) ||
                workloads.ValueKind != JsonValueKind.Array)
                continue;
            foreach (var candidate in workloads.EnumerateArray())
            {
                if (candidate.TryGetProperty("suspended", out var suspended) && suspended.GetBoolean())
                    continue;
                if (!candidate.TryGetProperty("cells", out var cells) ||
                    !cells.EnumerateArray().Any(value => value.GetString() == cell) ||
                    !candidate.TryGetProperty("role", out var role))
                    continue;
                var descriptor = Enum.TryParse<AdmittedRole>(role.GetString(), ignoreCase: false, out var parsed) &&
                                 Enum.IsDefined(parsed)
                    ? AdmittedRoleCatalog.Get(parsed)
                    : null;
                if (descriptor is null || descriptor.ArtifactKey != workload)
                    continue;
                var replicas = candidate.TryGetProperty("replicas", out var replicaValue) &&
                               replicaValue.TryGetInt32(out var parsedReplicas)
                    ? parsedReplicas
                    : descriptor.MinimumReplicas;
                if (!candidate.TryGetProperty("artifactDigest", out var artifact) || artifact.ValueKind != JsonValueKind.String)
                    throw new InvalidDataException("An admitted workload must identify its exact artifact.");
                var candidateDigest = "sha256:" + new ArtifactDigest(artifact.GetString()!).Value;
                if (digest is not null && digest != candidateDigest)
                    throw new InvalidDataException("One regional workload fleet cannot converge conflicting artifact digests.");
                digest = candidateDigest;
                desired = checked(desired + replicas);
            }
        }

        // Zero is outside every admitted fleet policy and blocks provisioning.
        // A policy minimum is a bound, not permission to create a workload
        // before its desired state is published (or after it is suspended).
        return new(desired, digest);
    }
}
