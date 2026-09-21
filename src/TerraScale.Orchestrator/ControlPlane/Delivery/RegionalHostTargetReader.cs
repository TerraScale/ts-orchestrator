using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>Controller-only current target read, shared by independently signed selection and artifact operations.</summary>
internal sealed class RegionalHostTargetReader(INatsKVStore delivery)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 4
    };
    internal async Task<RegionalHostTarget> ReadAsync(string artifact, string environment, string cell, CancellationToken cancellationToken)
    {
        try
        {
            var key = DirectDeliveryTargetKey.For(artifact, environment, cell);
            for (var attempt = 0; attempt < 8; attempt++)
            {
                string? digest = null;
                ulong revision = 0;
                try
                {
                    var entry = await delivery.GetEntryAsync<string>(key, cancellationToken: cancellationToken).ConfigureAwait(false);
                    entry.EnsureSuccess();
                    if (entry.Revision == 0 || entry.Value is not { Length: > 0 and <= 2048 } json || Encoding.UTF8.GetByteCount(json) > 2048)
                        throw new InvalidDataException("The desired target exceeds its bounds.");
                    var target = JsonSerializer.Deserialize<DesiredTarget>(json, JsonOptions);
                    if (target is null || !HostDesiredArtifactReader.ValidDigest(target.ArtifactDigest) ||
                        !HostDesiredArtifactReader.ValidDigest(target.ManifestDigest) || target.Kind is not ("service" or "package" or "site"))
                        throw new InvalidDataException("The desired target is malformed.");
                    // Reject stale positive replica reads without inventing a sentinel that the producer does not own.
                    // Absence can only delay work; it does not permit a stale artifact to start.
                    cancellationToken.ThrowIfCancellationRequested();
                    revision = await delivery.UpdateAsync(key, json, entry.Revision, cancellationToken: cancellationToken).ConfigureAwait(false);
                    digest = target.ArtifactDigest.ToLowerInvariant();
                }
                catch (NatsKVWrongLastRevisionException) { continue; }
                catch (Exception exception) when (exception is NatsKVKeyNotFoundException or NatsKVKeyDeletedException) { }

                cancellationToken.ThrowIfCancellationRequested();
                return new(RegionalHostSessionDecision.Accepted, digest, revision);
            }
            return new(RegionalHostSessionDecision.Contention, null, 0);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is InvalidDataException or JsonException)
        { return new(RegionalHostSessionDecision.InvalidStore, null, 0); }
        catch (Exception exception) when (exception is NatsException or IOException or TimeoutException)
        { return new(RegionalHostSessionDecision.StoreUnavailable, null, 0); }
    }

    private sealed record DesiredTarget(string ArtifactDigest, string ManifestDigest, string Kind);
}

internal sealed record RegionalHostTarget(RegionalHostSessionDecision Decision, string? Digest, ulong Revision);
