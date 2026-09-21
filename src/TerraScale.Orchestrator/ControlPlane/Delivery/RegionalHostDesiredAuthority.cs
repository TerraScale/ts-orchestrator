using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>Controller-only access to the exact target derived from a current signed host session.</summary>
internal sealed class RegionalHostDesiredAuthority(INatsKVStore delivery, RegionalHostSessionAuthority sessions)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 4
    };
    internal string Cell => sessions.Cell;
    internal DateTimeOffset Now => sessions.Now;

    internal async Task<RegionalHostDesiredResponse> ReadAsync(RegionalHostDesiredRequest request, CancellationToken cancellationToken)
    {
        var admitted = await sessions.AuthorizeDesiredAsync(request, cancellationToken).ConfigureAwait(false);
        if (!admitted.Authorized) return RegionalHostDesiredResponse.Deny(request, admitted.Decision);
        try
        {
            var key = DirectDeliveryTargetKey.For(AdmittedRoleCatalog.Get(request.Role).ArtifactKey,
                request.Enrollment.Scope.Environment, Cell);
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

                // A store read may outlast a lease, credential validity or revocation. Recheck before releasing data.
                var current = await sessions.AuthorizeDesiredAsync(request, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (!current.Authorized) return RegionalHostDesiredResponse.Deny(request, current.Decision);
                var expires = admitted.ExpiresAt < current.ExpiresAt ? admitted.ExpiresAt : current.ExpiresAt;
                return new(1, request.RequestId, request.RequestDigest, RegionalHostSessionDecision.Accepted,
                    request.Enrollment.BootstrapGeneration, request.Epoch, expires, digest, revision);
            }
            return RegionalHostDesiredResponse.Deny(request, RegionalHostSessionDecision.Contention);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is InvalidDataException or JsonException)
        { return RegionalHostDesiredResponse.Deny(request, RegionalHostSessionDecision.InvalidStore); }
        catch (Exception exception) when (exception is NatsException or IOException or TimeoutException)
        { return RegionalHostDesiredResponse.Deny(request, RegionalHostSessionDecision.StoreUnavailable); }
    }

    private sealed record DesiredTarget(string ArtifactDigest, string ManifestDigest, string Kind);
}
