using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal sealed class RegionalHostArtifactAuthority(INatsKVStore delivery, RegionalHostSessionAuthority sessions, IRegionalArtifactReader artifacts)
{
    private readonly RegionalHostTargetReader targets = new(delivery);
    internal string Cell => sessions.Cell;
    internal DateTimeOffset Now => sessions.Now;
    internal (long Bytes, int Entries, bool Downloading) CacheSnapshot => artifacts is RegionalArtifactCache cache ? cache.Snapshot : default;

    internal async Task<RegionalHostArtifactResponse> ReadAsync(RegionalHostArtifactRequest request, CancellationToken cancellationToken)
    {
        var admitted = await AuthorizeAsync(request, cancellationToken).ConfigureAwait(false);
        if (!admitted.Authorized) return RegionalHostArtifactResponse.Deny(request, admitted.Decision);
        try
        {
            var chunk = await artifacts.ReadAsync(request.ArtifactDigest, request.Offset, request.Length, cancellationToken).ConfigureAwait(false);
            var current = await AuthorizeAsync(request, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!current.Authorized) return RegionalHostArtifactResponse.Deny(request, current.Decision);
            var expires = admitted.ExpiresAt < current.ExpiresAt ? admitted.ExpiresAt : current.ExpiresAt;
            var response = new RegionalHostArtifactResponse(1, request.RequestId, request.RequestDigest,
                RegionalHostSessionDecision.Accepted, request.Enrollment.BootstrapGeneration, request.Epoch, expires,
                request.ArtifactDigest, request.Offset, chunk.TotalBytes, chunk.Bytes, request.Offset + chunk.Bytes.Length == chunk.TotalBytes);
            response.RequireBinding(request, Now);
            return response;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (InvalidDataException) { return RegionalHostArtifactResponse.Deny(request, RegionalHostSessionDecision.InvalidStore); }
        catch (Exception exception) when (exception is NatsException or IOException or TimeoutException or OperationCanceledException)
        { return RegionalHostArtifactResponse.Deny(request, RegionalHostSessionDecision.StoreUnavailable); }
    }

    private async Task<RegionalHostActionAuthorization> AuthorizeAsync(RegionalHostArtifactRequest request, CancellationToken cancellationToken)
    {
        var session = await sessions.AuthorizeArtifactAsync(request, cancellationToken).ConfigureAwait(false);
        if (!session.Authorized) return session;
        var target = await targets.ReadAsync(AdmittedRoleCatalog.Get(request.Role).ArtifactKey,
            request.Enrollment.Scope.Environment, Cell, cancellationToken).ConfigureAwait(false);
        if (target.Decision != RegionalHostSessionDecision.Accepted) return new(target.Decision, null);
        if (target.Digest != request.ArtifactDigest) return new(RegionalHostSessionDecision.EnrollmentDenied, null);
        // The target operation may have waited on a slow store; confirm the session after it too.
        return await sessions.AuthorizeArtifactAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
