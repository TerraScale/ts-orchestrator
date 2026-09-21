using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>Controller-only access to the exact target derived from a current signed host session.</summary>
internal sealed class RegionalHostDesiredAuthority(INatsKVStore delivery, RegionalHostSessionAuthority sessions)
{
    private readonly RegionalHostTargetReader targets = new(delivery);
    internal string Cell => sessions.Cell;
    internal DateTimeOffset Now => sessions.Now;

    internal async Task<RegionalHostDesiredResponse> ReadAsync(RegionalHostDesiredRequest request, CancellationToken cancellationToken)
    {
        var admitted = await sessions.AuthorizeDesiredAsync(request, cancellationToken).ConfigureAwait(false);
        if (!admitted.Authorized) return RegionalHostDesiredResponse.Deny(request, admitted.Decision);
        var target = await targets.ReadAsync(AdmittedRoleCatalog.Get(request.Role).ArtifactKey,
            request.Enrollment.Scope.Environment, Cell, cancellationToken).ConfigureAwait(false);
        if (target.Decision != RegionalHostSessionDecision.Accepted) return RegionalHostDesiredResponse.Deny(request, target.Decision);
        var current = await sessions.AuthorizeDesiredAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (!current.Authorized) return RegionalHostDesiredResponse.Deny(request, current.Decision);
        var expires = admitted.ExpiresAt < current.ExpiresAt ? admitted.ExpiresAt : current.ExpiresAt;
        return new(1, request.RequestId, request.RequestDigest, RegionalHostSessionDecision.Accepted,
            request.Enrollment.BootstrapGeneration, request.Epoch, expires, target.Digest, target.Revision);
    }
}
