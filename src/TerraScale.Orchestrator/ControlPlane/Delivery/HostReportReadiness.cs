namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>A serving report needs current admission for the same artifact and process lease.</summary>
internal static class HostReportReadiness
{
    internal static async Task<DateTimeOffset?> ConfirmAdmissionAsync(IAuthorizedHostReportReader reader,
        AuthorizedHostReport runtime, TimeProvider clock, CancellationToken cancellationToken)
    {
        if (runtime.Runtime is not { } observation) return null;
        // Read admission last so an already committed withdrawal supersedes runtime readiness.
        var admission = await reader.ReadAsync(HostAdmissionObservation.Key(observation.Instance, observation.ArtifactKey),
            cancellationToken).ConfigureAwait(false);
        var now = clock.GetUtcNow();
        if (admission?.Admission is not { SchemaVersion: HostAdmissionObservation.CurrentSchemaVersion, Ready: true } accepted ||
            admission.Session != runtime.Session || accepted.Cell != observation.Cell || accepted.Instance != observation.Instance ||
            accepted.ArtifactKey != observation.ArtifactKey || accepted.Digest != observation.Digest ||
            accepted.ObservedAt > now || accepted.ObservedAt < now.AddMinutes(-10) ||
            admission.ExpiresAt <= now || runtime.ExpiresAt <= now) return null;
        return admission.ExpiresAt < runtime.ExpiresAt ? admission.ExpiresAt : runtime.ExpiresAt;
    }
}
