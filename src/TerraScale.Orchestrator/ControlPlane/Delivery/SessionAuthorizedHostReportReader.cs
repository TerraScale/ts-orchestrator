using System.Text;
using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>The proof and exact observation are one atomic stored value, never separate keys.</summary>
internal sealed record StoredHostReport(int SchemaVersion, RegionalHostReportProof Proof,
    HostAdmissionObservation? Admission, HostConvergenceObservation? Runtime)
{
    internal const int MaximumBytes = 32_768;

    internal string Key => Admission is { } admission
        ? HostAdmissionObservation.Key(admission.Instance, admission.ArtifactKey)
        : $"host.{Runtime!.Instance}.{Runtime.ArtifactKey}";
}

internal sealed record HostReportSession(string EnrollmentDigest, ulong Generation, string Process, ulong Epoch);

internal sealed record AuthorizedHostReport(HostAdmissionObservation? Admission, HostConvergenceObservation? Runtime,
    HostReportSession Session, DateTimeOffset ExpiresAt);

internal interface IAuthorizedHostReportReader
{
    Task<AuthorizedHostReport?> ReadAsync(string key, CancellationToken cancellationToken);
}

/// <summary>
/// Readiness requires both the current report and the current authorized process. Successful
/// CAS barriers reject stale replica reads without changing report bytes or renewing a lease.
/// A result is an observation at those barriers, not a physical writer fence or revocation cache.
/// </summary>
internal sealed class SessionAuthorizedHostReportReader(INatsKVStore runtime,
    RegionalHostSessionAuthority authority, TimeProvider? clock = null) : IAuthorizedHostReportReader
{
    private readonly TimeProvider time = clock ?? TimeProvider.System;

    public async Task<AuthorizedHostReport?> ReadAsync(string key, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        try { return await ReadCoreAsync(key, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
    }

    private async Task<AuthorizedHostReport?> ReadCoreAsync(string key, CancellationToken cancellationToken)
    {
        try
        {
            for (var attempt = 0; attempt < 8; attempt++)
            {
                var entry = await runtime.GetEntryAsync<string>(key, cancellationToken: cancellationToken).ConfigureAwait(false);
                entry.EnsureSuccess();
                if (entry.Value is not { Length: > 0 and <= StoredHostReport.MaximumBytes } json ||
                    Encoding.UTF8.GetByteCount(json) > StoredHostReport.MaximumBytes) return null;
                var stored = JsonSerializer.Deserialize<StoredHostReport>(json, RegionalHostSessionAuthority.JsonOptions);
                if (stored is not { SchemaVersion: 1, Proof: not null } ||
                    (stored.Admission is null) == (stored.Runtime is null) || stored.Key != key) return null;
                var node = stored.Admission?.Instance ?? stored.Runtime!.Instance;
                if (node is null || node.Split('.')[0] is "admission" or "backoff" or "replace") return null;
                var authorization = stored.Admission is { } admission
                    ? await authority.AuthorizeAdmissionReportAsync(stored.Proof, admission, cancellationToken).ConfigureAwait(false)
                    : await authority.AuthorizeRuntimeReportAsync(stored.Proof, stored.Runtime!, cancellationToken).ConfigureAwait(false);
                if (!authorization.Authorized || authorization.ExpiresAt is not { } expiresAt) return null;
                try
                {
                    // Even an unchanged latest-report retry must reject a stale pre-withdrawal read.
                    await runtime.UpdateAsync(key, json, entry.Revision, cancellationToken: cancellationToken).ConfigureAwait(false);
                    if (expiresAt <= time.GetUtcNow()) return null;
                    var proof = stored.Proof;
                    return new(stored.Admission, stored.Runtime,
                        new(proof.Enrollment.Digest, proof.Enrollment.BootstrapGeneration, proof.SessionId, proof.Epoch), expiresAt);
                }
                catch (NatsKVWrongLastRevisionException) { }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is NatsException or JsonException or InvalidOperationException or
            ArgumentException or IOException or TimeoutException) { }
        return null;
    }
}
