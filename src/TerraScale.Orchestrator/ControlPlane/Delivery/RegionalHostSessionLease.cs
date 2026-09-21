using System.Security.Cryptography;
using System.Text.Json;
using NATS.Client.Core;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal interface IHostExecutionLease : IHostAdmissionGate
{
    CancellationToken ExecutionToken { get; }
}

internal sealed record HostSessionLeaseSnapshot(string State, string? Need, ulong Generation, ulong Epoch,
    DateTimeOffset ExpiresAt, DateTimeOffset ExecuteUntil, long Renewals, long FailedRenewals);

/// <summary>
/// Renews independently of workload/desired-state progress. Losing this local execution
/// window is terminal: cancellation requests workload shutdown, never proves writer fencing.
/// </summary>
internal sealed class RegionalHostSessionLease : IHostExecutionLease, IAsyncDisposable
{
    internal static readonly TimeSpan ShutdownReserve = TimeSpan.FromSeconds(5);
    // The authority can be ahead of the host by almost MaximumAge when it accepts a request.
    // Reserve that skew, cleanup time, and scheduling slack before allowing a new owner.
    internal static readonly TimeSpan ExecutionLifetime = RegionalHostSessionAuthority.LeaseLifetime -
        RegionalHostSessionRequest.MaximumAge - ShutdownReserve - TimeSpan.FromSeconds(1);
    private static readonly TimeSpan RenewalInterval = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(5);
    private readonly object gate = new();
    private readonly IRegionalHostSessionClient client;
    private readonly NatsAuthenticationFiles authentication;
    private readonly Func<CancellationToken, ValueTask<bool>> materialReady;
    private readonly TimeProvider clock;
    private readonly CancellationTokenSource execution = new();
    private readonly CancellationTokenSource stopping = new();
    private readonly ITimer watchdog;
    private readonly CancellationTokenRegistration shutdown;
    private readonly Task renewal;
    private readonly TaskCompletionSource<HostSessionLeaseSnapshot> ended = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private AcceptedSession current;
    private HostSessionLeaseSnapshot snapshot;
    private DateTimeOffset lastUtc;
    private bool terminal;
    private Task cancellation = Task.CompletedTask;
    private Task? disposal;

    private RegionalHostSessionLease(IRegionalHostSessionClient client, NatsAuthenticationFiles authentication,
        Func<CancellationToken, ValueTask<bool>> materialReady, TimeProvider clock,
        AcceptedSession current, CancellationToken cancellationToken)
    {
        this.client = client;
        this.authentication = authentication;
        this.materialReady = materialReady;
        this.clock = clock;
        this.current = current;
        lastUtc = clock.GetUtcNow();
        snapshot = new("active", null, current.Lease.Generation, current.Lease.Epoch,
            current.Lease.ExpiresAt!.Value, current.Request.IssuedAt + ExecutionLifetime, 0, 0);
        ExecutionToken = execution.Token;
        watchdog = clock.CreateTimer(static state => ((RegionalHostSessionLease)state!).CheckActive(), this,
            TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(100));
        shutdown = cancellationToken.UnsafeRegister(static state => ((RegionalHostSessionLease)state!).Lose("shutdown", stopped: true), this);
        renewal = RenewAsync();
    }

    public CancellationToken ExecutionToken { get; }
    internal Task<HostSessionLeaseSnapshot> Completion => ended.Task;
    internal HostSessionLeaseSnapshot Snapshot { get { CheckActive(); lock (gate) return snapshot; } }

    internal static async Task<RegionalHostSessionLease> StartAsync(IRegionalHostSessionClient client,
        RegionalNodeEnrollmentEnvelope enrollment, NatsAuthenticationFiles authentication,
        Func<CancellationToken, ValueTask<bool>> materialReady, CancellationToken cancellationToken, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(enrollment);
        ArgumentNullException.ThrowIfNull(authentication);
        ArgumentNullException.ThrowIfNull(materialReady);
        var time = clock ?? TimeProvider.System;
        using var startup = new CancellationTokenSource(TimeSpan.FromSeconds(8), time);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(startup.Token, cancellationToken);
        try
        {
            if (!await materialReady(deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false))
                throw new InvalidOperationException("The host credential material is not ready.");
            var stamp = time.GetTimestamp();
            var request = RegionalHostSessionRequest.Sign(enrollment, authentication, RegionalHostSessionOperation.Acquire,
                Guid.NewGuid().ToString("N"), 0, time.GetUtcNow());
            while (true)
            {
                deadline.Token.ThrowIfCancellationRequested();
                RegionalHostSessionResponse? response = null;
                try { response = await SendAsync(client, request, time, deadline.Token).ConfigureAwait(false); }
                catch (Exception exception) when (Transient(exception) && !deadline.IsCancellationRequested) { }
                if (response is not null)
                {
                    response.RequireBinding(request);
                    if (response.Accepted)
                    {
                        deadline.Token.ThrowIfCancellationRequested();
                        RequireWindow(time, request, stamp);
                        var accepted = new AcceptedSession(request, response,
                            new(request, response, authentication, time), stamp);
                        cancellationToken.ThrowIfCancellationRequested();
                        return new(client, authentication, materialReady, time, accepted, cancellationToken);
                    }
                    if (!Unavailable(response.Decision))
                        throw new InvalidOperationException($"Regional host admission was denied: {response.Decision}.");
                }
                await Task.Delay(RetryInterval, time, deadline.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        { throw new TimeoutException("Regional host admission did not complete before its startup deadline.", exception); }
    }

    public ValueTask<HostAdmissionSnapshot> ObserveAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            CheckActiveLocked();
            return ValueTask.FromResult(new HostAdmissionSnapshot(!terminal, !terminal, snapshot.Need ?? "authorized"));
        }
    }

    internal RegionalHostReportSigner GetReportSigner()
    {
        lock (gate)
        {
            CheckActiveLocked();
            if (terminal) throw new InvalidOperationException("The host execution lease is no longer active.");
            return current.Signer;
        }
    }

    private void CheckActive() { lock (gate) CheckActiveLocked(); }

    private void CheckActiveLocked()
    {
        if (terminal) return;
        var now = clock.GetUtcNow();
        if (now < lastUtc) { LoseLocked("clock-moved-backward"); return; }
        lastUtc = now;
        if (now >= snapshot.ExecuteUntil || clock.GetElapsedTime(current.Stamp) >= ExecutionLifetime)
            LoseLocked("execution-window-expired");
    }

    private async Task RenewAsync()
    {
        try
        {
            while (!stopping.IsCancellationRequested)
            {
                await Task.Delay(RenewalInterval, clock, stopping.Token).ConfigureAwait(false);
                RegionalHostSessionRequest? pending = null;
                long stamp = 0;
                while (!stopping.IsCancellationRequested)
                {
                    CheckActive();
                    stopping.Token.ThrowIfCancellationRequested();
                    using var materialDeadline = new CancellationTokenSource(RequestTimeout, clock);
                    using var materialCancellation = CancellationTokenSource.CreateLinkedTokenSource(stopping.Token, materialDeadline.Token);
                    try
                    {
                        if (!await materialReady(materialCancellation.Token).AsTask().WaitAsync(materialCancellation.Token).ConfigureAwait(false))
                        { Lose("credential-material-not-ready"); return; }
                        lock (gate)
                        {
                            CheckActiveLocked();
                            if (terminal) return;
                        }
                        // Signing reloads protected files. Never hold the watchdog's lock
                        // across file I/O; a stalled read must not extend execution.
                        if (pending is null || clock.GetUtcNow() - pending.IssuedAt >= RegionalHostSessionRequest.MaximumAge - RetryInterval)
                        {
                            stamp = clock.GetTimestamp();
                            pending = RegionalHostSessionRequest.Sign(current.Request.Enrollment, authentication,
                                RegionalHostSessionOperation.Renew, current.Request.SessionId, current.Lease.Epoch, clock.GetUtcNow());
                        }
                        lock (gate)
                        {
                            CheckActiveLocked();
                            if (terminal) return;
                            snapshot = snapshot with { State = "renewing" };
                        }
                        var response = await SendAsync(client, pending, clock, stopping.Token).ConfigureAwait(false);
                        response.RequireBinding(pending);
                        if (response.Accepted)
                        {
                            lock (gate)
                            {
                                CheckActiveLocked();
                                if (terminal) return; // A late reply can never revive expired execution.
                                RequireWindow(clock, pending, stamp);
                                current = new(pending, response, new(pending, response, authentication, clock), stamp);
                                snapshot = snapshot with { State = "active", Need = null, ExpiresAt = response.ExpiresAt!.Value,
                                    ExecuteUntil = pending.IssuedAt + ExecutionLifetime, Renewals = snapshot.Renewals + 1 };
                            }
                            break;
                        }
                        if (!Unavailable(response.Decision)) { Lose("session-" + response.Decision.ToString().ToLowerInvariant()); return; }
                        RetryNeeded();
                    }
                    catch (OperationCanceledException) when (stopping.IsCancellationRequested) { return; }
                    catch (Exception exception) when (Transient(exception)) { RetryNeeded(); }
                    catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or InvalidDataException or JsonException or CryptographicException)
                    { Lose("session-material-or-response-invalid"); return; }
                    await Task.Delay(RetryInterval, clock, stopping.Token).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
        catch (Exception) { Lose("renewal-failed"); }
    }

    private void RetryNeeded()
    {
        lock (gate)
        {
            CheckActiveLocked();
            if (!terminal) snapshot = snapshot with { State = "retrying", Need = "renewal-unavailable", FailedRenewals = snapshot.FailedRenewals + 1 };
        }
    }

    private void Lose(string need, bool stopped = false) { lock (gate) LoseLocked(need, stopped); }

    private void LoseLocked(string need, bool stopped = false)
    {
        if (terminal) return;
        terminal = true;
        snapshot = snapshot with { State = stopped ? "stopped" : "lost", Need = need };
        // CancelAsync marks tokens synchronously, while arbitrary consumer callbacks run outside this lock.
        cancellation = Task.WhenAll(execution.CancelAsync(), stopping.CancelAsync());
        ended.TrySetResult(snapshot);
    }

    private static void RequireWindow(TimeProvider clock, RegionalHostSessionRequest request, long stamp)
    {
        var now = clock.GetUtcNow();
        if (now < request.IssuedAt || now >= request.IssuedAt + ExecutionLifetime ||
            clock.GetElapsedTime(stamp) >= ExecutionLifetime)
            throw new InvalidOperationException("The acknowledged host lease has no safe local execution window.");
    }

    private static async Task<RegionalHostSessionResponse> SendAsync(IRegionalHostSessionClient client,
        RegionalHostSessionRequest request, TimeProvider clock, CancellationToken cancellationToken)
    {
        using var timeout = new CancellationTokenSource(RequestTimeout, clock);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        var response = await client.SendAsync(request, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
        deadline.Token.ThrowIfCancellationRequested();
        return response;
    }

    private static bool Unavailable(RegionalHostSessionDecision decision) =>
        decision is RegionalHostSessionDecision.StoreUnavailable or RegionalHostSessionDecision.InvalidStore or RegionalHostSessionDecision.Contention;

    private static bool Transient(Exception exception) =>
        exception is NatsException or TimeoutException or OperationCanceledException or IOException;

    public ValueTask DisposeAsync() { lock (gate) return new(disposal ??= DisposeCoreAsync()); }

    private async Task DisposeCoreAsync()
    {
        Lose("shutdown", stopped: true);
        await watchdog.DisposeAsync().ConfigureAwait(false);
        await shutdown.DisposeAsync().ConfigureAwait(false);
        try { await renewal.ConfigureAwait(false); await cancellation.ConfigureAwait(false); }
        finally { execution.Dispose(); stopping.Dispose(); }
    }

    private sealed record AcceptedSession(RegionalHostSessionRequest Request, RegionalHostSessionResponse Lease,
        RegionalHostReportSigner Signer, long Stamp);
}
