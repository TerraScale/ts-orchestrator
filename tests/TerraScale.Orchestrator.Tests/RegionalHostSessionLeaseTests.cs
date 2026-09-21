using System.Collections.Concurrent;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalHostSessionLeaseTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Successful_renewals_never_extend_the_initial_material_deadline_even_when_UTC_freezes(bool frozenUtc)
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        var evidence = new HostExecutionMaterial(clock.GetUtcNow() + RegionalHostSessionLease.ExecutionReserve + TimeSpan.FromSeconds(10));
        await using var lease = await StartAsync(material, clock, new Client(), _ => ValueTask.FromResult<HostExecutionMaterial?>(evidence));
        await Assert.That(lease.Snapshot.MaterialExpiresAt).IsEqualTo(evidence.ExpiresAt);
        await Assert.That(lease.Snapshot.ExecuteUntil).IsEqualTo(evidence.ExpiresAt - RegionalHostSessionLease.ExecutionReserve);
        for (var renewal = 1; renewal <= 3; renewal++)
        {
            clock.Advance(TimeSpan.FromSeconds(3), advanceUtc: !frozenUtc);
            await UntilAsync(() => lease.Snapshot.Renewals == renewal);
            await Assert.That(lease.ExecutionToken.IsCancellationRequested).IsFalse();
        }
        clock.Advance(TimeSpan.FromSeconds(1), advanceUtc: !frozenUtc);
        var lost = await lease.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(lost.Need).IsEqualTo("credential-material-expired");
        await Assert.That(lost.Renewals).IsEqualTo(3);
        await Assert.That(lease.ExecutionToken.IsCancellationRequested).IsTrue();
    }

    [Test]
    [Arguments("missing")]
    [Arguments("expired")]
    [Arguments("reserve")]
    [Arguments("non-utc")]
    public async Task Invalid_initial_material_never_sends_an_acquisition(string invalid)
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        HostExecutionMaterial? evidence = invalid switch
        {
            "missing" => null,
            "expired" => new(clock.GetUtcNow().AddSeconds(-1)),
            "reserve" => new(clock.GetUtcNow() + RegionalHostSessionLease.ExecutionReserve),
            "non-utc" => new(clock.GetUtcNow().AddHours(1).ToOffset(TimeSpan.FromHours(1))),
            _ => throw new ArgumentOutOfRangeException(nameof(invalid))
        };
        var client = new Client();
        await Assert.That(async () => { _ = await StartAsync(material, clock, client, _ => ValueTask.FromResult(evidence)); })
            .Throws<InvalidOperationException>();
        await Assert.That(client.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Changed_or_non_UTC_material_is_rejected_before_a_renewal_request(bool nonUtc)
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        var evidence = new HostExecutionMaterial(clock.GetUtcNow().AddHours(1));
        var client = new Client();
        await using var lease = await StartAsync(material, clock, client, _ => ValueTask.FromResult<HostExecutionMaterial?>(evidence));
        evidence = new(nonUtc ? evidence.ExpiresAt.ToOffset(TimeSpan.FromHours(1)) : evidence.ExpiresAt.AddHours(1));
        clock.Advance(TimeSpan.FromSeconds(3));
        var lost = await lease.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(lost.Need).IsEqualTo(nonUtc ? "session-material-or-response-invalid" : "credential-material-changed");
        await Assert.That(client.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("probe")]
    [Arguments("client")]
    public async Task Synchronous_startup_blocks_cannot_hold_cancellation_hostage(string blocked)
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var caller = new CancellationTokenSource();
        var client = new Client { Acquisition = request =>
        {
            if (blocked == "client") Block();
            return Task.FromResult(Accept(request));
        } };
        try
        {
            var starting = StartAsync(material, clock, client, _ =>
            {
                if (blocked == "probe") Block();
                return ValueTask.FromResult<HostExecutionMaterial?>(new(clock.GetUtcNow().AddHours(1)));
            }, caller.Token);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            await caller.CancelAsync();
            await Assert.That(async () => { _ = await starting.WaitAsync(TimeSpan.FromSeconds(2)); }).Throws<OperationCanceledException>();
            await Assert.That(client.Requests.Count).IsEqualTo(blocked == "probe" ? 0 : 1);
        }
        finally
        {
            release.Set();
            if (entered.Task.IsCompleted) await exited.Task.WaitAsync(TimeSpan.FromSeconds(2));
        }
        void Block() { entered.TrySetResult(); release.Wait(); exited.TrySetResult(); }
    }

    [Test]
    public async Task A_synchronous_renewal_probe_cannot_outlive_known_material_or_block_disposal()
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        var evidence = new HostExecutionMaterial(clock.GetUtcNow() + RegionalHostSessionLease.ExecutionReserve + TimeSpan.FromSeconds(4));
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        await using var lease = await StartAsync(material, clock, new Client(), _ =>
        {
            if (Interlocked.Increment(ref calls) > 1)
            {
                entered.TrySetResult();
                release.Wait();
                exited.TrySetResult();
            }
            return ValueTask.FromResult<HostExecutionMaterial?>(evidence);
        });
        try
        {
            clock.Advance(TimeSpan.FromSeconds(3));
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            clock.Advance(TimeSpan.FromSeconds(1));
            var lost = await lease.Completion.WaitAsync(TimeSpan.FromSeconds(2));
            await Assert.That(lost.Need).IsEqualTo("credential-material-expired");
            await lease.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(2));
            await Assert.That(lease.ExecutionToken.IsCancellationRequested).IsTrue();
        }
        finally
        {
            release.Set();
            if (entered.Task.IsCompleted) await exited.Task.WaitAsync(TimeSpan.FromSeconds(2));
        }
    }

    [Test]
    public async Task Renewal_replaces_the_signer_without_changing_session_epoch_or_replaying_bootstrap()
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        var client = new Client();
        await using var lease = await StartAsync(material, clock, client);
        var initial = lease.Snapshot;
        var signer = lease.GetReportSigner();
        for (var renewal = 1; renewal <= 5; renewal++)
        {
            clock.Advance(TimeSpan.FromSeconds(3));
            await UntilAsync(() => lease.Snapshot.Renewals == renewal);
            await Assert.That(lease.ExecutionToken.IsCancellationRequested).IsFalse();
            await Assert.That((await lease.ObserveAsync(CancellationToken.None)).Ready).IsTrue();
        }
        await Assert.That(lease.Snapshot.ExecuteUntil).IsGreaterThan(initial.ExpiresAt - RegionalHostSessionLease.ShutdownReserve);
        await Assert.That(ReferenceEquals(signer, lease.GetReportSigner())).IsFalse();
        var requests = client.Requests.ToArray();
        await Assert.That(requests.Count(value => value.Operation == RegionalHostSessionOperation.Acquire)).IsEqualTo(1);
        await Assert.That(requests.Select(value => value.SessionId).Distinct().Count()).IsEqualTo(1);
        await Assert.That(requests.Select(value => value.EnrollmentDigest).Distinct().Count()).IsEqualTo(1);
        await Assert.That(requests.Skip(1).All(value => value.Operation == RegionalHostSessionOperation.Renew && value.Epoch == 1)).IsTrue();
    }

    [Test]
    public async Task A_withheld_renewal_cannot_extend_execution_and_a_late_success_cannot_revive_it()
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        var response = new TaskCompletionSource<RegionalHostSessionResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new Client { Renewal = _ => response.Task };
        await using var lease = await StartAsync(material, clock, client);
        var end = lease.Snapshot.ExecuteUntil;
        clock.Advance(TimeSpan.FromSeconds(3));
        await UntilAsync(() => client.Requests.Count == 2);
        clock.Advance(TimeSpan.FromSeconds(5));
        await UntilAsync(() => lease.Snapshot.FailedRenewals == 1);
        await Assert.That(lease.Snapshot.State).IsEqualTo("retrying");
        await Assert.That(lease.Snapshot.ExecuteUntil).IsEqualTo(end);
        await Assert.That(lease.ExecutionToken.IsCancellationRequested).IsFalse();
        clock.Advance(RegionalHostSessionLease.ExecutionLifetime - TimeSpan.FromSeconds(8));
        var lost = await lease.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(lost.Need).IsEqualTo("execution-window-expired");
        await Assert.That(lease.ExecutionToken.IsCancellationRequested).IsTrue();
        response.SetResult(Accept(client.Requests.Last()));
        await lease.DisposeAsync();
        await Assert.That(lease.Snapshot.Renewals).IsEqualTo(0);
        await Assert.That((await lease.ObserveAsync(CancellationToken.None)).Ready).IsFalse();
        await Assert.That(() => lease.GetReportSigner()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Lost_acquisition_ack_retries_the_exact_request_and_does_not_gain_a_new_expiry()
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        var calls = 0;
        var client = new Client { Acquisition = request => ++calls == 1
            ? Task.FromException<RegionalHostSessionResponse>(new TimeoutException("Injected lost acknowledgement."))
            : Task.FromResult(Accept(request)) };
        var starting = StartAsync(material, clock, client);
        await UntilAsync(() => client.Requests.Count == 1 && clock.PendingOneSecondDelay);
        clock.Advance(TimeSpan.FromSeconds(1));
        await using var lease = await starting.WaitAsync(TimeSpan.FromSeconds(2));
        var requests = client.Requests.ToArray();
        await Assert.That(requests[0].RequestId).IsEqualTo(requests[1].RequestId);
        await Assert.That(requests[0].RequestDigest).IsEqualTo(requests[1].RequestDigest);
        await Assert.That(lease.Snapshot.ExpiresAt).IsEqualTo(requests[0].IssuedAt + RegionalHostSessionAuthority.LeaseLifetime);
        await Assert.That(lease.Snapshot.ExecuteUntil).IsEqualTo(requests[0].IssuedAt + RegionalHostSessionLease.ExecutionLifetime);
    }

    [Test]
    [Arguments("backward")]
    [Arguments("forward")]
    [Arguments("frozen")]
    public async Task UTC_changes_cannot_extend_the_monotonic_execution_window(string change)
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        await using var lease = await StartAsync(material, clock, new Client());
        if (change == "backward") clock.ShiftUtc(TimeSpan.FromSeconds(-1));
        if (change == "forward") clock.ShiftUtc(RegionalHostSessionAuthority.LeaseLifetime);
        clock.Advance(change == "frozen" ? RegionalHostSessionLease.ExecutionLifetime : TimeSpan.FromMilliseconds(100), advanceUtc: false);
        await lease.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(lease.ExecutionToken.IsCancellationRequested).IsTrue();
        await Assert.That(lease.Snapshot.State).IsEqualTo("lost");
        await Assert.That(lease.Snapshot.Need).IsEqualTo(change == "backward" ? "clock-moved-backward" : "execution-window-expired");
    }

    [Test]
    public async Task Missing_material_cancels_execution_without_waiting_for_the_controller()
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        HostExecutionMaterial? ready = new(clock.GetUtcNow().AddHours(1));
        var client = new Client();
        await using var lease = await StartAsync(material, clock, client, _ => ValueTask.FromResult<HostExecutionMaterial?>(ready));
        ready = null;
        clock.Advance(TimeSpan.FromSeconds(3));
        var ended = await lease.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(ended.Need).IsEqualTo("credential-material-not-ready");
        await Assert.That(client.Requests.Count).IsEqualTo(1);
        await Assert.That(lease.ExecutionToken.IsCancellationRequested).IsTrue();
    }

    [Test]
    public async Task Replaced_private_key_is_detected_on_renewal_even_if_the_material_probe_says_ready()
    {
        using var material = new SessionMaterial();
        using var replacement = new NatsAuthenticationFilesTests.SeedFile();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        var client = new Client();
        await using var lease = await StartAsync(material, clock, client);
        File.Copy(replacement.Path, material.Authentication.NKeyFile!, overwrite: true);
        clock.Advance(TimeSpan.FromSeconds(3));
        var ended = await lease.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(ended.State).IsEqualTo("lost");
        await Assert.That(client.Requests.Count).IsEqualTo(1);
        await Assert.That(lease.ExecutionToken.IsCancellationRequested).IsTrue();
    }

    [Test]
    public async Task A_stalled_material_check_cannot_block_the_independent_watchdog()
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        var calls = 0;
        var withheld = new TaskCompletionSource<HostExecutionMaterial?>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var lease = await StartAsync(material, clock, new Client(), _ => ++calls == 1
            ? ValueTask.FromResult<HostExecutionMaterial?>(new(clock.GetUtcNow().AddHours(1))) : new(withheld.Task));
        clock.Advance(TimeSpan.FromSeconds(3));
        await UntilAsync(() => calls == 2);
        clock.Advance(RegionalHostSessionLease.ExecutionLifetime - TimeSpan.FromSeconds(3));
        await lease.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(lease.ExecutionToken.IsCancellationRequested).IsTrue();
        withheld.SetResult(new(clock.GetUtcNow().AddHours(1)));
        await lease.DisposeAsync();
        await Assert.That(lease.Snapshot.Renewals).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task A_rejected_or_wrongly_bound_renewal_is_terminal_and_never_acquires_again(bool invalidBinding)
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        var client = new Client { Renewal = request => Task.FromResult(invalidBinding
            ? Accept(request) with { Epoch = 2 }
            : Accept(request) with { Decision = RegionalHostSessionDecision.Revoked, Epoch = 0, ExpiresAt = null }) };
        await using var lease = await StartAsync(material, clock, client);
        clock.Advance(TimeSpan.FromSeconds(3));
        var ended = await lease.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(ended.State).IsEqualTo("lost");
        clock.Advance(TimeSpan.FromMinutes(1));
        await lease.DisposeAsync();
        await Assert.That(client.Requests.Count).IsEqualTo(2);
        await Assert.That(lease.Snapshot.Renewals).IsEqualTo(0);
    }

    [Test]
    public async Task Startup_deadline_and_caller_cancellation_do_not_accept_a_late_acquisition()
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        var withheld = new TaskCompletionSource<RegionalHostSessionResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new Client { Acquisition = _ => withheld.Task };
        var attempt = StartAsync(material, clock, client);
        await UntilAsync(() => client.Requests.Count == 1);
        clock.Advance(TimeSpan.FromSeconds(8));
        await Assert.That(async () => { _ = await attempt.WaitAsync(TimeSpan.FromSeconds(2)); }).Throws<TimeoutException>();
        using var caller = new CancellationTokenSource();
        attempt = StartAsync(material, clock, client, cancellationToken: caller.Token);
        await UntilAsync(() => client.Requests.Count == 2);
        caller.Cancel();
        await Assert.That(async () => { _ = await attempt.WaitAsync(TimeSpan.FromSeconds(2)); }).Throws<OperationCanceledException>();
        withheld.SetResult(Accept(client.Requests.First()));
    }

    [Test]
    public async Task An_already_completed_reply_cannot_bypass_the_startup_deadline()
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        var client = new Client { Acquisition = request =>
        {
            clock.Advance(TimeSpan.FromSeconds(8));
            return Task.FromResult(Accept(request));
        } };
        await Assert.That(async () => { _ = await StartAsync(material, clock, client); }).Throws<TimeoutException>();
        await Assert.That(client.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task Disposal_and_external_shutdown_cancel_execution_and_callbacks_can_read_status_without_deadlock()
    {
        using var material = new SessionMaterial();
        var clock = new LeaseTestClock(material.Clock.GetUtcNow());
        using var shutdown = new CancellationTokenSource();
        var lease = await StartAsync(material, clock, new Client(), cancellationToken: shutdown.Token);
        var observed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var callback = lease.ExecutionToken.Register(() => observed.SetResult(lease.Snapshot.State));
        shutdown.Cancel();
        await Assert.That(await observed.Task.WaitAsync(TimeSpan.FromSeconds(2))).IsEqualTo("stopped");
        await Task.WhenAll(lease.DisposeAsync().AsTask(), lease.DisposeAsync().AsTask()).WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.That(lease.ExecutionToken.IsCancellationRequested).IsTrue();
        await Assert.That((await lease.ObserveAsync(CancellationToken.None)).Ready).IsFalse();
    }

    [Test]
    [NotInParallel("NatsR3")]
    public async Task Real_restricted_host_renews_reports_and_loses_execution_after_authoritative_revocation()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var cluster = await NatsControlR3L0cFixture.StartAsync(deadline.Token);
        await cluster.ProvisionAsync(deadline.Token);
        await using var controller = await cluster.ConnectAsync(cluster.Controller, cancellationToken: deadline.Token);
        await using var host = await cluster.ConnectAsync(cluster.HostAgent, cancellationToken: deadline.Token);
        using var files = new HostCredentialMaterialFixture(authentication:
            NatsAuthenticationFiles.FromCredentialsFile(cluster.HostAgent.CredentialsFile, "host lease test"),
            tls: new(cluster.CaFile, cluster.HostAgent.CertificateFile, cluster.HostAgent.KeyFile),
            account: cluster.HostAgent.AccountPublicKey, node: "host-1");
        var material = files.Session;
        var credentials = files.Load();
        var stores = controller.CreateJetStreamContext().CreateKeyValueStoreContext();
        var authority = new RegionalHostSessionAuthority(await stores.GetStoreAsync("ORCH_NODE_ENROLLMENTS", deadline.Token), material.Policy());
        var runtime = await stores.GetStoreAsync("ORCH_RUNTIME", deadline.Token);
        await using var service = await RegionalHostSessionService.StartAsync(controller.Connection, authority, deadline.Token);
        await using var relay = await HostObservationRelay.StartAsync(controller.Connection, runtime, authority, deadline.Token);
        await using var lease = await RegionalHostSessionLease.StartAsync(new NatsRegionalHostSessionClient(host.Connection, "gru", "host-1"),
            credentials.Enrollment, files.Authentication, credentials.ObserveAsync, deadline.Token);
        await using var inventory = new HostInventoryFixture();
        using var native = new HostWorkloadLifetimeTests.ChildProcess();
        await using var workloads = new HostWorkloadLifetime(native, lease.ExecutionToken, inventory.Inventory, HostInventoryFixture.EmptyProbe);
        await workloads.ConvergeAsync(HostRuntimePlan.Create(AdmittedRole.TerraBaseMember, RuntimeDriver.NativeSystemd,
            HostConvergenceRuntime.AllocationIdFor("gru", "host-1", "terrabase-server"), new(new string('a', 64)), HostArchitecture.X64), deadline.Token);
        await Assert.That(native.Exited).IsFalse();
        var publisher = new NatsHostObservationPublisher(host.Connection, "gru", "host-1", lease.GetReportSigner);
        await UntilAsync(() => lease.Snapshot.Renewals >= 2, TimeSpan.FromSeconds(12));
        var report = new HostAdmissionObservation(1, "gru", "host-1", "production", "terrabase-server",
            "sha256:" + new string('a', 64), true, DateTimeOffset.UtcNow);
        await publisher.PublishAsync(report, deadline.Token);
        var reader = new SessionAuthorizedHostReportReader(runtime, authority);
        await Assert.That((await reader.ReadAsync(HostAdmissionObservation.Key("host-1", report.ArtifactKey), deadline.Token))?.Admission?.Ready).IsTrue();
        await Assert.That(await authority.RevokeAsync("host-1", 1, lease.Snapshot.Epoch, deadline.Token)).IsTrue();
        var lost = await lease.Completion.WaitAsync(TimeSpan.FromSeconds(8), deadline.Token);
        await Assert.That(lost.Need).IsEqualTo("session-revoked");
        await Assert.That(lease.ExecutionToken.IsCancellationRequested).IsTrue();
        await Assert.That((await workloads.Completion.WaitAsync(TimeSpan.FromSeconds(3), deadline.Token)).State).IsEqualTo("stopped");
        await Assert.That(native.Exited).IsTrue();
        await Assert.That(await reader.ReadAsync(HostAdmissionObservation.Key("host-1", report.ArtifactKey), deadline.Token)).IsNull();
        await Assert.That(() => publisher.PublishAsync(report, deadline.Token)).Throws<InvalidOperationException>();
        await Assert.That(service.Snapshot.Renewed).IsGreaterThanOrEqualTo(2L);
    }

    private static Task<RegionalHostSessionLease> StartAsync(SessionMaterial material, LeaseTestClock clock, Client client,
        Func<CancellationToken, ValueTask<HostExecutionMaterial?>>? materialReady = null, CancellationToken cancellationToken = default)
    {
        var evidence = new HostExecutionMaterial(clock.GetUtcNow().AddHours(1));
        return RegionalHostSessionLease.StartAsync(client, material.Enroll(1), material.Authentication,
            materialReady ?? (_ => ValueTask.FromResult<HostExecutionMaterial?>(evidence)), cancellationToken, clock);
    }

    private static RegionalHostSessionResponse Accept(RegionalHostSessionRequest request) =>
        new(2, request.RequestId, request.RequestDigest, RegionalHostSessionDecision.Accepted,
            request.Enrollment.BootstrapGeneration, request.Epoch == 0 ? 1 : request.Epoch,
            request.IssuedAt + RegionalHostSessionAuthority.LeaseLifetime);

    private static async Task UntilAsync(Func<bool> condition, TimeSpan? timeout = null)
    {
        using var deadline = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(2));
        while (!condition()) await Task.Delay(5, deadline.Token);
    }

    private sealed class Client : IRegionalHostSessionClient
    {
        internal ConcurrentQueue<RegionalHostSessionRequest> Requests { get; } = new();
        internal Func<RegionalHostSessionRequest, Task<RegionalHostSessionResponse>>? Acquisition { get; init; }
        internal Func<RegionalHostSessionRequest, Task<RegionalHostSessionResponse>>? Renewal { get; init; }
        public Task<RegionalHostSessionResponse> SendAsync(RegionalHostSessionRequest request, CancellationToken cancellationToken)
        {
            Requests.Enqueue(request);
            return (request.Operation == RegionalHostSessionOperation.Acquire ? Acquisition : Renewal)?.Invoke(request) ?? Task.FromResult(Accept(request));
        }
    }
}
