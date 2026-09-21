using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using NATS.Client.Services;
using NATS.Net;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

// Each test owns three containerized NATS servers, three JetStream stores, and an
// ephemeral mTLS/JWT identity tree. Keep this lane serial with every R3 test.
[NotInParallel("NatsR3")]
public sealed class NatsControlR3L0cTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Regional_runtime_starts_with_JWT_mTLS_credentials_and_serves_operator_status(bool sessionsEnabled)
    {
        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var environment = new Dictionary<string, string>
        {
            ["TS_ORCH_CELL"] = "gru",
            ["TS_ORCH_INSTANCE"] = "controller-1",
            ["TS_ORCH_REPLICAS"] = "3",
            ["TS_ORCH_NATS_URL"] = $"tls://127.0.0.1:{fixture.ClientPorts[0]}",
            ["TS_ORCH_NATS_CREDENTIALS_FILE"] = fixture.Controller.CredentialsFile,
            ["TS_ORCH_NATS_TLS_CA_FILE"] = fixture.CaFile,
            ["TS_ORCH_NATS_TLS_CERT_FILE"] = fixture.Controller.CertificateFile,
            ["TS_ORCH_NATS_TLS_KEY_FILE"] = fixture.Controller.KeyFile,
        };
        using var commandKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var artifactKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var commandPath = Path.Combine(fixture.DirectoryPath, "command-trust.pem");
        var artifactPath = Path.Combine(fixture.DirectoryPath, "artifact-trust.pem");
        await File.WriteAllTextAsync(commandPath, commandKey.ExportSubjectPublicKeyInfoPem());
        await File.WriteAllTextAsync(artifactPath, artifactKey.ExportSubjectPublicKeyInfoPem());
        using var commands = EcdsaCommandSignatureVerifier.LoadPublicPem([commandPath]);
        using var artifacts = EcdsaCommandSignatureVerifier.LoadPublicPem([artifactPath]);
        var hostAuthentication = NatsAuthenticationFiles.FromCredentialsFile(fixture.HostAgent.CredentialsFile, "host-session test");
        using var sessionMaterial = new SessionMaterial(hostAuthentication, fixture.HostAgent.AccountPublicKey, "host-1", realTime: true);
        RegionalHostSessionConfiguration? sessions = null;
        if (sessionsEnabled)
        {
            var policyPath = Path.Combine(fixture.DirectoryPath, "host-session-policy.json");
            await File.WriteAllTextAsync(policyPath, sessionMaterial.ConfigurationJson());
            sessions = RegionalHostSessionConfiguration.Load(policyPath, "gru");
        }
        var options = OrchestratorOptions.Parse(["run"], environment.GetValueOrDefault);
        await using var runtime = await NatsRuntime.StartAsync(options, deadline.Token,
            commandSignatureVerifier: commands,
            admittedDeliveryTargets: DirectDeliveryAdmittedTargets.Parse(["authentication:development:gru"]),
            ciArtifactSignatures: artifacts, autoProvision: false, hostSessions: sessions);
        await using var reportWriter = await fixture.ConnectAsync(fixture.Controller, cancellationToken: deadline.Token);
        RegionalHostSessionAuthority? reportAuthority = null;
        ulong reportEpoch = 0;
        if (sessionsEnabled)
        {
            var acquisitions = new List<long>();
            using var listener = new MeterListener();
            listener.InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == Observability.OrchestratorTelemetry.InstrumentationName &&
                    instrument.Name == "terrascale.orchestrator.host.session.requests")
                    meterListener.EnableMeasurementEvents(instrument);
            };
            listener.SetMeasurementEventCallback<long>((_, count, tags, _) =>
            {
                foreach (var tag in tags)
                    if (tag.Key == "result" && Equals(tag.Value, "acquired")) acquisitions.Add(count);
            });
            listener.Start();
            using var telemetry = Observability.OrchestratorTelemetry.Start(options, _ => null);
            runtime.AttachServiceTelemetry(telemetry);
            await using var host = await fixture.ConnectAsync(fixture.HostAgent, cancellationToken: deadline.Token);
            var client = new NatsRegionalHostSessionClient(host.Connection, "gru", "host-1");
            var request = sessionMaterial.Request(sessionMaterial.Enroll(1));
            var acquired = await client.SendAsync(request, deadline.Token);
            await Assert.That(acquired.Accepted).IsTrue();
            while (!acquisitions.Contains(1))
            {
                deadline.Token.ThrowIfCancellationRequested();
                acquisitions.Clear();
                listener.RecordObservableInstruments();
                if (!acquisitions.Contains(1)) await Task.Delay(10, deadline.Token);
            }
            var report = new HostConvergenceObservation(2, "gru", "host-1", "terrabase-server",
                "sha256:" + new string('a', 64), "converged", "member.service", DateTimeOffset.UtcNow, MemberUp: true);
            var signer = new RegionalHostSessionSigner(request, acquired, hostAuthentication);
            await new NatsHostObservationPublisher(host.Connection, "gru", "host-1", () => signer).PublishAsync(
                new HostAdmissionObservation(1, "gru", "host-1", "production", "terrabase-server", report.Digest, true, report.ObservedAt), deadline.Token);
            await new NatsHostObservationPublisher(host.Connection, "gru", "host-1", () => signer).PublishAsync(report, deadline.Token);
            var stores = reportWriter.CreateJetStreamContext().CreateKeyValueStoreContext();
            var desiredStore = await stores.GetStoreAsync("ORCH_DELIVERY", deadline.Token);
            await desiredStore.PutAsync(DirectDeliveryTargetKey.For("terrabase-server", "production", "gru"),
                JsonSerializer.Serialize(new { artifactDigest = report.Digest, manifestDigest = report.Digest, kind = "service" }),
                cancellationToken: deadline.Token);
            var desiredSource = new NatsHostDesiredArtifactSource(host.Connection, "gru", "host-1", () => signer);
            await Assert.That(await desiredSource.ReadAsync(Runtime.AdmittedRole.TerraBaseMember, "production", "gru", deadline.Token))
                .IsEqualTo(report.Digest);
            reportAuthority = new(await stores.GetStoreAsync("ORCH_NODE_ENROLLMENTS", deadline.Token), sessionMaterial.Policy());
            reportEpoch = acquired.Epoch;
        }
        await using var operatorClient = await fixture.ConnectAsync(fixture.Operator, cancellationToken: deadline.Token);
        var response = await operatorClient.RequestAsync<string, string>(fixture.Topology.OperatorStatusSubject,
            string.Empty, cancellationToken: deadline.Token);
        response.EnsureSuccess();
        await Assert.That(response.Data!.Contains("host-report-relay", StringComparison.Ordinal)).IsEqualTo(sessionsEnabled);
        await Assert.That(response.Data!.Contains("host-session-authority", StringComparison.Ordinal)).IsEqualTo(sessionsEnabled);
        await Assert.That(response.Data!.Contains("host-desired", StringComparison.Ordinal)).IsEqualTo(sessionsEnabled);
        var status = JsonSerializer.Deserialize(response.Data!, Operations.OperatorStatusJsonContext.Default.OperatorStatusDocument)!;
        await Assert.That(status.Workloads.Single(value => value.Workload == "terrabase-server").ObservedReplicas).IsEqualTo(sessionsEnabled ? 1 : 0);
        if (reportAuthority is not null)
        {
            await Assert.That(await reportAuthority.RevokeAsync("host-1", 1, reportEpoch, deadline.Token)).IsTrue();
            var revoked = await operatorClient.RequestAsync<string, string>(fixture.Topology.OperatorStatusSubject,
                string.Empty, cancellationToken: deadline.Token);
            revoked.EnsureSuccess();
            status = JsonSerializer.Deserialize(revoked.Data!, Operations.OperatorStatusJsonContext.Default.OperatorStatusDocument)!;
            await Assert.That(status.Workloads.Single(value => value.Workload == "terrabase-server").ObservedReplicas).IsEqualTo(0);
        }
        await Assert.That(runtime.Completion.IsCompleted).IsFalse();
        environment["TS_ORCH_NATS_CREDENTIALS_FILE"] = fixture.Operator.CredentialsFile;
        environment["TS_ORCH_NATS_TLS_CERT_FILE"] = fixture.Operator.CertificateFile;
        environment["TS_ORCH_NATS_TLS_KEY_FILE"] = fixture.Operator.KeyFile;
        var exitCode = await Operations.OperatorCli.ExecuteAsync(["operator-status"],
            environment.GetValueOrDefault, deadline.Token);
        await Assert.That(exitCode).IsEqualTo(0);

    }

    [Test]
    public async Task Host_report_relay_persists_under_controller_credentials_across_relay_restart()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var host = harness.First;
        var ready = new HostAdmissionObservation(1, "gru", host.Node, "production", host.Artifact,
            "sha256:" + new string('a', 64), true, harness.Material.Clock.GetUtcNow());
        var original = host.Signer.Sign(ready);
        await host.Publisher.PublishAsync(original, deadline.Token);
        await harness.StopRelayAsync();
        await using var second = await harness.Cluster.ConnectAsync(harness.Cluster.ControllerTwo, cancellationToken: deadline.Token);
        var stores = second.CreateJetStreamContext().CreateKeyValueStoreContext();
        var reports = await stores.GetStoreAsync("ORCH_RUNTIME", deadline.Token);
        var authority = new RegionalHostSessionAuthority(await stores.GetStoreAsync("ORCH_NODE_ENROLLMENTS", deadline.Token),
            harness.Material.Policy(), harness.Material.Clock);
        await using var replacement = await HostObservationRelay.StartAsync(second.Connection, reports, authority, deadline.Token);
        harness.Material.Clock.Advance(TimeSpan.FromSeconds(1));
        await host.Publisher.PublishAsync(ready with { Ready = false, ObservedAt = harness.Material.Clock.GetUtcNow() }, deadline.Token);
        await Assert.That(() => host.Publisher.PublishAsync(original, deadline.Token)).Throws<InvalidOperationException>();
        var current = await GetWithQuorumRetryAsync(reports, HostAdmissionObservation.Key(host.Node, host.Artifact));
        await Assert.That(JsonSerializer.Deserialize<StoredHostReport>(current.Value!, HostObservationRelay.JsonOptions)!.Admission!.Ready).IsFalse();
    }

    [Test]
    public async Task FixtureAccountJwtClaimsAreExactAndCrossAccountServiceSurvivesReconnect()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        var authority = NatsClaim(fixture.GlobalAuthorityAccountJwt);
        var directory = NatsClaim(fixture.GlobalDirectoryAccountJwt);
        var regional = NatsClaim(fixture.RegionalControlSfoAccountJwt);
        await Assert.That(fixture.GlobalAuthorityAccountPublicKey)
            .IsNotEqualTo(fixture.GlobalDirectoryAccountPublicKey);
        await Assert.That(fixture.GlobalDirectoryAccountPublicKey)
            .IsNotEqualTo(fixture.RegionalControlSfoAccountPublicKey);
        await Assert.That(fixture.Authority.AccountPublicKey)
            .IsEqualTo(fixture.GlobalAuthorityAccountPublicKey);
        await Assert.That(ReadUserIssuer(fixture.Authority))
            .IsEqualTo(fixture.GlobalAuthorityAccountPublicKey);

        var authorityNats = authority.GetProperty("nats");
        await Assert.That(authorityNats.GetProperty("exports").GetArrayLength()).IsEqualTo(0);
        await Assert.That(authorityNats.GetProperty("imports").GetArrayLength()).IsEqualTo(0);

        var exports = directory.GetProperty("nats").GetProperty("exports");
        await Assert.That(exports.GetArrayLength()).IsEqualTo(1);
        var serviceExport = exports[0];
        await Assert.That(serviceExport.EnumerateObject().Select(static property => property.Name))
            .IsEquivalentTo(["subject", "type", "response_type"]);
        await Assert.That(serviceExport.GetProperty("subject").GetString())
            .IsEqualTo(GlobalNatsTopology.CellDirectorySubject);
        await Assert.That(serviceExport.GetProperty("type").GetString()).IsEqualTo("service");
        await Assert.That(serviceExport.GetProperty("response_type").GetString()).IsEqualTo("Singleton");
        await Assert.That(directory.GetProperty("nats").GetProperty("imports").GetArrayLength())
            .IsEqualTo(0);

        var imports = regional.GetProperty("nats").GetProperty("imports");
        await Assert.That(imports.GetArrayLength()).IsEqualTo(1);
        var serviceImport = imports[0];
        await Assert.That(serviceImport.EnumerateObject().Select(static property => property.Name))
            .IsEquivalentTo(["account", "subject", "to", "type"]);
        await Assert.That(serviceImport.GetProperty("account").GetString())
            .IsEqualTo(fixture.GlobalDirectoryAccountPublicKey);
        await Assert.That(serviceImport.GetProperty("subject").GetString())
            .IsEqualTo(GlobalNatsTopology.CellDirectorySubject);
        await Assert.That(serviceImport.GetProperty("type").GetString()).IsEqualTo("service");
        await Assert.That(regional.GetProperty("nats").GetProperty("exports").GetArrayLength())
            .IsEqualTo(0);

        await using var serviceClient = await fixture.ConnectAsync(fixture.CellDirectoryService);
        await using var service = await serviceClient.CreateServicesContext().AddServiceAsync(
            new NatsSvcConfig("terrascale-global-cell-directory-gru", "1.0.0")
            {
                QueueGroup = "ts-orch-global-cell-directory"
            });
        await service.AddEndpointAsync<string>(
            message => message.ReplyAsync("directory-snapshot"),
            name: "cells",
            subject: GlobalNatsTopology.CellDirectorySubject);

        await using (var reader = await fixture.ConnectAsync(fixture.CellDirectoryReader))
        {
            var response = await reader.RequestAsync<string, string>(
                GlobalNatsTopology.CellDirectorySubject,
                string.Empty);
            response.EnsureSuccess();
            await Assert.That(response.Data).IsEqualTo("directory-snapshot");
        }

        await using var reconnectedReader = await fixture.ConnectAsync(fixture.CellDirectoryReader);
        await Assert.That(async () => _ = await reconnectedReader.RequestAsync<string, string>(
                "$KV.GLOBAL_CELLS.cell.sfo", "forbidden"))
            .Throws<NatsException>();
        await Assert.That(async () => _ = await reconnectedReader.RequestAsync<string, string>(
                GlobalNatsTopology.CiSubject, "forbidden"))
            .Throws<NatsException>();
        await Assert.That(async () => _ = await reconnectedReader.RequestAsync<string, string>(
                "$KV.ORCH_LEADERS.global", "forbidden"))
            .Throws<NatsException>();
    }

    [Test]
    public async Task ProductionDirectoryAndServiceR3RuntimePublishesSnapshotThroughRegionalImport()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionGlobalCellDirectoryAsync();

        var endpoint = $"tls://127.0.0.1:{fixture.ClientPorts[0]}";
        var directoryConfiguration = new GlobalDirectoryNatsConfiguration(
            endpoint,
            NatsAuthenticationFiles.FromCredentialsFile(
                fixture.CellDirectoryPublisher.CredentialsFile,
                "TEST_GLOBAL_DIRECTORY"),
            new(
                fixture.CaFile,
                fixture.CellDirectoryPublisher.CertificateFile,
                fixture.CellDirectoryPublisher.KeyFile),
            3,
            "sfo",
            ["tls://control-sfo.internal:4222"]);
        var serviceConfiguration = new GlobalDirectoryServiceNatsConfiguration(
            endpoint,
            NatsAuthenticationFiles.FromCredentialsFile(
                fixture.CellDirectoryService.CredentialsFile,
                "TEST_GLOBAL_DIRECTORY_SERVICE"),
            new(
                fixture.CaFile,
                fixture.CellDirectoryService.CertificateFile,
                fixture.CellDirectoryService.KeyFile),
            3,
            "gru");
        var membership = SfoMembershipSnapshot();
        var authority = new RegionalAuthoritySnapshot(
            "leader",
            true,
            1,
            1,
            DateTimeOffset.UtcNow.AddSeconds(15),
            DateTimeOffset.UtcNow,
            null);

        GlobalCellDirectoryRuntime? directory = null;
        GlobalCellDirectoryServiceRuntime? service = null;
        NatsClient? reader = null;
        try
        {
            var observedDirectory = directory = await GlobalCellDirectoryRuntime.StartAsync(
                directoryConfiguration,
                () => membership,
                () => authority,
                publishEnabled: true);
            var observedService = service = await GlobalCellDirectoryServiceRuntime.StartAsync(
                serviceConfiguration,
                () => observedDirectory.Snapshot);
            var observedReader = reader = await fixture.ConnectAsync(fixture.CellDirectoryReader);

            GlobalCellDirectorySnapshot? snapshot = null;
            for (var attempt = 0; attempt < 50; attempt++)
            {
                try
                {
                    var response = await observedReader.RequestAsync<string, string>(
                        GlobalNatsTopology.CellDirectorySubject,
                        "snapshot");
                    response.EnsureSuccess();
                    snapshot = JsonSerializer.Deserialize(
                        response.Data ?? throw new InvalidDataException("The directory service returned no snapshot."),
                        GlobalCellDirectoryJsonContext.Default.GlobalCellDirectorySnapshot);
                    if (snapshot is { ActiveCells: 1 } &&
                        snapshot.Cells is [{ Cell: "sfo", IsStale: false }])
                        break;
                }
                catch (NatsException) when (attempt < 49)
                {
                }

                await Task.Delay(TimeSpan.FromMilliseconds(100));
            }

            await Assert.That(snapshot).IsNotNull();
            snapshot!.Validate();
            await Assert.That(snapshot.Condition).IsEqualTo(GlobalCellDirectoryCondition.Healthy);
            await Assert.That(snapshot.ActiveCells).IsEqualTo(1);
            await Assert.That(snapshot.Cells[0].Cell).IsEqualTo("sfo");
            await Assert.That(snapshot.Cells[0].Cluster).IsEqualTo("orchestrator-control-sfo");
            await Assert.That(snapshot.Cells[0].IsStale).IsFalse();

            await observedService.DisposeAsync();
            service = null;
            await Assert.That(async () => _ = await observedReader.RequestAsync<string, string>(
                    GlobalNatsTopology.CellDirectorySubject,
                    "after-dispose"))
                .Throws<NatsException>();
        }
        finally
        {
            if (reader is not null)
                await reader.DisposeAsync();
            if (service is not null)
                await service.DisposeAsync();
            if (directory is not null)
                await directory.DisposeAsync();
        }

        await Assert.That(directory?.Completion.IsCompleted ?? true).IsTrue();
    }

    [Test]
    public async Task ProductionGlobalAuthorityR3RuntimeReconcilesItsTopologyAndCannotCrossAccountBoundaries()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionGlobalCellDirectoryAsync();

        var topology = new GlobalNatsTopology(3);
        var endpoint = $"tls://127.0.0.1:{fixture.ClientPorts[0]}";
        var configuration = new GlobalAuthorityNatsConfiguration(
            endpoint,
            NatsAuthenticationFiles.FromCredentialsFile(
                fixture.Authority.CredentialsFile,
                "TEST_GLOBAL_AUTHORITY"),
            new(
                fixture.CaFile,
                fixture.Authority.CertificateFile,
                fixture.Authority.KeyFile),
            3,
            "gru");

        await using var runtime = await GlobalNatsRuntime.StartAsync(
            configuration,
            "global-authority-1",
            "gru",
            ciRunnerNatsSigner: null,
            cancellationToken: CancellationToken.None,
            ciArtifactSignatures: new DenyingArtifactSignatureVerifier(),
            admittedDeliveryTargets: DirectDeliveryAdmittedTargets.Parse([
                "terrascale-dashboard:production:gru,sfo,fra",
            ]));
        await using var authority = await fixture.ConnectAsync(fixture.Authority);
        var jetStream = authority.CreateJetStreamContext();

        foreach (var expected in topology.Streams)
        {
            if (expected.Name is not { } streamName || expected.Subjects is not { } subjects)
                throw new InvalidOperationException("The expected control stream topology is incomplete.");
            var stream = await jetStream.GetStreamAsync(streamName);
            await stream.RefreshAsync();
            await Assert.That(stream.Info.Config.NumReplicas).IsEqualTo(3);
            await Assert.That(stream.Info.Config.Subjects).IsEquivalentTo(subjects);
        }

        var stores = jetStream.CreateKeyValueStoreContext();
        var releases = await stores.GetStoreAsync(topology.Releases.Bucket);
        var releaseRevision = await releases.CreateAsync("release.conformance", "accepted");
        // R3 direct reads may hit a follower before the acknowledged write arrives.
        // Retry only absence, then still require the exact acknowledged revision.
        var release = await GetWithQuorumRetryAsync(releases, "release.conformance");
        release.EnsureSuccess();
        await Assert.That(release.Revision).IsEqualTo(releaseRevision);

        var runnerJobs = await stores.GetStoreAsync(topology.RunnerJobs.Bucket);
        var jobRevision = await runnerJobs.CreateAsync("ci.runner.conformance.job.1", "accepted");
        var job = await GetWithQuorumRetryAsync(runnerJobs, "ci.runner.conformance.job.1");
        job.EnsureSuccess();
        await Assert.That(job.Revision).IsEqualTo(jobRevision);

        var objects = jetStream.CreateObjectStoreContext();
        foreach (var bucket in new[] { topology.Bundles.Bucket, topology.RunnerBundles.Bucket })
        {
            var store = await objects.GetObjectStoreAsync(bucket);
            _ = await store.PutAsync("conformance", new byte[] { 3, 5, 8 });
            await Assert.That(await store.GetBytesAsync("conformance"))
                .IsEquivalentTo(new byte[] { 3, 5, 8 });
        }

        foreach (var subject in new[]
                 {
                     "$JS.API.STREAM.INFO.KV_GLOBAL_CELLS",
                     "$KV.GLOBAL_CELLS.cell.gru",
                     "$JS.API.STREAM.INFO.KV_ORCH_RUNTIME",
                     "$KV.ORCH_RUNTIME.runtime.protected",
                     "$JS.API.STREAM.INFO.KV_ORCH_OPERATIONS",
                     "$KV.ORCH_OPERATIONS.operation.protected",
                     "$JS.API.STREAM.INFO.KV_ORCH_OPERATION_PROOFS",
                     "$KV.ORCH_OPERATION_PROOFS.proof.protected",
                     "$JS.API.STREAM.INFO.CELL_SPEC",
                     "$JS.API.STREAM.INFO.UNRELATED",
                 })
        {
            await Assert.That(async () => _ = await authority.RequestAsync<string, string>(subject, "{}"))
                .Throws<NatsException>();
        }
    }

    [Test]
    public async Task GlobalAuthorityRetentionEnumerationRunsUnderItsOwnEnforcedPermissions()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionGlobalCellDirectoryAsync();

        var topology = new GlobalNatsTopology(3);
        var endpoint = $"tls://127.0.0.1:{fixture.ClientPorts[0]}";
        var configuration = new GlobalAuthorityNatsConfiguration(
            endpoint,
            NatsAuthenticationFiles.FromCredentialsFile(
                fixture.Authority.CredentialsFile,
                "TEST_GLOBAL_AUTHORITY"),
            new(
                fixture.CaFile,
                fixture.Authority.CertificateFile,
                fixture.Authority.KeyFile),
            3,
            "gru");

        await using var runtime = await GlobalNatsRuntime.StartAsync(
            configuration,
            "global-authority-1",
            "gru",
            ciRunnerNatsSigner: null,
            cancellationToken: CancellationToken.None,
            ciArtifactSignatures: new DenyingArtifactSignatureVerifier(),
            admittedDeliveryTargets: DirectDeliveryAdmittedTargets.Parse([
                "terrascale-dashboard:production:gru,sfo,fra",
            ]));
        // Production-shaped request timeout (the runtime's own connections allow 15s):
        // consumer creation on an R3 stream needs a raft-quorum ack from all three
        // members, which the fixture's tight 3s probe timeout cannot absorb while the
        // runtime reconciles its topology on a loaded host.
        var authorityClient = new NatsClient(fixture.ClientOptions(fixture.Authority) with
        {
            RequestTimeout = TimeSpan.FromSeconds(15),
        });
        await using (authorityClient)
        {
            await authorityClient.ConnectAsync();
            var store = await authorityClient.CreateJetStreamContext().CreateKeyValueStoreContext()
                .GetStoreAsync(topology.Releases.Bucket);
            await RetentionUnderEnforcedPermissionsAsync(store);
        }
    }

    private static async Task RetentionUnderEnforcedPermissionsAsync(INatsKVStore store)
    {
        var ledger = new NatsForgejoDeliveryLedger(store);

        // Seed journal keys through the production ledger exactly as the journals do.
        foreach (var key in new[] { "r3retention.a", "r3retention.b", "r3retention.c", "r3retention.d" })
            _ = await ledger.CreateAsync(key, $"journal-{key}", CancellationToken.None);

        // Key enumeration (ListKeysAsync -> NatsKVStore.GetKeysAsync) is the live
        // retention/pruning surface. NATS.Net 2.7.2 implements it with one
        // $JS.API.CONSUMER.CREATE.KV_GLOBAL_RELEASES.<ephemeral>.$KV.GLOBAL_RELEASES.<filter>
        // publish and an _INBOX.<nuid>.* subscription: the enforced authority JWT —
        // whose plan grants only the consumer-create forms plus _INBOX.> and no
        // $KV.GLOBAL_RELEASES subscription — must admit exactly that and nothing more.
        // Like every production caller, the filter ends with the > wildcard: a
        // prefix without it makes the client's inline-filter consumer-create subject
        // end in an empty token, which the server denies as a permissions violation.
        var enumerated = new List<string>();
        await foreach (var key in ledger.ListKeysAsync("r3retention.>", CancellationToken.None))
            enumerated.Add(key);
        await Assert.That(enumerated.Order(StringComparer.Ordinal)).IsEquivalentTo(
            ["r3retention.a", "r3retention.b", "r3retention.c", "r3retention.d"]);

        // The production pruning call drives enumeration, reads revisions, and deletes
        // oldest-first down to the retention cap through the same enforced identity.
        await DeliveryJournalRetention.PruneAsync(
            ledger,
            "r3retention.",
            cap: 2,
            (entry, _, _) => Task.FromResult(new DeliveryJournalPruneDecision(Prunable: true)),
            "prunable test records",
            CancellationToken.None);

        var remaining = new List<string>();
        await foreach (var key in ledger.ListKeysAsync("r3retention.>", CancellationToken.None))
            remaining.Add(key);
        await Assert.That(remaining.Order(StringComparer.Ordinal))
            .IsEquivalentTo(["r3retention.c", "r3retention.d"]);
        foreach (var pruned in new[] { "r3retention.a", "r3retention.b" })
            await Assert.That(await ledger.GetAsync(pruned, CancellationToken.None)).IsNull();
    }

    [Test]
    public async Task CellDirectoryReaderCanOnlyCallTheAuthenticatedReadOnlyService()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await using var serviceClient = await fixture.ConnectAsync(fixture.CellDirectoryService);
        await using var reader = await fixture.ConnectAsync(fixture.CellDirectoryReader);
        await using var service = await serviceClient.CreateServicesContext().AddServiceAsync(
            new NatsSvcConfig("terrascale-global-cell-directory-gru", "1.0.0")
            {
                QueueGroup = "ts-orch-global-cell-directory"
            });
        await service.AddEndpointAsync<string>(
            message => message.ReplyAsync("directory-snapshot"),
            name: "cells",
            subject: GlobalNatsTopology.CellDirectorySubject);

        // The endpoint registration gossips across the three R3 members; the
        // first request can arrive before interest has converged, which surfaces
        // as no-responders. Retry the warm-up request, not the assertions below.
        for (var attempt = 0; attempt < 50; attempt++)
        {
            try
            {
                var warmup = await reader.RequestAsync<string, string>(
                    GlobalNatsTopology.CellDirectorySubject,
                    "warmup");
                warmup.EnsureSuccess();
                await Assert.That(warmup.Data).IsEqualTo("directory-snapshot");
                break;
            }
            catch (NatsException) when (attempt < 49)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100));
            }
        }

        var response = await reader.RequestAsync<string, string>(
            GlobalNatsTopology.CellDirectorySubject,
            string.Empty);
        response.EnsureSuccess();
        await Assert.That(response.Data).IsEqualTo("directory-snapshot");
        using (var stopTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
            await service.StopAsync(stopTimeout.Token);

        await Assert.That(async () => _ = await reader.RequestAsync<string, string>(
                "$KV.GLOBAL_CELLS.cell.sfo", "forbidden"))
            .Throws<NatsException>();
        await Assert.That(async () => _ = await reader.RequestAsync<string, string>(
                GlobalNatsTopology.CiSubject, "forbidden"))
            .Throws<NatsException>();
        await Assert.That(async () => _ = await reader.RequestAsync<string, string>(
                "$KV.ORCH_LEADERS.global", "forbidden"))
            .Throws<NatsException>();
        await Assert.That(async () => _ = await serviceClient.RequestAsync<string, string>(
                "$KV.GLOBAL_CELLS.cell.gru", "forbidden"))
            .Throws<NatsException>();
    }

    [Test]
    public async Task CellDirectoryPublisherJwtIsEnforcedByAuthenticatedR3Servers()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionGlobalCellDirectoryAsync();
        await using var publisher = await fixture.ConnectAsync(fixture.CellDirectoryPublisher);

        var store = await publisher.CreateJetStreamContext().CreateKeyValueStoreContext()
            .GetStoreAsync("GLOBAL_CELLS");
        await using var watcher = store.WatchAsync<string>("cell.>").GetAsyncEnumerator();
        var observed = watcher.MoveNextAsync().AsTask();
        var revision = await store.CreateAsync("cell.sfo", "sfo-advertisement");
        await Assert.That(await observed.WaitAsync(TimeSpan.FromSeconds(5))).IsTrue();
        await Assert.That(watcher.Current.Key).IsEqualTo("cell.sfo");
        await Assert.That(watcher.Current.Value).IsEqualTo("sfo-advertisement");
        var entry = await store.GetEntryAsync<string>("cell.sfo");
        entry.EnsureSuccess();
        await Assert.That(entry.Revision).IsEqualTo(revision);
        await Assert.That(entry.Value).IsEqualTo("sfo-advertisement");

        await Assert.That(async () => _ = await store.CreateAsync("cell.gru", "forbidden"))
            .Throws<NatsException>();
        await Assert.That(async () => _ = await publisher.RequestAsync<string, string>(
                "$KV.ORCH_LEADERS.global", "forbidden"))
            .Throws<NatsException>();
        await Assert.That(async () => _ = await publisher.RequestAsync<string, string>(
                GlobalNatsTopology.CiSubject, "forbidden"))
            .Throws<NatsException>();
    }

    [Test]
    public async Task ControllerNativeGitOpsPermissionsAreExactAndProtectedJournalsStayDenied()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionAsync();
        await using var controller = await fixture.ConnectAsync(fixture.Controller);
        var topology = fixture.Topology;
        var jetStream = controller.CreateJetStreamContext();
        var consumer = await jetStream.GetConsumerAsync("CELL_SPEC", topology.CellSpecConsumer.Name!);
        await consumer.RefreshAsync();
        var publish = await jetStream.PublishAsync<byte[]>(
            topology.CellSpecSubject,
            new byte[] { 1 },
            opts: new NatsJSPubOpts { ExpectedStream = "CELL_SPEC" });
        publish.EnsureSuccess();
        var delivery = await consumer.NextAsync<byte[]>(
            opts: new NatsJSNextOpts { Expires = TimeSpan.FromSeconds(1) });
        await Assert.That(delivery).IsNotNull();
        await delivery!.AckAsync(new AckOpts { DoubleAck = true });

        var deliveryStore = await jetStream.CreateKeyValueStoreContext().GetStoreAsync(topology.Delivery.Bucket);
        var revision = await deliveryStore.CreateAsync(
            "gitops.acl", "regional", cancellationToken: CancellationToken.None);
        var entry = await deliveryStore.GetEntryAsync<string>("gitops.acl");
        entry.EnsureSuccess();
        await Assert.That(entry.Revision).IsEqualTo(revision);
        await Assert.That(entry.Value).IsEqualTo("regional");

        var bundles = await jetStream.CreateObjectStoreContext().GetObjectStoreAsync(topology.Bundles.Bucket);
        _ = await bundles.PutAsync(
            "gitops-acl", new byte[] { 2, 3, 5 }, cancellationToken: CancellationToken.None);
        await Assert.That(await bundles.GetBytesAsync("gitops-acl")).IsEquivalentTo(new byte[] { 2, 3, 5 });

        foreach (var subject in new[]
                 {
                     "$JS.API.STREAM.CREATE.CELL_EVENTS",
                     "$JS.API.STREAM.UPDATE.KV_ORCH_RUNTIME",
                     "$O.ORCH_PROTOCOL_PACKAGE.M.tampered",
                     "$JS.API.CONSUMER.INFO.CELL_SPEC.gitops_cell_spec_controller-2",
                     "ts.orch.v2.fra.desired.cross-region",
                     "$JS.API.DIRECT.GET.KV_ORCH_OPERATIONS",
                     "$JS.API.STREAM.MSG.GET.KV_ORCH_OPERATIONS",
                     "$JS.API.CONSUMER.DURABLE.CREATE.KV_ORCH_OPERATIONS.exfiltration",
                     "$JS.API.DIRECT.GET.KV_ORCH_OPERATION_PROOFS",
                     "$JS.API.STREAM.MSG.GET.KV_ORCH_OPERATION_PROOFS",
                     "$JS.API.CONSUMER.DURABLE.CREATE.KV_ORCH_OPERATION_PROOFS.exfiltration",
                 })
        {
            await Assert.That(async () => _ = await controller.RequestAsync<string, string>(subject, "{}"))
                .Throws<NatsException>();
        }
    }

    [Test]
    public async Task FixtureDisposesEveryServerProcessAndPrivateRoot()
    {
        if (!OperatingSystem.IsLinux()) return;

        var fixture = await NatsControlR3L0cFixture.StartAsync();
        var root = fixture.DirectoryPath;
        var processIds = fixture.ProcessIds.ToArray();
        await fixture.DisposeAsync();

        await Assert.That(fixture.ProcessIds).IsEmpty();
        await Assert.That(Directory.Exists(root)).IsFalse();
        foreach (var processId in processIds)
            await Assert.That(IsProcessRunning(processId)).IsFalse();
    }

    [Test]
    public async Task TlsJwtNkeyR3TopologyAndLeastPrivilegeBoundariesAreEnforced()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionAsync();
        var topology = fixture.Topology;
        var root = NatsSubjectTaxonomy.RegionalRoot(topology.Cell);

        await using var infrastructure = await fixture.ConnectAsync(fixture.Infrastructure);
        var jetStream = infrastructure.CreateJetStreamContext();
        foreach (var expected in topology.Streams)
        {
            var actual = (await jetStream.GetStreamAsync(expected.Name!)).Info.Config;
            await Assert.That(actual.NumReplicas).IsEqualTo(3);
            await Assert.That(actual.Subjects).IsEquivalentTo(expected.Subjects ?? []);
            await Assert.That(actual.Storage).IsEqualTo(StreamConfigStorage.File);
        }

        var operations = await jetStream.GetStreamAsync("KV_ORCH_OPERATIONS");
        await Assert.That(operations.Info.Config.NumReplicas).IsEqualTo(3);
        await Assert.That(operations.Info.Config.MaxAge).IsEqualTo(TimeSpan.FromDays(30));
        await Assert.That(operations.Info.Config.DenyDelete).IsTrue();
        await Assert.That(operations.Info.Config.DenyPurge).IsTrue();
        await Assert.That(operations.Info.Config.AllowDirect).IsTrue();
        await Assert.That(operations.Info.Config.Subjects)
            .IsEquivalentTo(["$KV.ORCH_OPERATIONS.>"]);

        var proofs = await jetStream.GetStreamAsync("KV_ORCH_OPERATION_PROOFS");
        await Assert.That(proofs.Info.Config.NumReplicas).IsEqualTo(3);
        await Assert.That(proofs.Info.Config.MaxAge).IsEqualTo(TimeSpan.FromMinutes(5));
        await Assert.That(proofs.Info.Config.DenyDelete).IsTrue();
        await Assert.That(proofs.Info.Config.DenyPurge).IsTrue();

        foreach (var identity in new[]
                     {
                         fixture.Controller,
                         fixture.ControllerTwo,
                         fixture.Infrastructure,
                         fixture.JournalWriter,
                         fixture.Operator,
                         fixture.WrongAccount,
                     })
        {
            using var certificate = X509Certificate2.CreateFromPemFile(
                identity.CertificateFile,
                identity.KeyFile);
            await Assert.That(certificate.HasPrivateKey).IsTrue();
            await Assert.That(certificate.Extensions["2.5.29.17"]!.Format(false))
                .Contains(identity.SpiffeId);
            var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
            await Assert.That(eku.EnhancedKeyUsages.Cast<Oid>().Select(static oid => oid.Value!))
                .Contains("1.3.6.1.5.5.7.3.2");
            await Assert.That(File.GetUnixFileMode(identity.KeyFile))
                .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        await using var controller = await fixture.ConnectAsync(fixture.Controller);
        await using var writer = await fixture.ConnectAsync(fixture.JournalWriter);
        await using var operatorRead = await fixture.ConnectAsync(fixture.Operator);
        await using var wrongAccount = await fixture.ConnectAsync(fixture.WrongAccount);

        await Assert.That(async () =>
        {
            await using var anonymous = await fixture.ConnectAsync(
                fixture.Operator,
                authenticate: false);
        }).Throws<NatsException>();

        await Assert.That(async () => _ = await controller.RequestAsync<string, string>(
                $"{root}.forbidden.mutation", "{}"))
            .Throws<NatsException>();
        foreach (var subject in new[]
                 {
                     "$KV.ORCH_OPERATIONS.operation.denied",
                     "$JS.API.DIRECT.GET.KV_ORCH_OPERATIONS",
                     "$JS.API.STREAM.MSG.GET.KV_ORCH_OPERATIONS",
                     "$JS.API.STREAM.INFO.KV_ORCH_OPERATIONS",
                     "$JS.API.STREAM.CREATE.unauthorized",
                     "$JS.API.STREAM.UPDATE.CELL_EVENTS",
                 })
        {
            await Assert.That(async () => _ = await controller.RequestAsync<string, string>(subject, "{}"))
                .Throws<NatsException>();
        }

        await Assert.That(async () => _ = await infrastructure.RequestAsync<string, string>(
                "$KV.ORCH_OPERATIONS.operation.denied", "{}"))
            .Throws<NatsException>();
        await Assert.That(async () => _ = await operatorRead.RequestAsync<string, string>(
                "$JS.API.STREAM.INFO.KV_ORCH_OPERATIONS", "{}"))
            .Throws<NatsException>();
        await Assert.That(async () => _ = await wrongAccount.CreateJetStreamContext()
                .GetStreamAsync("KV_ORCH_OPERATIONS"))
            .Throws<NatsJSApiException>();
        await Assert.That(async () => _ = await wrongAccount.RequestAsync<string, string>(
                $"{root}.query.status", "{}"))
            .Throws<NatsException>();

        var writerStore = await writer.CreateJetStreamContext().CreateKeyValueStoreContext()
            .GetStoreAsync(topology.Operations.Bucket);
        var writerKey = "operation." + new string('e', 64);
        var writerRevision = await writerStore.CreateAsync(writerKey, "writer-authorized");
        var writerEntry = await GetWithQuorumRetryAsync(writerStore, writerKey);
        writerEntry.EnsureSuccess();
        await Assert.That(writerEntry.Revision).IsEqualTo(writerRevision);
        await Assert.That(writerEntry.Value).IsEqualTo("writer-authorized");
    }

    [Test]
    public async Task JournalWriterCannotObserveLiveAuthorityLeaseForMutationFencing()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionAsync();
        await using var writer = await fixture.ConnectAsync(fixture.JournalWriter);

        // The mutation service currently receives only the operation/proof KV stores
        // and static authority verifier. Its dedicated identity must not gain a live
        // ORCH_LEADERS read as an implicit authority provider: that would cross the
        // journal writer's least-privilege boundary without carrying a protocol fence.
        foreach (var subject in new[]
                 {
                     "$KV.ORCH_LEADERS.authority.regional",
                     "$JS.API.STREAM.INFO.KV_ORCH_LEADERS",
                     "$JS.API.DIRECT.GET.KV_ORCH_LEADERS",
                 })
        {
            await Assert.That(async () => _ = await writer.RequestAsync<string, string>(subject, "{}"))
                .Throws<NatsException>();
        }
    }

    [Test]
    public async Task ProofLedgerAndJournalCasSurviveMemberLossRestartAndStaleWriterFence()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        await fixture.ProvisionAsync();
        var topology = fixture.Topology;
        await using var writer = await fixture.ConnectAsync(fixture.JournalWriter, member: 0);
        await using var writerTwo = await fixture.ConnectAsync(fixture.JournalWriter, member: 1);
        await using var controller = await fixture.ConnectAsync(fixture.Controller, member: 0);
        await using var controllerTwo = await fixture.ConnectAsync(fixture.ControllerTwo, member: 1);

        var writerStore = await OpenStoreAsync(writer, topology.Operations.Bucket);
        var writerStoreTwo = await OpenStoreAsync(writerTwo, topology.Operations.Bucket);
        var proofStore = await OpenStoreAsync(writer, topology.OperationProofConsumptions.Bucket);
        var proofStoreTwo = await OpenStoreAsync(writerTwo, topology.OperationProofConsumptions.Bucket);
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var replyKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var authorityPublicKey = authorityKey.ExportSubjectPublicKeyInfo();
        var replyPublicKey = replyKey.ExportSubjectPublicKeyInfo();
        var replyPrivateKey = replyKey.ExportPkcs8PrivateKey();
        var controllerSigner = new NatsOperationJournalMutationAuthoritySigner(
            fixture.Controller.PublicKey,
            authorityKey);
        var controllerTwoSigner = new NatsOperationJournalMutationAuthoritySigner(
            fixture.ControllerTwo.PublicKey,
            authorityKey);
        await using var writerService = await NatsOperationJournalMutationService.StartAsync(
            writer,
            writerStore,
            proofStore,
            topology,
            new NatsOperationJournalMutationAuthorityVerifier(authorityPublicKey),
            new HashSet<string>(StringComparer.Ordinal)
            {
                fixture.Controller.PublicKey,
                fixture.ControllerTwo.PublicKey,
            },
            CreateReplySigner(replyPrivateKey),
            default);
        await using var writerServiceTwo = await NatsOperationJournalMutationService.StartAsync(
            writerTwo,
            writerStoreTwo,
            proofStoreTwo,
            topology,
            new NatsOperationJournalMutationAuthorityVerifier(authorityPublicKey),
            new HashSet<string>(StringComparer.Ordinal)
            {
                fixture.Controller.PublicKey,
                fixture.ControllerTwo.PublicKey,
            },
            CreateReplySigner(replyPrivateKey),
            default);
        var mutationClient = new NatsOperationJournalMutationClient(
            controller,
            topology,
            controllerSigner,
            new NatsOperationJournalMutationReplyVerifier(replyPublicKey));
        var mutationClientTwo = new NatsOperationJournalMutationClient(
            controllerTwo,
            topology,
            controllerTwoSigner,
            new NatsOperationJournalMutationReplyVerifier(replyPublicKey));

        var firstKey = "operation." + new string('a', 64);
        var secondKey = "operation." + new string('b', 64);
        var concurrent = await Task.WhenAll(
            mutationClient.CreateAsync(firstKey, "first"),
            mutationClientTwo.CreateAsync(secondKey, "second"));
        await Assert.That(concurrent.All(static reply => reply.Succeeded)).IsTrue();

        var first = concurrent[0];
        var beforeLoss = await writerStore.GetEntryAsync<string>(firstKey);
        beforeLoss.EnsureSuccess();
        await Assert.That(beforeLoss.Revision).IsEqualTo(first.Revision);

        var proof = controllerSigner.Issue(
            topology.Cell,
            "create",
            "operation." + new string('c', 64),
            0,
            "single-use-proof");
        var consumed = await Task.WhenAll(
            NatsOperationJournalMutationProofConsumption.TryConsumeAsync(proofStore, proof, default).AsTask(),
            NatsOperationJournalMutationProofConsumption.TryConsumeAsync(proofStoreTwo, proof, default).AsTask());
        await Assert.That(consumed.Count(static value => value)).IsEqualTo(1);

        await fixture.KillMemberAsync(2);
        var afterLoss = writerStore;
        var afterLossRevision = await UpdateWithQuorumRetryAsync(
            afterLoss,
            firstKey,
            "after-member-loss",
            beforeLoss.Revision);
        await Assert.That(afterLossRevision).IsGreaterThan(beforeLoss.Revision);

        await fixture.RestartMemberAsync(2);
        await fixture.WaitForMemberAsync(2);
        await using var restartedWriter = await fixture.ConnectAsync(fixture.JournalWriter, member: 2);
        var restartedStore = await OpenStoreAsync(restartedWriter, topology.Operations.Bucket);
        var reloaded = await restartedStore.GetEntryAsync<string>(firstKey);
        reloaded.EnsureSuccess();
        await Assert.That(reloaded.Value).IsEqualTo("after-member-loss");
        await Assert.That(reloaded.Revision).IsEqualTo(afterLossRevision);

        await Assert.That(async () => await restartedStore.UpdateAsync(
                firstKey,
                "stale-writer",
                beforeLoss.Revision))
            .Throws<NatsKVWrongLastRevisionException>();
        var restartedProofStore = await OpenStoreAsync(
            restartedWriter,
            topology.OperationProofConsumptions.Bucket);
        await Assert.That(await NatsOperationJournalMutationProofConsumption.TryConsumeAsync(
                restartedProofStore,
                proof,
                default))
            .IsFalse();
        var r3 = await fixture.ConnectAsync(fixture.Infrastructure, member: 2);
        await using (r3)
        {
            var stream = await r3.CreateJetStreamContext().GetStreamAsync("KV_ORCH_OPERATIONS");
            await Assert.That(stream.Info.Config.NumReplicas).IsEqualTo(3);
            await Assert.That(stream.Info.Config.DenyDelete).IsTrue();
            await Assert.That(stream.Info.Config.DenyPurge).IsTrue();
        }
    }

    private static async Task<INatsKVStore> OpenStoreAsync(
        NatsClient client,
        string bucket)
    {
        for (var attempt = 0; attempt < 8; attempt++)
        {
            try
            {
                return await client.CreateJetStreamContext()
                    .CreateKeyValueStoreContext()
                    .GetStoreAsync(bucket);
            }
            catch (NatsException) when (attempt < 7)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250));
            }
        }
        throw new TimeoutException("The R3 JetStream store did not become readable.");
    }

    private static async Task<ulong> UpdateWithQuorumRetryAsync(
        INatsKVStore store,
        string key,
        string value,
        ulong expectedRevision)
    {
        for (var attempt = 0; attempt < 8; attempt++)
        {
            try
            {
                return await store.UpdateAsync(key, value, expectedRevision);
            }
            catch (NatsException) when (attempt < 7)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250));
            }
        }
        throw new TimeoutException("The R3 operation journal did not regain quorum for CAS update.");
    }

    private static async Task<NatsKVEntry<string>> GetWithQuorumRetryAsync(
        INatsKVStore store,
        string key)
    {
        for (var attempt = 0; attempt < 8; attempt++)
        {
            try
            {
                return await store.GetEntryAsync<string>(key);
            }
            catch (NatsKVKeyNotFoundException) when (attempt < 7)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250));
            }
        }
        throw new TimeoutException("The R3 operation journal write did not become readable.");
    }

    private static NatsOperationJournalMutationReplySigner CreateReplySigner(byte[] privateKey)
    {
        var key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(privateKey, out _);
        return new(key);
    }

    private sealed class DenyingArtifactSignatureVerifier : IRepositoryCiArtifactSignatureVerifier
    {
        public VerificationOutcome Verify(
            string signingIdentity,
            ReadOnlyMemory<byte> canonicalMaterial,
            OpaqueSignature signature) => VerificationOutcome.Invalid;
    }

    private static bool IsProcessRunning(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static RegionalRuntimeMembershipSnapshot SfoMembershipSnapshot()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var health = new RegionalRuntimeMembershipHealth(
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            1,
            true,
            0,
            RegionalRuntimeMembershipCondition.Healthy,
            observedAt);
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var member = new RegionalRuntimeMember(
            1,
            "sfo",
            "orchestrator-control-sfo",
            "controller-1",
            Guid.NewGuid().ToString("N"),
            "test-build",
            ["authority", "messaging"],
            observedAt.AddSeconds(-1),
            observedAt,
            observedAt.AddSeconds(30),
            "leader",
            true,
            1,
            1,
            identity.KeyId,
            identity.PublicKey,
            string.Empty);
        member = member with { IdentitySignature = identity.Sign(member) };
        return new(2, "sfo", observedAt, health, [member]);
    }

    private static JsonElement NatsClaim(string jwt)
    {
        var segments = jwt.Split('.');
        return JsonDocument.Parse(Encoding.UTF8.GetString(Base64UrlDecode(segments[1]))).RootElement.Clone();
    }

    private static string ReadUserIssuer(NatsControlR3L0cFixture.NatsControlR3L0cIdentity identity)
    {
        var jwt = File.ReadLines(identity.CredentialsFile)
            .First(line => line.Length > 0 && line[0] != '-');
        return NatsClaim(jwt).GetProperty("iss").GetString()!;
    }

    private static byte[] Base64UrlDecode(string value)
    {
        value = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(value.PadRight(value.Length + ((4 - value.Length % 4) % 4), '='));
    }
}
