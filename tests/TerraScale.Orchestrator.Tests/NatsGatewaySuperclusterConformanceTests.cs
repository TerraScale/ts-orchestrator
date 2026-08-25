using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using NATS.Client.Services;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Real pinned-NATS conformance for the typed gateway plan, at the landed L0C
/// fidelity: three real clusters in one rootless Podman pod, connected by the
/// rendered full gateway mesh, under one operator JWT with the plan's account
/// model, service imports/exports, and regional JetStream domains. This lane
/// proves gateway handshakes, TLS, authorization, and domain isolation — it is
/// not R3 quorum evidence (that stays with <see cref="NatsControlR3L0cTests"/>).
/// </summary>
[NotInParallel("NatsR3")]
public sealed class NatsGatewaySuperclusterConformanceTests
{
    [Test]
    public async Task FullMeshGatewayCarriesTheApprovedServiceAcrossRegions()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsGatewaySuperclusterFixture.StartAsync();

        // The running supercluster was rendered from one validated typed plan.
        var mesh = fixture.Plan.GatewayRelationships;
        await Assert.That(mesh.Count()).IsEqualTo(6);
        foreach (var configuration in fixture.Configurations.Values)
        {
            var text = await File.ReadAllTextAsync(configuration);
            await Assert.That(text).Contains("gateway {");
            await Assert.That(string.Join("; ", NatsGatewayConfigurationRenderer.ScanForSecrets(text))).IsEmpty();
        }

        // The generated account JWTs match the typed plan's trust model exactly.
        var directoryClaims = NatsClaim(fixture.Accounts[GlobalNatsAccountNames.GlobalDirectory].Jwt);
        var exports = directoryClaims.GetProperty("nats").GetProperty("exports");
        await Assert.That(exports.GetArrayLength()).IsEqualTo(1);
        await Assert.That(exports[0].GetProperty("subject").GetString())
            .IsEqualTo(GlobalNatsTopology.CellDirectorySubject);
        foreach (var cell in new[] { "sfo", "fra" })
        {
            var claims = NatsClaim(fixture.Accounts[GlobalNatsAccountNames.RegionalControl(cell)].Jwt);
            var imports = claims.GetProperty("nats").GetProperty("imports");
            await Assert.That(imports.GetArrayLength()).IsEqualTo(1);
            await Assert.That(imports[0].GetProperty("account").GetString())
                .IsEqualTo(fixture.Accounts[GlobalNatsAccountNames.GlobalDirectory].PublicKey);
        }
        var gruClaims = NatsClaim(fixture.Accounts[GlobalNatsAccountNames.RegionalControl("gru")].Jwt);
        await Assert.That(gruClaims.GetProperty("nats").TryGetProperty("imports", out _)).IsFalse();

        // GRU serves the directory service; SFO and FRA reach it through the
        // gateway mesh via their cross-account service import.
        await using var serviceClient = await fixture.ConnectAsync(
            fixture.Users["directory-service-gru"], "gru");
        await using var service = await serviceClient.CreateServicesContext().AddServiceAsync(
            new NatsSvcConfig("terrascale-global-cell-directory-gru", "1.0.0")
            {
                QueueGroup = "ts-orch-global-cell-directory",
            });
        await service.AddEndpointAsync<string>(
            message => message.ReplyAsync("conformance-directory-snapshot"),
            name: "cells",
            subject: GlobalNatsTopology.CellDirectorySubject);

        foreach (var cell in new[] { "sfo", "fra" })
        {
            var response = default(NatsMsg<string>);
            for (var attempt = 0; attempt < 50; attempt++)
            {
                try
                {
                    await using var reader = await fixture.ConnectAsync(
                        fixture.Users[$"directory-reader-{cell}"], cell);
                    response = await reader.RequestAsync<string, string>(
                        GlobalNatsTopology.CellDirectorySubject,
                        string.Empty);
                    response.EnsureSuccess();
                    break;
                }
                catch (NatsException) when (attempt < 49)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(200));
                }
            }
            await Assert.That(response.Data ?? "<no-response>").IsEqualTo("conformance-directory-snapshot");
        }
    }

    [Test]
    public async Task RegionalJetStreamDomainsStayIsolatedAcrossTheGatewayMesh()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsGatewaySuperclusterFixture.StartAsync();
        await using var gruInfrastructure = await fixture.ConnectAsync(
            fixture.Users["gru-infrastructure"], "gru");

        // GRU owns the global authority assets inside its own JetStream domain.
        // Clustered JetStream needs a moment for meta-leader election, so the
        // provisioning path retries like the R3 lane's provisioner.
        var globalTopology = new GlobalNatsTopology(3);
        var gruJetStream = gruInfrastructure.CreateJetStreamContext();
        var streamSubject = globalTopology.Streams
            .Single(stream => stream.Name == GlobalNatsTopology.CellSpecStream)
            .Subjects!.First();
        var provisioned = false;
        for (var attempt = 0; attempt < 75 && !provisioned; attempt++)
        {
            try
            {
                await gruJetStream.CreateStreamAsync(new StreamConfig(
                    GlobalNatsTopology.CellSpecStream,
                    [streamSubject]));
                provisioned = true;
            }
            catch (NatsException) when (attempt < 74)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(200));
            }
        }
        if (!provisioned)
        {
            var diagnostics = fixture.SanitizedServerDiagnostics()
                .Select(pair => $"{pair.Key}: {pair.Value}")
                .Where(line => line.Length > 0)
                .ToArray();
            throw new InvalidOperationException(
                "Creating the global stream in the GRU domain failed. " +
                $"Server diagnostics: {string.Join(" ;; ", diagnostics)}");
        }
        var gruStore = await CreateGlobalCellsStoreAsync(gruInfrastructure, globalTopology);
        await gruStore.PutAsync(GlobalNatsTopology.CellAdvertisementKey("sfo"), "sfo-advertisement");

        var gruStream = await gruJetStream.GetStreamAsync(GlobalNatsTopology.CellSpecStream);
        await Assert.That(gruStream.Info.Config.NumReplicas).IsEqualTo(1);

        // SFO's domain has neither the global stream nor the global KV bucket:
        // nothing JetStream-spanning crosses the gateway. Checked repeatedly so
        // a not-yet-ready SFO domain cannot masquerade as isolation.
        await using var sfoInfrastructure = await fixture.ConnectAsync(
            fixture.Users["sfo-infrastructure"], "sfo");
        var sfoJetStream = sfoInfrastructure.CreateJetStreamContext();
        for (var attempt = 0; attempt < 5; attempt++)
        {
            await Assert.That(async () => await sfoJetStream.GetStreamAsync(GlobalNatsTopology.CellSpecStream))
                .Throws<NatsException>();
            await Assert.That(async () => await sfoInfrastructure.CreateJetStreamContext()
                    .CreateKeyValueStoreContext()
                    .GetStoreAsync(globalTopology.Cells.Bucket))
                .Throws<NatsException>();
            await Task.Delay(TimeSpan.FromMilliseconds(200));
        }

        // The approved service still flows through the mesh alongside the
        // isolated domains: isolation is per JetStream domain, not per gateway.
        await using var serviceClient = await fixture.ConnectAsync(
            fixture.Users["directory-service-gru"], "gru");
        await using var service = await serviceClient.CreateServicesContext().AddServiceAsync(
            new NatsSvcConfig("terrascale-global-cell-directory-gru", "1.0.0")
            {
                QueueGroup = "ts-orch-global-cell-directory",
            });
        await service.AddEndpointAsync<string>(
            message => message.ReplyAsync("conformance-directory-snapshot"),
            name: "cells",
            subject: GlobalNatsTopology.CellDirectorySubject);
        await using var reader = await fixture.ConnectAsync(fixture.Users["directory-reader-sfo"], "sfo");
        var response = await reader.RequestAsync<string, string>(
            GlobalNatsTopology.CellDirectorySubject,
            string.Empty);
        response.EnsureSuccess();
        await Assert.That(response.Data).IsEqualTo("conformance-directory-snapshot");
    }

    [Test]
    public async Task UnauthorizedAndProductSubjectsNeverTraverseTheGateway()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsGatewaySuperclusterFixture.StartAsync();
        await using var reader = await fixture.ConnectAsync(fixture.Users["directory-reader-sfo"], "sfo");
        await using var gruOperator = await fixture.ConnectAsync(fixture.Users["gru-operator-read"], "gru");

        // Product-plane subjects are denied at the publish boundary.
        await Assert.That(async () => _ = await reader.RequestAsync<string, string>(
                "ts.product.v1.gru.queue.customer", "forbidden"))
            .Throws<NatsException>();

        // Another region's journal and control subjects are denied too.
        await Assert.That(async () => _ = await reader.RequestAsync<string, string>(
                "ts.orch.v1.gru.internal.operation-journal.create", "forbidden"))
            .Throws<NatsException>();
        await Assert.That(async () => _ = await reader.RequestAsync<string, string>(
                "ts.orch.v1.gru.desired.gitops", "forbidden"))
            .Throws<NatsException>();
        await Assert.That(async () => _ = await reader.RequestAsync<string, string>(
                "$KV.GLOBAL_RELEASES.release.1", "forbidden"))
            .Throws<NatsException>();

        // GRU's regional account has no directory import, so its request for the
        // directory subject finds no responder even though GRU hosts the service
        // account: cross-account access is import-gated, not implicit.
        var responded = false;
        try
        {
            var denied = await gruOperator.RequestAsync<string, string>(
                GlobalNatsTopology.CellDirectorySubject,
                string.Empty);
            responded = denied.Data is not null;
        }
        catch (NatsException)
        {
            responded = false;
        }
        await Assert.That(responded).IsFalse();
    }

    [Test]
    public async Task ConfigurationRotationRestartsOneClusterAndRejoinsTheMesh()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var fixture = await NatsGatewaySuperclusterFixture.StartAsync();
        await using var serviceClient = await fixture.ConnectAsync(
            fixture.Users["directory-service-gru"], "gru");
        await using var service = await serviceClient.CreateServicesContext().AddServiceAsync(
            new NatsSvcConfig("terrascale-global-cell-directory-gru", "1.0.0")
            {
                QueueGroup = "ts-orch-global-cell-directory",
            });
        await service.AddEndpointAsync<string>(
            message => message.ReplyAsync("conformance-directory-snapshot"),
            name: "cells",
            subject: GlobalNatsTopology.CellDirectorySubject);

        var before = default(string);
        for (var attempt = 0; attempt < 50; attempt++)
        {
            try
            {
                await using var reader = await fixture.ConnectAsync(
                    fixture.Users["directory-reader-sfo"], "sfo");
                var response = await reader.RequestAsync<string, string>(
                    GlobalNatsTopology.CellDirectorySubject, string.Empty);
                response.EnsureSuccess();
                before = response.Data;
                break;
            }
            catch (NatsException) when (attempt < 49)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(200));
            }
        }
        await Assert.That(before).IsEqualTo("conformance-directory-snapshot");

        // Roll SFO one configuration generation: the next plan changes only the
        // generation, the rendered digest changes, and the rolling restart
        // brings SFO back into the mesh without touching the other clusters.
        var current = fixture.Plan;
        var next = new NatsGatewayPlan(
            current.Plane,
            current.OperatorName,
            current.TrustGeneration,
            current.ConfigurationGeneration + 1,
            [.. current.Clusters.Select(cluster => new NatsGatewayCluster(
                cluster.Plane,
                cluster.Cell,
                cluster.ClusterName,
                cluster.JetStreamDomain,
                cluster.OperatorName,
                cluster.Servers,
                cluster.Accounts,
                cluster.JetStreamAssets,
                cluster.CgroupSlice,
                cluster.TrustGeneration,
                cluster.Cell == "sfo"
                    ? cluster.ConfigurationGeneration + 1
                    : cluster.ConfigurationGeneration))],
            current.GatewayRelationships,
            current.Accounts,
            current.Exports,
            current.Imports);
        var digests = current.Clusters
            .SelectMany(static cluster => cluster.Servers)
            .ToDictionary(
                static server => server.ServerName,
                server => (
                    $"before-{server.ServerName}",
                    $"after-{server.ServerName}-{current.ConfigurationGeneration + 1}"),
                StringComparer.Ordinal);
        var steps = NatsGatewayRotation.Plan(current, next, digests);
        await Assert.That(steps.Count()).IsEqualTo(2);
        await Assert.That(steps.Select(static step => step.ServerName).ToArray())
            .IsEquivalentTo(["sfo-control-nats-1", "sfo-control-nats-2"]);
        await Assert.That(steps[0].RollbackTarget.ConfigurationGeneration).IsEqualTo(current.ConfigurationGeneration);
        await Assert.That(string.Join("; ", NatsGatewayRotation.ValidateSteps(current, steps))).IsEmpty();

        var renderedBefore = await File.ReadAllTextAsync(fixture.Configurations["sfo-control-nats-1"]);
        foreach (var step in steps)
        {
            var renderedNext = RenderServerConfiguration(fixture, next, step.ServerName);
            if (step.ServerName == "sfo-control-nats-1")
            {
                await Assert.That(NatsGatewayConfigurationRenderer.Digest(renderedNext))
                    .IsNotEqualTo(NatsGatewayConfigurationRenderer.Digest(renderedBefore));
            }
            await fixture.RestartServerAsync(step.ServerName, renderedNext);
        }

        var after = default(string);
        for (var attempt = 0; attempt < 50; attempt++)
        {
            try
            {
                await using var reader = await fixture.ConnectAsync(
                    fixture.Users["directory-reader-sfo"], "sfo");
                var response = await reader.RequestAsync<string, string>(
                    GlobalNatsTopology.CellDirectorySubject, string.Empty);
                response.EnsureSuccess();
                after = response.Data;
                break;
            }
            catch (NatsException) when (attempt < 49)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(200));
            }
        }
        await Assert.That(after).IsEqualTo("conformance-directory-snapshot");

        // FRA keeps serving through the mesh throughout the SFO rollout.
        await using var fraReader = await fixture.ConnectAsync(
            fixture.Users["directory-reader-fra"], "fra");
        var fraResponse = await fraReader.RequestAsync<string, string>(
            GlobalNatsTopology.CellDirectorySubject,
            string.Empty);
        fraResponse.EnsureSuccess();
        await Assert.That(fraResponse.Data).IsEqualTo("conformance-directory-snapshot");
    }

    private static async Task<INatsKVStore> CreateGlobalCellsStoreAsync(
        NatsClient infrastructure,
        GlobalNatsTopology globalTopology)
    {
        // A freshly formed cluster can briefly lack placement-qualified peers
        // for the two-replica bucket even after the fixture's JetStream
        // readiness gate passes; retry only that transient placement failure
        // (mirroring how the R3 lane tolerates raft-ack latency) so real
        // errors surface immediately.
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return await infrastructure.CreateJetStreamContext()
                    .CreateKeyValueStoreContext()
                    .CreateStoreAsync(globalTopology.Cells with
                    {
                        // The conformance lane runs two servers per region; the
                        // landed three-replica bucket stays a production-plan
                        // property.
                        NumberOfReplicas = NatsGatewaySuperclusterFixture.ServersPerRegion,
                    });
            }
            catch (NatsJSApiException exception) when (
                attempt < 2 &&
                exception.Message.Contains("no suitable peers", StringComparison.Ordinal))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(500));
            }
        }
    }

    private static string RenderServerConfiguration(
        NatsGatewaySuperclusterFixture fixture,
        NatsGatewayPlan plan,
        string serverName)
    {
        var context = new NatsGatewayRenderContext(
            fixture.OperatorJwtFile,
            [.. fixture.Accounts.Values.Select(account => new NatsGatewayRenderAccount(
                account.Name, account.PublicKey, account.Jwt))]);
        var cell = serverName.Split('-')[0];
        return NatsGatewayConfigurationRenderer.Render(
            plan,
            cell,
            serverName,
            context,
            NatsGatewayValidationOptions.LocalConformance);
    }

    private static JsonElement NatsClaim(string jwt)
    {
        var payload = jwt.Split('.')[1];
        var padded = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        return JsonDocument.Parse(Convert.FromBase64String(padded
                .Replace('-', '+')
                .Replace('_', '/')))
            .RootElement;
    }
}
