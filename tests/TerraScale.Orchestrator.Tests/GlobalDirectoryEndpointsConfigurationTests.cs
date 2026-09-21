using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Composition seam for the advertised cell endpoints: the
/// <c>TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS</c> family member that a real Run
/// composition uses to give its publisher valid control endpoints, and the
/// fail-fast behavior when publishing is enabled without any.
/// </summary>
public sealed class GlobalDirectoryEndpointsConfigurationTests
{
    // TODO(rehome-agent): OptionsWireTheEndpointsIntoTheDirectoryConfiguration was removed with
    // the production Development/ lab fixtures; rehome it onto a test-owned NATS identity
    // fixture so the endpoint wiring through OrchestratorOptions keeps its positive path.

    [Test]
    public async Task EndpointListParsesBothSeparatorsAndSorts()
    {
        await Assert.That(GlobalDirectoryNatsConfiguration.ParseEndpoints(null)).IsNull();
        await Assert.That(GlobalDirectoryNatsConfiguration.ParseEndpoints("")).IsNull();
        await Assert.That(GlobalDirectoryNatsConfiguration.ParseEndpoints("   ")).IsNull();

        var single = GlobalDirectoryNatsConfiguration.ParseEndpoints("tls://control-sfo.internal:4222");
        await Assert.That(single).IsEquivalentTo(["tls://control-sfo.internal:4222"]);

        var mixed = GlobalDirectoryNatsConfiguration.ParseEndpoints(
            "tls://b.internal:4223; tls://a.internal:4222,https://c.internal:8443");
        await Assert.That(mixed).IsEquivalentTo(
            ["https://c.internal:8443", "tls://a.internal:4222", "tls://b.internal:4223"]);
    }

    [Test]
    public async Task InvalidEndpointListsFailClosed()
    {
        foreach (var invalid in new[]
                 {
                     "control-gru.internal",
                     "tls://control-gru.internal",
                     "tls://control-gru.internal:99999",
                     "tls://control-gru.internal:4222/path",
                     "tls://control-gru.internal:4222?query=1",
                     "https://user:secret@control-gru.internal:4222",
                     ";,",
                     string.Join(",", Enumerable.Range(0, 9).Select(index => $"tls://c{index}.internal:4222")),
                 })
        {
            await Assert.That(() => GlobalDirectoryNatsConfiguration.ParseEndpoints(invalid))
                .Throws<ArgumentException>()
                .Because(invalid);
        }
    }

    [Test]
    public async Task PublishingWithoutConfiguredEndpointsFailsFast()
    {
        var authority = new RegionalAuthoritySnapshot(
            "leader", true, 1, 1,
            DateTimeOffset.UtcNow.AddSeconds(15), DateTimeOffset.UtcNow, null);
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var observedAt = DateTimeOffset.UtcNow;
        var health = new RegionalRuntimeMembershipHealth(
            1, 1, 0, 0, 0, 0, 0, 1, true, 0,
            RegionalRuntimeMembershipCondition.Healthy, observedAt);
        var member = MembershipRecord("sfo", identity, observedAt);
        var membership = new RegionalRuntimeMembershipSnapshot(2, "sfo", observedAt, health, [member]);

        using var seed = new NatsAuthenticationFilesTests.SeedFile();
        // A watch-only composition may legitimately carry no endpoints.
        var watchOnly = new GlobalDirectoryNatsConfiguration(
            "tls://global-directory.internal:4222",
            NatsAuthenticationFiles.FromNKeyFile(seed.Path),
            new NatsTlsFiles("ca.pem", "cert.pem", "key.pem"),
            3,
            "sfo");
        await Assert.That(watchOnly.Endpoints).IsEmpty();

        // The composition entry point (the supervised lifecycle's start function)
        // refuses a publishing runtime without endpoints BEFORE any connection is
        // created. Note: through the supervised lifecycle this surfaces as a
        // logged-and-retried failure (the process stays regionally healthy but
        // never advertises) - config-class failures are not yet terminal there;
        // the follow-up to reject Run-without-endpoints at options parse is
        // recorded on the ticket.
        try
        {
            await GlobalCellDirectoryRuntime.StartAsync(
                watchOnly,
                () => membership,
                () => authority,
                publishEnabled: true);
            throw new InvalidOperationException("The publishing start without endpoints unexpectedly succeeded.");
        }
        catch (ArgumentException failure)
        {
            await Assert.That(failure.Message)
                .Contains("Publishing a cell advertisement requires the cell's advertised control endpoints");
        }
    }

    private static RegionalRuntimeMember MembershipRecord(
        string cell,
        RegionalRuntimeMembershipIdentity identity,
        DateTimeOffset observedAt)
    {
        var member = new RegionalRuntimeMember(
            1,
            cell,
            $"orchestrator-control-{cell}",
            "controller-1",
            Guid.NewGuid().ToString("N"),
            "test-build",
            ["authority", "regional-membership", "service-discovery"],
            observedAt.AddMinutes(-1),
            observedAt,
            observedAt.Add(RegionalRuntimeMembership.LeaseDuration),
            "leader",
            true,
            7,
            11,
            identity.KeyId,
            identity.PublicKey,
            string.Empty);
        return member with { IdentitySignature = identity.Sign(member) };
    }
}

