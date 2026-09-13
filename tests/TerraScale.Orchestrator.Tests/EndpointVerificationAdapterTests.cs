using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TUnit.Assertions;
using TUnit.Core;
using TerraScale.Orchestrator.ControlPlane.Delivery.EndpointVerification;
using TerraScale.Orchestrator.Delivery.EndpointVerification;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Ticket TerraScale.Orchestrator#5 adapters: the managed/recorded lane composition may wire, and
/// the live DNS/HTTP resolver sketch whose transport seams deliberately have no implementation in
/// this repository (the live-lane authorization gate).
/// </summary>
public sealed class EndpointVerificationAdapterTests
{
    private static readonly DateTimeOffset Start = new(2026, 8, 24, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Recorded_resolver_serves_recorded_truth_and_fails_closed_when_unrecorded()
    {
        var resolver = new RecordedEndpointResolver(new FixedClock(Start));
        resolver.RecordStrict("gru.api.terrascale.tech", "gru");
        resolver.RecordGlobal("gru-edge", "gru");
        resolver.RecordGlobalFailure("sfo-edge", EndpointFailureCode.DnsFailure);

        var strict = await resolver.ResolveAsync(
            new EndpointProbeTarget("gru.api.terrascale.tech", "gru", EndpointRouteKind.StrictRegional),
            null, default);
        await Assert.That(strict.Resolved).IsTrue();
        await Assert.That(strict.ObservedRegion).IsEqualTo("gru");
        await Assert.That(strict.AddressCount).IsEqualTo(1);
        await Assert.That(strict.ObservedAt).IsEqualTo(Start);

        var global = await resolver.ResolveAsync(
            new EndpointProbeTarget("api.terrascale.tech", "global", EndpointRouteKind.Global),
            new EndpointVantage("sfo-edge", ["sfo", "gru", "fra"]), default);
        await Assert.That(global.Resolved).IsFalse();
        await Assert.That(global.FailureCode).IsEqualTo(EndpointFailureCode.DnsFailure);

        // Unrecorded truth is absent evidence, never an implied healthy route.
        var unrecorded = await resolver.ResolveAsync(
            new EndpointProbeTarget("fra.api.terrascale.tech", "fra", EndpointRouteKind.StrictRegional),
            null, default);
        await Assert.That(unrecorded.Resolved).IsFalse();
        await Assert.That(unrecorded.FailureCode).IsEqualTo(EndpointFailureCode.NotRecorded);
    }

    [Test]
    public async Task Dns_http_sketch_maps_transport_results_into_typed_resolutions()
    {
        var dns = new FakeDnsTransport
        {
            Answers = new Dictionary<string, EndpointDnsAnswer>(StringComparer.Ordinal)
            {
                ["api.terrascale.tech"] = new(true, 3),
                ["gru.api.terrascale.tech"] = new(true, 2),
                ["sfo.api.terrascale.tech"] = new(false, 0),
                ["fra.api.terrascale.tech"] = new(true, 1),
            },
        };
        var https = new FakeHttpsProbeTransport
        {
            Probes = new Dictionary<string, EndpointHttpsProbe>(StringComparer.Ordinal)
            {
                ["api.terrascale.tech"] = new(true, "gru", true),
                ["gru.api.terrascale.tech"] = new(true, "gru", true),
                ["fra.api.terrascale.tech"] = new(false, null, null, "connection_refused"),
            },
        };
        var resolver = new DnsHttpEndpointResolver(dns, https, new FixedClock(Start));

        var healthy = await resolver.ResolveAsync(
            new EndpointProbeTarget("gru.api.terrascale.tech", "gru", EndpointRouteKind.StrictRegional),
            null, default);
        await Assert.That(healthy.Resolved).IsTrue();
        await Assert.That(healthy.ObservedRegion).IsEqualTo("gru");
        await Assert.That(healthy.AddressCount).IsEqualTo(2);
        await Assert.That(healthy.TlsAccepted).IsTrue();

        var dnsFailure = await resolver.ResolveAsync(
            new EndpointProbeTarget("sfo.api.terrascale.tech", "sfo", EndpointRouteKind.StrictRegional),
            null, default);
        await Assert.That(dnsFailure.Resolved).IsFalse();
        await Assert.That(dnsFailure.FailureCode).IsEqualTo(EndpointFailureCode.DnsFailure);

        var unreachable = await resolver.ResolveAsync(
            new EndpointProbeTarget("fra.api.terrascale.tech", "fra", EndpointRouteKind.StrictRegional),
            null, default);
        await Assert.That(unreachable.Resolved).IsFalse();
        // An unknown transport-authored code collapses to the stable fallback: raw transport
        // diagnostics never flow through the typed resolution.
        await Assert.That(unreachable.FailureCode).IsEqualTo(EndpointFailureCode.Unclassified);

        // W2: a transport reporting raw diagnostics (address material, punctuation) gets the
        // stable fallback, and the hostile text never appears in the typed resolution.
        dns.Hostile = ("gru.api.terrascale.tech", "dial tcp 203.0.113.9:443: i/o timeout");
        var hostile = await resolver.ResolveAsync(
            new EndpointProbeTarget("gru.api.terrascale.tech", "gru", EndpointRouteKind.StrictRegional),
            null, default);
        await Assert.That(hostile.Resolved).IsFalse();
        await Assert.That(hostile.FailureCode).IsEqualTo(EndpointFailureCode.Unclassified);
        await Assert.That(hostile.ObservedRegion).IsNull();

        // The vantage name flows to the DNS transport so live answers stay vantage-bound.
        var globalResolution = await resolver.ResolveAsync(
            new EndpointProbeTarget("api.terrascale.tech", "global", EndpointRouteKind.Global),
            new EndpointVantage("gru-edge", ["gru", "sfo", "fra"]), default);
        await Assert.That(globalResolution.Resolved).IsTrue();
        await Assert.That(globalResolution.ObservedRegion).IsEqualTo("gru");
        await Assert.That(dns.ObservedVantages.OrderBy(static vantage => vantage, StringComparer.Ordinal).ToArray())
            .IsEquivalentTo(new[] { "(null)", "(null)", "(null)", "(null)", "gru-edge" });
    }

    [Test]
    public async Task Managed_lane_composition_produces_a_complete_bounded_report()
    {
        var clock = new FixedClock(Start);
        var resolver = new RecordedEndpointResolver(clock);
        var health = new RecordedRegionHealthSource(clock);
        var checks = new RecordedPublicContractCheckExecutor(clock);
        var plan = new EndpointVerificationPlan(
            "platform",
            "api.terrascale.tech",
            ["gru", "sfo", "fra"],
            ["gru", "sfo", "fra"],
            [
                new StrictRegionalEndpoint("gru", "gru.api.terrascale.tech"),
                new StrictRegionalEndpoint("sfo", "sfo.api.terrascale.tech"),
                new StrictRegionalEndpoint("fra", "fra.api.terrascale.tech"),
            ],
            [new EndpointVantage("gru-edge", ["gru", "sfo", "fra"])],
            "sha256:" + new string('a', 64),
            "sha256:" + new string('c', 64),
            TimeSpan.FromSeconds(60),
            TimeSpan.FromSeconds(30));
        resolver.RecordStrict("gru.api.terrascale.tech", "gru");
        resolver.RecordStrict("sfo.api.terrascale.tech", "sfo");
        resolver.RecordStrict("fra.api.terrascale.tech", "fra");
        resolver.RecordGlobal("gru-edge", "gru");
        health.Set("gru", true, plan.ArtifactDigest, plan.ConfigurationRevision);
        health.Set("sfo", true, plan.ArtifactDigest, plan.ConfigurationRevision);
        health.Set("fra", true, plan.ArtifactDigest, plan.ConfigurationRevision);
        checks.Set("public-contract:gru:tenant-isolation", true);
        var engine = new EndpointVerificationEngine(plan, resolver, health, checks, clock);

        var report = await engine.RunRoundAsync(default);

        // 3 health + 3 strict + 1 global + 15 contract-check observations.
        await Assert.That(report.Observations.Count).IsEqualTo(22);
        await Assert.That(report.Observations.Count(static observation =>
            observation.Status == EndpointObservationStatus.Deferred)).IsEqualTo(14);
        await Assert.That(report.PublicClaim.Regions.All(
            static region => region.Availability == EndpointRegionAvailability.Available)).IsTrue();
        await Assert.That(report.PublicClaim.GlobalRoutingAvailable).IsTrue();
        var json = EndpointVerificationWireCodec.SerializeReport(report);
        await Assert.That(json.Length).IsGreaterThan(0);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class FakeDnsTransport : IEndpointDnsTransport
    {
        public IReadOnlyDictionary<string, EndpointDnsAnswer> Answers { get; init; } =
            new Dictionary<string, EndpointDnsAnswer>();

        /// <summary>When set, this hostname fails with the given raw (hostile) failure text.</summary>
        public (string Hostname, string FailureCode)? Hostile { get; set; }

        public List<string> ObservedVantages { get; } = [];

        public ValueTask<EndpointDnsAnswer> ResolveAsync(string hostname, string? vantage, CancellationToken cancellationToken)
        {
            ObservedVantages.Add(vantage ?? "(null)");
            if (Hostile is { } hostile && hostname == hostile.Hostname)
                return ValueTask.FromResult(new EndpointDnsAnswer(false, 1, hostile.FailureCode));
            return ValueTask.FromResult(Answers.TryGetValue(hostname, out var answer)
                ? answer
                : new EndpointDnsAnswer(false, 0, null));
        }
    }

    private sealed class FakeHttpsProbeTransport : IEndpointHttpsProbeTransport
    {
        public IReadOnlyDictionary<string, EndpointHttpsProbe> Probes { get; init; } =
            new Dictionary<string, EndpointHttpsProbe>();

        public ValueTask<EndpointHttpsProbe> ProbeAsync(string hostname, CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(Probes.TryGetValue(hostname, out var probe)
                ? probe
                : new EndpointHttpsProbe(false, null, null, null));
        }
    }
}

