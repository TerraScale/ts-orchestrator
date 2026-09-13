using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TUnit.Assertions;
using TUnit.Core;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.ControlPlane.Delivery.EndpointVerification;
using TerraScale.Orchestrator.Delivery.EndpointVerification;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

/// <summary>
/// Ticket TerraScale.Orchestrator#5: continuous verification of the global endpoint and the
/// strict gru/sfo/fra endpoints at managed fidelity (virtual clock, recorded resolver/health
/// sources). Live DNS/HTTP and live outage/recovery evidence are deferred to the authorized live
/// lane; these tests verify the decision core that will drive it.
/// </summary>
public sealed class EndpointVerificationTests
{
    private const string Service = "platform";
    private const string GlobalHostname = "api.terrascale.tech";
    private static readonly string ArtifactDigest = "sha256:" + new string('a', 64);
    private static readonly string ConfigurationRevision = "sha256:" + new string('c', 64);
    private static readonly string OtherDigest = "sha256:" + new string('b', 64);
    private static readonly DateTimeOffset Start = new(2026, 8, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan Freshness = TimeSpan.FromSeconds(60);

    [Test]
    public async Task Healthy_round_binds_every_observation_and_verifies_global_and_strict_routes()
    {
        var lane = Lane();
        lane.RunHealthy();

        var report = await lane.Engine.RunRoundAsync(default);

        await Assert.That(report.PublicClaim.GlobalRoutingAvailable).IsTrue();
        await Assert.That(report.PublicClaim.Regions.Select(static region => region.Availability).ToArray())
            .IsEquivalentTo(new[]
            {
                EndpointRegionAvailability.Available, EndpointRegionAvailability.Available,
                EndpointRegionAvailability.Available,
            });
        // AC-2: every observation binds service, region, artifact digest, configuration revision,
        // and observation time — no observation travels unbound.
        foreach (var observation in report.Observations)
        {
            await Assert.That(observation.Service).IsEqualTo(Service);
            await Assert.That(observation.Region).IsNotEmpty();
            await Assert.That(observation.ArtifactDigest).IsEqualTo(ArtifactDigest);
            await Assert.That(observation.ConfigurationRevision).IsEqualTo(ConfigurationRevision);
            await Assert.That(observation.ObservedAt).IsEqualTo(Start);
            await Assert.That(observation.Status).IsEqualTo(
                observation.ProbeKind == EndpointProbeKind.ContractCheck
                    ? EndpointObservationStatus.Deferred
                    : EndpointObservationStatus.Passed);
            await Assert.That(observation.FailureCode).IsNull();
        }
        var strict = report.Observations.Where(static o => o.ProbeKind == EndpointProbeKind.StrictRoute).ToArray();
        await Assert.That(strict.Select(static o => o.ObservedRegion ?? string.Empty).ToArray())
            .IsEquivalentTo(new[] { "gru", "sfo", "fra" });
        foreach (var observation in strict)
            await Assert.That(observation.ExpectedRegion).IsEqualTo(observation.ObservedRegion);
        // Nearest-healthy-selected global routing per vantage.
        var global = report.Observations.Where(static o => o.ProbeKind == EndpointProbeKind.GlobalRoute).ToArray();
        await Assert.That(global.Select(static o => $"{o.Vantage}->{o.ObservedRegion}" ?? string.Empty).ToArray())
            .IsEquivalentTo(new[] { "gru-edge->gru", "sfo-edge->sfo", "fra-edge->fra" });
        await Assert.That(lane.Engine.RoundsCompleted).IsEqualTo(1L);
        await Assert.That(lane.Engine.NextRoundAt).IsEqualTo(Start + Interval);
    }

    [Test]
    public async Task Strict_dns_failure_marks_only_that_region_outage()
    {
        var lane = Lane();
        lane.RunHealthy();
        lane.Resolver.RecordStrictFailure("gru.api.terrascale.tech", EndpointFailureCode.DnsFailure);

        var report = await lane.Engine.RunRoundAsync(default);

        var gru = report.PublicClaim.Regions.Single(static region => region.Region == "gru");
        await Assert.That(gru.Availability).IsEqualTo(EndpointRegionAvailability.Outage);
        await Assert.That(gru.LastFailureCode).IsEqualTo(EndpointFailureCode.DnsFailure);
        foreach (var region in report.PublicClaim.Regions.Where(static region => region.Region != "gru"))
            await Assert.That(region.Availability).IsEqualTo(EndpointRegionAvailability.Available);
        var transition = report.Transitions.Single(static transition => transition.Region == "gru");
        await Assert.That(transition.From).IsEqualTo(EndpointRegionAvailability.Unknown);
        await Assert.That(transition.To).IsEqualTo(EndpointRegionAvailability.Outage);
        await Assert.That(transition.FailureCode).IsEqualTo(EndpointFailureCode.DnsFailure);
        await Assert.That(report.PublicClaim.GlobalRoutingAvailable).IsTrue();
    }

    [Test]
    public async Task Global_dns_failure_from_one_vantage_fails_the_global_claim_only()
    {
        var lane = Lane();
        lane.RunHealthy();
        lane.Resolver.RecordGlobalFailure("sfo-edge", EndpointFailureCode.DnsFailure);

        var report = await lane.Engine.RunRoundAsync(default);

        await Assert.That(report.PublicClaim.GlobalRoutingAvailable).IsFalse();
        await Assert.That(report.PublicClaim.Regions.Select(static region => region.Availability).ToArray())
            .IsEquivalentTo(new[]
            {
                EndpointRegionAvailability.Available, EndpointRegionAvailability.Available,
                EndpointRegionAvailability.Available,
            });
        var failed = report.Observations.Single(static observation =>
            observation.ProbeKind == EndpointProbeKind.GlobalRoute &&
            observation.Status == EndpointObservationStatus.Failed);
        await Assert.That(failed.Vantage).IsEqualTo("sfo-edge");
        await Assert.That(failed.FailureCode).IsEqualTo(EndpointFailureCode.DnsFailure);
    }

    [Test]
    public async Task Stale_health_is_not_eligible_and_a_misroute_to_the_stale_region_fails_the_vantage()
    {
        var lane = Lane();
        lane.RunHealthy();
        lane.Health.Set("gru", true, ArtifactDigest, ConfigurationRevision, Start - Freshness - TimeSpan.FromSeconds(1));
        // The global endpoint wrongly keeps routing the gru vantage to the stale region instead of
        // the nearest healthy selected region (sfo).
        lane.Resolver.RecordGlobal("gru-edge", "gru");

        var report = await lane.Engine.RunRoundAsync(default);

        var stale = report.Observations.Single(static observation =>
            observation.ProbeKind == EndpointProbeKind.RegionHealth && observation.Region == "gru");
        await Assert.That(stale.Status).IsEqualTo(EndpointObservationStatus.Failed);
        await Assert.That(stale.FailureCode).IsEqualTo(EndpointFailureCode.StaleHealth);
        var gruClaim = report.PublicClaim.Regions.Single(static region => region.Region == "gru");
        await Assert.That(gruClaim.Availability).IsEqualTo(EndpointRegionAvailability.Outage);
        var misrouted = report.Observations.Single(static observation =>
            observation.ProbeKind == EndpointProbeKind.GlobalRoute && observation.Vantage == "gru-edge");
        await Assert.That(misrouted.Status).IsEqualTo(EndpointObservationStatus.Failed);
        await Assert.That(misrouted.FailureCode).IsEqualTo(EndpointFailureCode.Misroute);
        await Assert.That(misrouted.ExpectedRegion).IsEqualTo("sfo");
        await Assert.That(report.PublicClaim.GlobalRoutingAvailable).IsFalse();
    }

    [Test]
    public async Task Unknown_health_is_never_eligible_as_healthy_for_global_selection()
    {
        var lane = Lane();
        lane.RunHealthy();
        lane.Health.Set("gru", null, ArtifactDigest, ConfigurationRevision);
        lane.Resolver.RecordGlobal("gru-edge", "sfo");

        var report = await lane.Engine.RunRoundAsync(default);

        var unknown = report.Observations.Single(static observation =>
            observation.ProbeKind == EndpointProbeKind.RegionHealth && observation.Region == "gru");
        await Assert.That(unknown.FailureCode).IsEqualTo(EndpointFailureCode.UnknownHealth);
        var gruClaim = report.PublicClaim.Regions.Single(static region => region.Region == "gru");
        await Assert.That(gruClaim.Availability).IsEqualTo(EndpointRegionAvailability.Outage);
        var routed = report.Observations.Single(static observation =>
            observation.ProbeKind == EndpointProbeKind.GlobalRoute && observation.Vantage == "gru-edge");
        await Assert.That(routed.Status).IsEqualTo(EndpointObservationStatus.Passed);
        await Assert.That(routed.ExpectedRegion).IsEqualTo("sfo");
        await Assert.That(report.PublicClaim.GlobalRoutingAvailable).IsTrue();
    }

    [Test]
    public async Task Regional_outage_and_recovery_produce_truthful_public_and_operator_state()
    {
        var lane = Lane();
        lane.RunHealthy();

        var healthy = await lane.Engine.RunRoundAsync(default);
        await Assert.That(healthy.PublicClaim.Regions.All(
            static region => region.Availability == EndpointRegionAvailability.Available)).IsTrue();

        lane.Clock.Advance(Interval);
        lane.Health.Set("gru", false, ArtifactDigest, ConfigurationRevision);
        var outage = await lane.Engine.RunRoundAsync(default);

        // Public state is truthful immediately: the claim reports the outage in the same round.
        var gruOutage = outage.PublicClaim.Regions.Single(static region => region.Region == "gru");
        await Assert.That(gruOutage.Availability).IsEqualTo(EndpointRegionAvailability.Outage);
        await Assert.That(gruOutage.LastFailureCode).IsEqualTo(EndpointFailureCode.UnhealthyRegion);
        // Operator state carries the failed observation and the transition with its evidence.
        var outageTransition = outage.Transitions.Single(static transition => transition.Region == "gru");
        await Assert.That(outageTransition.From).IsEqualTo(EndpointRegionAvailability.Available);
        await Assert.That(outageTransition.To).IsEqualTo(EndpointRegionAvailability.Outage);
        await Assert.That(outageTransition.ObservedAt).IsEqualTo(Start + Interval);
        await Assert.That(outage.Observations.Any(static observation =>
            observation.Region == "gru" && observation.FailureCode == EndpointFailureCode.UnhealthyRegion)).IsTrue();

        lane.Clock.Advance(Interval);
        lane.Health.Set("gru", true, ArtifactDigest, ConfigurationRevision);
        var recovery = await lane.Engine.RunRoundAsync(default);

        var gruRecovered = recovery.PublicClaim.Regions.Single(static region => region.Region == "gru");
        await Assert.That(gruRecovered.Availability).IsEqualTo(EndpointRegionAvailability.Available);
        await Assert.That(gruRecovered.LastFailureCode).IsNull();
        var recoveryTransition = recovery.Transitions.Single(static transition => transition.Region == "gru");
        await Assert.That(recoveryTransition.From).IsEqualTo(EndpointRegionAvailability.Outage);
        await Assert.That(recoveryTransition.To).IsEqualTo(EndpointRegionAvailability.Available);
        await Assert.That(recoveryTransition.ObservedAt).IsEqualTo(Start + Interval + Interval);
        await Assert.That(lane.Sink.Reports.Count).IsEqualTo(3);
    }

    [Test]
    public async Task Strict_endpoint_never_silently_fails_over_to_another_region()
    {
        var lane = Lane();
        lane.RunHealthy();
        // gru.api.terrascale.tech resolves, but to sfo — a silent regional failover attempt.
        lane.Resolver.RecordStrict("gru.api.terrascale.tech", "sfo");

        var report = await lane.Engine.RunRoundAsync(default);

        var violation = report.Observations.Single(static observation =>
            observation.ProbeKind == EndpointProbeKind.StrictRoute && observation.Region == "gru");
        await Assert.That(violation.Status).IsEqualTo(EndpointObservationStatus.Failed);
        await Assert.That(violation.FailureCode).IsEqualTo(EndpointFailureCode.StrictAffinityViolation);
        await Assert.That(violation.ExpectedRegion).IsEqualTo("gru");
        await Assert.That(violation.ObservedRegion).IsEqualTo("sfo");
        var gruClaim = report.PublicClaim.Regions.Single(static region => region.Region == "gru");
        await Assert.That(gruClaim.Availability).IsEqualTo(EndpointRegionAvailability.Outage);
        await Assert.That(gruClaim.LastFailureCode).IsEqualTo(EndpointFailureCode.StrictAffinityViolation);
        // The region that received the misroute is not penalized for gru's violation.
        var sfoClaim = report.PublicClaim.Regions.Single(static region => region.Region == "sfo");
        await Assert.That(sfoClaim.Availability).IsEqualTo(EndpointRegionAvailability.Available);
    }

    [Test]
    public async Task Health_evidence_under_a_different_artifact_identity_fails_the_binding()
    {
        var lane = Lane();
        lane.RunHealthy();
        lane.Health.Set("fra", true, OtherDigest, ConfigurationRevision);

        var report = await lane.Engine.RunRoundAsync(default);

        var mismatch = report.Observations.Single(static observation =>
            observation.ProbeKind == EndpointProbeKind.RegionHealth && observation.Region == "fra");
        await Assert.That(mismatch.Status).IsEqualTo(EndpointObservationStatus.Failed);
        await Assert.That(mismatch.FailureCode).IsEqualTo(EndpointFailureCode.BindingMismatch);
        var fraClaim = report.PublicClaim.Regions.Single(static region => region.Region == "fra");
        await Assert.That(fraClaim.Availability).IsEqualTo(EndpointRegionAvailability.Outage);
    }

    [Test]
    public async Task Failed_public_contract_check_drops_the_region_claim()
    {
        var lane = Lane();
        lane.RunHealthy();
        lane.Checks.Set("public-contract:sfo:tenant-isolation", false);

        var report = await lane.Engine.RunRoundAsync(default);

        var failed = report.Observations.Single(static observation =>
            observation.ProbeKind == EndpointProbeKind.ContractCheck &&
            observation.Status == EndpointObservationStatus.Failed);
        await Assert.That(failed.FailureCode).IsEqualTo(EndpointFailureCode.ContractCheckFailed);
        var sfoClaim = report.PublicClaim.Regions.Single(static region => region.Region == "sfo");
        await Assert.That(sfoClaim.Availability).IsEqualTo(EndpointRegionAvailability.Outage);
        await Assert.That(sfoClaim.LastFailureCode).IsEqualTo(EndpointFailureCode.ContractCheckFailed);
    }

    [Test]
    public async Task Deferred_public_contract_checks_stay_descriptor_only_and_never_change_the_claim()
    {
        var lane = Lane();
        lane.RunHealthy();

        var report = await lane.Engine.RunRoundAsync(default);

        var deferred = report.Observations.Where(static observation =>
            observation.ProbeKind == EndpointProbeKind.ContractCheck).ToArray();
        await Assert.That(deferred.Length).IsEqualTo(15);
        foreach (var observation in deferred)
        {
            await Assert.That(observation.Status).IsEqualTo(EndpointObservationStatus.Deferred);
            await Assert.That(observation.FailureCode).IsNull();
            await Assert.That(observation.Note).Contains("deferred");
        }
        await Assert.That(report.PublicClaim.Regions.All(
            static region => region.Availability == EndpointRegionAvailability.Available)).IsTrue();
    }

    [Test]
    public async Task Failed_checks_change_the_claim_but_never_touch_authorization_policy()
    {
        var lane = Lane();
        lane.RunHealthy();
        lane.Health.Set("gru", false, ArtifactDigest, ConfigurationRevision);

        var report = await lane.Engine.RunRoundAsync(default);

        // AC-6: the availability claim is data. It changed because a check failed...
        var gruClaim = report.PublicClaim.Regions.Single(static region => region.Region == "gru");
        await Assert.That(gruClaim.Availability).IsEqualTo(EndpointRegionAvailability.Outage);
        // ...and authorization policy is untouched by construction, not by assertion: the
        // EndpointVerificationEngine constructor's entire dependency surface is
        // (plan, resolver, healthSource, contractChecks, clock, sink) — it holds no authorizer,
        // policy writer, or mutation seam, so verification cannot consult or mutate the
        // authorization boundary (IDeliveryAuthorizer and friends) even in principle. A runtime
        // "authorizer recorded no calls" assertion here would be tautological (nothing in this
        // test routes a delivery through one); the type signature IS the guarantee.
        //
        // The claim and report surfaces are bounded, machine-readable data with no policy,
        // credential, or address material.
        var claimJson = EndpointVerificationWireCodec.SerializeClaim(report.PublicClaim);
        var reportJson = EndpointVerificationWireCodec.SerializeReport(report);
        await Assert.That(claimJson.Contains("authorization", StringComparison.OrdinalIgnoreCase)).IsFalse();
        await Assert.That(reportJson.Contains("authorization", StringComparison.OrdinalIgnoreCase)).IsFalse();
        await Assert.That(claimJson.Contains("policy", StringComparison.OrdinalIgnoreCase)).IsFalse();
        await Assert.That(claimJson.Contains("secret", StringComparison.OrdinalIgnoreCase)).IsFalse();
        await Assert.That(reportJson.Contains("addressCount", StringComparison.OrdinalIgnoreCase)).IsFalse();
        await Assert.That(TopLevelKeys(claimJson).ToArray())
            .IsEquivalentTo(new[]
            {
                "schemaVersion", "service", "claimedAt", "artifactDigest", "configurationRevision",
                "globalRoutingAvailable", "regions",
            });
    }

    [Test]
    public async Task Unavailable_check_source_is_distinguishable_from_authorized_deferral()
    {
        var lane = Lane();
        lane.RunHealthy();
        // One check's executor throws, one returns null: both are source outages, not deferrals.
        lane.Checks.ThrowFor("public-contract:gru:tenant-isolation");
        lane.Checks.ReturnNullFor("public-contract:gru:metering");

        var report = await lane.Engine.RunRoundAsync(default);

        var gruChecks = report.Observations.Where(static observation =>
            observation.ProbeKind == EndpointProbeKind.ContractCheck && observation.Region == "gru").ToArray();
        await Assert.That(gruChecks.Length).IsEqualTo(5);
        var unavailable = gruChecks.Where(static observation =>
            observation.Status == EndpointObservationStatus.Unavailable).ToArray();
        await Assert.That(unavailable.Length).IsEqualTo(2);
        foreach (var observation in unavailable)
        {
            await Assert.That(observation.FailureCode).IsEqualTo(EndpointFailureCode.SourceUnavailable);
            await Assert.That(observation.Note).IsEqualTo("check source unavailable; not the authorized live-lane deferral");
        }
        var deferred = gruChecks.Where(static observation =>
            observation.Status == EndpointObservationStatus.Deferred).ToArray();
        await Assert.That(deferred.Length).IsEqualTo(3);
        foreach (var observation in deferred)
        {
            await Assert.That(observation.FailureCode).IsNull();
            await Assert.That(observation.Note).Contains("deferred");
        }
        // Absence of evidence never gates the claim, and the fidelity field says so.
        var gruClaim = report.PublicClaim.Regions.Single(static region => region.Region == "gru");
        await Assert.That(gruClaim.Availability).IsEqualTo(EndpointRegionAvailability.Available);
        await Assert.That(gruClaim.ContractEvidence).IsEqualTo(EndpointContractEvidence.RoutingHealthOnly);
        var reportJson = EndpointVerificationWireCodec.SerializeReport(report);
        await Assert.That(reportJson.Contains("\"status\":\"unavailable\"", StringComparison.Ordinal)).IsTrue();
        // W5: the delivery-health projection keeps the distinction in the check name.
        var delivery = EndpointVerificationDeliveryHealth.ToDeliveryHealth(report);
        await Assert.That(delivery.Checks.Count(static check =>
            check.Name.StartsWith("endpoint-verification:contract_check:gru:unavailable", StringComparison.Ordinal) &&
            check.Status == DeliveryHealthStatus.Passed)).IsEqualTo(2);
        await Assert.That(delivery.Converged).IsTrue();
    }

    [Test]
    public async Task Adapter_authored_text_is_redacted_at_the_boundary()
    {
        var lane = Lane(
            resolver: new HostileResolver(new AdjustableClock(Start)),
            executor: new HostileContractExecutor(new AdjustableClock(Start)));
        lane.Health.Set("gru", true, ArtifactDigest, ConfigurationRevision);
        lane.Health.Set("sfo", true, ArtifactDigest, ConfigurationRevision);
        lane.Health.Set("fra", true, ArtifactDigest, ConfigurationRevision);

        var report = await lane.Engine.RunRoundAsync(default);

        // Unknown adapter failure codes collapse to the stable fallback everywhere they surface.
        var gruStrict = report.Observations.Single(static observation =>
            observation.ProbeKind == EndpointProbeKind.StrictRoute && observation.Region == "gru");
        await Assert.That(gruStrict.FailureCode).IsEqualTo(EndpointFailureCode.Unclassified);
        var gruClaim = report.PublicClaim.Regions.Single(static region => region.Region == "gru");
        await Assert.That(gruClaim.Availability).IsEqualTo(EndpointRegionAvailability.Outage);
        await Assert.That(gruClaim.LastFailureCode).IsEqualTo(EndpointFailureCode.Unclassified);
        var gruContract = report.Observations.Single(static observation =>
            observation.ProbeKind == EndpointProbeKind.ContractCheck && observation.Region == "sfo" &&
            observation.Status == EndpointObservationStatus.Failed);
        await Assert.That(gruContract.FailureCode).IsEqualTo(EndpointFailureCode.Unclassified);
        // Adapter-authored notes that are not bounded token text are dropped, not clamped.
        await Assert.That(gruContract.Note).DoesNotContain("203.0.113.9");
        // Nothing hostile reaches the published documents.
        var reportJson = EndpointVerificationWireCodec.SerializeReport(report);
        var claimJson = EndpointVerificationWireCodec.SerializeClaim(report.PublicClaim);
        await Assert.That(reportJson.Contains("203.0.113.9", StringComparison.Ordinal)).IsFalse();
        await Assert.That(claimJson.Contains("203.0.113.9", StringComparison.Ordinal)).IsFalse();
        await Assert.That(reportJson.Contains("dial tcp", StringComparison.Ordinal)).IsFalse();
        await Assert.That(claimJson.Contains("dial tcp", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task Claim_reports_contract_evidence_fidelity_per_region()
    {
        var lane = Lane();
        lane.RunHealthy();

        var deferred = await lane.Engine.RunRoundAsync(default);

        // A fully-deferred round is Available on routing-and-health evidence only — and says so.
        foreach (var region in deferred.PublicClaim.Regions)
        {
            await Assert.That(region.Availability).IsEqualTo(EndpointRegionAvailability.Available);
            await Assert.That(region.ContractEvidence).IsEqualTo(EndpointContractEvidence.RoutingHealthOnly);
        }

        lane.Checks.Set("public-contract:sfo:tenant-isolation", true);
        var executed = await lane.Engine.RunRoundAsync(default);

        foreach (var region in executed.PublicClaim.Regions)
        {
            var expected = region.Region == "sfo"
                ? EndpointContractEvidence.WithContractChecks
                : EndpointContractEvidence.RoutingHealthOnly;
            await Assert.That(region.ContractEvidence).IsEqualTo(expected);
            await Assert.That(region.Availability).IsEqualTo(EndpointRegionAvailability.Available);
        }
        var claimJson = EndpointVerificationWireCodec.SerializeClaim(executed.PublicClaim);
        await Assert.That(claimJson.Contains("\"contractEvidence\":\"withContractChecks\"", StringComparison.Ordinal)).IsTrue();
        await Assert.That(claimJson.Contains("\"contractEvidence\":\"routingHealthOnly\"", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    public async Task Delivery_health_adapter_projects_the_round_onto_the_direct_delivery_seam()
    {
        var lane = Lane();
        lane.RunHealthy();

        var healthy = await lane.Engine.RunRoundAsync(default);
        var healthyResult = EndpointVerificationDeliveryHealth.ToDeliveryHealthResult(healthy);
        await Assert.That(healthyResult.Passed).IsTrue();
        await Assert.That(healthyResult.Checks!.Count).IsEqualTo(healthy.Observations.Count);
        var deliveryHealth = EndpointVerificationDeliveryHealth.ToDeliveryHealth(healthy);
        await Assert.That(deliveryHealth.Converged).IsTrue();
        await Assert.That(deliveryHealth.Checks.All(static check =>
            check.Status == DeliveryHealthStatus.Passed)).IsTrue();

        lane.Health.Set("sfo", false, ArtifactDigest, ConfigurationRevision);
        var outage = await lane.Engine.RunRoundAsync(default);
        var outageResult = EndpointVerificationDeliveryHealth.ToDeliveryHealthResult(outage);
        await Assert.That(outageResult.Passed).IsFalse();
        var failedCheck = outageResult.Checks!.Single(static check =>
            check.Name == "endpoint-verification:region_health:sfo");
        await Assert.That(failedCheck.Status).IsEqualTo(DeliveryHealthStatus.Failed);
        // Deferred contract evidence is absence of evidence, never failure evidence; every
        // deferred descriptor for the region stays a passing check whose NAME carries the
        // deferral signal, and vantages name the global checks.
        await Assert.That(outageResult.Checks!.Count(check =>
            check.Name == "endpoint-verification:contract_check:sfo:deferred" &&
            check.Status == DeliveryHealthStatus.Passed)).IsEqualTo(5);
        var globalCheck = outageResult.Checks!.Single(static check =>
            check.Name == "endpoint-verification:global_route:gru-edge");
        await Assert.That(globalCheck.Status).IsEqualTo(DeliveryHealthStatus.Passed);
    }

    [Test]
    public async Task Continuous_loop_runs_exactly_one_round_per_interval_on_the_virtual_clock()
    {
        var clock = new VirtualTimerClock(Start);
        var lane = Lane(clock);
        lane.RunHealthy();
        using var cancellation = new CancellationTokenSource();
        var loop = Task.Run(() => lane.Engine.RunAsync(cancellation.Token), cancellation.Token);

        await UntilAsync(() => lane.Engine.RoundsCompleted >= 1 && clock.PendingTimerCount == 1);
        await Assert.That(lane.Engine.NextRoundAt).IsEqualTo(Start + Interval);
        clock.FirePendingTimers();
        lane.Clock.Advance(Interval);

        await UntilAsync(() => lane.Engine.RoundsCompleted >= 2);
        await Assert.That(lane.Engine.RoundsCompleted).IsEqualTo(2L);
        // No third round without the next interval firing.
        await Task.Delay(50);
        await Assert.That(lane.Engine.RoundsCompleted).IsEqualTo(2L);
        await Assert.That(clock.PendingTimerCount).IsEqualTo(1);

        cancellation.Cancel();
        await Assert.ThrowsAsync<TaskCanceledException>(() => loop);
    }

    [Test]
    public async Task Adapter_failures_become_failed_observations_never_exceptions()
    {
        var lane = Lane();
        lane.RunHealthy();
        lane.Resolver.ThrowForStrict("gru.api.terrascale.tech");
        lane.Health.ThrowFor("fra");

        var report = await lane.Engine.RunRoundAsync(default);

        var strictFailure = report.Observations.Single(static observation =>
            observation.ProbeKind == EndpointProbeKind.StrictRoute && observation.Region == "gru");
        await Assert.That(strictFailure.FailureCode).IsEqualTo(EndpointFailureCode.ResolverUnavailable);
        var healthFailure = report.Observations.Single(static observation =>
            observation.ProbeKind == EndpointProbeKind.RegionHealth && observation.Region == "fra");
        await Assert.That(healthFailure.FailureCode).IsEqualTo(EndpointFailureCode.SourceUnavailable);
        await Assert.That(report.PublicClaim.Regions.Select(static region => region.Availability).ToArray())
            .IsEquivalentTo(new[]
            {
                EndpointRegionAvailability.Outage, EndpointRegionAvailability.Available,
                EndpointRegionAvailability.Outage,
            });
    }

    [Test]
    public async Task Wire_codec_round_trips_reports_and_claims_canonically()
    {
        var lane = Lane();
        lane.RunHealthy();
        lane.Resolver.RecordGlobalFailure("fra-edge", EndpointFailureCode.DnsFailure);

        var report = await lane.Engine.RunRoundAsync(default);

        var reportJson = EndpointVerificationWireCodec.SerializeReport(report);
        var roundTrip = EndpointVerificationWireCodec.DeserializeReport(reportJson);
        await Assert.That(EndpointVerificationWireCodec.SerializeReport(roundTrip)).IsEqualTo(reportJson);
        var claimJson = EndpointVerificationWireCodec.SerializeClaim(report.PublicClaim);
        await Assert.That(EndpointVerificationWireCodec.SerializeClaim(
            EndpointVerificationWireCodec.DeserializeClaim(claimJson))).IsEqualTo(claimJson);
        await Assert.That(EndpointVerificationWireCodec.SerializeClaim(roundTrip.PublicClaim)).IsEqualTo(claimJson);
        Assert.Throws<JsonException>(() =>
            EndpointVerificationWireCodec.DeserializeClaim(claimJson.TrimEnd('}') + ",\"unknown\":1}"));
        // W7: an unsupported schema version is a typed rejection, never a best-effort read.
        Assert.Throws<JsonException>(() => EndpointVerificationWireCodec.DeserializeClaim(
            claimJson.Replace("\"schemaVersion\":1", "\"schemaVersion\":2", StringComparison.Ordinal)));
        Assert.Throws<JsonException>(() => EndpointVerificationWireCodec.DeserializeReport(
            reportJson.Replace("\"schemaVersion\":1", "\"schemaVersion\":2", StringComparison.Ordinal)));
    }

    [Test]
    public async Task Engine_rejects_plans_that_violate_the_region_and_identity_rules()
    {
        Assert.Throws<ArgumentException>(() => Lane(plan: Plan(vantages:
        [
            new EndpointVantage("edge", ["moon"]),
        ])));
        Assert.Throws<ArgumentException>(() => Lane(plan: Plan(selected: ["moon"])));
        Assert.Throws<ArgumentException>(() => Lane(plan: Plan(artifactDigest: "latest")));
        Assert.Throws<ArgumentException>(() => Lane(plan: Plan(interval: TimeSpan.Zero)));
        // W4: a qualified region without a strict endpoint could reach Available on health alone.
        Assert.Throws<ArgumentException>(() => Lane(plan: Plan(strict:
        [
            new StrictRegionalEndpoint("gru", "gru.api.terrascale.tech"),
            new StrictRegionalEndpoint("sfo", "sfo.api.terrascale.tech"),
        ])));
    }

    private static string[] TopLevelKeys(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.EnumerateObject().Select(static property => property.Name).ToArray();
    }

    private static async Task UntilAsync(Func<bool> condition, TimeSpan? timeout = null)
    {
        var deadline = Environment.TickCount64 + (long)(timeout ?? TimeSpan.FromSeconds(10)).TotalMilliseconds;
        while (Environment.TickCount64 < deadline)
        {
            if (condition())
                return;
            await Task.Delay(5);
        }
        throw new TimeoutException("The condition was not met before the deadline.");
    }

    private static EndpointVerificationPlan Plan(
        IReadOnlyList<string>? selected = null,
        IReadOnlyList<EndpointVantage>? vantages = null,
        string? artifactDigest = null,
        TimeSpan? interval = null,
        IReadOnlyList<StrictRegionalEndpoint>? strict = null) => new(
        Service,
        GlobalHostname,
        ["gru", "sfo", "fra"],
        selected ?? ["gru", "sfo", "fra"],
        strict ??
        [
            new StrictRegionalEndpoint("gru", "gru.api.terrascale.tech"),
            new StrictRegionalEndpoint("sfo", "sfo.api.terrascale.tech"),
            new StrictRegionalEndpoint("fra", "fra.api.terrascale.tech"),
        ],
        vantages ??
        [
            new EndpointVantage("gru-edge", ["gru", "sfo", "fra"]),
            new EndpointVantage("sfo-edge", ["sfo", "gru", "fra"]),
            new EndpointVantage("fra-edge", ["fra", "sfo", "gru"]),
        ],
        artifactDigest ?? ArtifactDigest,
        ConfigurationRevision,
        Freshness,
        interval ?? Interval);

    private static VerificationLane Lane(
        AdjustableClock? clock = null,
        EndpointVerificationPlan? plan = null,
        IEndpointRouteResolver? resolver = null,
        IPublicContractCheckExecutor? executor = null)
    {
        var adjustable = clock ?? new AdjustableClock(Start);
        var recordedResolver = new RecordedEndpointResolver(adjustable);
        var recordedExecutor = new RecordedPublicContractCheckExecutor(adjustable);
        return new VerificationLane(
            plan ?? Plan(),
            resolver ?? recordedResolver,
            recordedResolver,
            recordedExecutor,
            adjustable,
            executor ?? recordedExecutor);
    }

    private sealed class VerificationLane
    {
        public VerificationLane(
            EndpointVerificationPlan plan,
            IEndpointRouteResolver resolver,
            RecordedEndpointResolver recordedResolver,
            RecordedPublicContractCheckExecutor recordedExecutor,
            AdjustableClock clock,
            IPublicContractCheckExecutor executor)
        {
            Plan = plan;
            Resolver = recordedResolver;
            Health = new RecordedRegionHealthSource(clock);
            Checks = recordedExecutor;
            Clock = clock;
            Engine = new EndpointVerificationEngine(
                plan, resolver, Health, executor, clock, Sink);
        }

        public EndpointVerificationPlan Plan { get; }
        public RecordedEndpointResolver Resolver { get; }
        public RecordedRegionHealthSource Health { get; }
        public RecordedPublicContractCheckExecutor Checks { get; }
        public AdjustableClock Clock { get; }
        public RecordingSink Sink { get; } = new();
        public EndpointVerificationEngine Engine { get; }

        /// <summary>Records the healthy managed lane: pinned strict routes, nearest-healthy global routes.</summary>
        public void RunHealthy()
        {
            Resolver.RecordStrict("gru.api.terrascale.tech", "gru");
            Resolver.RecordStrict("sfo.api.terrascale.tech", "sfo");
            Resolver.RecordStrict("fra.api.terrascale.tech", "fra");
            Resolver.RecordGlobal("gru-edge", "gru");
            Resolver.RecordGlobal("sfo-edge", "sfo");
            Resolver.RecordGlobal("fra-edge", "fra");
            Health.Set("gru", true, ArtifactDigest, ConfigurationRevision);
            Health.Set("sfo", true, ArtifactDigest, ConfigurationRevision);
            Health.Set("fra", true, ArtifactDigest, ConfigurationRevision);
        }
    }

    private sealed class RecordingSink : IEndpointVerificationSink
    {
        public List<EndpointVerificationReport> Reports { get; } = [];

        public ValueTask OnRoundAsync(EndpointVerificationReport report, CancellationToken cancellationToken)
        {
            Reports.Add(report);
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// W2 fake: a resolver that reports raw transport diagnostics (unknown code, free-form text)
    /// instead of closed-set failure codes. Strict routes fail with the hostile code; global
    /// routes resolve correctly so the test isolates the strict path.
    /// </summary>
    private sealed class HostileResolver(AdjustableClock clock) : IEndpointRouteResolver
    {
        public ValueTask<EndpointRouteResolution> ResolveAsync(
            EndpointProbeTarget target, EndpointVantage? vantage, CancellationToken cancellationToken)
        {
            EndpointRouteResolution resolution = target.RouteKind == EndpointRouteKind.StrictRegional
                ? new(false, null, 1, clock.GetUtcNow(), "dial tcp 203.0.113.9:443: i/o timeout", null)
                : new(true, vantage?.RegionPreference[0], 1, clock.GetUtcNow(), null, null);
            return ValueTask.FromResult(resolution);
        }
    }

    /// <summary>
    /// W2 fake: an executor that executes one check and reports a raw error string as the failure
    /// code plus a free-form note with address material.
    /// </summary>
    private sealed class HostileContractExecutor(AdjustableClock clock) : IPublicContractCheckExecutor
    {
        public ValueTask<PublicContractCheckResult> ExecuteAsync(
            PublicContractCheckDescriptor descriptor, CancellationToken cancellationToken)
        {
            var executed = descriptor.CheckId == "public-contract:sfo:tenant-isolation";
            var result = executed
                ? new PublicContractCheckResult(
                    descriptor, true, false, clock.GetUtcNow(),
                    "upstream 203.0.113.9 refused: dial tcp 203.0.113.9:443",
                    "upstream error: dial tcp 203.0.113.9:443: connection refused")
                : new PublicContractCheckResult(
                    descriptor, false, null, clock.GetUtcNow(), null, null);
            return ValueTask.FromResult(result);
        }
    }

    private class AdjustableClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset now = now;

        public override DateTimeOffset GetUtcNow()
        {
            lock (gate) return now;
        }

        public void Advance(TimeSpan by)
        {
            lock (gate) now += by;
        }

        private readonly object gate = new();
    }

    /// <summary>
    /// A virtual clock whose timers fire only when the test fires them: the interval loop is
    /// fully deterministic and no round can happen without time passing.
    /// </summary>
    private sealed class VirtualTimerClock(DateTimeOffset initial) : AdjustableClock(initial)
    {
        private readonly object gate = new();
        private readonly List<FireableTimer> timers = [];

        public int PendingTimerCount
        {
            get
            {
                lock (gate) return timers.Count;
            }
        }

        public void FirePendingTimers()
        {
            // Snapshot and clear BEFORE firing: firing completes the pending delay inline, the
            // loop's next round re-arms a fresh timer during the cascade, and that new timer must
            // survive this fire.
            FireableTimer[] pending;
            lock (gate)
            {
                pending = [.. timers];
                timers.Clear();
            }
            foreach (var timer in pending)
                timer.Fire();
        }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            ArgumentNullException.ThrowIfNull(callback);
            var timer = new FireableTimer(() => callback(state));
            lock (gate) timers.Add(timer);
            return timer;
        }

        private sealed class FireableTimer(Action fire) : ITimer
        {
            public void Fire() => fire();

            public void Dispose() { }

            public ValueTask DisposeAsync() => ValueTask.CompletedTask;

            public bool Change(TimeSpan dueTime, TimeSpan period) => true;
        }
    }
}

