using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace TerraScale.Orchestrator.ControlPlane.Delivery.EndpointVerification;

/// <summary>
/// The continuous endpoint verification runtime (ticket TerraScale.Orchestrator#5). Each round
/// verifies the global endpoint routes every vantage to the nearest HEALTHY selected region and
/// every strict regional endpoint keeps its own affinity, classifies regional health with
/// freshness and identity binding, evaluates public-contract checks, and derives a truthful
/// availability claim. The claim is data: a failed check changes it, and nothing here touches
/// authorization policy.
/// </summary>
/// <remarks>
/// The engine is a coordinator over observation seams: routing, health, and contract checks are
/// typed interfaces (managed/recorded adapters until the live lane is authorized), and time comes
/// from the injected <see cref="TimeProvider"/> so the interval loop is virtual-clock testable.
/// Infrastructure failures become failed or deferred observations — a round never throws an
/// adapter exception, because an unobservable round must not look like a healthy one.
/// </remarks>
public sealed class EndpointVerificationEngine
{
    public const int MaximumServiceLength = 128;
    public const int MaximumHostnameLength = 253;
    public const int MaximumRegionLength = 32;
    public const int MaximumVantageNameLength = 64;
    public const int MaximumRegionCount = 64;
    public const int MaximumVantageCount = 16;
    public const int MaximumVantagePreferenceCount = 64;

    private readonly EndpointVerificationPlan _plan;
    private readonly IEndpointRouteResolver _resolver;
    private readonly IRegionHealthSource _healthSource;
    private readonly IPublicContractCheckExecutor _contractChecks;
    private readonly TimeProvider _clock;
    private readonly IEndpointVerificationSink? _sink;
    private readonly Dictionary<string, EndpointRegionAvailability> _availability = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> _lastTransitionAt = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string?> _lastFailureCode = new(StringComparer.Ordinal);
    private long _rounds;

    public EndpointVerificationEngine(
        EndpointVerificationPlan plan,
        IEndpointRouteResolver resolver,
        IRegionHealthSource healthSource,
        IPublicContractCheckExecutor contractChecks,
        TimeProvider clock,
        IEndpointVerificationSink? sink = null)
    {
        _plan = ValidatePlan(plan);
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _healthSource = healthSource ?? throw new ArgumentNullException(nameof(healthSource));
        _contractChecks = contractChecks ?? throw new ArgumentNullException(nameof(contractChecks));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _sink = sink;
        var claimedAt = _clock.GetUtcNow();
        foreach (var region in _plan.QualifiedRegions)
        {
            _availability[region] = EndpointRegionAvailability.Unknown;
            _lastTransitionAt[region] = claimedAt;
            _lastFailureCode[region] = null;
        }
        CurrentClaim = BuildClaim(claimedAt, globalRoutingAvailable: false);
    }

    /// <summary>Number of completed rounds.</summary>
    public long RoundsCompleted => _rounds;

    /// <summary>The latest completed round's operator state.</summary>
    public EndpointVerificationReport? LatestReport { get; private set; }

    /// <summary>The current public verified-region claim.</summary>
    public VerifiedRegionSet CurrentClaim { get; private set; }

    /// <summary>
    /// When the next interval-driven round is due; null before the first round. This is an
    /// approximation computed from the last round's completion time: the loop's real cadence
    /// drifts by each round's duration and does not catch up with bursts.
    /// </summary>
    public DateTimeOffset? NextRoundAt { get; private set; }

    /// <summary>
    /// Runs verification rounds continuously on the plan interval until cancelled. Single flight:
    /// the loop itself performs at most one round at a time.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            await RunRoundAsync(cancellationToken).ConfigureAwait(false);
            await Task.Delay(_plan.Interval, _clock, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Runs exactly one verification round and returns its redacted report. Single-flight
    /// contract: the engine does not serialize concurrent direct calls — callers driving this
    /// surface directly (instead of <see cref="RunAsync"/>) must not invoke it concurrently.
    /// Within one round, <see cref="LatestReport"/>, <see cref="CurrentClaim"/>, and
    /// <see cref="NextRoundAt"/> are published together after the round completes, so a reader
    /// never observes one round's claim mixed with another round's report.
    /// </summary>
    public async ValueTask<EndpointVerificationReport> RunRoundAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var observedAt = _clock.GetUtcNow();
        var roundId = Interlocked.Increment(ref _rounds);
        var observations = new List<EndpointObservation>();
        var health = new Dictionary<string, HealthClassification>(StringComparer.Ordinal);

        foreach (var region in _plan.QualifiedRegions)
        {
            var classification = await ClassifyHealthAsync(region, observedAt, cancellationToken).ConfigureAwait(false);
            health[region] = classification;
            observations.Add(HealthObservation(region, observedAt, classification));
        }

        var strictOutcome = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var endpoint in _plan.StrictRegionalEndpoints)
        {
            var failure = await ObserveStrictEndpointAsync(endpoint, observedAt, observations, cancellationToken)
                .ConfigureAwait(false);
            strictOutcome[endpoint.Region] = failure;
        }

        var globalAvailable = await ObserveGlobalEndpointAsync(health, observedAt, observations, cancellationToken)
            .ConfigureAwait(false);

        var contractOutcome = new Dictionary<string, ContractRoundOutcome>(StringComparer.Ordinal);
        foreach (var endpoint in _plan.StrictRegionalEndpoints)
            contractOutcome[endpoint.Region] = await ObserveContractChecksAsync(
                endpoint.Region, observedAt, observations, cancellationToken).ConfigureAwait(false);

        var transitions = ApplyAvailabilityTransitions(
            strictOutcome, health, contractOutcome, roundId, observedAt);
        var claim = BuildClaim(
            observedAt,
            globalAvailable,
            contractOutcome.ToDictionary(
                static pair => pair.Key,
                static pair => pair.Value.AnyExecuted
                    ? EndpointContractEvidence.WithContractChecks
                    : EndpointContractEvidence.RoutingHealthOnly,
                StringComparer.Ordinal));
        var report = new EndpointVerificationReport(
            EndpointVerificationReport.CurrentSchemaVersion,
            _plan.Service,
            roundId,
            observedAt,
            _plan.ArtifactDigest,
            _plan.ConfigurationRevision,
            observations,
            transitions,
            claim);

        LatestReport = report;
        CurrentClaim = claim;
        NextRoundAt = observedAt + _plan.Interval;
        await PublishAsync(report, cancellationToken).ConfigureAwait(false);
        return report;
    }

    private async Task<HealthClassification> ClassifyHealthAsync(
        string region, DateTimeOffset observedAt, CancellationToken cancellationToken)
    {
        RegionHealthSnapshot? snapshot;
        try
        {
            snapshot = await _healthSource.ObserveAsync(region, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsAdapterFailure(exception))
        {
            return new HealthClassification(null, EndpointFailureCode.SourceUnavailable);
        }
        if (snapshot is null)
            return new HealthClassification(null, EndpointFailureCode.UnknownHealth);
        if (observedAt - snapshot.ObservedAt > _plan.HealthFreshnessWindow)
            return new HealthClassification(snapshot, EndpointFailureCode.StaleHealth);
        if (snapshot.Healthy is null)
            return new HealthClassification(snapshot, EndpointFailureCode.UnknownHealth);
        if (snapshot.Healthy is false)
            return new HealthClassification(snapshot, EndpointFailureCode.UnhealthyRegion);
        if (IsBindingMismatch(snapshot))
            return new HealthClassification(snapshot, EndpointFailureCode.BindingMismatch);
        return new HealthClassification(snapshot, null);
    }

    private bool IsBindingMismatch(RegionHealthSnapshot snapshot) =>
        _plan.ArtifactDigest is { } artifact &&
        !string.Equals(snapshot.ArtifactDigest, artifact, StringComparison.OrdinalIgnoreCase) ||
        _plan.ConfigurationRevision is { } revision &&
        !string.Equals(snapshot.ConfigurationRevision, revision, StringComparison.OrdinalIgnoreCase);

    private EndpointObservation HealthObservation(
        string region, DateTimeOffset observedAt, HealthClassification classification) =>
        new(_plan.Service,
            region,
            _plan.ArtifactDigest,
            _plan.ConfigurationRevision,
            observedAt,
            EndpointProbeKind.RegionHealth,
            classification.IsHealthy ? EndpointObservationStatus.Passed : EndpointObservationStatus.Failed,
            classification.FailureCode,
            Note: classification.FailureCode == EndpointFailureCode.BindingMismatch
                ? "the region's health evidence was observed under a different artifact or configuration identity"
                : null);

    private async Task<string?> ObserveStrictEndpointAsync(
        StrictRegionalEndpoint endpoint,
        DateTimeOffset observedAt,
        List<EndpointObservation> observations,
        CancellationToken cancellationToken)
    {
        var target = new EndpointProbeTarget(endpoint.Hostname, endpoint.Region, EndpointRouteKind.StrictRegional);
        var resolution = await ResolveGuardedAsync(target, null, cancellationToken).ConfigureAwait(false);
        string? failure;
        if (!resolution.Resolved)
            failure = EndpointVerificationRedaction.SanitizeFailureCode(resolution.FailureCode) ??
                EndpointFailureCode.DnsFailure;
        else if (!string.Equals(resolution.ObservedRegion, endpoint.Region, StringComparison.Ordinal))
            // Strict endpoints never silently fail over: routing to ANY other region — healthy or
            // not — is the typed violation, not a fallback.
            failure = EndpointFailureCode.StrictAffinityViolation;
        else if (resolution.TlsAccepted is false)
            failure = EndpointFailureCode.TlsRejected;
        else
            failure = null;
        var status = failure is null ? EndpointObservationStatus.Passed : EndpointObservationStatus.Failed;
        observations.Add(new EndpointObservation(
            _plan.Service, endpoint.Region, _plan.ArtifactDigest, _plan.ConfigurationRevision, observedAt,
            EndpointProbeKind.StrictRoute, status, failure,
            ExpectedRegion: endpoint.Region, ObservedRegion: resolution.ObservedRegion));
        return failure;
    }

    private async Task<bool> ObserveGlobalEndpointAsync(
        IReadOnlyDictionary<string, HealthClassification> health,
        DateTimeOffset observedAt,
        List<EndpointObservation> observations,
        CancellationToken cancellationToken)
    {
        if (_plan.Vantages.Count == 0)
            return false;
        var target = new EndpointProbeTarget(_plan.GlobalHostname, "global", EndpointRouteKind.Global);
        var allPassed = true;
        foreach (var vantage in _plan.Vantages)
        {
            var expected = NearestHealthySelectedRegion(vantage, health);
            var resolution = await ResolveGuardedAsync(target, vantage, cancellationToken).ConfigureAwait(false);
            string status;
            string? failure;
            if (expected is null)
                // Unknown or unhealthy regions are never eligible as healthy: the global endpoint
                // must stop routing to them, not quietly keep them.
                failure = EndpointFailureCode.NoHealthySelectedRegion;
            else if (!resolution.Resolved)
                failure = EndpointVerificationRedaction.SanitizeFailureCode(resolution.FailureCode) ??
                    EndpointFailureCode.DnsFailure;
            else if (!string.Equals(resolution.ObservedRegion, expected, StringComparison.Ordinal))
                failure = EndpointFailureCode.Misroute;
            else if (resolution.TlsAccepted is false)
                failure = EndpointFailureCode.TlsRejected;
            else
                failure = null;
            status = failure is null ? EndpointObservationStatus.Passed : EndpointObservationStatus.Failed;
            allPassed &= failure is null;
            observations.Add(new EndpointObservation(
                _plan.Service, "global", _plan.ArtifactDigest, _plan.ConfigurationRevision, observedAt,
                EndpointProbeKind.GlobalRoute, status, failure,
                Vantage: vantage.Name, ExpectedRegion: expected, ObservedRegion: resolution.ObservedRegion));
        }
        return allPassed;
    }

    private string? NearestHealthySelectedRegion(
        EndpointVantage vantage, IReadOnlyDictionary<string, HealthClassification> health)
    {
        foreach (var region in vantage.RegionPreference)
            if (_plan.SelectedRegions.Contains(region, StringComparer.Ordinal) &&
                health.TryGetValue(region, out var classification) && classification.IsHealthy)
                return region;
        return null;
    }

    private const string DeferredContractNote = "live evaluation deferred; descriptor recorded only";
    private const string UnavailableContractNote =
        "check source unavailable; not the authorized live-lane deferral";

    private async Task<ContractRoundOutcome> ObserveContractChecksAsync(
        string region, DateTimeOffset observedAt, List<EndpointObservation> observations, CancellationToken cancellationToken)
    {
        string? firstFailure = null;
        var anyExecuted = false;
        foreach (var descriptor in StandardPublicContractChecks.ForRegion(region))
        {
            PublicContractCheckResult result;
            try
            {
                result = await _contractChecks.ExecuteAsync(descriptor, cancellationToken).ConfigureAwait(false)
                    ?? new PublicContractCheckResult(descriptor, false, null, observedAt,
                        EndpointFailureCode.SourceUnavailable, null);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception) when (IsAdapterFailure(exception))
            {
                result = new PublicContractCheckResult(descriptor, false, null, observedAt,
                    EndpointFailureCode.SourceUnavailable, null);
            }
            if (result.Executed)
                anyExecuted = true;
            // Adapter-authored text is untrusted: unknown codes collapse to the stable fallback
            // and unbounded notes are dropped at this boundary, before anything is published.
            var note = EndpointVerificationRedaction.SanitizeNote(result.Note);
            string status;
            string? failure;
            if (!result.Executed)
            {
                if (EndpointVerificationRedaction.SanitizeFailureCode(result.FailureCode) is { } unavailable)
                {
                    // The check did not execute because its SOURCE failed (executor threw,
                    // returned null, or reported a cause). This must stay distinguishable from the
                    // authorized live-lane deferral: distinct status plus the retained code.
                    status = EndpointObservationStatus.Unavailable;
                    failure = unavailable;
                    note = UnavailableContractNote;
                }
                else
                {
                    // Descriptor-only evidence at this fidelity: recorded, never counted as a
                    // pass, and never allowed to change the claim.
                    status = EndpointObservationStatus.Deferred;
                    failure = null;
                    note ??= DeferredContractNote;
                }
            }
            else if (result.Passed is not true)
            {
                status = EndpointObservationStatus.Failed;
                failure = EndpointVerificationRedaction.SanitizeFailureCode(result.FailureCode) ??
                    EndpointFailureCode.ContractCheckFailed;
                firstFailure ??= failure;
            }
            else
            {
                status = EndpointObservationStatus.Passed;
                failure = null;
            }
            observations.Add(new EndpointObservation(
                _plan.Service, region, _plan.ArtifactDigest, _plan.ConfigurationRevision, observedAt,
                EndpointProbeKind.ContractCheck, status, failure,
                Note: note ?? descriptor.Kind));
        }
        return new ContractRoundOutcome(firstFailure, anyExecuted);
    }

    private List<EndpointRegionTransition> ApplyAvailabilityTransitions(
        IReadOnlyDictionary<string, string?> strictOutcome,
        IReadOnlyDictionary<string, HealthClassification> health,
        IReadOnlyDictionary<string, ContractRoundOutcome> contractOutcome,
        long roundId,
        DateTimeOffset observedAt)
    {
        var transitions = new List<EndpointRegionTransition>();
        foreach (var region in _plan.QualifiedRegions)
        {
            // Truthful transitions only: Available requires this round's strict pass, fresh bound
            // health, and no failed executed contract check; anything else is Outage — including
            // unknown, because unknown health is never eligible as healthy. Not-executed checks
            // (deferred or unavailable) are absence of evidence: they never gate the claim, and
            // the per-region ContractEvidence field carries that honesty instead.
            strictOutcome.TryGetValue(region, out var strictFailure);
            var healthy = health.TryGetValue(region, out var classification) && classification.IsHealthy;
            contractOutcome.TryGetValue(region, out var contractRound);
            var available = strictFailure is null && healthy && contractRound.FirstFailure is null;
            var next = available ? EndpointRegionAvailability.Available : EndpointRegionAvailability.Outage;
            var failure = available ? null : RegionFailureCode(strictFailure, classification, contractRound.FirstFailure);
            var current = _availability[region];
            if (current != next)
            {
                transitions.Add(new EndpointRegionTransition(region, current, next, roundId, observedAt, failure));
                _availability[region] = next;
                _lastTransitionAt[region] = observedAt;
            }
            _lastFailureCode[region] = failure;
        }
        return transitions;
    }

    private static string? RegionFailureCode(
        string? strictFailure, HealthClassification classification, string? contractFailure) =>
        strictFailure ??
        (classification.IsHealthy ? null : classification.FailureCode) ??
        contractFailure;

    private VerifiedRegionSet BuildClaim(
        DateTimeOffset claimedAt,
        bool globalRoutingAvailable,
        IReadOnlyDictionary<string, EndpointContractEvidence>? contractEvidence = null) =>
        new(VerifiedRegionSet.CurrentSchemaVersion,
            _plan.Service,
            claimedAt,
            _plan.ArtifactDigest,
            _plan.ConfigurationRevision,
            globalRoutingAvailable,
            _plan.QualifiedRegions.Select(region => new VerifiedRegion(
                region,
                _availability[region],
                _plan.SelectedRegions.Contains(region, StringComparer.Ordinal),
                _lastTransitionAt[region],
                _lastFailureCode[region],
                contractEvidence is not null && contractEvidence.TryGetValue(region, out var evidence)
                    ? evidence
                    : EndpointContractEvidence.RoutingHealthOnly)).ToArray());

    private async ValueTask<EndpointRouteResolution> ResolveGuardedAsync(
        EndpointProbeTarget target, EndpointVantage? vantage, CancellationToken cancellationToken)
    {
        try
        {
            return await _resolver.ResolveAsync(target, vantage, cancellationToken).ConfigureAwait(false)
                ?? new EndpointRouteResolution(false, null, 0, _clock.GetUtcNow(), EndpointFailureCode.ResolverUnavailable);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsAdapterFailure(exception))
        {
            return new EndpointRouteResolution(false, null, 0, _clock.GetUtcNow(), EndpointFailureCode.ResolverUnavailable);
        }
    }

    private async ValueTask PublishAsync(EndpointVerificationReport report, CancellationToken cancellationToken)
    {
        if (_sink is null)
            return;
        try
        {
            await _sink.OnRoundAsync(report, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsAdapterFailure(exception))
        {
            // An operator sink that is down never stops verification and never falsifies a round:
            // the report is already durably returned to the caller.
        }
    }

    private static bool IsAdapterFailure(Exception exception) =>
        exception is not OutOfMemoryException and not StackOverflowException and
            not AccessViolationException and not OperationCanceledException;

    private static EndpointVerificationPlan ValidatePlan(EndpointVerificationPlan? plan)
    {
        if (plan is null)
            throw new ArgumentNullException(nameof(plan));
        if (!ValidText(plan.Service, MaximumServiceLength))
            throw new ArgumentException("The verification plan service is invalid.", nameof(plan));
        if (!ValidHostname(plan.GlobalHostname))
            throw new ArgumentException("The verification plan global hostname is invalid.", nameof(plan));
        if (plan.QualifiedRegions is not { Count: > 0 and <= MaximumRegionCount } qualified ||
            qualified.Any(static region => !ValidText(region, MaximumRegionLength)) ||
            qualified.Distinct(StringComparer.Ordinal).Count() != qualified.Count)
            throw new ArgumentException("The verification plan qualified-region set is invalid.", nameof(plan));
        if (plan.SelectedRegions is null ||
            plan.SelectedRegions.Any(selected => !qualified.Contains(selected, StringComparer.Ordinal)) ||
            plan.SelectedRegions.Distinct(StringComparer.Ordinal).Count() != plan.SelectedRegions.Count)
            throw new ArgumentException("The verification plan selected-region set is invalid.", nameof(plan));
        if (plan.StrictRegionalEndpoints is not { Count: > 0 } strict ||
            strict.Any(static endpoint => endpoint is null) ||
            strict.Any(endpoint => !ValidText(endpoint.Region, MaximumRegionLength) || !ValidHostname(endpoint.Hostname)) ||
            strict.Select(static endpoint => endpoint.Region).Distinct(StringComparer.Ordinal).Count() != strict.Count ||
            strict.Select(static endpoint => endpoint.Hostname).Distinct(StringComparer.Ordinal).Count() != strict.Count ||
            strict.Any(endpoint => !qualified.Contains(endpoint.Region, StringComparer.Ordinal)))
            throw new ArgumentException("The verification plan strict-endpoint set is invalid.", nameof(plan));
        // Every qualified region must be covered by exactly one strict endpoint: an uncovered
        // region would reach Available on health evidence alone with zero routing evidence.
        if (!strict.Select(static endpoint => endpoint.Region).ToHashSet(StringComparer.Ordinal).SetEquals(qualified))
            throw new ArgumentException(
                "The verification plan strict endpoints must cover the qualified regions exactly.", nameof(plan));
        if (plan.Vantages is not { Count: > 0 and <= MaximumVantageCount } vantages ||
            vantages.Any(static vantage => vantage is null) ||
            vantages.Any(vantage => !ValidText(vantage.Name, MaximumVantageNameLength)) ||
            vantages.Select(static vantage => vantage.Name).Distinct(StringComparer.Ordinal).Count() != vantages.Count ||
            vantages.Any(vantage => vantage.RegionPreference is not { Count: > 0 and <= MaximumVantagePreferenceCount } ||
                vantage.RegionPreference.Any(region => !qualified.Contains(region, StringComparer.Ordinal)) ||
                vantage.RegionPreference.Distinct(StringComparer.Ordinal).Count() != vantage.RegionPreference.Count))
            throw new ArgumentException("The verification plan vantage set is invalid.", nameof(plan));
        if (plan.HealthFreshnessWindow <= TimeSpan.Zero || plan.Interval <= TimeSpan.Zero)
            throw new ArgumentException("The verification plan windows must be positive.", nameof(plan));
        if (plan.ArtifactDigest is not null && !IsDigest(plan.ArtifactDigest) ||
            plan.ConfigurationRevision is not null && !IsDigest(plan.ConfigurationRevision))
            throw new ArgumentException("The verification plan identity binding must be a sha256 digest.", nameof(plan));
        return plan;

        static bool ValidText(string? value, int maximum) =>
            value is { Length: > 0 } && value.Length <= maximum &&
            !value.Any(char.IsControl) && !value.Any(char.IsWhiteSpace);

        static bool ValidHostname(string? value) =>
            value is { Length: > 0 } && value.Length <= MaximumHostnameLength &&
            !value.Any(char.IsControl) && !value.Any(char.IsWhiteSpace) &&
            value.All(static c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_') &&
            !value.StartsWith('-');

        static bool IsDigest(string value) => value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) &&
            value[7..].Length == 64 &&
            value[7..].All(static c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
    }

    private readonly record struct HealthClassification(RegionHealthSnapshot? Snapshot, string? FailureCode)
    {
        public bool IsHealthy => Snapshot is { Healthy: true } && FailureCode is null;
    }

    private readonly record struct ContractRoundOutcome(string? FirstFailure, bool AnyExecuted);
}
