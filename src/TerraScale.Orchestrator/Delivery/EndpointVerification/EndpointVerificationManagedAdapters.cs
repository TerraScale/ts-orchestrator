using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using TerraScale.Orchestrator.ControlPlane.Delivery.EndpointVerification;

namespace TerraScale.Orchestrator.Delivery.EndpointVerification;

/// <summary>
/// The managed/recorded endpoint resolver: composition's only wireable resolver until the live
/// lane is authorized. It serves explicitly recorded routing truth and never performs IO. An
/// unrecorded resolution fails closed with <see cref="EndpointFailureCode.NotRecorded"/> — absent
/// evidence is never treated as a healthy route.
/// </summary>
public sealed class RecordedEndpointResolver : IEndpointRouteResolver
{
    private readonly object gate = new();
    private readonly Dictionary<string, RecordedRoute> strictByHostname = new(StringComparer.Ordinal);
    private readonly Dictionary<string, RecordedRoute> globalByVantage = new(StringComparer.Ordinal);
    private readonly HashSet<string> throwingStrictHostnames = new(StringComparer.Ordinal);
    private readonly TimeProvider clock;

    public RecordedEndpointResolver(TimeProvider? clock = null) => this.clock = clock ?? TimeProvider.System;

    /// <summary>Makes one strict hostname fail like an unreachable adapter (test hook).</summary>
    public RecordedEndpointResolver ThrowForStrict(string hostname)
    {
        lock (gate) throwingStrictHostnames.Add(hostname);
        return this;
    }

    /// <summary>Records a strict endpoint resolving to its pinned region.</summary>
    public RecordedEndpointResolver RecordStrict(string hostname, string observedRegion, bool? tlsAccepted = null) =>
        RecordStrict(hostname, new RecordedRoute(true, observedRegion, 1, null, tlsAccepted));

    /// <summary>Records a strict endpoint failing (for example a DNS failure).</summary>
    public RecordedEndpointResolver RecordStrictFailure(string hostname, string failureCode) =>
        RecordStrict(hostname, new RecordedRoute(false, null, 0, failureCode, null));

    /// <summary>Records the global endpoint routing one vantage to a region.</summary>
    public RecordedEndpointResolver RecordGlobal(string vantage, string observedRegion, bool? tlsAccepted = null) =>
        RecordGlobal(vantage, new RecordedRoute(true, observedRegion, 1, null, tlsAccepted));

    /// <summary>Records the global endpoint failing for one vantage.</summary>
    public RecordedEndpointResolver RecordGlobalFailure(string vantage, string failureCode) =>
        RecordGlobal(vantage, new RecordedRoute(false, null, 0, failureCode, null));

    public ValueTask<EndpointRouteResolution> ResolveAsync(
        EndpointProbeTarget target, EndpointVantage? vantage, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        cancellationToken.ThrowIfCancellationRequested();
        RecordedRoute route = default;
        bool present;
        lock (gate)
        {
            if (target.RouteKind == EndpointRouteKind.StrictRegional && throwingStrictHostnames.Contains(target.Hostname))
                throw new InvalidOperationException("The recorded endpoint resolver is unavailable.");
            if (target.RouteKind == EndpointRouteKind.StrictRegional)
                present = strictByHostname.TryGetValue(target.Hostname, out route);
            else if (vantage is not null)
                present = globalByVantage.TryGetValue(vantage.Name, out route);
            else
                present = false;
        }
        var observedAt = clock.GetUtcNow();
        var resolution = present
            ? new EndpointRouteResolution(route.Resolved, route.ObservedRegion, route.AddressCount, observedAt,
                route.FailureCode, route.TlsAccepted)
            : new EndpointRouteResolution(false, null, 0, observedAt, EndpointFailureCode.NotRecorded, null);
        return ValueTask.FromResult(resolution);
    }

    private RecordedEndpointResolver RecordStrict(string hostname, RecordedRoute route)
    {
        lock (gate) strictByHostname[hostname] = route;
        return this;
    }

    private RecordedEndpointResolver RecordGlobal(string vantage, RecordedRoute route)
    {
        lock (gate) globalByVantage[vantage] = route;
        return this;
    }

    private readonly record struct RecordedRoute(
        bool Resolved, string? ObservedRegion, int AddressCount, string? FailureCode, bool? TlsAccepted);
}

/// <summary>
/// The managed/recorded regional health source. Snapshots are explicitly recorded; a region with
/// no record reports no snapshot, which the engine classifies as unknown health (never healthy).
/// </summary>
public sealed class RecordedRegionHealthSource : IRegionHealthSource
{
    private readonly object gate = new();
    private readonly Dictionary<string, RegionHealthSnapshot> snapshots = new(StringComparer.Ordinal);
    private readonly HashSet<string> throwingRegions = new(StringComparer.Ordinal);
    private readonly TimeProvider clock;

    public RecordedRegionHealthSource(TimeProvider? clock = null) => this.clock = clock ?? TimeProvider.System;

    /// <summary>Makes one region fail like an unreachable adapter (test hook).</summary>
    public RecordedRegionHealthSource ThrowFor(string region)
    {
        lock (gate) throwingRegions.Add(region);
        return this;
    }

    public RecordedRegionHealthSource Set(
        string region,
        bool? healthy,
        string? artifactDigest = null,
        string? configurationRevision = null,
        DateTimeOffset? observedAt = null)
    {
        lock (gate)
        {
            throwingRegions.Remove(region);
            snapshots[region] = new RegionHealthSnapshot(
                region, healthy, observedAt ?? clock.GetUtcNow(), artifactDigest, configurationRevision);
        }
        return this;
    }

    public RecordedRegionHealthSource Remove(string region)
    {
        lock (gate) snapshots.Remove(region);
        return this;
    }

    public ValueTask<RegionHealthSnapshot?> ObserveAsync(string region, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (throwingRegions.Contains(region))
                throw new InvalidOperationException("The recorded health source is unavailable.");
            return ValueTask.FromResult(snapshots.TryGetValue(region, out var snapshot) ? snapshot : null);
        }
    }
}

/// <summary>
/// The managed/recorded public-contract check executor. Unscripted checks report
/// <c>Executed=false</c> so their evidence stays descriptor-only (deferred) and never changes a
/// claim. Live evaluation through the public contracts is deferred with the live lane.
/// </summary>
public sealed class RecordedPublicContractCheckExecutor : IPublicContractCheckExecutor
{
    public const string DeferredNote = "live evaluation deferred; descriptor recorded only";

    private readonly object gate = new();
    private readonly Dictionary<string, PublicContractCheckResult> results = new(StringComparer.Ordinal);
    private readonly HashSet<string> throwingCheckIds = new(StringComparer.Ordinal);
    private readonly HashSet<string> nullingCheckIds = new(StringComparer.Ordinal);
    private readonly TimeProvider clock;

    public RecordedPublicContractCheckExecutor(TimeProvider? clock = null) => this.clock = clock ?? TimeProvider.System;

    /// <summary>Makes one check's executor throw like an unreachable source (test hook).</summary>
    public RecordedPublicContractCheckExecutor ThrowFor(string checkId)
    {
        lock (gate) throwingCheckIds.Add(checkId);
        return this;
    }

    /// <summary>Makes one check's executor return null like a failed source (test hook).</summary>
    public RecordedPublicContractCheckExecutor ReturnNullFor(string checkId)
    {
        lock (gate) nullingCheckIds.Add(checkId);
        return this;
    }

    public RecordedPublicContractCheckExecutor Set(string checkId, bool passed, string? note = null)
    {
        lock (gate)
        {
            var descriptor = new PublicContractCheckDescriptor(checkId, string.Empty, string.Empty, string.Empty, string.Empty);
            results[checkId] = new PublicContractCheckResult(descriptor, true, passed, clock.GetUtcNow(), null, note);
        }
        return this;
    }

    public RecordedPublicContractCheckExecutor Clear(string checkId)
    {
        lock (gate) results.Remove(checkId);
        return this;
    }

    public ValueTask<PublicContractCheckResult> ExecuteAsync(
        PublicContractCheckDescriptor descriptor, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        cancellationToken.ThrowIfCancellationRequested();
        PublicContractCheckResult? scripted;
        lock (gate)
        {
            if (throwingCheckIds.Contains(descriptor.CheckId))
                throw new InvalidOperationException("The recorded contract-check executor is unavailable.");
            if (nullingCheckIds.Contains(descriptor.CheckId))
                return ValueTask.FromResult<PublicContractCheckResult>(null!);
            scripted = results.TryGetValue(descriptor.CheckId, out var recorded)
                ? recorded with { Descriptor = descriptor }
                : null;
        }
        var result = scripted ?? new PublicContractCheckResult(
            descriptor, false, null, clock.GetUtcNow(), null, DeferredNote);
        return ValueTask.FromResult(result);
    }
}
