using System;
using System.Threading;
using System.Threading.Tasks;

using TerraScale.Orchestrator.ControlPlane.Delivery.EndpointVerification;

namespace TerraScale.Orchestrator.Delivery.EndpointVerification;

/// <summary>The typed DNS answer for one hostname from one vantage.</summary>
/// <remarks>Redacted by construction: addresses appear only as a count, never as values.</remarks>
public sealed record EndpointDnsAnswer(bool Resolved, int AddressCount, string? FailureCode = null);

/// <summary>
/// The typed HTTPS identity probe for one hostname: whether it was reached, which region it
/// served, and whether TLS was accepted. <see cref="TlsAccepted"/> is nullable because the probe
/// may not evaluate TLS; <c>null</c> never means accepted.
/// </summary>
public sealed record EndpointHttpsProbe(bool Reached, string? ObservedRegion, bool? TlsAccepted = null, string? FailureCode = null);

/// <summary>
/// LIVE LANE SEAM — resolves hostnames through a real resolver. No implementation of this
/// interface exists in this repository on purpose: wiring one is the live lane authorization gate
/// for ticket TerraScale.Orchestrator#5. The vantage must bind the query (a real resolver serves
/// vantage-dependent answers for the global hostname).
/// </summary>
public interface IEndpointDnsTransport
{
    ValueTask<EndpointDnsAnswer> ResolveAsync(string hostname, string? vantage, CancellationToken cancellationToken);
}

/// <summary>
/// LIVE LANE SEAM — probes the public HTTPS surface of a hostname (status, TLS 1.2+ acceptance,
/// certificate dates, and regional identity through the public contract). No implementation of
/// this interface exists in this repository on purpose.
/// </summary>
public interface IEndpointHttpsProbeTransport
{
    ValueTask<EndpointHttpsProbe> ProbeAsync(string hostname, CancellationToken cancellationToken);
}

/// <summary>
/// SKETCH of the live DNS/HTTP-backed endpoint resolver. The mapping logic is complete and tested
/// against typed fake transports, but it performs no network IO itself and no
/// <see cref="IEndpointDnsTransport"/> or <see cref="IEndpointHttpsProbeTransport"/> implementation
/// exists in this repository: composition must keep wiring <see cref="RecordedEndpointResolver"/>
/// until the live lane is authorized. Wiring this class before then is impossible without adding
/// a live transport, which is the deliberate gate.
/// </summary>
public sealed class DnsHttpEndpointResolver : IEndpointRouteResolver
{
    private readonly IEndpointDnsTransport dns;
    private readonly IEndpointHttpsProbeTransport https;
    private readonly TimeProvider clock;

    public DnsHttpEndpointResolver(
        IEndpointDnsTransport dns,
        IEndpointHttpsProbeTransport https,
        TimeProvider? clock = null)
    {
        this.dns = dns ?? throw new ArgumentNullException(nameof(dns));
        this.https = https ?? throw new ArgumentNullException(nameof(https));
        this.clock = clock ?? TimeProvider.System;
    }

    public async ValueTask<EndpointRouteResolution> ResolveAsync(
        EndpointProbeTarget target, EndpointVantage? vantage, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        cancellationToken.ThrowIfCancellationRequested();
        var dnsAnswer = await dns.ResolveAsync(target.Hostname, vantage?.Name, cancellationToken)
            .ConfigureAwait(false) ?? new EndpointDnsAnswer(false, 0, null);
        var observedAt = clock.GetUtcNow();
        if (!dnsAnswer.Resolved)
            return new EndpointRouteResolution(
                false, null, dnsAnswer.AddressCount, observedAt,
                // Transport-authored codes are untrusted: unknown codes collapse to the stable
                // fallback here so every consumer of this typed resolution sees a closed-set code.
                EndpointVerificationRedaction.SanitizeFailureCode(dnsAnswer.FailureCode) ??
                    EndpointFailureCode.DnsFailure,
                null);
        var probe = await https.ProbeAsync(target.Hostname, cancellationToken).ConfigureAwait(false)
            ?? new EndpointHttpsProbe(false, null, null, null);
        if (!probe.Reached)
            return new EndpointRouteResolution(
                false, null, dnsAnswer.AddressCount, observedAt,
                EndpointVerificationRedaction.SanitizeFailureCode(probe.FailureCode) ??
                    EndpointFailureCode.ProbeUnreachable,
                probe.TlsAccepted);
        return new EndpointRouteResolution(
            true, probe.ObservedRegion, dnsAnswer.AddressCount, observedAt, null, probe.TlsAccepted);
    }
}

