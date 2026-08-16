using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using Oci.Common;
using Oci.Common.Auth;
using Oci.CoreService;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using Oci.CoreService.Responses;

namespace TerraScale.Orchestrator.ControlPlane.Providers;

/// <summary>
/// Immutable, region-bound configuration for the OCI Block Volume expansion transport.
/// The endpoint is deliberately constrained to the OCI regional IaaS root so that a
/// provider response cannot be redirected to an untrusted service or another region.
/// </summary>
internal sealed class OciBlockVolumeExpansionTransportConfiguration
{
    internal OciBlockVolumeExpansionTransportConfiguration(string configuredRegion, string endpoint)
    {
        ConfiguredRegion = RequireRegion(configuredRegion);
        Endpoint = ParseEndpoint(ConfiguredRegion, endpoint);
        EndpointText = Endpoint.ToString().TrimEnd('/');
    }

    internal OciBlockVolumeExpansionTransportConfiguration(string configuredRegion, Uri endpoint)
        : this(configuredRegion, endpoint?.ToString() ?? throw new ArgumentNullException(nameof(endpoint)))
    {
    }

    internal string ConfiguredRegion { get; }
    internal Uri Endpoint { get; }
    internal string EndpointText { get; }

    internal static OciBlockVolumeExpansionTransportConfiguration Create(
        string configuredRegion,
        string endpoint) => new(configuredRegion, endpoint);

    internal static Uri ParseEndpoint(string configuredRegion, string endpoint)
    {
        ArgumentNullException.ThrowIfNull(configuredRegion);
        ArgumentNullException.ThrowIfNull(endpoint);

        var region = RequireRegion(configuredRegion);
        var endpointText = endpoint.Trim();
        if (!Uri.TryCreate(endpointText, UriKind.Absolute, out var endpointUri) ||
            endpointUri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(endpointUri.UserInfo) ||
            !string.IsNullOrEmpty(endpointUri.Query) ||
            !string.IsNullOrEmpty(endpointUri.Fragment) ||
            endpointUri.AbsolutePath != "/" ||
            !endpointUri.IsDefaultPort ||
            !string.Equals(endpointUri.Host, ExpectedHost(region), StringComparison.Ordinal))
        {
            throw new ArgumentException("The OCI Block Volume endpoint is invalid.", nameof(endpoint));
        }

        return endpointUri;
    }

    private static string RequireRegion(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length is < 1 or > 63 || value[0] == '-' || value[^1] == '-')
            throw new ArgumentException("The configured OCI region is not canonical.", nameof(value));

        var previousWasSeparator = false;
        foreach (var character in value)
        {
            var valid = character is >= 'a' and <= 'z' || character is >= '0' and <= '9' || character == '-';
            if (!valid || character == '-' && previousWasSeparator)
                throw new ArgumentException("The configured OCI region is not canonical.", nameof(value));
            previousWasSeparator = character == '-';
        }

        return value;
    }

    private static string ExpectedHost(string region) => $"iaas.{region}.oraclecloud.com";
}

/// <summary>Constructs the credential-free-at-rest OCI transport with instance-principal auth.</summary>
internal static class OciBlockVolumeExpansionTransportFactory
{
    internal const int ClientTimeoutMillis = 30_000;

    internal static OciBlockVolumeExpansionTransport Create(
        OciBlockVolumeExpansionTransportConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        // Configuration is fully validated before instance-principal resolution or client
        // construction. No credential material is accepted by this factory.
        var provider = new InstancePrincipalsAuthenticationDetailsProvider();
        var clientConfiguration = new ClientConfiguration { TimeoutMillis = ClientTimeoutMillis };
        BlockstorageClient? client = null;
        try
        {
            client = new BlockstorageClient(provider, clientConfiguration, configuration.EndpointText);
            return new OciBlockVolumeExpansionTransport(client);
        }
        catch
        {
            client?.Dispose();
            throw;
        }
    }

    internal static OciBlockVolumeExpansionTransport Create(
        string configuredRegion,
        string endpoint) => Create(new OciBlockVolumeExpansionTransportConfiguration(configuredRegion, endpoint));

    internal static OciBlockVolumeExpansionTransport CreateForInstancePrincipal(
        string configuredRegion,
        string endpoint) => Create(configuredRegion, endpoint);
}

/// <summary>
/// OCI SDK boundary for the already-authorized Block Volume expansion intent.
/// It performs no retries and never emits provider identifiers or response details.
/// </summary>
internal sealed class OciBlockVolumeExpansionTransport : IOciBlockVolumeExpansionTransport, IDisposable
{
    private readonly BlockstorageClient client;
    private int disposed;

    internal OciBlockVolumeExpansionTransport(BlockstorageClient client)
    {
        this.client = client ?? throw new ArgumentNullException(nameof(client));
    }

    public async ValueTask<OciBlockVolumeObservation?> GetVolumeAsync(
        OciBlockVolumeReadRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        var sdkRequest = OciBlockVolumeExpansionTransportMapping.GetVolumeRequest(request);
        var response = await client.GetVolume(sdkRequest, null, cancellationToken);
        return OciBlockVolumeExpansionTransportMapping.ToObservation(response);
    }

    public async ValueTask<OciBlockVolumeObservation?> UpdateVolumeAsync(
        OciBlockVolumeUpdateRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        var sdkRequest = OciBlockVolumeExpansionTransportMapping.UpdateVolumeRequest(request);
        try
        {
            var response = await client.UpdateVolume(sdkRequest, null, cancellationToken);
            return OciBlockVolumeExpansionTransportMapping.ToObservation(response);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new OciBlockVolumeResponseLostException();
        }
        catch (TimeoutException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new OciBlockVolumeResponseLostException();
        }
        catch (HttpRequestException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new OciBlockVolumeResponseLostException();
        }
        catch (SocketException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new OciBlockVolumeResponseLostException();
        }
        catch (IOException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new OciBlockVolumeResponseLostException();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
            client.Dispose();
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed != 0, this);
}

/// <summary>Pure SDK request and response mapping seams for deterministic boundary tests.</summary>
internal static class OciBlockVolumeExpansionTransportMapping
{
    internal const ulong BytesPerGiB = 1_073_741_824UL;
    // OCI ETags are opaque HTTP header values. Keep the persisted/fence value bounded while
    // preserving its exact contents; controls (including CR/LF) are never sent to the SDK.
    internal const int MaximumETagLength = 256;

    internal static GetVolumeRequest GetVolumeRequest(OciBlockVolumeReadRequest request)
    {
        RequireReadRequest(request);
        return new() { VolumeId = request.VolumeId.Value };
    }

    internal static UpdateVolumeRequest UpdateVolumeRequest(OciBlockVolumeUpdateRequest request)
    {
        RequireUpdateRequest(request);
        return new()
        {
            VolumeId = request.VolumeId.Value,
            IfMatch = request.IfMatch,
            UpdateVolumeDetails = new UpdateVolumeDetails { SizeInGBs = RequireSdkGigabytes(request.NewSize) },
        };
    }

    internal static OciBlockVolumeObservation? ToObservation(GetVolumeResponse? response) =>
        response is null ? null : ToObservation(response.Volume, response.Etag);

    internal static OciBlockVolumeObservation? ToObservation(UpdateVolumeResponse? response) =>
        response is null ? null : ToObservation(response.Volume, response.Etag);

    internal static bool TryGetSdkGigabytes(ProviderByteCount? byteCount, out long gigabytes)
    {
        gigabytes = 0;
        if (byteCount is null || byteCount.Value == 0 || byteCount.Value % BytesPerGiB != 0)
            return false;

        var value = byteCount.Value / BytesPerGiB;
        if (value == 0 || value > (ulong)long.MaxValue)
            return false;

        gigabytes = (long)value;
        return true;
    }

    internal static bool IsIndeterminateTransportException(Exception exception) =>
        exception is OperationCanceledException or TimeoutException or HttpRequestException or SocketException or IOException;

    private static OciBlockVolumeObservation? ToObservation(Volume? volume, string? etag)
    {
        if (volume is null || !IsHeaderSafeOpaque(etag) ||
            !IsOciIdentity(volume.Id, "volume") ||
            !IsOciIdentity(volume.CompartmentId, "compartment") ||
            !TryGetBytes(volume.SizeInGBs, out var bytes))
            return null;

        try
        {
            return new(
                new ProviderResourceId(volume.Id!),
                new ProviderCompartmentId(volume.CompartmentId!),
                new ProviderByteCount(bytes),
                etag);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static bool TryGetBytes(long? gigabytes, out ulong bytes)
    {
        bytes = 0;
        if (gigabytes is not { } value || value <= 0)
            return false;

        try
        {
            bytes = checked((ulong)value * BytesPerGiB);
            return bytes > 0;
        }
        catch (OverflowException)
        {
            return false;
        }
    }

    private static long RequireSdkGigabytes(ProviderByteCount? byteCount)
    {
        if (TryGetSdkGigabytes(byteCount, out var gigabytes))
            return gigabytes;
        throw new ArgumentException("The OCI Block Volume size must be a positive integral GiB value within the SDK range.", nameof(byteCount));
    }

    private static void RequireReadRequest(OciBlockVolumeReadRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireOciIdentity(request.VolumeId?.Value, "volume");
        RequireOciIdentity(request.CompartmentId?.Value, "compartment");
    }

    private static void RequireUpdateRequest(OciBlockVolumeUpdateRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireOciIdentity(request.VolumeId?.Value, "volume");
        RequireOciIdentity(request.CompartmentId?.Value, "compartment");
        if (!IsHeaderSafeOpaque(request.IfMatch))
            throw new ArgumentException("The OCI Block Volume update fence is invalid.", nameof(request));
        _ = RequireSdkGigabytes(request.NewSize);
    }

    private static void RequireOciIdentity(string? value, string kind)
    {
        if (!IsOciIdentity(value, kind))
            throw new ArgumentException("The OCI Block Volume identity is invalid.");
    }

    private static bool IsOciIdentity(string? value, string kind) =>
        value is { Length: >= 12 and <= 255 } &&
        value.StartsWith($"ocid1.{kind}.", StringComparison.Ordinal) &&
        value.All(static character => !char.IsWhiteSpace(character) && !char.IsControl(character));

    private static bool IsHeaderSafeOpaque(string? value) =>
        value is { Length: > 0 and <= MaximumETagLength } &&
        !string.IsNullOrWhiteSpace(value) &&
        value.All(static character => !char.IsControl(character));
}
