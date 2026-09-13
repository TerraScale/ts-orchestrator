using System.Net.Http;
using System.Net.Sockets;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using Oci.CoreService.Responses;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class OciBlockVolumeExpansionTransportTests
{
    private const string Region = "sa-saopaulo-1";
    private const string VolumeId = "ocid1.volume.oc1.sa-saopaulo-1.volume";
    private const string CompartmentId = "ocid1.compartment.oc1..terrascale";

    [Test]
    public async Task Request_mapping_preserves_exact_volume_fence_and_checked_size()
    {
        var read = OciBlockVolumeExpansionTransportMapping.GetVolumeRequest(
            new(new(VolumeId), new(CompartmentId)));
        var update = OciBlockVolumeExpansionTransportMapping.UpdateVolumeRequest(
            new(new(VolumeId), new(CompartmentId), new(2UL * OciBlockVolumeExpansionTransportMapping.BytesPerGiB), "etag-1"));

        await Assert.That(read).IsTypeOf<GetVolumeRequest>();
        await Assert.That(read.VolumeId).IsEqualTo(VolumeId);
        await Assert.That(update).IsTypeOf<UpdateVolumeRequest>();
        await Assert.That(update.VolumeId).IsEqualTo(VolumeId);
        await Assert.That(update.IfMatch).IsEqualTo("etag-1");
        await Assert.That(update.UpdateVolumeDetails).IsNotNull();
        await Assert.That(update.UpdateVolumeDetails.SizeInGBs).IsEqualTo(2L);
    }

    [Test]
    public async Task Non_integral_sizes_are_rejected_without_rounding_and_integral_sizes_use_gib()
    {
        var invalid = new[]
        {
            new ProviderByteCount(1),
            new ProviderByteCount(OciBlockVolumeExpansionTransportMapping.BytesPerGiB - 1),
        };

        foreach (var size in invalid)
        {
            await Assert.That(() => OciBlockVolumeExpansionTransportMapping.UpdateVolumeRequest(
                    new(new(VolumeId), new(CompartmentId), size, "etag-1")))
                .Throws<ArgumentException>();
        }

        await Assert.That(OciBlockVolumeExpansionTransportMapping.TryGetSdkGigabytes(
                new(OciBlockVolumeExpansionTransportMapping.BytesPerGiB), out var gigabytes))
            .IsTrue();
        await Assert.That(gigabytes).IsEqualTo(1L);
    }

    [Test]
    public async Task Response_mapping_requires_body_etag_identity_and_positive_non_overflow_size()
    {
        var valid = new GetVolumeResponse
        {
            Etag = "etag-2",
            Volume = new Volume
            {
                Id = VolumeId,
                CompartmentId = CompartmentId,
                SizeInGBs = 2,
            },
        };
        var observation = OciBlockVolumeExpansionTransportMapping.ToObservation(valid);

        await Assert.That(observation).IsNotNull();
        await Assert.That(observation!.VolumeId!.Value).IsEqualTo(VolumeId);
        await Assert.That(observation.CompartmentId!.Value).IsEqualTo(CompartmentId);
        await Assert.That(observation.Size!.Value).IsEqualTo(2UL * OciBlockVolumeExpansionTransportMapping.BytesPerGiB);
        await Assert.That(observation.ETag).IsEqualTo("etag-2");

        var malformed = new GetVolumeResponse?[]
        {
            null,
            new() { Volume = valid.Volume, Etag = null },
            new() { Volume = null, Etag = "etag-2" },
            new() { Volume = VolumeModel("not-an-ocid", CompartmentId, 2), Etag = "etag-2" },
            new() { Volume = VolumeModel(VolumeId, "not-an-ocid", 2), Etag = "etag-2" },
            new() { Volume = VolumeModel(VolumeId, CompartmentId, null), Etag = "etag-2" },
            new() { Volume = VolumeModel(VolumeId, CompartmentId, 0), Etag = "etag-2" },
            new() { Volume = VolumeModel(VolumeId, CompartmentId, -1), Etag = "etag-2" },
            new() { Volume = VolumeModel(VolumeId, CompartmentId, long.MaxValue), Etag = "etag-2" },
            new() { Volume = valid.Volume, Etag = "  " },
            new() { Volume = valid.Volume, Etag = "etag-2\r\n" },
            new() { Volume = valid.Volume, Etag = new string('e', OciBlockVolumeExpansionTransportMapping.MaximumETagLength + 1) },
        };

        foreach (var response in malformed)
            await Assert.That(OciBlockVolumeExpansionTransportMapping.ToObservation(response)).IsNull();
    }

    [Test]
    public async Task Endpoint_is_https_root_only_and_bound_to_the_canonical_configured_region()
    {
        var configuration = new OciBlockVolumeExpansionTransportConfiguration(
            Region,
            $"  https://iaas.{Region}.oraclecloud.com/  ");

        await Assert.That(configuration.ConfiguredRegion).IsEqualTo(Region);
        await Assert.That(configuration.Endpoint.Host).IsEqualTo($"iaas.{Region}.oraclecloud.com");
        await Assert.That(configuration.EndpointText).IsEqualTo($"https://iaas.{Region}.oraclecloud.com");

        var invalid = new[]
        {
            (Region, $"http://iaas.{Region}.oraclecloud.com/"),
            (Region, $"https://user:pass@iaas.{Region}.oraclecloud.com/"),
            (Region, $"https://iaas.{Region}.oraclecloud.com/v1"),
            (Region, $"https://iaas.{Region}.oraclecloud.com/?query=1"),
            (Region, $"https://iaas.{Region}.oraclecloud.com/#fragment"),
            (Region, $"https://iaas.{Region}.oraclecloud.com:8443/"),
            (Region, "https://iaas.us-phoenix-1.oraclecloud.com/"),
            ("SA-SAOPAULO-1", $"https://iaas.{Region}.oraclecloud.com/"),
            ("sa--saopaulo-1", $"https://iaas.sa--saopaulo-1.oraclecloud.com/"),
        };

        foreach (var (region, endpoint) in invalid)
            await Assert.That(() => new OciBlockVolumeExpansionTransportConfiguration(region, endpoint))
                .Throws<ArgumentException>();

        await Assert.That(() => OciBlockVolumeExpansionTransportMapping.UpdateVolumeRequest(
                new(new(VolumeId), new(CompartmentId), new(OciBlockVolumeExpansionTransportMapping.BytesPerGiB), "etag\r\n")))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task Invalid_configuration_is_rejected_before_factory_authentication_and_client_creation()
    {
        await Assert.That(() => OciBlockVolumeExpansionTransportFactory.Create(
                "SA-SAOPAULO-1", $"https://iaas.{Region}.oraclecloud.com/"))
            .Throws<ArgumentException>();
        var timeoutMillis = OciBlockVolumeExpansionTransportFactory.ClientTimeoutMillis;
        await Assert.That(timeoutMillis).IsEqualTo(30_000);
    }

    [Test]
    public async Task Only_connection_reset_timeout_and_non_caller_cancellation_are_indeterminate()
    {
        var expected = new Exception[]
        {
            new HttpRequestException(),
            new SocketException(),
            new IOException(),
            new TimeoutException(),
            new OperationCanceledException(),
        };

        foreach (var exception in expected)
            await Assert.That(OciBlockVolumeExpansionTransportMapping.IsIndeterminateTransportException(exception)).IsTrue();

        await Assert.That(OciBlockVolumeExpansionTransportMapping.IsIndeterminateTransportException(
                new InvalidOperationException()))
            .IsFalse();
    }

    private static Volume VolumeModel(string id, string compartmentId, long? sizeInGiBs) => new()
    {
        Id = id,
        CompartmentId = compartmentId,
        SizeInGBs = sizeInGiBs,
    };
}

