using System.Net;
using System.Text;
using TerraScale.Orchestrator.Lab.SmolVm;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class SmolVmV1_5OpenApiClientTests
{
    [Test]
    public async Task CreateUsesPinnedCamelCaseSchemaAndImmutableSidecar()
    {
        string? body = null;
        var handler = new StubHandler(async request =>
        {
            body = await request.Content!.ReadAsStringAsync();
            return Json(HttpStatusCode.OK, MachineJson("ts-run-gru-seed-1", "created"));
        });
        using var client = new SmolVmV1_5OpenApiClient(new HttpClient(handler));
        var plan = SmolVmRegionsTopology.Create(
            "run",
            "/artifacts/base.smolmachine",
            new ArtifactDigest("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            new(2, 2048, 20, 4),
            ["10.0.0.0/8"])
            .Machines[0];

        await client.CreateMachineAsync(SmolVmCreateMachineRequest.FromPlan(plan), CancellationToken.None);

        await Assert.That(body).Contains("\"memoryMb\":2048");
        await Assert.That(body).Contains("\"networkBackend\":\"virtio-net\"");
        await Assert.That(body).Contains("\"from\":\"/artifacts/base.smolmachine\"");
        await Assert.That(body).DoesNotContain("\"image\"");
    }

    [Test]
    public async Task NotFoundObservationIsTypedAsAbsent()
    {
        using var client = new SmolVmV1_5OpenApiClient(new HttpClient(new StubHandler(_ =>
            Task.FromResult(Json(HttpStatusCode.NotFound, "{\"error\":\"missing\",\"code\":\"NOT_FOUND\"}")))));

        var observation = await client.GetMachineAsync("ts-run-gru-seed-1", CancellationToken.None);

        await Assert.That(observation).IsNull();
    }

    [Test]
    public async Task ErrorCodeIsPreservedWithoutLeakingAnUnboundedBody()
    {
        using var client = new SmolVmV1_5OpenApiClient(new HttpClient(new StubHandler(_ =>
            Task.FromResult(Json(HttpStatusCode.Conflict, "{\"error\":\"port busy\",\"code\":\"PORT_IN_USE\"}")))));

        var exception = await Assert.That(async () => await client.StartMachineAsync(
                "ts-run-gru-seed-1",
                CancellationToken.None))
            .Throws<SmolVmApiException>();

        await Assert.That(exception!.ErrorCode).IsEqualTo("PORT_IN_USE");
        await Assert.That(exception.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
    }

    [Test]
    public async Task GuestFileTraversalIsRejectedBeforeSendingARequest()
    {
        Uri? observed = null;
        using var client = new SmolVmV1_5OpenApiClient(new HttpClient(new StubHandler(request =>
        {
            observed = request.RequestUri;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent([1, 2, 3])
            });
        })));

        await Assert.That(async () => await client.DownloadFileAsync(
                "ts-run-gru-seed-1",
                "/tmp/../proof",
                CancellationToken.None))
            .Throws<ArgumentException>();
        await Assert.That(observed).IsNull();
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body) => new(status)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json")
    };

    private static string MachineJson(string name, string state) => $$"""
        {"name":"{{name}}","state":"{{state}}","cpus":2,"memoryMb":2048,"ports":[],"mounts":[],"network":true,"networkBackend":"virtio-net","storageGb":20,"overlayGb":4,"createdAt":1}
        """;

    private sealed class StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => respond(request);
    }
}
