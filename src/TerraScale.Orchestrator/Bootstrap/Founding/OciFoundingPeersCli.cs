using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.Nodes;

namespace TerraScale.Orchestrator.Bootstrap.Founding;

internal static class OciFoundingPeersCli
{
    internal static async Task<int> ExecuteAsync(string[] arguments, CancellationToken cancellationToken,
        Func<CancellationToken, Task<string>>? seedIdentity = null,
        Func<IOciCiRunnerComputeTransport>? transportFactory = null,
        TimeProvider? timeProvider = null, TextWriter? output = null, TextWriter? error = null)
    {
        output ??= Console.Out;
        error ??= Console.Error;
        try
        {
            if (arguments.Length != 8) throw new ArgumentException("Expected plan, trust key, region intent, and state directory.");
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var i = 0; i < arguments.Length; i += 2)
                if (arguments[i] is not ("--plan" or "--trust-key" or "--region-intent" or "--state-dir") ||
                    string.IsNullOrWhiteSpace(arguments[i + 1]) || !values.TryAdd(arguments[i], arguments[i + 1]))
                    throw new ArgumentException("The founding command arguments are invalid.");
            var verified = OciFoundingPlan.Load(values["--plan"], values["--trust-key"], OciRegionIntent.Load(values["--region-intent"]));
            using var state = OciFoundingState.Open(values["--state-dir"], verified);
            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            bounded.CancelAfter(TimeSpan.FromMinutes(3));
            var identity = await (seedIdentity ?? ReadSeedIdentityAsync)(bounded.Token).ConfigureAwait(false);
            if (identity != verified.Plan.SeedInstanceId)
                throw new InvalidOperationException("This node is not the grant's seed.");
            using var transport = transportFactory?.Invoke() ?? OciWorkloadComputeTransport.CreateForInstancePrincipal(
                "https://iaas.sa-saopaulo-1.oraclecloud.com");
            var status = await new OciFoundingPeerReconciler(transport, timeProvider ?? TimeProvider.System)
                .TickAsync(verified, state, identity, bounded.Token).ConfigureAwait(false);
            await output.WriteLineAsync(JsonSerializer.Serialize(status, OciFoundingPlan.JsonOptions)).ConfigureAwait(false);
            return status.State == "peers-running" ? 0 : 2;
        }
        catch (Exception exception)
        {
            // Provider errors can contain metadata or remote response bodies.
            await error.WriteLineAsync($"OCI founding reconciliation failed ({exception.GetType().Name}); inspect the private state receipt.")
                .ConfigureAwait(false);
            return 1;
        }
    }

    private static async Task<string> ReadSeedIdentityAsync(CancellationToken cancellationToken)
    {
        using var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        using var request = new HttpRequestMessage(HttpMethod.Get, "http://169.254.169.254/opc/v2/instance/id");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "Oracle");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var bytes = new byte[1025];
        var length = await stream.ReadAtLeastAsync(bytes, bytes.Length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        if (length is < 1 or > 1024) throw new InvalidDataException("OCI instance identity exceeds its bound.");
        var text = Encoding.UTF8.GetString(bytes, 0, length).Trim();
        var id = text.StartsWith('"') ? JsonSerializer.Deserialize<string>(text) : text;
        return OciFoundingPlan.RegionalOcid(id, "instance") ? id! : throw new InvalidDataException("OCI instance identity is invalid.");
    }
}
