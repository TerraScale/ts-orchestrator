using System.Text.Json;
using System.Text.Json.Nodes;

namespace TsOrch.AppHost;

internal sealed record class LocalSeederOptions(Uri WorkerUrl, string RepoRoot, string? LocalRegion, Uri? EdgeUrl)
{
    public const string Flag = "--seed";

    public static Parsed<LocalSeederOptions> Parse(IReadOnlyList<string> args) =>
        AppHostArguments.AbsoluteUrl(args, "--worker-url") switch
        {
            Uri workerUrl => WithRepoRoot(workerUrl, args),
            InvalidArguments invalid => invalid,
        };

    private static Parsed<LocalSeederOptions> WithRepoRoot(Uri workerUrl, IReadOnlyList<string> args)
    {
        if (AppHostArguments.Value(args, "--repo-root") is not { Length: > 0 } repoRoot || !Directory.Exists(Path.Combine(repoRoot, "deploy")))
        {
            return new InvalidArguments("--repo-root <dir> must point at the ts-orchestrator checkout containing deploy/.");
        }

        if (AppHostArguments.Value(args, "--edge-url") is null)
        {
            return new LocalSeederOptions(workerUrl, Path.GetFullPath(repoRoot), null, null);
        }

        return AppHostArguments.AbsoluteUrl(args, "--edge-url") switch
        {
            Uri edgeUrl => AppHostArguments.Value(args, "--local-region") is { Length: > 0 } region
                ? new LocalSeederOptions(workerUrl, Path.GetFullPath(repoRoot), region, edgeUrl)
                : new InvalidArguments("--edge-url requires --local-region <label>."),
            InvalidArguments invalid => invalid,
        };
    }
}

internal sealed class LocalSeeder(LocalDevClient client, TextWriter stdout, TextWriter stderr)
{
    private static readonly TimeSpan WorkerStartupTimeout = TimeSpan.FromMinutes(3);

    public static async Task<int> RunAsync(LocalSeederOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        using var httpClient = LocalDevClient.CreateHttpClient();
        var seeder = new LocalSeeder(new LocalDevClient(httpClient, TimeProvider.System), Console.Out, Console.Error);
        return await seeder.SeedAsync(options, cancellationToken);
    }

    private async Task<int> SeedAsync(LocalSeederOptions options, CancellationToken cancellationToken)
    {
        var ready = await client.WaitForLocalWorkerAsync(options.WorkerUrl, WorkerStartupTimeout, cancellationToken);
        return ready switch
        {
            string => await LoginAndSeedAsync(options, cancellationToken),
            WorkerFailure failure => Fail(failure),
        };
    }

    private async Task<int> LoginAndSeedAsync(LocalSeederOptions options, CancellationToken cancellationToken)
    {
        var login = await client.DevLoginAsync(options.WorkerUrl, cancellationToken);
        return login switch
        {
            string cookie => await SeedFleetAsync(options, cookie, cancellationToken),
            WorkerFailure failure => Fail(failure),
        };
    }

    private async Task<int> SeedFleetAsync(LocalSeederOptions options, string cookie, CancellationToken cancellationToken)
    {
        var request = BuildSeedRequest(options);
        var seeded = request switch
        {
            SeedRequestDocument document => await client.PostJsonAsync(
                new Uri(options.WorkerUrl, "/api/fleet/seed"),
                document,
                AppHostJsonContext.Default.SeedRequestDocument,
                cookie,
                cancellationToken),
            InvalidArguments invalid => new WorkerFailure(invalid.Message),
        };
        return seeded switch
        {
            string body => await EnsureTlsAsync(options, cookie, body, cancellationToken),
            WorkerFailure failure => Fail(failure),
        };
    }

    private async Task<int> EnsureTlsAsync(LocalSeederOptions options, string cookie, string seedBody, CancellationToken cancellationToken)
    {
        stdout.WriteLine($"fleet seeded: {seedBody}");
        var tls = await client.PostAsync(new Uri(options.WorkerUrl, "/api/tls/ensure"), "{}", cookie, cancellationToken);
        return tls switch
        {
            string body => Done(body),
            WorkerFailure failure => Fail(failure),
        };
    }

    private int Done(string tlsBody)
    {
        stdout.WriteLine($"tls ensured: {tlsBody}");
        return 0;
    }

    private int Fail(WorkerFailure failure)
    {
        stderr.WriteLine($"seed failed: {failure.Message}");
        return 1;
    }

    private static Parsed<SeedRequestDocument> BuildSeedRequest(LocalSeederOptions options)
    {
        try
        {
            var deploy = Path.Combine(options.RepoRoot, "deploy");
            if (JsonNode.Parse(File.ReadAllText(Path.Combine(deploy, "fleet.json"))) is not JsonObject fleet || fleet["regions"] is not JsonArray regions)
            {
                return new InvalidArguments("deploy/fleet.json must be an object with a regions array.");
            }

            Dictionary<string, string> poolIds = new(StringComparer.Ordinal);
            foreach (var node in regions)
            {
                if (node is not JsonObject region || Text(region, "label") is not { } label || Text(region, "ociRegion") is not { } ociRegion)
                {
                    return new InvalidArguments("every deploy/fleet.json region needs label and ociRegion.");
                }

                poolIds[label] = $"ocid1.instancepool.oc1.{ociRegion}.local-{label}";
                if (options.EdgeUrl is { } edgeUrl && string.Equals(label, options.LocalRegion, StringComparison.Ordinal) && region["endpoints"] is JsonObject endpoints)
                {
                    var origin = edgeUrl.GetLeftPart(UriPartial.Authority);
                    endpoints["api"] = origin;
                    endpoints["auth"] = origin;
                }
            }

            List<JsonNode> services = [];
            foreach (var file in Directory.EnumerateFiles(Path.Combine(deploy, "services"), "*.json").Order(StringComparer.Ordinal))
            {
                if (JsonNode.Parse(File.ReadAllText(file)) is not JsonObject service)
                {
                    return new InvalidArguments($"{file} must hold one service object.");
                }

                services.Add(service);
            }

            return new SeedRequestDocument(fleet, services, true, poolIds);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new InvalidArguments($"deploy/ could not be read: {exception.Message}");
        }
    }

    private static string? Text(JsonObject node, string name) =>
        node[name] is JsonValue value && value.TryGetValue<string>(out var text) && text.Length > 0 ? text : null;
}
