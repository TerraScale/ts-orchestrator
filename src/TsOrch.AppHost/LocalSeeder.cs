using System.Text.Json.Nodes;
using TsOrch.Protocol;

namespace TsOrch.AppHost;

internal sealed record class LocalSeederOptions(Uri WorkerUrl, string RepoRoot, string? LocalRegion, Uri? EdgeUrl)
{
    public const string Flag = "--seed";

    public static Result<LocalSeederOptions, Validation> Parse(IReadOnlyList<string> args) =>
        AppHostArguments.AbsoluteUrl(args, "--worker-url") switch
        {
            Uri workerUrl => WithRepoRoot(workerUrl, args),
            Validation invalid => invalid,
        };

    private static Result<LocalSeederOptions, Validation> WithRepoRoot(Uri workerUrl, IReadOnlyList<string> args)
    {
        if (AppHostArguments.Value(args, "--repo-root") is not { Length: > 0 } repoRoot || !Directory.Exists(Path.Combine(repoRoot, "deploy")))
        {
            return new Validation("--repo-root <dir> must point at the ts-orchestrator checkout containing deploy/.");
        }

        if (AppHostArguments.Value(args, "--edge-url") is null)
        {
            return new LocalSeederOptions(workerUrl, Path.GetFullPath(repoRoot), null, null);
        }

        return AppHostArguments.AbsoluteUrl(args, "--edge-url") switch
        {
            Uri edgeUrl => AppHostArguments.Value(args, "--local-region") is { Length: > 0 } region
                ? new LocalSeederOptions(workerUrl, Path.GetFullPath(repoRoot), region, edgeUrl)
                : new Validation("--edge-url requires --local-region <label>."),
            Validation invalid => invalid,
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
            Done => await LoginAndSeedAsync(options, cancellationToken),
            RequestTimeout timedOut => Fail(timedOut.Message),
        };
    }

    private async Task<int> LoginAndSeedAsync(LocalSeederOptions options, CancellationToken cancellationToken)
    {
        var login = await client.DevLoginAsync(options.WorkerUrl, cancellationToken);
        return login switch
        {
            string cookie => await SeedFleetAsync(options, cookie, cancellationToken),
            PreconditionFailed notLocal => Fail(notLocal.Message),
            Unavailable unavailable => Fail(unavailable.Message),
        };
    }

    private async Task<int> SeedFleetAsync(LocalSeederOptions options, string cookie, CancellationToken cancellationToken) =>
        BuildSeedRequest(options) switch
        {
            SeedRequestDocument document => await PostSeedAsync(options, cookie, document, cancellationToken),
            Validation invalid => Fail(invalid.Message),
        };

    private async Task<int> PostSeedAsync(LocalSeederOptions options, string cookie, SeedRequestDocument document, CancellationToken cancellationToken)
    {
        var seeded = await client.PostJsonAsync(
            new Uri(options.WorkerUrl, "/api/fleet/seed"),
            document,
            AppHostJsonContext.Default.SeedRequestDocument,
            cookie,
            cancellationToken);
        return seeded switch
        {
            string body => await EnsureTlsAsync(options, cookie, body, cancellationToken),
            Validation rejected => Fail(rejected.Message),
            Unauthorized denied => Fail(denied.Message),
            Unavailable unavailable => Fail(unavailable.Message),
        };
    }

    private async Task<int> EnsureTlsAsync(LocalSeederOptions options, string cookie, string seedBody, CancellationToken cancellationToken)
    {
        stdout.WriteLine($"fleet seeded: {seedBody}");
        var tls = await client.PostAsync(new Uri(options.WorkerUrl, "/api/tls/ensure"), "{}", cookie, cancellationToken);
        return tls switch
        {
            string body => Succeed(body),
            Validation rejected => Fail(rejected.Message),
            Unauthorized denied => Fail(denied.Message),
            Unavailable unavailable => Fail(unavailable.Message),
        };
    }

    private int Succeed(string tlsBody)
    {
        stdout.WriteLine($"tls ensured: {tlsBody}");
        return 0;
    }

    private int Fail(string message)
    {
        stderr.WriteLine($"seed failed: {message}");
        return 1;
    }

    private static Result<SeedRequestDocument, Validation> BuildSeedRequest(LocalSeederOptions options)
    {
        var deploy = Path.Combine(options.RepoRoot, "deploy");
        return JsonFiles.Read(Path.Combine(deploy, "fleet.json")) switch
        {
            JsonFile { Node: JsonObject fleet } when fleet["regions"] is JsonArray regions => WithPools(options, deploy, fleet, regions),
            JsonFile => new Validation("deploy/fleet.json must be an object with a regions array."),
            Validation invalid => invalid,
        };
    }

    private static Result<SeedRequestDocument, Validation> WithPools(LocalSeederOptions options, string deploy, JsonObject fleet, JsonArray regions)
    {
        Dictionary<string, string> poolIds = [with(StringComparer.Ordinal)];
        foreach (var node in regions)
        {
            if (node is not JsonObject region || Text(region, "label") is not { } label || Text(region, "ociRegion") is not { } ociRegion)
            {
                return new Validation("every deploy/fleet.json region needs label and ociRegion.");
            }

            poolIds[label] = $"ocid1.instancepool.oc1.{ociRegion}.local-{label}";
            if (options.EdgeUrl is { } edgeUrl && string.Equals(label, options.LocalRegion, StringComparison.Ordinal) && region["endpoints"] is JsonObject endpoints)
            {
                var origin = edgeUrl.GetLeftPart(UriPartial.Authority);
                endpoints["api"] = origin;
                endpoints["auth"] = origin;
            }
        }

        return JsonFiles.ReadDirectories([Path.Combine(deploy, "services")]) switch
        {
            JsonFile[] files => WithServices(fleet, poolIds, files),
            Validation invalid => invalid,
        };
    }

    private static Result<SeedRequestDocument, Validation> WithServices(JsonObject fleet, IReadOnlyDictionary<string, string> poolIds, JsonFile[] files)
    {
        List<JsonNode> services = [];
        foreach (var file in files)
        {
            if (file.Node is not JsonObject service)
            {
                return new Validation($"{file.Path} must hold one service object.");
            }

            services.Add(service);
        }

        return new SeedRequestDocument(fleet, services, true, poolIds);
    }

    private static string? Text(JsonObject node, string name) =>
        node[name] is JsonValue value && value.TryGetValue<string>(out var text) && text.Length > 0 ? text : null;
}
