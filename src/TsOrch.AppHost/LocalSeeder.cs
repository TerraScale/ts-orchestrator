using System.Text.Json.Nodes;

namespace TsOrch.AppHost;

internal readonly union LocalSeederConfiguration(LocalSeederOptions, AppHostArgumentInvalid);

internal sealed record class LocalSeedDefinitionInvalid(string Message);

internal readonly union LocalSeedRequest(SeedRequestDocument, LocalSeedDefinitionInvalid, AppHostFileUnreadable);

internal sealed record class LocalSeederOptions(Uri WorkerUrl, string RepoRoot, string? LocalRegion, Uri? EdgeUrl)
{
    public const string Flag = "--seed";

    public static LocalSeederConfiguration Parse(IReadOnlyList<string> args) =>
        AppHostArguments.AbsoluteUrl(args, "--worker-url") switch
        {
            Uri workerUrl => WithRepoRoot(workerUrl, args),
            AppHostArgumentInvalid invalid => invalid,
        };

    private static LocalSeederConfiguration WithRepoRoot(Uri workerUrl, IReadOnlyList<string> args)
    {
        if (AppHostArguments.Value(args, "--repo-root") is not { Length: > 0 } repoRoot || !Directory.Exists(Path.Combine(repoRoot, "deploy")))
        {
            return new AppHostArgumentInvalid("--repo-root <dir> must point at the ts-orchestrator checkout containing deploy/.");
        }

        if (AppHostArguments.Value(args, "--edge-url") is null)
        {
            return new LocalSeederOptions(workerUrl, Path.GetFullPath(repoRoot), null, null);
        }

        return AppHostArguments.AbsoluteUrl(args, "--edge-url") switch
        {
            Uri edgeUrl => AppHostArguments.Value(args, "--local-region") is { Length: > 0 } region
                ? new LocalSeederOptions(workerUrl, Path.GetFullPath(repoRoot), region, edgeUrl)
                : new AppHostArgumentInvalid("--edge-url requires --local-region <label>."),
            AppHostArgumentInvalid invalid => invalid,
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
            LocalWorkerReady => await LoginAndSeedAsync(options, cancellationToken),
            LocalWorkerStartupTimedOut timedOut => Fail(timedOut.Message),
        };
    }

    private async Task<int> LoginAndSeedAsync(LocalSeederOptions options, CancellationToken cancellationToken)
    {
        var login = await client.DevLoginAsync(options.WorkerUrl, cancellationToken);
        return login switch
        {
            string cookie => await SeedFleetAsync(options, cookie, cancellationToken),
            LocalDevNotEnabled notLocal => Fail(notLocal.Message),
            LocalWorkerUnavailable unavailable => Fail(unavailable.Message),
        };
    }

    private async Task<int> SeedFleetAsync(LocalSeederOptions options, string cookie, CancellationToken cancellationToken) =>
        BuildSeedRequest(options) switch
        {
            SeedRequestDocument document => await PostSeedAsync(options, cookie, document, cancellationToken),
            LocalSeedDefinitionInvalid invalid => Fail(invalid.Message),
            AppHostFileUnreadable unreadable => Fail(unreadable.Message),
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
            LocalWorkerRequestRejected rejected => Fail(rejected.Message),
            LocalWorkerAccessDenied denied => Fail(denied.Message),
            LocalWorkerUnavailable unavailable => Fail(unavailable.Message),
        };
    }

    private async Task<int> EnsureTlsAsync(LocalSeederOptions options, string cookie, string seedBody, CancellationToken cancellationToken)
    {
        stdout.WriteLine($"fleet seeded: {seedBody}");
        var tls = await client.PostAsync(new Uri(options.WorkerUrl, "/api/tls/ensure"), "{}", cookie, cancellationToken);
        return tls switch
        {
            string body => Succeed(body),
            LocalWorkerRequestRejected rejected => Fail(rejected.Message),
            LocalWorkerAccessDenied denied => Fail(denied.Message),
            LocalWorkerUnavailable unavailable => Fail(unavailable.Message),
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

    private static LocalSeedRequest BuildSeedRequest(LocalSeederOptions options)
    {
        var deploy = Path.Combine(options.RepoRoot, "deploy");
        return JsonFiles.Read(Path.Combine(deploy, "fleet.json")) switch
        {
            JsonFile { Node: JsonObject fleet } when fleet["regions"] is JsonArray regions => WithPools(options, deploy, fleet, regions),
            JsonFile => new LocalSeedDefinitionInvalid("deploy/fleet.json must be an object with a regions array."),
            AppHostFileUnreadable unreadable => unreadable,
        };
    }

    private static LocalSeedRequest WithPools(LocalSeederOptions options, string deploy, JsonObject fleet, JsonArray regions)
    {
        Dictionary<string, string> poolIds = [with(StringComparer.Ordinal)];
        foreach (var node in regions)
        {
            if (node is not JsonObject region || Text(region, "label") is not { } label || Text(region, "ociRegion") is not { } ociRegion)
            {
                return new LocalSeedDefinitionInvalid("every deploy/fleet.json region needs label and ociRegion.");
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
            IReadOnlyList<JsonFile> files => WithServices(fleet, poolIds, files),
            AppHostFileUnreadable unreadable => unreadable,
        };
    }

    private static LocalSeedRequest WithServices(JsonObject fleet, IReadOnlyDictionary<string, string> poolIds, IReadOnlyList<JsonFile> files)
    {
        List<JsonNode> services = [];
        foreach (var file in files)
        {
            if (file.Node is not JsonObject service)
            {
                return new LocalSeedDefinitionInvalid($"{file.Path} must hold one service object.");
            }

            services.Add(service);
        }

        return new SeedRequestDocument(fleet, services, true, poolIds);
    }

    private static string? Text(JsonObject node, string name) =>
        node[name] is JsonValue value && value.TryGetValue<string>(out var text) && text.Length > 0 ? text : null;
}
