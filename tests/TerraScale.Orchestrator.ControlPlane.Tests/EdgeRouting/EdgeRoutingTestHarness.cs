using System.Net;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.DatabasePlacement;
using TerraScale.Orchestrator.ControlPlane.EdgeRouting;

namespace TerraScale.Orchestrator.ControlPlane.Tests.EdgeRouting;

/// <summary>
/// In-memory Cloudflare KV transport: serves the REST routes the client uses, records every
/// call in order, and scripts transient failures for retry assertions. A values/bulk call
/// against a namespace id the account no longer lists answers the Cloudflare
/// namespace-not-found 404 envelope, so a stale id is distinguishable from an absent key.
/// </summary>
internal sealed class FakeCloudflareKvTransport : HttpMessageHandler
{
    public const string AccountId = "test-account";
    public const string RegionsNamespaceId = "ns-regions";
    public const string PlacementNamespaceId = "ns-placement";

    private readonly List<(string Id, string Title)> namespaces = new()
    {
        (RegionsNamespaceId, "REGIONS"),
        (PlacementNamespaceId, "PLACEMENT"),
    };

    private readonly Dictionary<string, string> values = new(StringComparer.Ordinal);
    private readonly List<ScriptedFailure> scriptedFailures = new();

    public List<string> Calls { get; } = new();

    public void Fail(string method, string pathContains, HttpStatusCode status, int times = 1) =>
        scriptedFailures.Add(new(method, pathContains, status, times));

    public void Seed(string namespaceId, string key, string value) =>
        values[NamespacedKey(namespaceId, key)] = value;

    /// <summary>Simulates deleting and recreating a namespace: the title survives, the id does not.</summary>
    public void RecreateNamespace(string title, string newId)
    {
        var index = namespaces.FindIndex(pair => pair.Title == title);
        namespaces[index] = (newId, title);
    }

    public void RemoveNamespace(string title) => namespaces.RemoveAll(pair => pair.Title == title);

    public string? StoredValue(string namespaceId, string key) =>
        values.GetValueOrDefault(NamespacedKey(namespaceId, key));

    public bool HasKey(string namespaceId, string key) =>
        values.ContainsKey(NamespacedKey(namespaceId, key));

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        Calls.Add(Describe(request, body));
        if (TakeScriptedFailure(request) is { } failureStatus)
            return Envelope(failureStatus, success: false);

        var segments = request.RequestUri!.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (request.Method.Method == "GET" && segments[^1] == "namespaces")
            return Envelope(HttpStatusCode.OK, result: NamespaceListJson());

        if (segments[^2] == "values")
        {
            var namespaceId = segments[^3];
            if (!namespaces.Any(pair => pair.Id == namespaceId))
                return NamespaceNotFoundEnvelope(namespaceId);
            var key = Uri.UnescapeDataString(segments[^1]);
            if (request.Method.Method == "GET")
            {
                return HasKey(namespaceId, key)
                    ? new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(StoredValue(namespaceId, key)!, Encoding.UTF8, "application/json"),
                    }
                    : Envelope(HttpStatusCode.NotFound, success: false);
            }

            values[NamespacedKey(namespaceId, key)] = body!;
            return Envelope(HttpStatusCode.OK);
        }

        if (segments[^1] == "bulk")
        {
            var namespaceId = segments[^2];
            if (!namespaces.Any(pair => pair.Id == namespaceId))
                return NamespaceNotFoundEnvelope(namespaceId);
            using var document = JsonDocument.Parse(body!);
            if (request.Method.Method == "PUT")
            {
                foreach (var entry in document.RootElement.EnumerateArray())
                    values[NamespacedKey(namespaceId, entry.GetProperty("key").GetString()!)] =
                        entry.GetProperty("value").GetString()!;
            }
            else
            {
                foreach (var key in document.RootElement.EnumerateArray())
                    values.Remove(NamespacedKey(namespaceId, key.GetString()!));
            }

            return Envelope(HttpStatusCode.OK);
        }

        throw new InvalidOperationException($"The fake KV transport cannot route {request.Method} {request.RequestUri}.");
    }

    private string NamespaceListJson() =>
        "[" + string.Join(",", namespaces.Select(pair => $$"""{"id":"{{pair.Id}}","title":"{{pair.Title}}"}""")) + "]";

    private static string Describe(HttpRequestMessage request, string? body)
    {
        var segments = request.RequestUri!.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments[^1] == "namespaces") return "GET namespaces";
        if (segments[^2] == "values")
            return $"{request.Method.Method} {segments[^3]} values {Uri.UnescapeDataString(segments[^1])}";
        using var document = JsonDocument.Parse(body!);
        return $"{request.Method.Method} {segments[^2]} bulk {document.RootElement.GetArrayLength()}";
    }

    private HttpStatusCode? TakeScriptedFailure(HttpRequestMessage request)
    {
        foreach (var failure in scriptedFailures.Where(failure => failure.Times > 0))
        {
            if (!string.Equals(request.Method.Method, failure.Method, StringComparison.Ordinal) ||
                !request.RequestUri!.PathAndQuery.Contains(failure.PathContains, StringComparison.Ordinal))
                continue;
            failure.Times--;
            return failure.Status;
        }

        return null;
    }

    private static string NamespacedKey(string namespaceId, string key) => $"{namespaceId}\n{key}";

    private static HttpResponseMessage NamespaceNotFoundEnvelope(string namespaceId) =>
        Envelope(HttpStatusCode.NotFound, success: false, errorMessage: $"namespace not found with id {namespaceId}");

    private static HttpResponseMessage Envelope(
        HttpStatusCode status,
        bool success = true,
        string result = "null",
        string errorMessage = "scripted failure") =>
        new(status)
        {
            Content = new StringContent(
                success
                    ? $$"""{"success":true,"errors":[],"messages":[],"result":{{result}}}"""
                    : $$"""{"success":false,"errors":[{"code":10000,"message":"{{errorMessage}}"}],"messages":[],"result":null}""",
                Encoding.UTF8,
                "application/json"),
        };

    private sealed class ScriptedFailure
    {
        public ScriptedFailure(string method, string pathContains, HttpStatusCode status, int times)
        {
            Method = method;
            PathContains = pathContains;
            Status = status;
            Times = times;
        }

        public string Method { get; }
        public string PathContains { get; }
        public HttpStatusCode Status { get; }
        public int Times { get; set; }
    }
}

/// <summary>Fixed clock whose delays complete immediately and are recorded for backoff assertions.</summary>
internal sealed class FakeEdgeTimeProvider : TimeProvider
{
    public static readonly DateTimeOffset Timestamp = new(2026, 9, 18, 12, 0, 0, TimeSpan.Zero);

    public List<TimeSpan> Delays { get; } = new();

    public override DateTimeOffset GetUtcNow() => Timestamp;

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        Delays.Add(dueTime);
        callback(state);
        return new CompletedTimer();
    }

    private sealed class CompletedTimer : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => false;
        public void Dispose() { }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

/// <summary>A source whose snapshot can be swapped between passes.</summary>
internal sealed class MutableEdgePlacementSource : IEdgePlacementSource
{
    private EdgePlacementSnapshot snapshot;

    public MutableEdgePlacementSource(EdgePlacementSnapshot initial) => snapshot = initial;

    public void Set(EdgePlacementSnapshot value) => snapshot = value;

    public Task<EdgePlacementSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(snapshot);
}

/// <summary>A source answering from a delegate, including a null (missing) snapshot.</summary>
internal sealed class FuncEdgePlacementSource(Func<Task<EdgePlacementSnapshot?>> snapshot) : IEdgePlacementSource
{
    public async Task<EdgePlacementSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default) =>
        (await snapshot())!;
}

internal static class EdgeRoutingTestData
{
    public const long HealthUpdated = 1_725_300_000L;

    public static EdgeHealthDocument Health(
        IEnumerable<EdgeRegionHealth>? regions = null,
        IEnumerable<EdgeRegionCatalogEntry>? catalog = null) =>
        new(
            HealthUpdated,
            regions ??
            [
                new EdgeRegionHealth(RegionCode.Gru, true, 0, -23.43, -46.47),
                new EdgeRegionHealth(RegionCode.Sfo, true, 40, 37.37, -121.92),
                new EdgeRegionHealth(RegionCode.Fra, false, null, 50.03, 8.57),
            ],
            catalog ??
            [
                new EdgeRegionCatalogEntry(RegionCode.Gru, "Sao Paulo", "BR", -23.43, -46.47),
                new EdgeRegionCatalogEntry(RegionCode.Sfo, "San Francisco", "US", 37.37, -121.92),
                new EdgeRegionCatalogEntry(RegionCode.Fra, "Frankfurt", "DE", 50.03, 8.57),
            ]);

    /// <summary>A minimal one-Region health entry, patchable per test row.</summary>
    public static EdgeRegionHealth Region(
        RegionCode region,
        bool ok = true,
        int? lagMilliseconds = 0,
        double latitude = -23.43,
        double longitude = -46.47) =>
        new(region, ok, lagMilliseconds, latitude, longitude);

    /// <summary>A minimal one-Region catalog entry, patchable per test row.</summary>
    public static EdgeRegionCatalogEntry CatalogEntry(
        RegionCode region,
        string name = "Sao Paulo",
        string country = "BR",
        double latitude = -23.43,
        double longitude = -46.47) =>
        new(region, name, country, latitude, longitude);

    public static IReadOnlyDictionary<string, IReadOnlyList<EdgeBranchPlacement>> MainBranch(
        params (RegionCode Region, bool Read, bool Write)[] entries) =>
        new Dictionary<string, IReadOnlyList<EdgeBranchPlacement>>
        {
            ["main"] = entries.Select(entry => new EdgeBranchPlacement(entry.Region, entry.Read, entry.Write)).ToArray(),
        };

    public static EdgeDatabasePlacement Database(
        string name = "orders",
        int revision = 1,
        EdgeResidency? residency = null,
        IReadOnlyDictionary<string, IReadOnlyList<EdgeBranchPlacement>>? branches = null) =>
        new(name, residency, revision, branches ?? MainBranch((RegionCode.Gru, true, true), (RegionCode.Sfo, true, false)));

    public static EdgePlacementSnapshot Snapshot(
        EdgeHealthDocument? health = null,
        IReadOnlyDictionary<string, EdgeDatabasePlacement>? databases = null) =>
        new(health ?? Health(), databases);

    public static EdgeRoutingPublisher Publisher(
        FakeCloudflareKvTransport transport,
        IEdgePlacementSource source,
        EdgeRoutingPublisherOptions? options = null,
        TimeProvider? clock = null) =>
        new(
            new CloudflareKvClient("token", FakeCloudflareKvTransport.AccountId, new HttpClient(transport)),
            source,
            "REGIONS",
            "PLACEMENT",
            options,
            clock);
}
