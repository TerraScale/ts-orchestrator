using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Globalization;
using TsOrch.Protocol;

namespace TsOrch.Edge;

public sealed record class EdgeUpstream(string Address, int Port, bool Local)
{
    public string DestinationPrefix { get; } = string.Create(
        CultureInfo.InvariantCulture,
        $"http://{(Address.Contains(':', StringComparison.Ordinal) ? $"[{Address}]" : Address)}:{Port}/");
}

public sealed record class EdgeRoute(string ServiceName, ImmutableArray<EdgeUpstream> Upstreams);

public sealed record class EdgeRouteBlocked;

public sealed record class EdgeRouteNotFound;

public readonly union EdgeRouteMatch(EdgeRoute, EdgeRouteBlocked, EdgeRouteNotFound);

public sealed class EdgeRouteSnapshot
{
    private readonly FrozenDictionary<string, ImmutableArray<HttpRoute>>.AlternateLookup<ReadOnlySpan<char>> _httpExact;
    private readonly FrozenDictionary<string, ImmutableArray<HttpRoute>>.AlternateLookup<ReadOnlySpan<char>> _httpWildcard;
    private readonly FrozenDictionary<string, EdgeRoute>.AlternateLookup<ReadOnlySpan<char>> _postgresExact;
    private readonly FrozenDictionary<string, EdgeRoute>.AlternateLookup<ReadOnlySpan<char>> _postgresWildcard;

    private EdgeRouteSnapshot(
        long revision,
        FrozenDictionary<string, ImmutableArray<HttpRoute>> httpExact,
        FrozenDictionary<string, ImmutableArray<HttpRoute>> httpWildcard,
        FrozenDictionary<string, EdgeRoute> postgresExact,
        FrozenDictionary<string, EdgeRoute> postgresWildcard)
    {
        Revision = revision;
        _httpExact = httpExact.GetAlternateLookup<ReadOnlySpan<char>>();
        _httpWildcard = httpWildcard.GetAlternateLookup<ReadOnlySpan<char>>();
        _postgresExact = postgresExact.GetAlternateLookup<ReadOnlySpan<char>>();
        _postgresWildcard = postgresWildcard.GetAlternateLookup<ReadOnlySpan<char>>();
        HttpRoutes = [.. httpExact.Values.Concat(httpWildcard.Values).SelectMany(static routes => routes).Select(static route => route.Route).Distinct()];
        PostgresRoutes = [.. postgresExact.Values.Concat(postgresWildcard.Values).Distinct()];
    }

    public static EdgeRouteSnapshot Empty { get; } = new(0, [], [], [], []);

    public long Revision { get; }

    public IReadOnlyList<EdgeRoute> HttpRoutes { get; }

    public IReadOnlyList<EdgeRoute> PostgresRoutes { get; }

    public static EdgeRouteSnapshot From(EdgeRoutesSnapshot routes)
    {
        ArgumentNullException.ThrowIfNull(routes);
        var http = Index(routes.HttpRoutes.Select(static entry => (
            entry.Hostnames,
            new HttpRoute(
                new EdgeRoute(entry.ServiceName, [.. entry.Upstreams.Select(static upstream => new EdgeUpstream(upstream.Address, upstream.Port, upstream.Local))]),
                entry.PathPrefixes is { } prefixes ? [.. prefixes] : [],
                entry.MatchGrpc,
                entry.BlockedPaths is { } blocked ? [.. blocked] : []))));
        var postgres = Index(routes.PostgresRoutes.Select(static route => (
            route.Hostnames,
            new EdgeRoute(route.ServiceName, [.. route.Upstreams.Select(static upstream => new EdgeUpstream(upstream.Address, upstream.Port, upstream.Local))]))));
        return new EdgeRouteSnapshot(routes.Revision, http.Exact, http.Wildcard, postgres.Exact, postgres.Wildcard);
    }

    public EdgeRouteMatch ResolveHttpRoute(string host, PathString path, string? contentType)
    {
        if (Find(_httpExact, _httpWildcard, host.AsSpan()) is not { IsDefault: false } candidates)
        {
            return new EdgeRouteNotFound();
        }

        var blockedPath = path.Value is { } value && value.Contains("%2f", StringComparison.OrdinalIgnoreCase)
            ? new PathString(value.Replace("%2f", "/", StringComparison.OrdinalIgnoreCase))
            : path;
        var isGrpc = IsGrpc(contentType);
        HttpRoute? grpc = null;
        HttpRoute? best = null;
        HttpRoute? catchAll = null;
        var bestLength = -1;
        foreach (var candidate in candidates)
        {
            if (candidate.BlockedPaths.Any(prefix => MatchesPrefix(blockedPath, prefix) || MatchesPrefix(path, prefix)))
            {
                return new EdgeRouteBlocked();
            }

            if (candidate.MatchGrpc)
            {
                grpc ??= candidate;
            }

            if (candidate.PathPrefixes.IsEmpty && (catchAll is null || (catchAll.MatchGrpc && candidate.MatchGrpc is false)))
            {
                catchAll = candidate;
            }

            foreach (var prefix in candidate.PathPrefixes)
            {
                if (prefix.Length > bestLength && MatchesPrefix(path, prefix))
                {
                    bestLength = prefix.Length;
                    best = candidate;
                }
            }
        }

        var selected = (isGrpc ? grpc : null) ?? best ?? catchAll;
        return selected is null ? new EdgeRouteNotFound() : selected.Route;
    }

    internal static bool IsGrpc(string? contentType) =>
        contentType?.StartsWith("application/grpc", StringComparison.OrdinalIgnoreCase) is true;

    public EdgeRoute? FindPostgresRoute(ReadOnlySpan<char> serverName) => Find(_postgresExact, _postgresWildcard, serverName);

    private static bool MatchesPrefix(PathString path, string prefix) =>
        prefix.StartsWith('/') && path.StartsWithSegments(new PathString(prefix), StringComparison.Ordinal);

    private static T? Find<T>(
        FrozenDictionary<string, T>.AlternateLookup<ReadOnlySpan<char>> exact,
        FrozenDictionary<string, T>.AlternateLookup<ReadOnlySpan<char>> wildcard,
        ReadOnlySpan<char> hostname)
    {
        var normalized = hostname.TrimEnd('.');
        if (exact.TryGetValue(normalized, out var route))
        {
            return route;
        }

        var firstDot = normalized.IndexOf('.');
        return firstDot > 0 && wildcard.TryGetValue(normalized[(firstDot + 1)..], out var wildcardRoute) ? wildcardRoute : default;
    }

    private static (FrozenDictionary<string, ImmutableArray<HttpRoute>> Exact, FrozenDictionary<string, ImmutableArray<HttpRoute>> Wildcard) Index(
        IEnumerable<(IReadOnlyList<string> Hostnames, HttpRoute Route)> routes)
    {
        Dictionary<string, List<HttpRoute>> exact = [with(StringComparer.OrdinalIgnoreCase)];
        Dictionary<string, List<HttpRoute>> wildcard = [with(StringComparer.OrdinalIgnoreCase)];
        foreach (var (hostnames, route) in routes)
        {
            foreach (var hostname in hostnames)
            {
                var normalized = hostname.Trim().TrimEnd('.');
                if (normalized.Length == 0)
                {
                    continue;
                }

                var isWildcard = normalized.StartsWith("*.", StringComparison.Ordinal);
                var index = isWildcard ? wildcard : exact;
                var key = isWildcard ? normalized[2..] : normalized;
                if (index.TryGetValue(key, out var candidates) is false)
                {
                    candidates = [];
                    index.Add(key, candidates);
                }

                candidates.Add(route);
            }
        }

        return (Freeze(exact), Freeze(wildcard));
    }

    private static FrozenDictionary<string, ImmutableArray<HttpRoute>> Freeze(Dictionary<string, List<HttpRoute>> routes) =>
        routes.ToFrozenDictionary(static pair => pair.Key, static pair => pair.Value.ToImmutableArray(), StringComparer.OrdinalIgnoreCase);

    private static (FrozenDictionary<string, EdgeRoute> Exact, FrozenDictionary<string, EdgeRoute> Wildcard) Index(
        IEnumerable<(IReadOnlyList<string> Hostnames, EdgeRoute Route)> routes)
    {
        var exact = new Dictionary<string, EdgeRoute>(StringComparer.OrdinalIgnoreCase);
        var wildcard = new Dictionary<string, EdgeRoute>(StringComparer.OrdinalIgnoreCase);
        foreach (var (hostnames, route) in routes)
        {
            foreach (var hostname in hostnames)
            {
                var normalized = hostname.Trim().TrimEnd('.').ToLowerInvariant();
                if (normalized.StartsWith("*.", StringComparison.Ordinal))
                {
                    wildcard[normalized[2..]] = route;
                }
                else if (normalized.Length > 0)
                {
                    exact[normalized] = route;
                }
            }
        }

        return (exact.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase), wildcard.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase));
    }

    private sealed record class HttpRoute(EdgeRoute Route, ImmutableArray<string> PathPrefixes, bool MatchGrpc, ImmutableArray<string> BlockedPaths);
}
