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

public sealed class EdgeRouteSnapshot
{
    private readonly FrozenDictionary<string, EdgeRoute>.AlternateLookup<ReadOnlySpan<char>> _httpExact;
    private readonly FrozenDictionary<string, EdgeRoute>.AlternateLookup<ReadOnlySpan<char>> _httpWildcard;
    private readonly FrozenDictionary<string, EdgeRoute>.AlternateLookup<ReadOnlySpan<char>> _postgresExact;
    private readonly FrozenDictionary<string, EdgeRoute>.AlternateLookup<ReadOnlySpan<char>> _postgresWildcard;

    private EdgeRouteSnapshot(
        long revision,
        FrozenDictionary<string, EdgeRoute> httpExact,
        FrozenDictionary<string, EdgeRoute> httpWildcard,
        FrozenDictionary<string, EdgeRoute> postgresExact,
        FrozenDictionary<string, EdgeRoute> postgresWildcard)
    {
        Revision = revision;
        _httpExact = httpExact.GetAlternateLookup<ReadOnlySpan<char>>();
        _httpWildcard = httpWildcard.GetAlternateLookup<ReadOnlySpan<char>>();
        _postgresExact = postgresExact.GetAlternateLookup<ReadOnlySpan<char>>();
        _postgresWildcard = postgresWildcard.GetAlternateLookup<ReadOnlySpan<char>>();
        HttpRoutes = [.. httpExact.Values.Concat(httpWildcard.Values).Distinct()];
        PostgresRoutes = [.. postgresExact.Values.Concat(postgresWildcard.Values).Distinct()];
    }

    public static EdgeRouteSnapshot Empty { get; } = new(0, [], [], [], []);

    public long Revision { get; }

    public IReadOnlyList<EdgeRoute> HttpRoutes { get; }

    public IReadOnlyList<EdgeRoute> PostgresRoutes { get; }

    public static EdgeRouteSnapshot From(EdgeRoutesSnapshot routes)
    {
        ArgumentNullException.ThrowIfNull(routes);
        var http = Index(routes.HttpRoutes.Select(static route => (
            route.Hostnames,
            new EdgeRoute(route.ServiceName, [.. route.Upstreams.Select(static upstream => new EdgeUpstream(upstream.Address, upstream.Port, upstream.Local))]))));
        var postgres = Index(routes.PostgresRoutes.Select(static route => (
            route.Hostnames,
            new EdgeRoute(route.ServiceName, [.. route.Upstreams.Select(static upstream => new EdgeUpstream(upstream.Address, upstream.Port, upstream.Local))]))));
        return new EdgeRouteSnapshot(routes.Revision, http.Exact, http.Wildcard, postgres.Exact, postgres.Wildcard);
    }

    public EdgeRoute? FindHttpRoute(ReadOnlySpan<char> hostname) => Find(_httpExact, _httpWildcard, hostname);

    public EdgeRoute? FindPostgresRoute(ReadOnlySpan<char> serverName) => Find(_postgresExact, _postgresWildcard, serverName);

    private static EdgeRoute? Find(
        FrozenDictionary<string, EdgeRoute>.AlternateLookup<ReadOnlySpan<char>> exact,
        FrozenDictionary<string, EdgeRoute>.AlternateLookup<ReadOnlySpan<char>> wildcard,
        ReadOnlySpan<char> hostname)
    {
        var normalized = hostname.TrimEnd('.');
        if (exact.TryGetValue(normalized, out var route))
        {
            return route;
        }

        var firstDot = normalized.IndexOf('.');
        return firstDot > 0 && wildcard.TryGetValue(normalized[(firstDot + 1)..], out var wildcardRoute) ? wildcardRoute : null;
    }

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
}
