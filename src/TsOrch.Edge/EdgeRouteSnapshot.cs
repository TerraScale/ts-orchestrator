using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
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
    private const int MaxDecodePasses = 4;
    private static readonly TimeSpan PatternTimeout = TimeSpan.FromMilliseconds(100);

    private readonly FrozenDictionary<string, ImmutableArray<HttpRoute>>.AlternateLookup<ReadOnlySpan<char>> _httpExact;
    private readonly FrozenDictionary<string, ImmutableArray<HttpRoute>>.AlternateLookup<ReadOnlySpan<char>> _httpWildcard;
    private readonly FrozenDictionary<string, EdgeRoute>.AlternateLookup<ReadOnlySpan<char>> _postgresExact;
    private readonly FrozenDictionary<string, EdgeRoute>.AlternateLookup<ReadOnlySpan<char>> _postgresWildcard;
    private readonly FrozenDictionary<string, EdgeRoute> _internalRoutes;

    private EdgeRouteSnapshot(
        long revision,
        FrozenDictionary<string, ImmutableArray<HttpRoute>> httpExact,
        FrozenDictionary<string, ImmutableArray<HttpRoute>> httpWildcard,
        FrozenDictionary<string, EdgeRoute> postgresExact,
        FrozenDictionary<string, EdgeRoute> postgresWildcard,
        FrozenDictionary<string, EdgeRoute> internalRoutes)
    {
        Revision = revision;
        _httpExact = httpExact.GetAlternateLookup<ReadOnlySpan<char>>();
        _httpWildcard = httpWildcard.GetAlternateLookup<ReadOnlySpan<char>>();
        _postgresExact = postgresExact.GetAlternateLookup<ReadOnlySpan<char>>();
        _postgresWildcard = postgresWildcard.GetAlternateLookup<ReadOnlySpan<char>>();
        _internalRoutes = internalRoutes;
        HttpRoutes = [.. httpExact.Values.Concat(httpWildcard.Values).SelectMany(static routes => routes).Select(static route => route.Route).Distinct()];
        PostgresRoutes = [.. postgresExact.Values.Concat(postgresWildcard.Values).Distinct()];
        InternalRoutes = [.. internalRoutes.Values];
    }

    public static EdgeRouteSnapshot Empty { get; } = new(0, [], [], [], [], []);

    public long Revision { get; }

    public IReadOnlyList<EdgeRoute> HttpRoutes { get; }

    public IReadOnlyList<EdgeRoute> PostgresRoutes { get; }

    public IReadOnlyList<EdgeRoute> InternalRoutes { get; }

    public static EdgeRouteSnapshot From(EdgeRoutesSnapshot routes)
    {
        ArgumentNullException.ThrowIfNull(routes);
        var http = Index(routes.HttpRoutes.Select(static entry => (
            entry.Hostnames,
            new HttpRoute(
                new EdgeRoute(entry.ServiceName, [.. entry.Upstreams.Select(static upstream => new EdgeUpstream(upstream.Address, upstream.Port, upstream.Local))]),
                entry.PathPrefixes is { } prefixes ? [.. prefixes] : [],
                entry.MatchGrpc,
                entry.BlockedPaths is { } blocked ? [.. blocked] : [],
                CompilePatterns(entry.PathPatterns),
                entry.Methods is { } methods ? [.. methods] : []))));
        var postgres = Index(routes.PostgresRoutes.Select(static route => (
            route.Hostnames,
            new EdgeRoute(route.ServiceName, [.. route.Upstreams.Select(static upstream => new EdgeUpstream(upstream.Address, upstream.Port, upstream.Local))]))));
        Dictionary<string, EdgeRoute> internals = [with(StringComparer.OrdinalIgnoreCase)];
        foreach (var entry in routes.InternalRoutes ?? [])
        {
            internals[entry.ServiceName] = new EdgeRoute(
                entry.ServiceName,
                [.. entry.Upstreams.Select(static upstream => new EdgeUpstream(upstream.Address, upstream.Port, upstream.Local))]);
        }

        return new EdgeRouteSnapshot(
            routes.Revision,
            http.Exact,
            http.Wildcard,
            postgres.Exact,
            postgres.Wildcard,
            internals.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase));
    }

    public EdgeRouteMatch ResolveHttpRoute(string host, string method, PathString path, string? contentType)
    {
        if (Find(_httpExact, _httpWildcard, host.AsSpan()) is not { IsDefault: false } candidates)
        {
            return new EdgeRouteNotFound();
        }

        if (!TryCanonicalizePath(path.Value ?? "/", out var canonicalText))
        {
            return new EdgeRouteBlocked();
        }

        var canonicalPath = new PathString(canonicalText);
        foreach (var candidate in candidates)
        {
            if (candidate.BlockedPaths.Any(prefix => MatchesBlockedPrefix(canonicalPath, prefix)))
            {
                return new EdgeRouteBlocked();
            }
        }

        var isGrpc = IsGrpc(contentType);
        HttpRoute? grpc = null;
        HttpRoute? bestPattern = null;
        var bestPatternHasMethods = false;
        var bestPatternLength = -1;
        HttpRoute? bestPrefix = null;
        var bestPrefixLength = -1;
        HttpRoute? catchAll = null;

        foreach (var candidate in candidates)
        {
            if (candidate.MatchGrpc)
            {
                grpc ??= candidate;
            }

            if (!MatchesMethod(candidate.Methods, method))
            {
                continue;
            }

            if (!candidate.PathPatterns.IsEmpty)
            {
                foreach (var pattern in candidate.PathPatterns)
                {
                    if (MatchesRegex(pattern.Regex, canonicalText))
                    {
                        var hasMethods = !candidate.Methods.IsEmpty;
                        if (bestPattern is null
                            || (hasMethods && !bestPatternHasMethods)
                            || (hasMethods == bestPatternHasMethods && pattern.SourceLength > bestPatternLength))
                        {
                            bestPattern = candidate;
                            bestPatternHasMethods = hasMethods;
                            bestPatternLength = pattern.SourceLength;
                        }
                    }
                }
            }

            if (!candidate.PathPrefixes.IsEmpty)
            {
                foreach (var prefix in candidate.PathPrefixes)
                {
                    if (prefix.Length > bestPrefixLength && MatchesPrefix(canonicalPath, prefix))
                    {
                        bestPrefixLength = prefix.Length;
                        bestPrefix = candidate;
                    }
                }
            }

            if (candidate.PathPrefixes.IsEmpty && candidate.PathPatterns.IsEmpty && candidate.Methods.IsEmpty
                && (catchAll is null || (catchAll.MatchGrpc && candidate.MatchGrpc is false)))
            {
                catchAll = candidate;
            }
        }

        var selected = (isGrpc ? grpc : null) ?? bestPattern ?? bestPrefix ?? catchAll;
        return selected is null ? new EdgeRouteNotFound() : selected.Route;
    }

    public EdgeRoute? FindInternalRoute(string serviceName) =>
        _internalRoutes.TryGetValue(serviceName, out var route) ? route : null;

    internal static bool IsGrpc(string? contentType) =>
        contentType?.StartsWith("application/grpc", StringComparison.OrdinalIgnoreCase) is true;

    public EdgeRoute? FindPostgresRoute(ReadOnlySpan<char> serverName) => Find(_postgresExact, _postgresWildcard, serverName);

    internal static bool TryCanonicalizePath(string raw, out string canonical)
    {
        var decoded = raw;
        for (var pass = 0; pass < MaxDecodePasses; pass++)
        {
            if (!TryPercentDecode(decoded, out var next))
            {
                canonical = string.Empty;
                return false;
            }

            if (string.Equals(next, decoded, StringComparison.Ordinal))
            {
                break;
            }

            decoded = next;
        }

        if (decoded.Contains('\0', StringComparison.Ordinal))
        {
            canonical = string.Empty;
            return false;
        }

        var normalized = decoded.Replace('\\', '/');
        List<string> segments = [];
        foreach (var segment in normalized.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment == ".")
            {
                continue;
            }

            if (segment == "..")
            {
                if (segments.Count > 0)
                {
                    segments.RemoveAt(segments.Count - 1);
                }

                continue;
            }

            segments.Add(segment);
        }

        canonical = segments.Count == 0 ? "/" : "/" + string.Join('/', segments);
        return true;
    }

    private static bool TryPercentDecode(string input, out string output)
    {
        if (!input.Contains('%', StringComparison.Ordinal))
        {
            output = input;
            return true;
        }

        var bytes = new List<byte>(input.Length);
        var builder = new StringBuilder(input.Length);
        for (var index = 0; index < input.Length; index++)
        {
            if (input[index] != '%')
            {
                if (bytes.Count > 0)
                {
                    builder.Append(Encoding.UTF8.GetString(CollectionsMarshal.AsSpan(bytes)));
                    bytes.Clear();
                }

                builder.Append(input[index]);
                continue;
            }

            if (index + 2 >= input.Length
                || !TryHexNibble(input[index + 1], out var hi)
                || !TryHexNibble(input[index + 2], out var lo))
            {
                if (bytes.Count > 0)
                {
                    builder.Append(Encoding.UTF8.GetString(CollectionsMarshal.AsSpan(bytes)));
                    bytes.Clear();
                }

                builder.Append('%');
                continue;
            }

            var decodedByte = (byte)((hi << 4) | lo);
            if (decodedByte == 0)
            {
                output = string.Empty;
                return false;
            }

            bytes.Add(decodedByte);
            index += 2;
        }

        if (bytes.Count > 0)
        {
            builder.Append(Encoding.UTF8.GetString(CollectionsMarshal.AsSpan(bytes)));
        }

        output = builder.ToString();
        return true;
    }

    private static bool TryHexNibble(char ch, out int value)
    {
        if (ch is >= '0' and <= '9')
        {
            value = ch - '0';
            return true;
        }

        if (ch is >= 'a' and <= 'f')
        {
            value = ch - 'a' + 10;
            return true;
        }

        if (ch is >= 'A' and <= 'F')
        {
            value = ch - 'A' + 10;
            return true;
        }

        value = 0;
        return false;
    }

    private static ImmutableArray<CompiledPattern> CompilePatterns(IReadOnlyList<string>? patterns)
    {
        if (patterns is not { Count: > 0 })
        {
            return [];
        }

        var builder = ImmutableArray.CreateBuilder<CompiledPattern>(patterns.Count);
        foreach (var pattern in patterns)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                continue;
            }

            try
            {
                builder.Add(new CompiledPattern(
                    new Regex(pattern, RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, PatternTimeout),
                    pattern.Length));
            }
            catch (ArgumentException)
            {
            }
        }

        return builder.ToImmutable();
    }

    private static bool MatchesRegex(Regex regex, string input)
    {
        try
        {
            return regex.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static bool MatchesMethod(ImmutableArray<string> methods, string method) =>
        methods.IsEmpty || methods.Any(allowed => string.Equals(allowed, method, StringComparison.OrdinalIgnoreCase));

    private static bool MatchesPrefix(PathString path, string prefix) =>
        prefix.StartsWith('/') && path.StartsWithSegments(new PathString(prefix), StringComparison.Ordinal);

    private static bool MatchesBlockedPrefix(PathString path, string prefix) =>
        prefix.StartsWith('/') && path.StartsWithSegments(new PathString(prefix), StringComparison.OrdinalIgnoreCase);

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

    private sealed record class CompiledPattern(Regex Regex, int SourceLength);

    private sealed record class HttpRoute(
        EdgeRoute Route,
        ImmutableArray<string> PathPrefixes,
        bool MatchGrpc,
        ImmutableArray<string> BlockedPaths,
        ImmutableArray<CompiledPattern> PathPatterns,
        ImmutableArray<string> Methods);
}
