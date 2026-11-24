namespace TsOrch.Protocol;

public sealed record class EdgeRoutesSnapshot(
    long Revision,
    IReadOnlyList<HttpRouteEntry> HttpRoutes,
    IReadOnlyList<PostgresRouteEntry> PostgresRoutes,
    IReadOnlyList<InternalRouteEntry>? InternalRoutes = null);

public sealed record class HttpRouteEntry(
    string ServiceName,
    IReadOnlyList<string> Hostnames,
    IReadOnlyList<HttpUpstream> Upstreams,
    IReadOnlyList<string>? PathPrefixes = null,
    bool MatchGrpc = false,
    IReadOnlyList<string>? BlockedPaths = null,
    IReadOnlyList<string>? PathPatterns = null,
    IReadOnlyList<string>? Methods = null);

public sealed record class HttpUpstream(string PlacementId, string NodeId, string Address, int Port, bool Local);

public sealed record class InternalRouteEntry(
    string ServiceName,
    IReadOnlyList<HttpUpstream> Upstreams);

public sealed record class ClusterPeer(
    string NodeId,
    string Region,
    string Host,
    int QuicPort,
    int InternalHttpPort);

public sealed record class PostgresRouteEntry(
    string ServiceName,
    IReadOnlyList<string> Hostnames,
    int ListenPort,
    IReadOnlyList<PostgresUpstream> Upstreams);

public sealed record class PostgresUpstream(string PlacementId, string NodeId, string Address, int Port, bool Local);

public sealed record class EdgeAppliedRoutes(long Revision, long AppliedAt);
