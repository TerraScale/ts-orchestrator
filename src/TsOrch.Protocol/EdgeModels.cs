namespace TsOrch.Protocol;

public sealed record class EdgeRoutesSnapshot(
    long Revision,
    IReadOnlyList<HttpRouteEntry> HttpRoutes,
    IReadOnlyList<PostgresRouteEntry> PostgresRoutes);

public sealed record class HttpRouteEntry(
    string ServiceName,
    IReadOnlyList<string> Hostnames,
    IReadOnlyList<HttpUpstream> Upstreams);

public sealed record class HttpUpstream(string PlacementId, string NodeId, string Address, int Port, bool Local);

public sealed record class PostgresRouteEntry(
    string ServiceName,
    IReadOnlyList<string> Hostnames,
    int ListenPort,
    IReadOnlyList<PostgresUpstream> Upstreams);

public sealed record class PostgresUpstream(string PlacementId, string NodeId, string Address, int Port, bool Local);
