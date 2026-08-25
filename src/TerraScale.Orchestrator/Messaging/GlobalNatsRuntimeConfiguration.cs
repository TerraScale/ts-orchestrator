using TerraScale.Orchestrator;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Connection and access settings for a regional directory publisher. This
/// configuration has one durable capability, the GLOBAL_CELLS projection.
/// </summary>
public sealed class GlobalDirectoryNatsConfiguration
{
    internal GlobalDirectoryNatsConfiguration(
        string url,
        string nkeyFile,
        NatsTlsFiles tls,
        string cell)
        : this(url, NatsAuthenticationFiles.FromNKeyFile(nkeyFile), tls, 3, cell)
    {
    }

    internal GlobalDirectoryNatsConfiguration(
        string url,
        string nkeyFile,
        NatsTlsFiles tls,
        int replicas,
        string cell)
        : this(url, NatsAuthenticationFiles.FromNKeyFile(nkeyFile), tls, replicas, cell)
    {
    }

    internal GlobalDirectoryNatsConfiguration(
        string url,
        NatsAuthenticationFiles authentication,
        NatsTlsFiles tls,
        string cell)
        : this(url, authentication, tls, 3, cell)
    {
    }

    internal GlobalDirectoryNatsConfiguration(
        string url,
        NatsAuthenticationFiles authentication,
        NatsTlsFiles tls,
        int replicas,
        string cell)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "tls")
            throw new ArgumentException("The global directory NATS URL must be an absolute tls:// URL.", nameof(url));
        ArgumentNullException.ThrowIfNull(authentication);
        ArgumentNullException.ThrowIfNull(tls);
        if (replicas != 3)
            throw new ArgumentException("The global directory requires exactly three replicas.", nameof(replicas));
        if (!CellTokenRule.IsValid(cell))
            throw new ArgumentException("The global directory cell is invalid.", nameof(cell));

        Url = uri.ToString();
        Authentication = authentication;
        Tls = tls;
        Replicas = replicas;
        Cell = cell;
    }

    internal string Url { get; }
    internal NatsAuthenticationFiles Authentication { get; }
    internal NatsTlsFiles Tls { get; }
    internal int Replicas { get; }
    internal string Cell { get; }

    internal GlobalNatsAccessPlan AccessPlan =>
        GlobalNatsAccessContract.Create(Cell, GlobalNatsCapability.CellDirectoryPublisher);

    internal static GlobalDirectoryNatsConfiguration? Resolve(
        string? url,
        string? nkeyFile,
        string? caFile,
        string? certificateFile,
        string? keyFile,
        int replicas,
        string cell) => Resolve(
            url, nkeyFile, null, caFile, certificateFile, keyFile, replicas, cell);

    internal static GlobalDirectoryNatsConfiguration? Resolve(
        string? url,
        string? nkeyFile,
        string? credentialsFile,
        string? caFile,
        string? certificateFile,
        string? keyFile,
        int replicas,
        string cell)
    {
        var values = new[] { url, nkeyFile, credentialsFile, caFile, certificateFile, keyFile };
        var supplied = values.Count(static value => !string.IsNullOrWhiteSpace(value));
        if (supplied == 0) return null;
        ValidateCell(cell);
        var authentication = NatsAuthenticationFiles.Resolve(
            nkeyFile, credentialsFile, "TS_ORCH_GLOBAL_DIRECTORY_NATS");
        if (url is null || authentication is null || caFile is null || certificateFile is null || keyFile is null)
            throw new ArgumentException(
                "Global directory NATS requires URL, authentication, CA, certificate, and key together.");
        if (replicas != 3)
            throw new ArgumentException("Global directory NATS requires exactly three replicas.");
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "tls")
            throw new ArgumentException("TS_ORCH_GLOBAL_DIRECTORY_NATS_URL must be an absolute tls:// URL.");

        return new(
            uri.ToString(),
            authentication,
            NatsTlsFiles.Resolve(
                caFile,
                certificateFile,
                keyFile,
                "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS")!,
            replicas,
            cell);
    }

    private static void ValidateCell(string cell)
    {
        if (!CellTokenRule.IsValid(cell))
            throw new ArgumentException("The global directory cell is invalid.", nameof(cell));
    }

}

/// <summary>
/// GRU-only identity for the read-only global cell query service. It is kept
/// separate from the publisher/watch identity because the service has no
/// GLOBAL_CELLS write capability.
/// </summary>
public sealed class GlobalDirectoryServiceNatsConfiguration
{
    internal GlobalDirectoryServiceNatsConfiguration(
        string url,
        string nkeyFile,
        NatsTlsFiles tls,
        int replicas,
        string cell)
        : this(url, NatsAuthenticationFiles.FromNKeyFile(nkeyFile), tls, replicas, cell)
    {
    }

    internal GlobalDirectoryServiceNatsConfiguration(
        string url,
        NatsAuthenticationFiles authentication,
        NatsTlsFiles tls,
        int replicas,
        string cell)
    {
        ValidateCell(cell);
        if (cell != "gru")
            throw new ArgumentException(
                "The global directory service identity is GRU-only.", nameof(cell));
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "tls")
            throw new ArgumentException("The global directory service NATS URL must be an absolute tls:// URL.", nameof(url));
        ArgumentNullException.ThrowIfNull(authentication);
        ArgumentNullException.ThrowIfNull(tls);
        if (replicas != 3)
            throw new ArgumentException("The global directory service requires exactly three replicas.", nameof(replicas));

        Url = uri.ToString();
        Authentication = authentication;
        Tls = tls;
        Replicas = replicas;
        Cell = cell;
    }

    internal string Url { get; }
    internal NatsAuthenticationFiles Authentication { get; }
    internal NatsTlsFiles Tls { get; }
    internal int Replicas { get; }
    internal string Cell { get; }

    internal GlobalNatsAccessPlan AccessPlan =>
        GlobalNatsAccessContract.Create(Cell, GlobalNatsCapability.CellDirectoryService);

    internal static GlobalDirectoryServiceNatsConfiguration? Resolve(
        string? url,
        string? nkeyFile,
        string? caFile,
        string? certificateFile,
        string? keyFile,
        int replicas,
        string cell) => Resolve(
            url, nkeyFile, null, caFile, certificateFile, keyFile, replicas, cell);

    internal static GlobalDirectoryServiceNatsConfiguration? Resolve(
        string? url,
        string? nkeyFile,
        string? credentialsFile,
        string? caFile,
        string? certificateFile,
        string? keyFile,
        int replicas,
        string cell)
    {
        var values = new[] { url, nkeyFile, credentialsFile, caFile, certificateFile, keyFile };
        var supplied = values.Count(static value => !string.IsNullOrWhiteSpace(value));
        if (supplied == 0) return null;
        ValidateCell(cell);
        if (cell != "gru")
            throw new ArgumentException(
                "The global directory service identity is GRU-only.", nameof(cell));
        var authentication = NatsAuthenticationFiles.Resolve(
            nkeyFile, credentialsFile, "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS");
        if (url is null || authentication is null || caFile is null || certificateFile is null || keyFile is null)
            throw new ArgumentException(
                "Global directory service NATS requires URL, authentication, CA, certificate, and key together.");

        return new(
            url!,
            authentication,
            NatsTlsFiles.Resolve(
                caFile,
                certificateFile,
                keyFile,
                "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS")!,
            replicas,
            cell);
    }

    private static void ValidateCell(string cell)
    {
        if (!CellTokenRule.IsValid(cell))
            throw new ArgumentException("The global directory service cell is invalid.", nameof(cell));
    }
}

/// <summary>
/// GRU-only connection and access settings for the global authority. The
/// authority credential is selected separately from regional directory
/// credentials through the access plan.
/// </summary>
internal sealed class GlobalAuthorityNatsConfiguration
{
    internal GlobalAuthorityNatsConfiguration(
        string url,
        string nkeyFile,
        NatsTlsFiles tls,
        int replicas,
        string cell)
        : this(url, NatsAuthenticationFiles.FromNKeyFile(nkeyFile), tls, replicas, cell)
    {
    }

    internal GlobalAuthorityNatsConfiguration(
        string url,
        NatsAuthenticationFiles authentication,
        NatsTlsFiles tls,
        int replicas,
        string cell)
    {
        GlobalNatsConfiguration.ValidateLegacyAuthorityAlias(cell);
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "tls")
            throw new ArgumentException("The global authority NATS URL must be an absolute tls:// URL.", nameof(url));
        ArgumentNullException.ThrowIfNull(authentication);
        ArgumentNullException.ThrowIfNull(tls);
        if (replicas != 3)
            throw new ArgumentException("The global authority requires exactly three replicas.", nameof(replicas));

        Url = uri.ToString();
        Authentication = authentication;
        Tls = tls;
        Replicas = replicas;
        Cell = cell;
    }

    internal string Url { get; }
    internal NatsAuthenticationFiles Authentication { get; }
    internal NatsTlsFiles Tls { get; }
    internal int Replicas { get; }
    internal string Cell { get; }

    internal GlobalNatsAccessPlan AccessPlan =>
        GlobalNatsAccessContract.Create(Cell, GlobalNatsCapability.GlobalAuthority);

    internal static GlobalAuthorityNatsConfiguration From(
        GlobalNatsConfiguration configuration,
        string cell)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return new(
            configuration.Url,
            configuration.Authentication,
            configuration.Tls,
            3,
            cell);
    }
}
