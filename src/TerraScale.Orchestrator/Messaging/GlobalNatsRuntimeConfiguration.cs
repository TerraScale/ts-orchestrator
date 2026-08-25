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
        : this(url, nkeyFile, tls, 3, cell)
    {
    }

    internal GlobalDirectoryNatsConfiguration(
        string url,
        string nkeyFile,
        NatsTlsFiles tls,
        int replicas,
        string cell)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "tls")
            throw new ArgumentException("The global directory NATS URL must be an absolute tls:// URL.", nameof(url));
        if (string.IsNullOrWhiteSpace(nkeyFile))
            throw new ArgumentException("The global directory NATS NKey file is required.", nameof(nkeyFile));
        ArgumentNullException.ThrowIfNull(tls);
        if (replicas != 3)
            throw new ArgumentException("The global directory requires exactly three replicas.", nameof(replicas));
        if (!CellTokenRule.IsValid(cell))
            throw new ArgumentException("The global directory cell is invalid.", nameof(cell));

        Url = uri.ToString();
        NKeyFile = nkeyFile;
        Tls = tls;
        Replicas = replicas;
        Cell = cell;
    }

    internal string Url { get; }
    internal string NKeyFile { get; }
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
        string cell)
    {
        ValidateCell(cell);
        var values = new[] { url, nkeyFile, caFile, certificateFile, keyFile };
        var supplied = values.Count(static value => !string.IsNullOrWhiteSpace(value));
        if (supplied == 0) return null;
        if (supplied != values.Length)
            throw new ArgumentException(
                "Global directory NATS requires URL, NKey, CA, certificate, and key together.");
        if (replicas != 3)
            throw new ArgumentException("Global directory NATS requires exactly three replicas.");
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "tls")
            throw new ArgumentException("TS_ORCH_GLOBAL_DIRECTORY_NATS_URL must be an absolute tls:// URL.");

        return new(
            uri.ToString(),
            NatsCredentialFile.Resolve(nkeyFile, "TS_ORCH_GLOBAL_DIRECTORY_NATS_NKEY_FILE")!,
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
    {
        ValidateCell(cell);
        if (cell != "gru")
            throw new ArgumentException(
                "The global directory service identity is GRU-only.", nameof(cell));
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "tls")
            throw new ArgumentException("The global directory service NATS URL must be an absolute tls:// URL.", nameof(url));
        if (string.IsNullOrWhiteSpace(nkeyFile))
            throw new ArgumentException("The global directory service NATS NKey file is required.", nameof(nkeyFile));
        ArgumentNullException.ThrowIfNull(tls);
        if (replicas != 3)
            throw new ArgumentException("The global directory service requires exactly three replicas.", nameof(replicas));

        Url = uri.ToString();
        NKeyFile = nkeyFile;
        Tls = tls;
        Replicas = replicas;
        Cell = cell;
    }

    internal string Url { get; }
    internal string NKeyFile { get; }
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
        string cell)
    {
        ValidateCell(cell);
        if (cell != "gru")
            throw new ArgumentException(
                "The global directory service identity is GRU-only.", nameof(cell));
        var values = new[] { url, nkeyFile, caFile, certificateFile, keyFile };
        var supplied = values.Count(static value => !string.IsNullOrWhiteSpace(value));
        if (supplied == 0) return null;
        if (supplied != values.Length)
            throw new ArgumentException(
                "Global directory service NATS requires URL, NKey, CA, certificate, and key together.");

        return new(
            url!,
            NatsCredentialFile.Resolve(nkeyFile, "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_NKEY_FILE")!,
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
    {
        GlobalNatsConfiguration.ValidateLegacyAuthorityAlias(cell);
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "tls")
            throw new ArgumentException("The global authority NATS URL must be an absolute tls:// URL.", nameof(url));
        if (string.IsNullOrWhiteSpace(nkeyFile))
            throw new ArgumentException("The global authority NATS NKey file is required.", nameof(nkeyFile));
        ArgumentNullException.ThrowIfNull(tls);
        if (replicas != 3)
            throw new ArgumentException("The global authority requires exactly three replicas.", nameof(replicas));

        Url = uri.ToString();
        NKeyFile = nkeyFile;
        Tls = tls;
        Replicas = replicas;
        Cell = cell;
    }

    internal string Url { get; }
    internal string NKeyFile { get; }
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
            configuration.NKeyFile,
            configuration.Tls,
            3,
            cell);
    }
}
