namespace TerraScale.Orchestrator.Messaging;

public sealed class GlobalNatsConfiguration
{
    private GlobalNatsConfiguration(string url, string nkeyFile, NatsTlsFiles tls)
    {
        Url = url;
        NKeyFile = nkeyFile;
        Tls = tls;
    }

    public string Url { get; }
    public string NKeyFile { get; }
    public NatsTlsFiles Tls { get; }

    /// <summary>
    /// The legacy TS_ORCH_GLOBAL_NATS_* settings identify GRU global authority.
    /// This pure check keeps composition responsible for deciding when the
    /// alias is present without making configuration code perform I/O.
    /// </summary>
    internal static bool IsLegacyAuthorityAliasAllowed(string? cell) =>
        cell == "gru" && GlobalNatsTopology.IsCellToken(cell);

    internal static void ValidateLegacyAuthorityAlias(string? cell)
    {
        if (!IsLegacyAuthorityAliasAllowed(cell))
            throw new ArgumentException(
                "TS_ORCH_GLOBAL_NATS_* is a GRU-only global-authority alias.",
                nameof(cell));
    }

    internal static GlobalNatsConfiguration? Resolve(
        string? url,
        string? nkeyFile,
        string? caFile,
        string? certificateFile,
        string? keyFile,
        int replicas,
        string? cell = null)
    {
        var values = new[] { url, nkeyFile, caFile, certificateFile, keyFile };
        var supplied = values.Count(static value => !string.IsNullOrWhiteSpace(value));
        if (supplied > 0 && cell is not null)
            ValidateLegacyAuthorityAlias(cell);
        if (supplied == 0) return null;
        if (supplied != values.Length)
            throw new ArgumentException("Global control NATS requires URL, NKey, CA, certificate, and key together.");
        if (replicas != 3)
            throw new ArgumentException("Global control NATS requires exactly three replicas.");
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "tls")
            throw new ArgumentException("TS_ORCH_GLOBAL_NATS_URL must be an absolute tls:// URL.");

        var resolvedNkey = NatsCredentialFile.Resolve(nkeyFile, "TS_ORCH_GLOBAL_NATS_NKEY_FILE")!;
        var tls = NatsTlsFiles.Resolve(
            caFile,
            certificateFile,
            keyFile,
            "TS_ORCH_GLOBAL_NATS_TLS")!;
        return new(uri.ToString(), resolvedNkey, tls);
    }
}
