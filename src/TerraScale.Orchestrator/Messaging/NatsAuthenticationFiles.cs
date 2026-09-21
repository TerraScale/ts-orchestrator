using NATS.Client.Core;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Messaging;

internal sealed record NatsAuthenticationFiles
{
    private NatsAuthenticationFiles(string? nkeyFile, string? credentialsFile, string publicKey)
    {
        NKeyFile = nkeyFile;
        CredentialsFile = credentialsFile;
        PublicKey = publicKey;
    }

    internal string? NKeyFile { get; }
    internal string? CredentialsFile { get; }
    internal string PublicKey { get; }

    internal NatsAuthOpts Options => CredentialsFile is not null
        ? new NatsAuthOpts { CredsFile = CredentialsFile }
        : new NatsAuthOpts { NKeyFile = NKeyFile };

    /// <summary>Signs with the user key pinned when these authentication files were resolved.</summary>
    internal byte[] SignUserRequest(byte[] canonicalRequest)
    {
        if (canonicalRequest.Length is < 1 or > 16_384)
            throw new ArgumentException("The user request exceeds its signature bounds.", nameof(canonicalRequest));
        var current = Resolve(NKeyFile, CredentialsFile, "host request NATS")!;
        if (current.PublicKey != PublicKey || !PublicKey.StartsWith('U'))
            throw new InvalidOperationException("The NATS user identity changed after connection admission.");
        var seed = CredentialsFile is not null
            ? ReadCredentials(current.CredentialsFile!, "host request NATS").Seed
            : NatsCredentialFile.Seed(current.NKeyFile!);
        if (NKeys.PublicKeyFromSeed(seed) != PublicKey)
            throw new InvalidOperationException("The NATS user identity changed while loading its signing key.");
        using var key = NKeys.FromSeed(seed);
        return key.Sign(canonicalRequest);
    }

    internal static NatsAuthenticationFiles? Resolve(
        string? nkeyFile,
        string? credentialsFile,
        string optionPrefix)
    {
        var hasNkey = !string.IsNullOrWhiteSpace(nkeyFile);
        var hasCredentials = !string.IsNullOrWhiteSpace(credentialsFile);
        if (!hasNkey && !hasCredentials) return null;
        if (hasNkey && hasCredentials)
            throw new ArgumentException($"{optionPrefix} requires either an NKey seed file or a credentials file, not both.");

        if (hasNkey)
        {
            var path = NatsCredentialFile.Resolve(nkeyFile, $"{optionPrefix}_NKEY_FILE")!;
            return new(path, null, NatsCredentialFile.PublicKey(path));
        }

        var resolvedCredentials = ResolvePrivateFile(credentialsFile!, $"{optionPrefix}_CREDENTIALS_FILE");
        var seed = ReadCredentials(resolvedCredentials, optionPrefix).Seed;
        try
        {
            return new(null, resolvedCredentials, NKeys.PublicKeyFromSeed(seed));
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            throw new ArgumentException($"{optionPrefix}_CREDENTIALS_FILE does not contain a valid user NKey seed.", exception);
        }
    }

    internal static NatsAuthenticationFiles FromCredentialsFile(string credentialsFile, string optionPrefix) =>
        Resolve(null, credentialsFile, optionPrefix)
        ?? throw new ArgumentException($"{optionPrefix}_CREDENTIALS_FILE is required.");

    internal static NatsAuthenticationFiles FromNKeyFile(string nkeyFile) =>
        Resolve(nkeyFile, null, "TS_ORCH_NATS")
        ?? throw new ArgumentException("The NKey file path is required.", nameof(nkeyFile));

    private static string ResolvePrivateFile(string value, string optionName)
    {
        return NatsFileResolver.Resolve(value, optionName, 16_384, ownerPrivate: true);
    }

    private static readonly JsonSerializerOptions JsonOptions = new() { AllowDuplicateProperties = false };

    internal DateTimeOffset ExecutionExpiresAt(DateTimeOffset now)
    {
        var current = Resolve(NKeyFile, CredentialsFile, "host execution NATS")!;
        if (current.PublicKey != PublicKey)
            throw new InvalidDataException("The pinned NATS user identity changed.");
        if (CredentialsFile is null) return DateTimeOffset.MaxValue;
        var claims = ReadCredentials(current.CredentialsFile!, "host execution NATS").Identity;
        var expires = claims.Expires is null or 0 ? DateTimeOffset.MaxValue : DateTimeOffset.FromUnixTimeSeconds(claims.Expires.Value);
        if (expires <= now || claims.NotBefore is { } start && DateTimeOffset.FromUnixTimeSeconds(start) > now)
            throw new InvalidDataException("The pinned NATS user credential is outside its validity window.");
        return expires;
    }

    private static (string Seed, JwtIdentity Identity) ReadCredentials(string path, string optionPrefix)
    {
        try
        {
            var lines = File.ReadAllLines(path).Select(static line => line.Trim()).ToArray();
            var seed = SingleBlock(lines, "-----BEGIN USER NKEY SEED-----", "------END USER NKEY SEED------");
            var jwt = SingleBlock(lines, "-----BEGIN NATS USER JWT-----", "------END NATS USER JWT------");
            var publicKey = NKeys.PublicKeyFromSeed(seed);
            var parts = jwt.Split('.');
            if (!publicKey.StartsWith('U') || parts.Length != 3 || Decode(parts[2]).Length != 64)
                throw new FormatException();
            var header = JsonSerializer.Deserialize<JwtHeader>(Decode(parts[0]), JsonOptions);
            var claims = JsonSerializer.Deserialize<JwtIdentity>(Decode(parts[1]), JsonOptions);
            if (header is not { Algorithm: "ed25519-nkey", Type: "JWT" } ||
                claims is not { Nats.Type: "user", Nats.Version: 2 } || claims.Subject != publicKey)
                throw new FormatException();
            // The server verifies issuer trust, signature, expiry and grants. This parser
            // only ensures the runtime's bound identity matches the supplied credentials.
            return (seed, claims);
        }
        catch (Exception exception) when (exception is FormatException or JsonException or ArgumentException)
        {
            throw new ArgumentException($"{optionPrefix}_CREDENTIALS_FILE must contain one matching user JWT and NKey seed.");
        }
    }

    private static string SingleBlock(string[] lines, string begin, string end)
    {
        if (lines.Count(line => line == begin) != 1 || lines.Count(line => line == end) != 1)
            throw new FormatException();
        var start = Array.IndexOf(lines, begin);
        var finish = Array.IndexOf(lines, end);
        if (finish != start + 2 || lines[start + 1].Length == 0)
            throw new FormatException();
        return lines[start + 1];
    }

    private static byte[] Decode(string value)
    {
        if (value.Length == 0 || value.Any(static c => c is not (>= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_')))
            throw new FormatException();
        var bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
        if (Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') != value)
            throw new FormatException();
        return bytes;
    }

    private sealed record JwtHeader([property: JsonPropertyName("alg")] string Algorithm, [property: JsonPropertyName("typ")] string Type);
    private sealed record JwtIdentity([property: JsonPropertyName("sub")] string Subject, [property: JsonPropertyName("nats")] JwtKind Nats,
        [property: JsonPropertyName("exp")] long? Expires, [property: JsonPropertyName("nbf")] long? NotBefore);
    private sealed record JwtKind([property: JsonPropertyName("type")] string Type, [property: JsonPropertyName("version")] int Version);
}
