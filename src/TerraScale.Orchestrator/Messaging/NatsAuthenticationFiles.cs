using NATS.Client.Core;

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
        var seed = ReadCredentialsSeed(resolvedCredentials, optionPrefix);
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

    internal static NatsAuthenticationFiles FromNKeyFile(string nkeyFile)
    {
        if (string.IsNullOrWhiteSpace(nkeyFile))
            throw new ArgumentException("The NKey file path is required.", nameof(nkeyFile));
        return new(nkeyFile, null, nkeyFile);
    }

    private static string ResolvePrivateFile(string value, string optionName)
    {
        var path = Path.GetFullPath(value);
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is < 1 or > 16_384)
            throw new ArgumentException($"{optionName} must identify a bounded existing NATS credentials file.");
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("NATS credentials files require Linux file permissions.");
        var mode = File.GetUnixFileMode(path);
        if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                     UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
            throw new ArgumentException($"{optionName} must be private to the current user.");
        return path;
    }

    private static string ReadCredentialsSeed(string path, string optionPrefix)
    {
        var lines = File.ReadAllLines(path);
        var begin = Array.FindIndex(lines, static line =>
            line.Trim().Equals("-----BEGIN USER NKEY SEED-----", StringComparison.Ordinal));
        var end = Array.FindIndex(lines, static line =>
            line.Trim().Equals("------END USER NKEY SEED------", StringComparison.Ordinal));
        if (begin < 0 || end <= begin + 1)
            throw new ArgumentException($"{optionPrefix}_CREDENTIALS_FILE is not a valid NATS user credentials file.");
        return lines[(begin + 1)..end]
            .FirstOrDefault(static line => !string.IsNullOrWhiteSpace(line))?.Trim()
            ?? throw new ArgumentException($"{optionPrefix}_CREDENTIALS_FILE contains no user NKey seed.");
    }
}

