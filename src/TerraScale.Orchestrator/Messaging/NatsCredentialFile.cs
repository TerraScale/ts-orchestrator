namespace TerraScale.Orchestrator.Messaging;

internal static class NatsCredentialFile
{
    public static string? Resolve(string? value, string optionName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }
        var path = Path.GetFullPath(value);
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is < 1 or > 4096)
        {
            throw new ArgumentException($"{optionName} must identify a bounded existing NKey seed file.");
        }
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("NATS credential files require Linux file permissions.");
        }
        var mode = File.GetUnixFileMode(path);
        if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                     UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
        {
            throw new ArgumentException($"{optionName} must be private to the current user.");
        }
        try
        {
            _ = NATS.Client.Core.NKeys.PublicKeyFromSeed(Seed(path));
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            throw new ArgumentException($"{optionName} does not contain a valid NKey seed.", exception);
        }
        return path;
    }

    internal static bool SameIdentity(string first, string second) =>
        NATS.Client.Core.NKeys.PublicKeyFromSeed(Seed(first)) ==
        NATS.Client.Core.NKeys.PublicKeyFromSeed(Seed(second));

    internal static string PublicKey(string path) => NATS.Client.Core.NKeys.PublicKeyFromSeed(Seed(path));

    private static string Seed(string path) => File.ReadLines(path)
        .FirstOrDefault(static line => !string.IsNullOrWhiteSpace(line))
        ?? throw new ArgumentException("NKey seed file is empty.");
}
