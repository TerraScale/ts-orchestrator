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
        return path;
    }
}
