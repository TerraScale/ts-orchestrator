namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Common admission checks for NATS material loaded from the host filesystem.
///
/// The resolver is deliberately path-based because the NATS client APIs consume
/// paths. It therefore rejects links before any caller reads the path and checks
/// every existing directory component for symlink traversal.
/// </summary>
internal static class NatsFileResolver
{
    private const UnixFileMode GroupOrOtherWrite =
        UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;

    private const UnixFileMode GroupOrOtherMode =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    internal static string Resolve(
        string value,
        string optionName,
        long maximumLength,
        bool ownerPrivate)
    {
        var path = Path.GetFullPath(value);
        var file = new FileInfo(path);
        if (!file.Exists || file.LinkTarget is not null ||
            file.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            file.Attributes.HasFlag(FileAttributes.Directory) ||
            file.Attributes.HasFlag(FileAttributes.Device) ||
            HasSymlinkAncestor(file) || file.Length < 1 || file.Length > maximumLength)
        {
            throw new ArgumentException(
                $"{optionName} must identify a bounded existing regular file without symlink traversal.");
        }

        if (!OperatingSystem.IsLinux() && ownerPrivate)
        {
            throw new PlatformNotSupportedException($"{optionName} requires Linux file permissions.");
        }

        if (!OperatingSystem.IsLinux())
        {
            return path;
        }

        var mode = File.GetUnixFileMode(path);
        if (ownerPrivate)
        {
            if ((mode & GroupOrOtherMode) != 0)
            {
                throw new ArgumentException($"{optionName} must be private to the current user.");
            }
        }
        else if ((mode & GroupOrOtherWrite) != 0)
        {
            throw new ArgumentException($"{optionName} must not be writable by group or other users.");
        }

        return path;
    }

    private static bool HasSymlinkAncestor(FileInfo file)
    {
        var directory = file.Directory;
        while (directory is not null)
        {
            if (directory.LinkTarget is not null ||
                directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                return true;
            }

            var parent = directory.Parent;
            if (parent is null || string.Equals(parent.FullName, directory.FullName, StringComparison.Ordinal))
            {
                break;
            }

            directory = parent;
        }

        return false;
    }
}
