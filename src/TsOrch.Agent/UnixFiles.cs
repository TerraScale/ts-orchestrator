namespace TsOrch.Agent;

internal sealed record class AtomicWrite(string Path, ReadOnlyMemory<byte> Content, UnixFileMode Mode);

internal static class UnixFiles
{
    public const UnixFileMode OwnerReadWrite = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    public const UnixFileMode WorldReadable = OwnerReadWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
    public const UnixFileMode OwnerOnlyDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    public static Task<Result<Done, InternalFailure>> WriteAtomicAsync(string path, ReadOnlyMemory<byte> content, UnixFileMode mode, CancellationToken cancellationToken) =>
        WriteAtomicAsync([], [new AtomicWrite(path, content, mode)], cancellationToken);

    public static async Task<Result<Done, InternalFailure>> WriteAtomicAsync(
        IReadOnlyList<string> privateDirectories,
        IReadOnlyList<AtomicWrite> writes,
        CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("ts-orch agent requires a Unix host.");
        }

        var current = string.Empty;
        try
        {
            foreach (var directory in privateDirectories)
            {
                current = directory;
                Directory.CreateDirectory(directory, OwnerOnlyDirectory);
                File.SetUnixFileMode(directory, OwnerOnlyDirectory);
            }

            foreach (var write in writes)
            {
                current = write.Path;
                await WriteOneAsync(write, cancellationToken);
            }

            return new Done();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new InternalFailure($"Writing {current} failed: {exception.Message}");
        }
    }

    private static async Task WriteOneAsync(AtomicWrite write, CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("ts-orch agent requires a Unix host.");
        }

        var directory = Path.GetDirectoryName(write.Path) ?? throw new ArgumentException($"{write.Path} has no parent directory.", nameof(write));
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, $".{Path.GetFileName(write.Path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.Asynchronous,
                UnixCreateMode = write.Mode,
            };
            await using (var stream = new FileStream(temporary, options))
            {
                await stream.WriteAsync(write.Content, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, write.Path, overwrite: true);
        }
        finally
        {
            File.Delete(temporary);
        }
    }
}
