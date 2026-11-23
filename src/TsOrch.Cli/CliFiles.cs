using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace TsOrch.Cli;

internal closed record class CliFileReadProblem;

internal sealed record class CliFileMissing(string Path) : CliFileReadProblem;

internal sealed record class CliFileReadDenied(string Path, string Detail) : CliFileReadProblem;

internal sealed record class CliFileReadInterrupted(string Path, string Detail) : CliFileReadProblem;

internal readonly union CliFileText(string, CliFileReadProblem);

internal readonly record struct PrivateFileWritten;

internal sealed record class PrivateFileTargetInvalid(string Message);

internal sealed record class PrivateFileWriteDenied(string Path, string Detail);

internal sealed record class PrivateFileWriteInterrupted(string Path, string Detail);

internal readonly union PrivateFileWrite(PrivateFileWritten, PrivateFileTargetInvalid, PrivateFileWriteDenied, PrivateFileWriteInterrupted);

internal static class CliFiles
{
    private const UnixFileMode OwnerReadWrite = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode OwnerOnlyDirectory = OwnerReadWrite | UnixFileMode.UserExecute;

    public static string ExpandHome(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var expanded = path switch
        {
            "~" => home,
            ['~', '/', .. var rest] => Path.Combine(home, rest),
            _ => path,
        };
        return Path.GetFullPath(expanded);
    }

    public static async Task<CliFileText> ReadTextAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            return await File.ReadAllTextAsync(path, cancellationToken);
        }
        catch (FileNotFoundException)
        {
            return new CliFileMissing(path);
        }
        catch (DirectoryNotFoundException)
        {
            return new CliFileMissing(path);
        }
        catch (IOException exception)
        {
            return new CliFileReadInterrupted(path, exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            return new CliFileReadDenied(path, exception.Message);
        }
    }

    public static CliDiagnostic Describe(CliFileReadProblem failure) => failure switch
    {
        CliFileMissing missing => CliDiagnostic.Missing($"{missing.Path} does not exist."),
        CliFileReadDenied denied => new("forbidden", $"Reading {denied.Path} is not allowed: {denied.Detail}", ExitCodes.NoPermission),
        CliFileReadInterrupted interrupted => CliDiagnostic.Unavailable($"Reading {interrupted.Path} failed: {interrupted.Detail}"),
    };

    public static Task<PrivateFileWrite> WritePrivateJsonAsync<T>(string path, T value, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken) =>
        WritePrivateAsync(path, (stream, token) => JsonSerializer.SerializeAsync(stream, value, typeInfo, token), cancellationToken);

    public static Task<PrivateFileWrite> WritePrivateTextAsync(string path, string value, CancellationToken cancellationToken) =>
        WritePrivateAsync(path, (stream, token) => stream.WriteAsync(Encoding.UTF8.GetBytes(value), token).AsTask(), cancellationToken);

    private static async Task<PrivateFileWrite> WritePrivateAsync(
        string path, Func<Stream, CancellationToken, Task> write, CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows())
        {
            return new PrivateFileTargetInvalid("ts-orch keeps private files only on Unix hosts.");
        }

        if (Path.GetDirectoryName(path) is not { Length: > 0 } directory)
        {
            return new PrivateFileTargetInvalid($"{path} has no parent directory.");
        }

        var temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Path.GetRandomFileName()}");
        try
        {
            Directory.CreateDirectory(directory, OwnerOnlyDirectory);
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                UnixCreateMode = OwnerReadWrite,
            };
            await using (var stream = new FileStream(temporary, options))
            {
                await write(stream, cancellationToken);
            }

            File.SetUnixFileMode(temporary, OwnerReadWrite);
            File.Move(temporary, path, overwrite: true);
            return new PrivateFileWritten();
        }
        catch (IOException exception)
        {
            return new PrivateFileWriteInterrupted(path, exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            return new PrivateFileWriteDenied(path, exception.Message);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

}
