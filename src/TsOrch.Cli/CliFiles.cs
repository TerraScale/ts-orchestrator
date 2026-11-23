using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace TsOrch.Cli;

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

    public static async Task<Result<string, NotFound, Forbidden, Unavailable>> ReadTextAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return new NotFound($"{path} does not exist.");
        }

        try
        {
            return await File.ReadAllTextAsync(path, cancellationToken);
        }
        catch (IOException exception)
        {
            return new Unavailable($"Reading {path} failed: {exception.Message}");
        }
        catch (UnauthorizedAccessException exception)
        {
            return new Forbidden($"Reading {path} is not allowed: {exception.Message}");
        }
    }

    public static async Task<Result<T, NotFound, Validation, Forbidden, Unavailable>> ReadJsonAsync<T>(string path, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
        where T : notnull
    {
        if (!File.Exists(path))
        {
            return new NotFound($"{path} does not exist.");
        }

        try
        {
            await using var stream = File.OpenRead(path);
            return await JsonSerializer.DeserializeAsync(stream, typeInfo, cancellationToken) is { } value
                ? value
                : new Validation($"{path} holds an empty JSON document.");
        }
        catch (JsonException exception)
        {
            return new Validation($"{path} is not valid: {exception.Message}");
        }
        catch (IOException exception)
        {
            return new Unavailable($"Reading {path} failed: {exception.Message}");
        }
        catch (UnauthorizedAccessException exception)
        {
            return new Forbidden($"Reading {path} is not allowed: {exception.Message}");
        }
    }

    public static async Task<Result<Done, Validation, Forbidden, Unavailable>> WritePrivateJsonAsync<T>(string path, T value, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows())
        {
            return new Validation("ts-orch keeps private files only on Unix hosts.");
        }

        if (Path.GetDirectoryName(path) is not { Length: > 0 } directory)
        {
            return new Validation($"{path} has no parent directory.");
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
                await JsonSerializer.SerializeAsync(stream, value, typeInfo, cancellationToken);
            }

            File.Move(temporary, path, overwrite: true);
            return new Done();
        }
        catch (IOException exception)
        {
            return new Unavailable($"Writing {path} failed: {exception.Message}");
        }
        catch (UnauthorizedAccessException exception)
        {
            return new Forbidden($"Writing {path} is not allowed: {exception.Message}");
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    public static async Task<Result<string, Unauthorized, Forbidden, Unavailable>> WithScratchFileAsync(
        string name,
        string content,
        Func<string, CancellationToken, Task<Result<string, Unauthorized, Forbidden, Unavailable>>> use,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(use);
        DirectoryInfo scratch;
        try
        {
            scratch = Directory.CreateTempSubdirectory("ts-orch-");
        }
        catch (IOException exception)
        {
            return new Unavailable($"Creating a scratch directory failed: {exception.Message}");
        }

        try
        {
            var path = Path.Combine(scratch.FullName, name);
            return await WriteScratchAsync(path, content, cancellationToken) switch
            {
                Done => await use(path, cancellationToken),
                Unavailable failure => failure,
            };
        }
        finally
        {
            scratch.Delete(recursive: true);
        }
    }

    private static async Task<Result<Done, Unavailable>> WriteScratchAsync(string path, string content, CancellationToken cancellationToken)
    {
        try
        {
            await File.WriteAllTextAsync(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), cancellationToken);
            return new Done();
        }
        catch (IOException exception)
        {
            return new Unavailable($"Writing scratch file {path} failed: {exception.Message}");
        }
    }
}
