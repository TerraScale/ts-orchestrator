using System.Text.Json;
using System.Text.Json.Nodes;

namespace TsOrch.AppHost;

internal sealed record class AppHostFileUnreadable(string Message);

internal readonly union JsonFileRead(JsonFile, AppHostFileUnreadable);

internal readonly union JsonDirectoryRead(IReadOnlyList<JsonFile>, AppHostFileUnreadable);

internal sealed record class JsonFile(string Path, JsonNode? Node);

internal static class JsonFiles
{
    public static JsonFileRead Read(string path)
    {
        try
        {
            return new JsonFile(path, JsonNode.Parse(File.ReadAllText(path)));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new AppHostFileUnreadable($"{path} could not be read: {exception.Message}");
        }
    }

    public static JsonDirectoryRead ReadDirectories(IEnumerable<string> directories)
    {
        try
        {
            JsonFile[] files =
            [
                .. directories
                    .SelectMany(static directory => Directory.EnumerateFiles(directory, "*.json").Order(StringComparer.Ordinal))
                    .Select(static file => new JsonFile(file, JsonNode.Parse(File.ReadAllText(file)))),
            ];
            return files;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new AppHostFileUnreadable($"{string.Join(", ", directories)} could not be read: {exception.Message}");
        }
    }
}
