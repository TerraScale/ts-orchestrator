using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TerraScale.Orchestrator.Tooling;

internal sealed class ToolValidationException(IEnumerable<string> errors) : Exception
{
    public IReadOnlyList<string> Errors { get; } = errors.Distinct(StringComparer.Ordinal).ToArray();
}

internal static class ToolingSupport
{
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    public static string Root => FindRoot();

    public static JsonNode ReadJson(string relativePath) =>
        JsonNode.Parse(File.ReadAllBytes(Path.Combine(Root, relativePath)),
            documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 64 })
        ?? throw new InvalidDataException($"{relativePath}: empty JSON document");

    public static JsonObject ReadObject(string relativePath) =>
        ReadJson(relativePath) as JsonObject
        ?? throw new InvalidDataException($"{relativePath}: top-level JSON must be an object");

    public static string Serialize(JsonNode node) => node.ToJsonString(JsonOptions) + Environment.NewLine;

    public static string Sha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    public static string Sha256Text(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    public static void RequireNoErrors(IEnumerable<string> errors)
    {
        var materialized = errors.Distinct(StringComparer.Ordinal).ToArray();
        if (materialized.Length != 0)
        {
            throw new ToolValidationException(materialized);
        }
    }

    public static ProcessResult RunProcess(string fileName, IEnumerable<string> arguments, string? workingDirectory = null, int timeoutMilliseconds = 30_000)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                WorkingDirectory = workingDirectory ?? Root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            }
        };
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        process.StartInfo.Environment["DOTNET_CLI_USE_MSBUILD_SERVER"] = "0";
        process.StartInfo.Environment["MSBUILDDISABLENODEREUSE"] = "1";
        process.StartInfo.Environment["UseSharedCompilation"] = "false";

        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(timeoutMilliseconds))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"{fileName} exceeded {timeoutMilliseconds} ms");
        }

        Task.WaitAll(stdout, stderr);
        return new(process.ExitCode, stdout.Result, stderr.Result);
    }

    public static string Git(string repository, params string[] arguments)
    {
        var result = RunProcess("git", ["-C", repository, .. arguments]);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(result.StandardError.Trim());
        }

        return result.StandardOutput;
    }

    public static byte[] GitBytes(string repository, params string[] arguments)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "git",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            }
        };
        process.StartInfo.ArgumentList.Add("-C");
        process.StartInfo.ArgumentList.Add(repository);
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        process.Start();
        using var stdout = new MemoryStream();
        var copy = process.StandardOutput.BaseStream.CopyToAsync(stdout);
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        Task.WaitAll(copy, stderr);
        if (process.ExitCode != 0) throw new InvalidOperationException(stderr.Result.Trim());
        return stdout.ToArray();
    }

    public static string Sha256Bytes(byte[] value) => Convert.ToHexStringLower(SHA256.HashData(value));

    private static string FindRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "TerraScale.Orchestrator.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        current = new DirectoryInfo(Environment.CurrentDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "TerraScale.Orchestrator.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("TerraScale.Orchestrator repository root was not found.");
    }
}

internal sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);
