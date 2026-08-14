using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cysharp.Text;

namespace TerraScale.Orchestrator.Delivery;

internal enum CiRunnerBuildKitProcessDisposition
{
    Unspecified,
    Exited,
    TimedOut,
    LogLimitExceeded,
}

internal sealed record CiRunnerBuildKitProcessResult(
    CiRunnerBuildKitProcessDisposition Disposition,
    int ExitCode,
    string LogSha256,
    long LogBytes,
    byte[] RedactedLog);

internal interface ICiRunnerBuildKitProcess
{
    Task<CiRunnerBuildKitProcessResult> RunAsync(
        CiRunnerBuildKitInvocation invocation,
        CancellationToken cancellationToken);
}

internal sealed class ProcessCiRunnerBuildKitProcess : ICiRunnerBuildKitProcess
{
    public async Task<CiRunnerBuildKitProcessResult> RunAsync(
        CiRunnerBuildKitInvocation invocation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        using var timeout = new CancellationTokenSource(invocation.Timeout);
        using var overflow = new CancellationTokenSource();
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            timeout.Token,
            overflow.Token);
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(invocation.Executable)
            {
                WorkingDirectory = invocation.WorkingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };
        foreach (var argument in invocation.Arguments) process.StartInfo.ArgumentList.Add(argument);
        process.StartInfo.Environment.Clear();
        foreach (var variable in invocation.Environment) process.StartInfo.Environment.Add(variable.Key, variable.Value);

        process.Start();
        using var log = new BoundedRedactedLog(invocation.MaximumLogBytes, overflow);
        var standardOutput = CaptureAsync(process.StandardOutput, log, 0);
        var standardError = CaptureAsync(process.StandardError, log, 1);
        var disposition = CiRunnerBuildKitProcessDisposition.Exited;
        var exitCode = -1;
        try
        {
            await ProcessLifecycle.WaitForExitAsync(process, stopping.Token);
            exitCode = process.ExitCode;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await Task.WhenAll(standardOutput, standardError);
            throw;
        }
        catch (OperationCanceledException) when (overflow.IsCancellationRequested)
        {
            disposition = CiRunnerBuildKitProcessDisposition.LogLimitExceeded;
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            disposition = CiRunnerBuildKitProcessDisposition.TimedOut;
        }
        await Task.WhenAll(standardOutput, standardError);
        log.Complete();
        if (overflow.IsCancellationRequested)
        {
            disposition = CiRunnerBuildKitProcessDisposition.LogLimitExceeded;
            exitCode = -1;
        }
        var content = log.Content();
        return new(
            disposition,
            exitCode,
            Convert.ToHexStringLower(SHA256.HashData(content)),
            content.LongLength,
            content);
    }

    private static async Task CaptureAsync(StreamReader reader, BoundedRedactedLog log, int channel)
    {
        var buffer = new char[4 * 1024];
        while (await reader.ReadAsync(buffer) is var read && read > 0)
            log.Append(channel, buffer.AsSpan(0, read));
    }

    private sealed class BoundedRedactedLog(long maximumBytes, CancellationTokenSource overflow) : IDisposable
    {
        private const int MaximumPendingLineCharacters = 16 * 1024;
        private readonly object gate = new();
        private readonly MemoryStream retained = new();
        private readonly ZStringWriter[] pending = [new(), new()];
        private long observedBytes;
        private bool exceeded;

        internal void Append(int channel, ReadOnlySpan<char> characters)
        {
            var signal = false;
            lock (gate)
            {
                if (exceeded) return;
                var remaining = Math.Max(0, maximumBytes - observedBytes);
                var accepted = characters.Length;
                while (accepted > 0 && Encoding.UTF8.GetByteCount(characters[..accepted]) > remaining)
                    accepted--;
                if (accepted > 0)
                {
                    observedBytes += Encoding.UTF8.GetByteCount(characters[..accepted]);
                    pending[channel].Write(characters[..accepted]);
                    FlushLines(channel);
                }
                if (accepted != characters.Length)
                    exceeded = signal = true;
            }
            if (signal) overflow.Cancel();
        }

        internal void Complete()
        {
            lock (gate)
            {
                for (var index = 0; index < pending.Length; index++)
                {
                    var value = pending[index].ToString();
                    if (value.Length == 0) continue;
                    WriteLine(value);
                    Reset(index);
                }
            }
        }

        internal byte[] Content()
        {
            lock (gate) return retained.ToArray();
        }

        private void FlushLines(int channelIndex)
        {
            var channel = pending[channelIndex];
            var value = channel.ToString();
            var start = 0;
            while (value.IndexOf('\n', start) is var newline && newline >= 0)
            {
                WriteLine(value[start..(newline + 1)]);
                start = newline + 1;
            }
            Reset(channelIndex);
            var remainder = value.AsSpan(start);
            if (remainder.Length <= MaximumPendingLineCharacters)
            {
                pending[channelIndex].Write(remainder);
                return;
            }
            retained.Write("[REDACTED]\n"u8);
        }

        private void Reset(int channel)
        {
            pending[channel].Dispose();
            pending[channel] = new ZStringWriter();
        }

        private void WriteLine(string line)
        {
            var content = Encoding.UTF8.GetBytes(CiRunnerLogRedactor.IsSensitive(line)
                ? line.EndsWith('\n') ? "[REDACTED]\n" : "[REDACTED]"
                : line);
            retained.Write(content);
        }

        public void Dispose()
        {
            foreach (var channel in pending) channel.Dispose();
            retained.Dispose();
        }
    }
}

internal static class CiRunnerLogRedactor
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly string[] Markers =
    [
        "authorization", "bearer ", "password", "passwd", "secret", "token",
        "credential", "private key", "api key", "api_key", "access key", "nkey", "jwt",
    ];

    internal static bool IsSafe(ReadOnlySpan<byte> content)
    {
        string text;
        try
        {
            text = StrictUtf8.GetString(content);
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
        return text.Split('\n').All(static line => !IsSensitive(line));
    }

    internal static bool IsSensitive(string line)
    {
        if (Markers.Any(marker => line.Contains(marker, StringComparison.OrdinalIgnoreCase)) ||
            line.Contains("-----BEGIN ", StringComparison.Ordinal) ||
            line.Contains("://", StringComparison.Ordinal) && line.Contains('@'))
            return true;
        using var run = ZString.CreateStringBuilder();
        foreach (var character in line)
        {
            if (char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '+' or '/' or '=')
            {
                run.Append(character);
                continue;
            }
            if (LooksSecret(run.AsSpan())) return true;
            run.Remove(0, run.Length);
        }
        return LooksSecret(run.AsSpan()) || LooksLikeJwt(line);
    }

    private static bool LooksSecret(ReadOnlySpan<char> value)
    {
        if (value.Length < 40) return false;
        var text = value.ToString();
        if (text.All(static character => char.IsAsciiHexDigit(character))) return false;
        var upper = text.Any(char.IsAsciiLetterUpper);
        var lower = text.Any(char.IsAsciiLetterLower);
        var digit = text.Any(char.IsAsciiDigit);
        var symbol = text.Any(static character => character is '-' or '_' or '+' or '/' or '=');
        return (upper ? 1 : 0) + (lower ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0) >= 2;
    }

    private static bool LooksLikeJwt(string value)
    {
        foreach (var token in value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = token.Split('.');
            if (parts.Length == 3 && parts[0].Length >= 8 && parts[1].Length >= 8 && parts[2].Length >= 16 &&
                parts.All(static part => part.All(static character =>
                    char.IsAsciiLetterOrDigit(character) || character is '-' or '_')))
                return true;
        }
        return false;
    }
}

internal enum CiRunnerBuildKitExecutionDisposition
{
    Unspecified,
    Succeeded,
    ProcessFailed,
    TimedOut,
    LogLimitExceeded,
}

internal sealed record CiRunnerBuildKitExecutionResult(
    CiRunnerBuildKitExecutionDisposition Disposition,
    int ExitCode,
    string LogSha256,
    long LogBytes,
    byte[] RedactedLog,
    string MetadataSha256,
    string OutputSha256,
    int OutputFiles,
    long OutputBytes);

/// <summary>Executes one compiler-created buildctl request and accepts only bounded link-free output.</summary>
[SupportedOSPlatform("linux")]
internal sealed class CiRunnerBuildKitExecutor(ICiRunnerBuildKitProcess process)
{
    internal const int MaximumOutputFiles = 10_000;
    internal const long ArtifactArchiveOverheadBytes = 64L * 1024 * 1024;
    private const int MaximumMetadataBytes = 64 * 1024;
    private const long MaximumOutputFileBytes = 512L * 1024 * 1024;
    private static readonly UnixFileMode DirectoryMode = UnixFileMode.UserRead |
        UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private static readonly UnixFileMode FileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    internal async Task<CiRunnerBuildKitExecutionResult> ExecuteAsync(
        CiRunnerExecutionPlan plan,
        CiRunnerMaterializedSource source,
        CiRunnerBuildKitRuntime runtime,
        CancellationToken cancellationToken = default)
    {
        var invocation = CiRunnerBuildKitInvocationCompiler.Create(plan, source, runtime);
        RequireRuntimeDirectory(runtime.HomeDirectory);
        RequireRuntimeDirectory(runtime.OutputRoot);
        RequireRuntimeDirectory(runtime.DockerConfigDirectory);
        if (Directory.Exists(invocation.OutputDirectory) || File.Exists(invocation.OutputDirectory))
            throw new IOException("The CI BuildKit output directory already exists.");
        Directory.CreateDirectory(invocation.OutputDirectory, DirectoryMode);
        File.SetUnixFileMode(invocation.OutputDirectory, DirectoryMode);
        try
        {
            var result = await process.RunAsync(invocation, cancellationToken);
            if (!Digest(result.LogSha256) || result.LogBytes < 0 ||
                result.LogBytes > invocation.MaximumLogBytes ||
                result.RedactedLog.LongLength != result.LogBytes ||
                Convert.ToHexStringLower(SHA256.HashData(result.RedactedLog)) != result.LogSha256 ||
                !CiRunnerLogRedactor.IsSafe(result.RedactedLog) ||
                result.Disposition == CiRunnerBuildKitProcessDisposition.Exited && result.ExitCode < 0 ||
                result.Disposition is CiRunnerBuildKitProcessDisposition.TimedOut or
                    CiRunnerBuildKitProcessDisposition.LogLimitExceeded && result.ExitCode != -1)
                throw new InvalidDataException("The CI BuildKit process result is invalid.");
            var disposition = result.Disposition switch
            {
                CiRunnerBuildKitProcessDisposition.TimedOut => CiRunnerBuildKitExecutionDisposition.TimedOut,
                CiRunnerBuildKitProcessDisposition.LogLimitExceeded =>
                    CiRunnerBuildKitExecutionDisposition.LogLimitExceeded,
                CiRunnerBuildKitProcessDisposition.Exited when result.ExitCode != 0 =>
                    CiRunnerBuildKitExecutionDisposition.ProcessFailed,
                CiRunnerBuildKitProcessDisposition.Exited when result.ExitCode == 0 =>
                    CiRunnerBuildKitExecutionDisposition.Succeeded,
                _ => throw new InvalidDataException("The CI BuildKit process returned an invalid disposition."),
            };
            if (disposition != CiRunnerBuildKitExecutionDisposition.Succeeded)
            {
                Delete(invocation.OutputDirectory);
                return new(disposition, result.ExitCode, result.LogSha256, result.LogBytes, result.RedactedLog,
                    string.Empty, string.Empty, 0, 0);
            }

            var metadata = await ReadMetadataAsync(invocation.MetadataFile, cancellationToken);
            var output = await HashOutputAsync(
                invocation.ExportDirectory,
                Math.Min(
                    CiRunnerSourceMaterializer.MaximumExpandedBytes,
                    plan.Build.EphemeralDiskBytes / 2 - ArtifactArchiveOverheadBytes),
                cancellationToken);
            return new(
                disposition,
                result.ExitCode,
                result.LogSha256,
                result.LogBytes,
                result.RedactedLog,
                Convert.ToHexStringLower(SHA256.HashData(metadata)),
                output.Digest,
                output.Files,
                output.Bytes);
        }
        catch
        {
            Delete(invocation.OutputDirectory);
            throw;
        }
    }

    private static void RequireRuntimeDirectory(string path)
    {
        var directory = new DirectoryInfo(path);
        if (!directory.Exists || directory.LinkTarget is not null)
            throw new InvalidDataException("A CI BuildKit runtime directory is missing or linked.");
    }

    private static async Task<byte[]> ReadMetadataAsync(string path, CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null || info.Length is < 2 or > MaximumMetadataBytes)
            throw new InvalidDataException("The CI BuildKit metadata file is missing or invalid.");
        var content = await File.ReadAllBytesAsync(path, cancellationToken);
        try
        {
            using var document = JsonDocument.Parse(content, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });
            if (document.RootElement.ValueKind != JsonValueKind.Object || HasDuplicateProperties(content))
                throw new JsonException();
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The CI BuildKit metadata is invalid JSON.", exception);
        }
        return content;
    }

    internal static async Task<(string Digest, int Files, long Bytes)> HashOutputAsync(
        string root,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        var directory = new DirectoryInfo(root);
        if (!directory.Exists || directory.LinkTarget is not null || maximumBytes < 1)
            throw new InvalidDataException("The CI BuildKit output directory is missing or invalid.");
        var entries = EnumerateOutput(root)
            .OrderBy(static item => item.Relative, StringComparer.Ordinal)
            .ToArray();
        if (entries.Length is < 1 or > MaximumOutputFiles ||
            entries.Any(static item => UnsafeRelativePath(item.Relative)))
            throw new InvalidDataException("The CI BuildKit output tree is empty, linked, or oversized.");
        using var canonical = ZString.CreateStringBuilder();
        var files = 0;
        long bytes = 0;
        foreach (var (entry, relative) in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var normalized = relative.Replace(Path.DirectorySeparatorChar, '/');
            if (entry is DirectoryInfo)
            {
                File.SetUnixFileMode(entry.FullName, DirectoryMode);
                canonical.Append("d:");
                canonical.Append(normalized);
                canonical.Append('\n');
                continue;
            }
            if (entry is not FileInfo file || file.Length < 0 || file.Length > MaximumOutputFileBytes ||
                bytes > maximumBytes - file.Length)
                throw new InvalidDataException("The CI BuildKit output exceeded its file or byte bound.");
            var executable = (File.GetUnixFileMode(file.FullName) & (UnixFileMode.UserExecute |
                UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) != 0;
            File.SetUnixFileMode(file.FullName, executable ? FileMode | UnixFileMode.UserExecute : FileMode);
            await using var stream = file.OpenRead();
            var digest = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellationToken));
            canonical.Append("f:");
            canonical.Append(normalized);
            canonical.Append(':');
            canonical.Append(file.Length.ToString(CultureInfo.InvariantCulture));
            canonical.Append(':');
            canonical.Append(executable ? '1' : '0');
            canonical.Append(':');
            canonical.Append(digest);
            canonical.Append('\n');
            bytes += file.Length;
            files++;
        }
        if (files == 0) throw new InvalidDataException("The CI BuildKit output contains no regular files.");
        return (
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString()))),
            files,
            bytes);
    }

    private static IReadOnlyList<(FileSystemInfo Entry, string Relative)> EnumerateOutput(string root)
    {
        var result = new List<(FileSystemInfo Entry, string Relative)>();
        var pending = new Stack<DirectoryInfo>();
        pending.Push(new(root));
        while (pending.TryPop(out var directory))
        {
            foreach (var entry in directory.EnumerateFileSystemInfos())
            {
                if (result.Count == MaximumOutputFiles)
                    throw new InvalidDataException("The CI BuildKit output exceeded its entry bound.");
                var kind = FileKind(entry.FullName);
                if (kind == CiRunnerOutputFileKind.Directory && entry is DirectoryInfo child)
                    pending.Push(child);
                else if (kind != CiRunnerOutputFileKind.Regular || entry is not FileInfo)
                    throw new InvalidDataException("The CI BuildKit output contains a link or special file.");
                result.Add((entry, Path.GetRelativePath(root, entry.FullName)));
            }
        }
        return result;
    }

    internal static CiRunnerOutputFileKind FileKind(string path)
    {
        if (NativeMethods.Statx(
                NativeMethods.AtCurrentWorkingDirectory,
                path,
                NativeMethods.AtSymlinkNoFollow,
                NativeMethods.StatxType,
                out var status) != 0 || (status.Mask & NativeMethods.StatxType) == 0)
            throw new IOException("The CI BuildKit output file type could not be inspected.");
        return (status.Mode & NativeMethods.FileTypeMask) switch
        {
            NativeMethods.RegularFile => CiRunnerOutputFileKind.Regular,
            NativeMethods.Directory => CiRunnerOutputFileKind.Directory,
            NativeMethods.Socket => CiRunnerOutputFileKind.Socket,
            _ => CiRunnerOutputFileKind.Other,
        };
    }

    private static bool UnsafeRelativePath(string value) => value.Length is < 1 or > 4 * 1024 ||
        value[0] == Path.DirectorySeparatorChar || value.Split(Path.DirectorySeparatorChar).Any(static segment =>
            segment is "" or "." or ".." || segment.Any(char.IsControl));

    private static bool HasDuplicateProperties(byte[] payload)
    {
        var reader = new Utf8JsonReader(payload, new JsonReaderOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 16,
        });
        var fields = new Stack<HashSet<string>>();
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.StartObject) fields.Push(new(StringComparer.Ordinal));
            else if (reader.TokenType == JsonTokenType.EndObject) fields.Pop();
            else if (reader.TokenType == JsonTokenType.PropertyName && !fields.Peek().Add(reader.GetString()!))
                return true;
        }
        return fields.Count != 0;
    }

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');

    private static void Delete(string path)
    {
        try
        {
            if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
        }
        catch
        {
        }
    }

    private static class NativeMethods
    {
        internal const int AtCurrentWorkingDirectory = -100;
        internal const int AtSymlinkNoFollow = 0x100;
        internal const uint StatxType = 0x1;
        internal const ushort FileTypeMask = 0xf000;
        internal const ushort RegularFile = 0x8000;
        internal const ushort Directory = 0x4000;
        internal const ushort Socket = 0xc000;

        [DllImport("libc", EntryPoint = "statx", SetLastError = true, CharSet = CharSet.Ansi)]
        internal static extern int Statx(
            int directoryFileDescriptor,
            string path,
            int flags,
            uint mask,
            out StatxBuffer buffer);

        [StructLayout(LayoutKind.Sequential, Size = 256)]
        internal struct StatxBuffer
        {
            internal uint Mask;
            private uint blockSize;
            private ulong attributes;
            private uint linkCount;
            private uint userId;
            private uint groupId;
            internal ushort Mode;
            private ushort spare;
        }
    }
}

internal enum CiRunnerOutputFileKind
{
    Other,
    Regular,
    Directory,
    Socket,
}
