using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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
    long LogBytes);

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
        using var log = new BoundedLog(invocation.MaximumLogBytes, overflow);
        var standardOutput = CaptureAsync(process.StandardOutput, log);
        var standardError = CaptureAsync(process.StandardError, log);
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
        if (overflow.IsCancellationRequested)
        {
            disposition = CiRunnerBuildKitProcessDisposition.LogLimitExceeded;
            exitCode = -1;
        }
        return new(disposition, exitCode, log.Digest(), log.Bytes);
    }

    private static async Task CaptureAsync(StreamReader reader, BoundedLog log)
    {
        var buffer = new char[4 * 1024];
        while (await reader.ReadAsync(buffer) is var read && read > 0)
            log.Append(buffer.AsSpan(0, read));
    }

    private sealed class BoundedLog(long maximumBytes, CancellationTokenSource overflow) : IDisposable
    {
        private readonly object gate = new();
        private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private long bytes;
        private bool exceeded;

        internal long Bytes
        {
            get
            {
                lock (gate) return bytes;
            }
        }

        internal void Append(ReadOnlySpan<char> characters)
        {
            var content = Encoding.UTF8.GetBytes(characters.ToString());
            var signal = false;
            lock (gate)
            {
                if (exceeded) return;
                var accepted = (int)Math.Min(content.Length, Math.Max(0, maximumBytes - bytes));
                if (accepted > 0)
                {
                    hash.AppendData(content.AsSpan(0, accepted));
                    bytes += accepted;
                }
                if (accepted != content.Length)
                {
                    exceeded = signal = true;
                }
            }
            if (signal) overflow.Cancel();
        }

        internal string Digest()
        {
            lock (gate) return Convert.ToHexStringLower(hash.GetHashAndReset());
        }

        public void Dispose() => hash.Dispose();
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
    string MetadataSha256,
    string OutputSha256,
    int OutputFiles,
    long OutputBytes);

/// <summary>Executes one compiler-created buildctl request and accepts only bounded link-free output.</summary>
[SupportedOSPlatform("linux")]
internal sealed class CiRunnerBuildKitExecutor(ICiRunnerBuildKitProcess process)
{
    private const int MaximumMetadataBytes = 64 * 1024;
    private const int MaximumOutputFiles = 100_000;
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
                return new(disposition, result.ExitCode, result.LogSha256, result.LogBytes,
                    string.Empty, string.Empty, 0, 0);
            }

            var metadata = await ReadMetadataAsync(invocation.MetadataFile, cancellationToken);
            var output = await HashOutputAsync(
                invocation.ExportDirectory,
                Math.Min(CiRunnerSourceMaterializer.MaximumExpandedBytes, plan.Build.EphemeralDiskBytes / 2),
                cancellationToken);
            return new(
                disposition,
                result.ExitCode,
                result.LogSha256,
                result.LogBytes,
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

    private static async Task<(string Digest, int Files, long Bytes)> HashOutputAsync(
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
        var canonical = new StringBuilder();
        var files = 0;
        long bytes = 0;
        foreach (var (entry, relative) in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var normalized = relative.Replace(Path.DirectorySeparatorChar, '/');
            if (entry is DirectoryInfo)
            {
                File.SetUnixFileMode(entry.FullName, DirectoryMode);
                canonical.Append("d:").Append(normalized).Append('\n');
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
            canonical.Append("f:").Append(normalized).Append(':')
                .Append(file.Length.ToString(CultureInfo.InvariantCulture)).Append(':')
                .Append(executable ? '1' : '0').Append(':').Append(digest).Append('\n');
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
                if (kind == UnixFileKind.Directory && entry is DirectoryInfo child)
                    pending.Push(child);
                else if (kind != UnixFileKind.Regular || entry is not FileInfo)
                    throw new InvalidDataException("The CI BuildKit output contains a link or special file.");
                result.Add((entry, Path.GetRelativePath(root, entry.FullName)));
            }
        }
        return result;
    }

    private static UnixFileKind FileKind(string path)
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
            NativeMethods.RegularFile => UnixFileKind.Regular,
            NativeMethods.Directory => UnixFileKind.Directory,
            _ => UnixFileKind.Other,
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

    private enum UnixFileKind
    {
        Other,
        Regular,
        Directory,
    }

    private static class NativeMethods
    {
        internal const int AtCurrentWorkingDirectory = -100;
        internal const int AtSymlinkNoFollow = 0x100;
        internal const uint StatxType = 0x1;
        internal const ushort FileTypeMask = 0xf000;
        internal const ushort RegularFile = 0x8000;
        internal const ushort Directory = 0x4000;

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
