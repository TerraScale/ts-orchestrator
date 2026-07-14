using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Security.Cryptography;

namespace TerraScale.ReproduciblePublish;

public static class ReproduciblePublisher
{
    private const string ProjectRelativePath = "src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj";

    public static async Task<ReproduciblePublishResult> RunAsync(ReproduciblePublishRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        try { return await RunCoreAsync(request, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { return Empty(request, PublishFailureCode.Cancelled); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException or CryptographicException or InvalidOperationException or System.ComponentModel.Win32Exception)
        { return Empty(request, PublishFailureCode.IoFailure); }
    }

    public static InputTreeDigest ComputeInputTreeDigest(string sourceRoot)
    {
        var source = PublishPathPolicy.Normalize(sourceRoot);
        if (!Directory.Exists(source) || HasSymlinkAncestor(source)) throw new ArgumentException("Source root must be an existing non-symbolic-link directory.", nameof(sourceRoot));
        return new InputTreeDigest(ComputeTreeDigest(source));
    }

    private static async Task<ReproduciblePublishResult> RunCoreAsync(ReproduciblePublishRequest request, CancellationToken cancellationToken)
    {
        var rootFailure = PublishPathPolicy.ValidateRoots(request.SourceRoot, request.FirstOutputRoot, request.RepeatOutputRoot);
        if (rootFailure != PublishFailureCode.None) return Empty(request, rootFailure);

        string source;
        string firstRoot;
        string repeatRoot;
        try
        {
            source = PublishPathPolicy.Normalize(request.SourceRoot);
            firstRoot = PublishPathPolicy.Normalize(request.FirstOutputRoot);
            repeatRoot = PublishPathPolicy.Normalize(request.RepeatOutputRoot);
            if (!Directory.Exists(source) || !File.Exists(Path.Combine(source, ProjectRelativePath))) return Empty(request, PublishFailureCode.InvalidArgument);
            if (HasSymlinkAncestor(source) || HasSymlinkAncestor(firstRoot) || HasSymlinkAncestor(repeatRoot)) return Empty(request, PublishFailureCode.SymbolicLink);
            if (ExistsAndNotEmpty(firstRoot) || ExistsAndNotEmpty(repeatRoot)) return Empty(request, PublishFailureCode.OutputRootNotEmpty);
            Directory.CreateDirectory(firstRoot);
            Directory.CreateDirectory(repeatRoot);
            CopySourceTree(source, Path.Combine(firstRoot, "input"));
            CopySourceTree(source, Path.Combine(repeatRoot, "input"));
            var firstInputDigest = ComputeTreeDigest(Path.Combine(firstRoot, "input"));
            var repeatInputDigest = ComputeTreeDigest(Path.Combine(repeatRoot, "input"));
            var copyFailure = CopiedInputVerifier.Compare(firstInputDigest, repeatInputDigest, request.TreeDigest);
            if (copyFailure != PublishFailureCode.None) return Empty(request, copyFailure);
        }
        catch (OperationCanceledException) { return Empty(request, PublishFailureCode.Cancelled); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException) { return Empty(request, PublishFailureCode.IoFailure); }

        var firstRuns = new List<PublishRunObservation>();
        var repeatRuns = new List<PublishRunObservation>();
        foreach (var target in request.Targets)
        {
            var first = await PublishOnceAsync(request, firstRoot, target, cancellationToken).ConfigureAwait(false);
            if (first.Failure != PublishFailureCode.None) return Empty(request, first.Failure);
            firstRuns.Add(first.Run);
            if (!first.Run.Process.Successful) return PublishObservationVerifier.Evaluate(request, firstRuns.Concat(MissingRuns(request, request.Targets.Skip(firstRuns.Count), firstRoot)), MissingRuns(request, request.Targets, repeatRoot));
            var repeat = await PublishOnceAsync(request, repeatRoot, target, cancellationToken).ConfigureAwait(false);
            if (repeat.Failure != PublishFailureCode.None) return Empty(request, repeat.Failure);
            repeatRuns.Add(repeat.Run);
            if (!repeat.Run.Process.Successful) return PublishObservationVerifier.Evaluate(request, firstRuns.Concat(MissingRuns(request, request.Targets.Skip(firstRuns.Count), firstRoot)), repeatRuns.Concat(MissingRuns(request, request.Targets.Skip(repeatRuns.Count), repeatRoot)));
        }
        return PublishObservationVerifier.Evaluate(request, firstRuns, repeatRuns);
    }

    private static async Task<PublishAttempt> PublishOnceAsync(ReproduciblePublishRequest request, string root, PublishTarget target, CancellationToken cancellationToken)
    {
        var inputRoot = Path.Combine(root, "input");
        var outputRoot = Path.Combine(root, "publish", PublishTargetCatalog.Rid(target));
        Directory.CreateDirectory(outputRoot);
        var stateRoot = Path.Combine(root, "state");
        var home = Path.Combine(stateRoot, "home");
        var temp = Path.Combine(stateRoot, "tmp");
        Directory.CreateDirectory(home);
        Directory.CreateDirectory(temp);

        var startInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = inputRoot,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        var invocation = CreateInvocation(request, target, outputRoot, inputRoot);
        if (invocation.Failure != PublishFailureCode.None)
            return new PublishAttempt(new PublishRunObservation(PublishTarget.LinuxX64, outputRoot, new ProcessObservation(false, false, false, -1, 0, 0, false), request.OutputItemLimit, []), invocation.Failure);
        foreach (var argument in invocation.Arguments) startInfo.ArgumentList.Add(argument);
        ConfigureEnvironment(startInfo, request, home, temp);
        var process = await RunProcessAsync(startInfo, request.Timeout, request.DiagnosticLimit, cancellationToken).ConfigureAwait(false);
        var outputFailure = PublishFailureCode.None;
        IReadOnlyList<OutputItemObservation> items = process.Successful ? ObserveOutput(outputRoot, request.OutputItemLimit, out outputFailure) : Array.Empty<OutputItemObservation>();
        return new PublishAttempt(new PublishRunObservation(target, outputRoot, process, request.OutputItemLimit, items), outputFailure);
    }

    public static PublishInvocation CreateInvocation(ReproduciblePublishRequest request, PublishTarget target, string outputRoot, string inputRoot)
    {
        if (request is null || !Enum.IsDefined(target) || string.IsNullOrWhiteSpace(outputRoot) || string.IsNullOrWhiteSpace(inputRoot))
            return new PublishInvocation(PublishFailureCode.InvalidArgument, Array.Empty<string>());
        var project = Path.Combine(inputRoot, ProjectRelativePath);
        return new PublishInvocation(PublishFailureCode.None, new ReadOnlyCollection<string>(new[]
        {
            "publish", project,
            "--configuration", "Release",
            "--runtime", PublishTargetCatalog.Rid(target),
            "--self-contained", "true",
            "--no-restore",
            "--output", outputRoot,
            "--property:Deterministic=true",
            "--property:ContinuousIntegrationBuild=true",
            "--property:PublishSingleFile=true",
            "--property:IncludeNativeLibrariesForSelfExtract=true",
            "--property:EnableCompressionInSingleFile=false",
            "--property:DebugType=None",
            "--property:DebugSymbols=false",
            $"--property:PathMap={inputRoot}=/src",
        }));
    }

    private static void ConfigureEnvironment(ProcessStartInfo startInfo, ReproduciblePublishRequest request, string home, string temp)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        var dotnetRoot = Environment.GetEnvironmentVariable("DOTNET_ROOT");
        var packages = Environment.GetEnvironmentVariable("NUGET_PACKAGES");
        if (string.IsNullOrWhiteSpace(packages)) packages = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
        startInfo.Environment.Clear();
        if (!string.IsNullOrWhiteSpace(path)) startInfo.Environment["PATH"] = path;
        if (!string.IsNullOrWhiteSpace(dotnetRoot)) startInfo.Environment["DOTNET_ROOT"] = dotnetRoot;
        startInfo.Environment["NUGET_PACKAGES"] = packages;
        startInfo.Environment["HOME"] = home;
        startInfo.Environment["DOTNET_CLI_HOME"] = home;
        startInfo.Environment["TMPDIR"] = temp;
        startInfo.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        startInfo.Environment["DOTNET_NOLOGO"] = "1";
        startInfo.Environment["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"] = "1";
        startInfo.Environment["DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE"] = "1";
        startInfo.Environment["NUGET_XMLDOC_MODE"] = "skip";
        startInfo.Environment["SOURCE_DATE_EPOCH"] = request.SourceDateEpoch.ToString(System.Globalization.CultureInfo.InvariantCulture);
        startInfo.Environment["TZ"] = "UTC";
        startInfo.Environment["LANG"] = "C.UTF-8";
        startInfo.Environment["LC_ALL"] = "C.UTF-8";
    }

    private static async Task<ProcessObservation> RunProcessAsync(ProcessStartInfo startInfo, PositiveSeconds timeout, DiagnosticCharacterLimit limit, CancellationToken cancellationToken)
    {
        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start()) return new ProcessObservation(false, false, false, -1, 0, 0, false);
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return new ProcessObservation(false, false, false, -1, 0, 0, false);
        }

        using var timeoutSource = new CancellationTokenSource(TimeSpan.FromSeconds(timeout.Value));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);
        var diagnosticLimitReached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var diagnosticReadFailed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stdout = new DiagnosticCapture(process.StandardOutput, limit.Value, diagnosticLimitReached, diagnosticReadFailed);
        var stderr = new DiagnosticCapture(process.StandardError, limit.Value, diagnosticLimitReached, diagnosticReadFailed);
        var stdoutDrain = stdout.DrainAsync(linked.Token);
        var stderrDrain = stderr.DrainAsync(linked.Token);
        var drains = Task.WhenAll(stdoutDrain, stderrDrain);
        var exit = process.WaitForExitAsync(CancellationToken.None);
        var cancellation = WaitForCancellationAsync(linked.Token);

        var completion = await Task.WhenAny(exit, diagnosticLimitReached.Task, diagnosticReadFailed.Task, cancellation).ConfigureAwait(false);
        if (completion == exit)
        {
            completion = await Task.WhenAny(drains, diagnosticLimitReached.Task, diagnosticReadFailed.Task, cancellation).ConfigureAwait(false);
            if (completion == drains && drains.IsCompletedSuccessfully && !diagnosticLimitReached.Task.IsCompleted && !diagnosticReadFailed.Task.IsCompleted)
            {
                linked.Cancel();
                await cancellation.ConfigureAwait(false);
                return new ProcessObservation(true, false, false, process.ExitCode, stdout.Count, stderr.Count, false);
            }
        }

        var diagnosticExceeded = diagnosticLimitReached.Task.IsCompleted;
        var cancelled = cancellationToken.IsCancellationRequested;
        var timedOut = !diagnosticExceeded && !cancelled && timeoutSource.IsCancellationRequested;
        try { process.Kill(entireProcessTree: true); }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { }
        linked.Cancel();
        await Task.WhenAny(Task.WhenAll(exit, drains), Task.Delay(TimeSpan.FromSeconds(5), CancellationToken.None)).ConfigureAwait(false);
        return new ProcessObservation(true, timedOut, cancelled, process.HasExited ? process.ExitCode : -1, stdout.Count, stderr.Count, diagnosticExceeded, diagnosticReadFailed.Task.IsCompleted || drains.IsFaulted);
    }

    private static async Task WaitForCancellationAsync(CancellationToken cancellationToken)
    {
        try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }

    private static IReadOnlyList<OutputItemObservation> ObserveOutput(string outputRoot, OutputItemLimit limit, out PublishFailureCode failure)
    {
        var observations = new List<OutputItemObservation>();
        foreach (var path in EnumerateTreeNoFollow(outputRoot))
        {
            if ((uint)observations.Count >= limit.Value) { failure = PublishFailureCode.OutputItemLimitExceeded; return Array.Empty<OutputItemObservation>(); }
            var info = Directory.Exists(path) ? (FileSystemInfo)new DirectoryInfo(path) : new FileInfo(path);
            var kind = info.LinkTarget is not null ? OutputItemKind.SymbolicLink : info switch { DirectoryInfo => OutputItemKind.Directory, FileInfo candidate when IsRegular(candidate) => OutputItemKind.RegularFile, _ => OutputItemKind.Other };
            if (kind != OutputItemKind.RegularFile) { observations.Add(new OutputItemObservation(Path.GetFullPath(path), kind, 0, null, [], 0)); continue; }
            var file = (FileInfo)info;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
            var header = new byte[64];
            var read = stream.Read(header, 0, header.Length);
            stream.Position = 0;
            var digest = Convert.ToHexStringLower(SHA256.HashData(stream));
            observations.Add(new OutputItemObservation(Path.GetFullPath(path), kind, file.Length, digest, header.AsSpan(0, read).ToArray(), GetUnixMode(path)));
        }
        failure = PublishFailureCode.None;
        return new ReadOnlyCollection<OutputItemObservation>(observations);
    }

    private static bool IsRegular(FileInfo file) => (file.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) == 0;

    private static void CopySourceTree(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var path in EnumerateTreeNoFollow(source))
        {
            var relative = Path.GetRelativePath(source, path);
            var target = Path.GetFullPath(Path.Combine(destination, relative));
            if (!PublishPathPolicy.IsConfined(destination, target)) throw new IOException("Source copy escaped destination.");
            var info = Directory.Exists(path) ? (FileSystemInfo)new DirectoryInfo(path) : new FileInfo(path);
            if (info.LinkTarget is not null) throw new IOException("Symbolic links are forbidden in the input tree.");
            if (info is DirectoryInfo) Directory.CreateDirectory(target);
            else if (info is FileInfo file && IsRegular(file)) { Directory.CreateDirectory(Path.GetDirectoryName(target)!); File.Copy(path, target, overwrite: false); }
            else throw new IOException("Non-regular source item.");
        }
    }

    private static bool ExistsAndNotEmpty(string path) => (Directory.Exists(path) && Directory.EnumerateFileSystemEntries(path).Any()) || File.Exists(path);

    private static IEnumerable<string> EnumerateTreeNoFollow(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            var entries = Directory.EnumerateFileSystemEntries(directory).OrderBy(path => path, StringComparer.Ordinal).ToArray();
            for (var index = entries.Length - 1; index >= 0; index--)
            {
                var path = entries[index];
                var info = Directory.Exists(path) ? (FileSystemInfo)new DirectoryInfo(path) : new FileInfo(path);
                if (info is DirectoryInfo && info.LinkTarget is null) pending.Push(path);
            }
            foreach (var path in entries) yield return path;
        }
    }

    private static string ComputeTreeDigest(string root)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var path in EnumerateTreeNoFollow(root))
        {
            var relative = Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/');
            var pathBytes = System.Text.Encoding.UTF8.GetBytes(relative);
            hash.AppendData(BitConverter.GetBytes(pathBytes.Length));
            hash.AppendData(pathBytes);
            var info = Directory.Exists(path) ? (FileSystemInfo)new DirectoryInfo(path) : new FileInfo(path);
            if (info.LinkTarget is not null) throw new IOException("Symbolic link in copied input.");
            hash.AppendData([info is DirectoryInfo ? (byte)1 : (byte)2]);
            if (info is FileInfo file)
            {
                hash.AppendData(BitConverter.GetBytes(file.Length));
                hash.AppendData(BitConverter.GetBytes((int)GetUnixMode(path)));
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
                var buffer = new byte[64 * 1024];
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0) hash.AppendData(buffer.AsSpan(0, read));
            }
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static bool HasSymlinkAncestor(string path)
    {
        var current = new DirectoryInfo(Path.GetFullPath(path));
        while (current is not null)
        {
            if (current.Exists && current.LinkTarget is not null) return true;
            current = current.Parent;
        }
        return false;
    }

    private static UnixFileMode GetUnixMode(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Reproducible Linux publish requires a Linux host.");
        return File.GetUnixFileMode(path);
    }

    private static IEnumerable<PublishRunObservation> MissingRuns(ReproduciblePublishRequest request, IEnumerable<PublishTarget> targets, string root) => targets.Select(target => new PublishRunObservation(target, Path.Combine(root, "publish", PublishTargetCatalog.Rid(target)), new ProcessObservation(false, false, false, -1, 0, 0, false), request.OutputItemLimit, []));
    private static ReproduciblePublishResult Empty(ReproduciblePublishRequest request, PublishFailureCode failure) => new(request.TreeDigest, failure, Array.Empty<PublishArtifactResult>(), 0, 0);
    private readonly record struct PublishAttempt(PublishRunObservation Run, PublishFailureCode Failure);
}

public sealed record DiagnosticDrainResult
{
    internal DiagnosticDrainResult(ulong characters, bool limitExceeded, bool timedOut, bool cancelled, bool readFailed)
    { Characters = characters; LimitExceeded = limitExceeded; TimedOut = timedOut; Cancelled = cancelled; ReadFailed = readFailed; }
    public ulong Characters { get; }
    public bool LimitExceeded { get; }
    public bool TimedOut { get; }
    public bool Cancelled { get; }
    public bool ReadFailed { get; }
}

public static class BoundedDiagnosticDrain
{
    public static async Task<DiagnosticDrainResult> ObserveAsync(TextReader reader, DiagnosticCharacterLimit limit, PositiveSeconds timeout, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(limit);
        ArgumentNullException.ThrowIfNull(timeout);
        using var timeoutSource = new CancellationTokenSource(TimeSpan.FromSeconds(timeout.Value));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);
        var limitReached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var readFailed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var capture = new DiagnosticCapture(reader, limit.Value, limitReached, readFailed);
        var drain = capture.DrainAsync(linked.Token);
        var cancellation = WaitAsync(linked.Token);
        await Task.WhenAny(drain, limitReached.Task, readFailed.Task, cancellation).ConfigureAwait(false);
        linked.Cancel();
        reader.Dispose();
        var drained = await Task.WhenAny(drain, Task.Delay(TimeSpan.FromSeconds(1), CancellationToken.None)).ConfigureAwait(false) == drain;
        return new DiagnosticDrainResult(capture.Count, limitReached.Task.IsCompleted, timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested, cancellationToken.IsCancellationRequested, readFailed.Task.IsCompleted || !drained || drain.IsFaulted);
    }

    private static async Task WaitAsync(CancellationToken cancellationToken)
    {
        try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }
}

internal sealed class DiagnosticCapture(TextReader reader, uint limit, TaskCompletionSource limitReached, TaskCompletionSource readFailed)
{
    private long count;
    public ulong Count => (ulong)Math.Max(0, Interlocked.Read(ref count));

    public async Task DrainAsync(CancellationToken cancellationToken)
    {
        var buffer = new char[1024];
        try
        {
            while (true)
            {
                var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                if (read == 0) return;
                var observed = Interlocked.Add(ref count, read);
                if ((ulong)observed > limit) limitReached.TrySetResult();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or ObjectDisposedException)
        {
            readFailed.TrySetResult();
        }
    }
}
