using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record CiRunnerBuildKitDaemonInvocation(
    string Executable,
    ReadOnlyCollection<string> Arguments,
    ReadOnlyDictionary<string, string> Environment,
    string SocketPath,
    string StateDirectory,
    string BuildKitRoot);

internal static class CiRunnerBuildKitDaemonInvocationCompiler
{
    internal const string RootlessKitExecutable = "/usr/bin/rootlesskit";
    internal const string BuildKitExecutable = "/usr/bin/buildkitd";

    internal static CiRunnerBuildKitDaemonInvocation Create(CiRunnerBuildKitRuntime runtime)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        var roots = new[]
        {
            runtime.RuntimeDirectory,
            runtime.HomeDirectory,
            runtime.OutputRoot,
            runtime.DockerConfigDirectory,
        };
        for (var left = 0; left < roots.Length; left++)
            for (var right = left + 1; right < roots.Length; right++)
                if (Within(roots[left], roots[right]) || Within(roots[right], roots[left]))
                    throw new InvalidDataException("The CI BuildKit daemon paths overlap an unsafe runtime path.");
        var socket = Path.Combine(runtime.RuntimeDirectory, "buildkit", "buildkitd.sock");
        var state = Path.Combine(runtime.HomeDirectory, "rootlesskit-state");
        var root = Path.Combine(runtime.HomeDirectory, "buildkit-state");
        var arguments = Arguments(socket, state, root);
        var environment = Environment(runtime.HomeDirectory, runtime.RuntimeDirectory);
        return new(RootlessKitExecutable, Array.AsReadOnly(arguments), environment, socket, state, root);
    }

    internal static void Validate(CiRunnerBuildKitDaemonInvocation invocation)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        if (invocation.Executable != RootlessKitExecutable || invocation.Environment.Count != 4 ||
            !invocation.Environment.TryGetValue("HOME", out var home) ||
            !invocation.Environment.TryGetValue("XDG_RUNTIME_DIR", out var runtime) ||
            invocation.SocketPath != Path.Combine(runtime, "buildkit", "buildkitd.sock") ||
            invocation.StateDirectory != Path.Combine(home, "rootlesskit-state") ||
            invocation.BuildKitRoot != Path.Combine(home, "buildkit-state") ||
            !invocation.Arguments.SequenceEqual(Arguments(
                invocation.SocketPath,
                invocation.StateDirectory,
                invocation.BuildKitRoot)) ||
            !invocation.Environment.SequenceEqual(Environment(home, runtime)))
            throw new InvalidDataException("The CI BuildKit daemon invocation changed from the closed profile.");
    }

    private static string[] Arguments(string socket, string state, string root) =>
    [
        "--net=slirp4netns",
        "--copy-up=/etc",
        "--disable-host-loopback",
        $"--state-dir={state}",
        BuildKitExecutable,
        "--rootless",
        "--addr", $"unix://{socket}",
        "--root", root,
    ];

    private static ReadOnlyDictionary<string, string> Environment(string home, string runtime) =>
        new(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["PATH"] = "/usr/bin:/bin",
            ["HOME"] = home,
            ["XDG_RUNTIME_DIR"] = runtime,
            ["NO_COLOR"] = "1",
        });

    private static bool Within(string value, string parent)
    {
        var path = Path.GetFullPath(value);
        var root = Path.GetFullPath(parent);
        return path == root || path.StartsWith(
            root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar,
            StringComparison.Ordinal);
    }
}

/// <summary>Owns one exact rootless BuildKit daemon and verifies the connected Unix peer.</summary>
[SupportedOSPlatform("linux")]
internal sealed class CiRunnerBuildKitDaemon : IAsyncDisposable
{
    private const long MaximumDaemonLogBytes = 1024 * 1024;
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(15);
    private static readonly UnixFileMode PrivateDirectoryMode = UnixFileMode.UserRead |
        UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private readonly Process process;
    private readonly CancellationTokenSource stopping;
    private readonly Task completion;

    private CiRunnerBuildKitDaemon(Process process, CancellationTokenSource stopping, Task completion)
    {
        this.process = process;
        this.stopping = stopping;
        this.completion = completion;
    }

    internal Task Completion => completion;
    // True only once the connected peer was verified to be the closed buildkitd invocation in
    // its rootless user namespace — never a constant disconnected from that check.
    internal bool RootlessIsolationVerified { get; private set; }

    internal static async Task<CiRunnerBuildKitDaemon> StartAsync(
        CiRunnerBuildKitDaemonInvocation invocation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        CiRunnerBuildKitDaemonInvocationCompiler.Validate(invocation);
        var userId = NativeMethods.GetEffectiveUserId();
        if (userId == 0) throw new InvalidOperationException("The CI BuildKit daemon cannot run as root.");
        RequireExecutable(invocation.Executable);
        RequireExecutable(CiRunnerBuildKitDaemonInvocationCompiler.BuildKitExecutable);
        RequirePrivateDirectory(invocation.Environment["HOME"]);
        RequirePrivateDirectory(invocation.Environment["XDG_RUNTIME_DIR"]);
        if (invocation.Environment["XDG_RUNTIME_DIR"] != $"/run/user/{userId}")
            throw new InvalidDataException("The CI BuildKit runtime does not match the effective user.");
        var socketDirectory = Directory.GetParent(invocation.SocketPath)
            ?? throw new InvalidDataException("The CI BuildKit socket has no parent directory.");
        if (Directory.Exists(socketDirectory.FullName) || Path.Exists(invocation.SocketPath) ||
            Directory.Exists(invocation.StateDirectory) || Directory.Exists(invocation.BuildKitRoot))
            throw new IOException("The CI BuildKit daemon runtime is not fresh.");
        Directory.CreateDirectory(socketDirectory.FullName, PrivateDirectoryMode);
        File.SetUnixFileMode(socketDirectory.FullName, PrivateDirectoryMode);
        RequirePrivateDirectory(socketDirectory.FullName);

        var start = new ProcessStartInfo(invocation.Executable)
        {
            WorkingDirectory = invocation.Environment["HOME"],
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var argument in invocation.Arguments) start.ArgumentList.Add(argument);
        start.Environment.Clear();
        foreach (var variable in invocation.Environment) start.Environment.Add(variable.Key, variable.Value);
        var process = new Process { StartInfo = start };
        var stopping = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            process.Start();
            var output = DrainAsync(process.StandardOutput, stopping);
            var error = DrainAsync(process.StandardError, stopping);
            var processExit = ProcessLifecycle.WaitForExitAsync(process, stopping.Token);
            var completion = CompleteAsync(processExit, output, error, stopping.Token);
            var daemon = new CiRunnerBuildKitDaemon(process, stopping, completion);
            await daemon.WaitUntilReadyAsync(invocation, userId, cancellationToken);
            return daemon;
        }
        catch
        {
            stopping.Cancel();
            try
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
            catch
            {
            }
            process.Dispose();
            stopping.Dispose();
            throw;
        }
    }

    private async Task WaitUntilReadyAsync(
        CiRunnerBuildKitDaemonInvocation invocation,
        uint expectedUserId,
        CancellationToken cancellationToken)
    {
        using var timeout = new CancellationTokenSource(StartupTimeout);
        using var waiting = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        while (true)
        {
            if (process.HasExited)
                throw new InvalidOperationException("The rootless CI BuildKit daemon exited during startup.");
            if (Path.Exists(invocation.SocketPath))
            {
                if (CiRunnerBuildKitExecutor.FileKind(invocation.SocketPath) != CiRunnerOutputFileKind.Socket)
                    throw new InvalidDataException("The CI BuildKit endpoint is not a Unix socket.");
                using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(new UnixDomainSocketEndPoint(invocation.SocketPath), waiting.Token);
                    VerifyPeer(socket, invocation, expectedUserId);
                    RootlessIsolationVerified = true;
                    return;
                }
                catch (SocketException)
                {
                }
            }
            try
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), waiting.Token);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested &&
                !cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("The rootless CI BuildKit daemon did not become ready.");
            }
        }
    }

    private static void VerifyPeer(
        Socket socket,
        CiRunnerBuildKitDaemonInvocation invocation,
        uint expectedUserId)
    {
        var length = (uint)Marshal.SizeOf<NativeMethods.PeerCredential>();
        if (NativeMethods.GetSocketOption(socket.Handle, NativeMethods.SolSocket,
                NativeMethods.SoPeerCredentials, out var credential, ref length) != 0 ||
            length != Marshal.SizeOf<NativeMethods.PeerCredential>() || credential.ProcessId <= 0 ||
            credential.UserId != expectedUserId)
            throw new InvalidDataException("The CI BuildKit Unix peer identity is invalid.");
        var resolved = new FileInfo($"/proc/{credential.ProcessId}/exe")
            .ResolveLinkTarget(returnFinalTarget: true)?.FullName;
        if (resolved != CiRunnerBuildKitDaemonInvocationCompiler.BuildKitExecutable)
            throw new InvalidDataException("The CI BuildKit socket is owned by an unexpected executable.");
        var command = Split(File.ReadAllBytes($"/proc/{credential.ProcessId}/cmdline"), 0)
            .Where(static value => value.Length > 0)
            .Select(static value => Encoding.UTF8.GetString(value))
            .ToArray();
        var expected = invocation.Arguments
            .SkipWhile(static value => value != CiRunnerBuildKitDaemonInvocationCompiler.BuildKitExecutable)
            .ToArray();
        if (!command.SequenceEqual(expected))
            throw new InvalidDataException("The CI BuildKit peer arguments changed from the closed invocation.");
        if (!HasRootlessUserNamespace(
                File.ReadAllText($"/proc/{credential.ProcessId}/uid_map"),
                expectedUserId))
            throw new InvalidDataException("The CI BuildKit peer is not in its expected rootless user namespace.");
    }

    internal static bool HasRootlessUserNamespace(string uidMap, uint expectedUserId)
    {
        var mappings = uidMap.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(static line => line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
            .ToArray();
        return mappings.Length is > 0 and <= 5 && mappings.All(static fields => fields.Length == 3 &&
            uint.TryParse(fields[0], out _) && uint.TryParse(fields[1], out _) &&
            uint.TryParse(fields[2], out var length) && length > 0) &&
            mappings.Any(fields => fields[0] == "0" &&
                fields[1] == expectedUserId.ToString(System.Globalization.CultureInfo.InvariantCulture) &&
                fields[2] == "1");
    }

    private static IEnumerable<byte[]> Split(byte[] value, byte separator)
    {
        var start = 0;
        for (var index = 0; index <= value.Length; index++)
        {
            if (index != value.Length && value[index] != separator) continue;
            yield return value[start..index];
            start = index + 1;
        }
    }

    private static async Task DrainAsync(StreamReader reader, CancellationTokenSource stopping)
    {
        var buffer = new char[4 * 1024];
        long bytes = 0;
        while (await reader.ReadAsync(buffer) is var read && read > 0)
        {
            bytes += Encoding.UTF8.GetByteCount(buffer.AsSpan(0, read));
            if (bytes <= MaximumDaemonLogBytes) continue;
            stopping.Cancel();
            throw new InvalidDataException("The CI BuildKit daemon exceeded its startup log bound.");
        }
    }

    private static async Task CompleteAsync(Task processExit, Task output, Task error, CancellationToken token)
    {
        await Task.WhenAll(processExit, output, error);
        token.ThrowIfCancellationRequested();
        throw new InvalidOperationException("The rootless CI BuildKit daemon exited unexpectedly.");
    }

    private static void RequireExecutable(string path)
    {
        var file = new FileInfo(path);
        var mode = file.Exists ? File.GetUnixFileMode(path) : UnixFileMode.None;
        if (!file.Exists || file.LinkTarget is not null ||
            CiRunnerBuildKitExecutor.FileKind(path) != CiRunnerOutputFileKind.Regular ||
            (mode & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) == 0 ||
            (mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            throw new InvalidDataException("A CI BuildKit daemon executable is missing, linked, or writable.");
    }

    private static void RequirePrivateDirectory(string path)
    {
        var directory = new DirectoryInfo(path);
        if (!directory.Exists || directory.LinkTarget is not null ||
            (File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
                UnixFileMode.OtherExecute)) != 0)
            throw new InvalidDataException("A CI BuildKit daemon runtime directory is not owner-private.");
    }

    public async ValueTask DisposeAsync()
    {
        stopping.Cancel();
        try
        {
            await completion;
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested)
        {
        }
        finally
        {
            process.Dispose();
            stopping.Dispose();
        }
    }

    private static class NativeMethods
    {
        internal const int SolSocket = 1;
        internal const int SoPeerCredentials = 17;

        [DllImport("libc", EntryPoint = "geteuid")]
        internal static extern uint GetEffectiveUserId();

        [DllImport("libc", EntryPoint = "getsockopt", SetLastError = true)]
        internal static extern int GetSocketOption(
            IntPtr socket,
            int level,
            int option,
            out PeerCredential value,
            ref uint length);

        [StructLayout(LayoutKind.Sequential)]
        internal struct PeerCredential
        {
            internal int ProcessId;
            internal uint UserId;
            private uint groupId;
        }
    }
}

