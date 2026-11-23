using System.ComponentModel;
using System.Diagnostics;
using System.Formats.Tar;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;

namespace TsOrch.Agent;

public closed record class MaintenanceWork;

public sealed record class DrainWork(string NodeId, string Reason) : MaintenanceWork;

public sealed record class GrowVolumeWork(string NodeId, string MountPath) : MaintenanceWork;

public sealed record class UpgradeAgentWork(string Version, string Url, string Sha256) : MaintenanceWork;

public sealed record class ProcessOutput(int ExitCode, string Stdout, string Stderr);

public static class ProcessRunner
{
    public static async Task<Result<ProcessOutput, RequestTimeout, Unavailable>> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(arguments);
        var startInfo = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
        }
        catch (Win32Exception exception)
        {
            return new Unavailable($"{fileName} could not start: {exception.Message}");
        }

        using var timeoutSource = new CancellationTokenSource(timeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);
        var stdout = process.StandardOutput.ReadToEndAsync(linked.Token);
        var stderr = process.StandardError.ReadToEndAsync(linked.Token);
        try
        {
            await process.WaitForExitAsync(linked.Token);
            return new ProcessOutput(process.ExitCode, await stdout, await stderr);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new RequestTimeout(string.Create(CultureInfo.InvariantCulture, $"{fileName} exceeded {timeout.TotalSeconds:0} s."));
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
    }
}

public sealed class NodeMaintenance(
    ContainerReconciler reconciler,
    AgentOutbox outbox,
    IHttpClientFactory httpClientFactory,
    IHostApplicationLifetime lifetime,
    AgentOptions options,
    TimeProvider timeProvider,
    ILogger<NodeMaintenance> logger) : BackgroundService
{
    public const string DownloadClientName = "ts-orch-download";
    public const int UpgradeExitCode = 75;
    private const int QueueCapacity = 16;
    private static readonly TimeSpan ToolTimeout = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DownloadTimeout = TimeSpan.FromMinutes(10);

    private readonly Channel<MaintenanceWork> _queue = Channel.CreateBounded<MaintenanceWork>(new BoundedChannelOptions(QueueCapacity)
    {
        FullMode = BoundedChannelFullMode.Wait,
        SingleReader = true,
    });

    public ValueTask EnqueueAsync(MaintenanceWork work, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(work);
        return _queue.Writer.WriteAsync(work, cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var work in _queue.Reader.ReadAllAsync(stoppingToken))
        {
            var task = work switch
            {
                DrainWork drain => RunDrainAsync(drain, stoppingToken),
                GrowVolumeWork grow => RunGrowVolumeAsync(grow, stoppingToken),
                UpgradeAgentWork upgrade => RunUpgradeAsync(upgrade, stoppingToken),
            };
            await task;
        }
    }

    public async Task DrainAsync(string nodeId, string reason, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeId);
        AgentLog.DrainStarted(logger, reason);
        await reconciler.DrainAsync(cancellationToken);
        await outbox.EnqueueAsync(new DrainComplete(nodeId), cancellationToken);
        AgentLog.DrainCompleted(logger);
    }

    public async Task<Result<VolumeGrown, Validation, NotFound, RequestTimeout, Unavailable, InternalFailure>> GrowVolumeAsync(
        string nodeId,
        string mountPath,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeId);
        if (string.IsNullOrWhiteSpace(mountPath) || !Path.IsPathFullyQualified(mountPath) || Path.GetFullPath(mountPath) != mountPath.TrimEnd('/'))
        {
            return new Validation($"Mount path {mountPath} must be an absolute normalized path.");
        }

        if (!Directory.Exists(mountPath))
        {
            return new NotFound($"Mount path {mountPath} does not exist.");
        }

        var mounts = await MountTable.ReadAsync(cancellationToken);
        var mount = MountTable.FindContaining(mounts, mountPath);
        if (mount is null || mount.MountPoint != mountPath || !mount.Device.StartsWith("/dev/", StringComparison.Ordinal))
        {
            AgentLog.VolumeGrowSkipped(logger, mountPath);
            return new VolumeGrown(nodeId, mountPath, SizeGiB(mountPath));
        }

        var device = new FileInfo(mount.Device).ResolveLinkTarget(returnFinalTarget: true)?.FullName ?? mount.Device;
        var deviceName = Path.GetFileName(device);
        var sysBlock = Path.Combine("/sys/class/block", deviceName);
        if (!Directory.Exists(sysBlock))
        {
            return new Validation($"Block device {device} is not visible under /sys/class/block.");
        }

        var partitionFile = Path.Combine(sysBlock, "partition");
        var isPartition = File.Exists(partitionFile);
        var diskName = isPartition
            ? Path.GetFileName(Path.GetDirectoryName(new DirectoryInfo(sysBlock).ResolveLinkTarget(returnFinalTarget: true)?.FullName))
            : deviceName;
        if (diskName is null)
        {
            return new InternalFailure($"Cannot resolve the parent disk of {device}.");
        }

        var rescan = Path.Combine("/sys/class/block", diskName, "device", "rescan");
        if (File.Exists(rescan))
        {
            await File.WriteAllTextAsync(rescan, "1", cancellationToken);
        }

        if (!isPartition)
        {
            return await ResizeAsync(nodeId, mountPath, mount, device, cancellationToken);
        }

        var partitionNumber = (await File.ReadAllTextAsync(partitionFile, cancellationToken)).Trim();
        return await ProcessRunner.RunAsync("growpart", [$"/dev/{diskName}", partitionNumber], ToolTimeout, timeProvider, cancellationToken) switch
        {
            ProcessOutput { ExitCode: 0 } => await ResizeAsync(nodeId, mountPath, mount, device, cancellationToken),
            ProcessOutput output when output.Stdout.Contains("NOCHANGE", StringComparison.Ordinal) => await ResizeAsync(nodeId, mountPath, mount, device, cancellationToken),
            ProcessOutput output => new InternalFailure($"growpart failed with {output.ExitCode}: {output.Stderr.Trim()}"),
            RequestTimeout failure => failure,
            Unavailable failure => failure,
        };
    }

    public async Task<Result<Done, Validation, RequestTimeout, Unavailable, InternalFailure>> UpgradeAgentAsync(
        string version,
        string url,
        string sha256,
        CancellationToken cancellationToken)
    {
        if (!AgentNames.IsSafeToken(version))
        {
            return new Validation($"Agent version {version} is not a safe path token.");
        }

        if (sha256.Length != 64 || !sha256.All(char.IsAsciiHexDigit))
        {
            return new Validation("Agent bundle SHA-256 must be 64 hex characters.");
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var source) || !(source.Scheme == Uri.UriSchemeHttps || (source.Scheme == Uri.UriSchemeHttp && source.IsLoopback)))
        {
            return new Validation($"Agent bundle URL {url} must be https.");
        }

        var releaseDirectory = Path.Combine(options.ReleasesDirectory, version);
        var currentTarget = CurrentReleaseDirectory();
        if (currentTarget == releaseDirectory)
        {
            AgentLog.UpgradeAlreadyCurrent(logger, version);
            return new Done();
        }

        var token = Guid.NewGuid().ToString("N");
        var bundle = new UpgradeBundle(
            version,
            Path.Combine(options.ReleasesDirectory, $".{version}.{token}.tar.gz"),
            Path.Combine(options.ReleasesDirectory, $".{version}.{token}.staging"),
            releaseDirectory,
            currentTarget);
        try
        {
            return await DownloadVerifiedAsync(source, bundle.Archive, Convert.FromHexString(sha256), cancellationToken) switch
            {
                Done => await ExtractAsync(bundle, cancellationToken) switch
                {
                    Done => await ActivateAsync(bundle, cancellationToken),
                    Validation failure => failure,
                    InternalFailure failure => failure,
                },
                Validation failure => failure,
                RequestTimeout failure => failure,
                Unavailable failure => failure,
                InternalFailure failure => failure,
            };
        }
        finally
        {
            File.Delete(bundle.Archive);
            if (Directory.Exists(bundle.Staging))
            {
                Directory.Delete(bundle.Staging, recursive: true);
            }
        }
    }

    private async Task<Result<VolumeGrown, Validation, NotFound, RequestTimeout, Unavailable, InternalFailure>> ResizeAsync(
        string nodeId,
        string mountPath,
        MountEntry mount,
        string device,
        CancellationToken cancellationToken)
    {
        string[]? command = mount.FileSystem switch
        {
            "ext2" or "ext3" or "ext4" => ["resize2fs", device],
            "xfs" => ["xfs_growfs", mountPath],
            _ => null,
        };
        if (command is not [var tool, .. var arguments])
        {
            return new Validation($"File system {mount.FileSystem} on {mountPath} cannot be grown online.");
        }

        return await ProcessRunner.RunAsync(tool, arguments, ToolTimeout, timeProvider, cancellationToken) switch
        {
            ProcessOutput { ExitCode: 0 } => Grown(nodeId, mountPath),
            ProcessOutput output => new InternalFailure($"Resizing {mount.FileSystem} on {mountPath} failed with {output.ExitCode}: {output.Stderr.Trim()}"),
            RequestTimeout failure => failure,
            Unavailable failure => failure,
        };
    }

    private VolumeGrown Grown(string nodeId, string mountPath)
    {
        var size = SizeGiB(mountPath);
        AgentLog.VolumeGrown(logger, mountPath, size);
        return new VolumeGrown(nodeId, mountPath, size);
    }

    private async Task RunDrainAsync(DrainWork work, CancellationToken cancellationToken) =>
        await DrainAsync(work.NodeId, work.Reason, cancellationToken);

    private async Task RunGrowVolumeAsync(GrowVolumeWork work, CancellationToken cancellationToken)
    {
        var task = await GrowVolumeAsync(work.NodeId, work.MountPath, cancellationToken) switch
        {
            VolumeGrown message => outbox.EnqueueAsync(message, cancellationToken),
            Validation failure => GrowFailed(work, failure.Message),
            NotFound failure => GrowFailed(work, failure.Message),
            RequestTimeout failure => GrowFailed(work, failure.Message),
            Unavailable failure => GrowFailed(work, failure.Message),
            InternalFailure failure => GrowFailed(work, failure.Message),
        };
        await task;
    }

    private ValueTask GrowFailed(GrowVolumeWork work, string reason)
    {
        AgentLog.VolumeGrowFailed(logger, work.MountPath, reason);
        return ValueTask.CompletedTask;
    }

    private async Task RunUpgradeAsync(UpgradeAgentWork work, CancellationToken cancellationToken)
    {
        var failure = await UpgradeAgentAsync(work.Version, work.Url, work.Sha256, cancellationToken) switch
        {
            Done => null,
            Validation upgradeFailure => upgradeFailure.Message,
            RequestTimeout upgradeFailure => upgradeFailure.Message,
            Unavailable upgradeFailure => upgradeFailure.Message,
            InternalFailure upgradeFailure => upgradeFailure.Message,
        };
        if (failure is not null)
        {
            AgentLog.UpgradeFailed(logger, work.Version, failure);
            return;
        }

        if (CurrentReleaseDirectory() == Path.Combine(options.ReleasesDirectory, work.Version))
        {
            AgentLog.UpgradeRestarting(logger, work.Version);
            Environment.ExitCode = UpgradeExitCode;
            lifetime.StopApplication();
        }
    }

    private async Task<Result<Done, Validation, RequestTimeout, Unavailable, InternalFailure>> DownloadVerifiedAsync(
        Uri source,
        string destination,
        byte[] expectedHash,
        CancellationToken cancellationToken)
    {
        using var timeoutSource = new CancellationTokenSource(DownloadTimeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);
        using var client = httpClientFactory.CreateClient(DownloadClientName);
        try
        {
            Directory.CreateDirectory(options.ReleasesDirectory);
            using var response = await client.GetAsync(source, HttpCompletionOption.ResponseHeadersRead, linked.Token);
            if (!response.IsSuccessStatusCode)
            {
                return new Unavailable(string.Create(CultureInfo.InvariantCulture, $"Agent bundle download returned {(int)response.StatusCode}."));
            }

            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await using (var input = await response.Content.ReadAsStreamAsync(linked.Token))
            await using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
            {
                var buffer = new byte[81920];
                int read;
                while ((read = await input.ReadAsync(buffer, linked.Token)) > 0)
                {
                    hash.AppendData(buffer, 0, read);
                    await output.WriteAsync(buffer.AsMemory(0, read), linked.Token);
                }

                output.Flush(flushToDisk: true);
            }

            return CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), expectedHash)
                ? new Done()
                : new Validation("Agent bundle SHA-256 does not match the expected digest.");
        }
        catch (HttpRequestException exception)
        {
            return new Unavailable($"Agent bundle download failed: {exception.Message}");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new InternalFailure($"Writing the agent bundle failed: {exception.Message}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new RequestTimeout("Agent bundle download timed out.");
        }
    }

    private static async Task<Result<Done, Validation, InternalFailure>> ExtractAsync(UpgradeBundle bundle, CancellationToken cancellationToken)
    {
        try
        {
            Directory.CreateDirectory(bundle.Staging);
            await using (var file = File.OpenRead(bundle.Archive))
            await using (var gzip = new GZipStream(file, CompressionMode.Decompress))
            {
                await TarFile.ExtractToDirectoryAsync(gzip, bundle.Staging, overwriteFiles: false, cancellationToken);
            }

            return Directory.EnumerateFileSystemEntries(bundle.Staging).Any()
                ? new Done()
                : new Validation($"Agent bundle {bundle.Version} is empty.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return new InternalFailure($"Extracting agent bundle {bundle.Version} failed: {exception.Message}");
        }
    }

    private async Task<Result<Done, Validation, RequestTimeout, Unavailable, InternalFailure>> ActivateAsync(UpgradeBundle bundle, CancellationToken cancellationToken)
    {
        var temporaryLink = Path.Combine(options.InstallDirectory, $".current.{Guid.NewGuid():N}");
        try
        {
            if (Directory.Exists(bundle.ReleaseDirectory))
            {
                Directory.Delete(bundle.ReleaseDirectory, recursive: true);
            }

            Directory.Move(bundle.Staging, bundle.ReleaseDirectory);
            File.CreateSymbolicLink(temporaryLink, Path.Combine("releases", bundle.Version));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new InternalFailure($"Installing agent {bundle.Version} failed: {exception.Message}");
        }

        return await ProcessRunner.RunAsync("mv", ["-T", "-f", temporaryLink, options.CurrentReleaseLink], ToolTimeout, timeProvider, cancellationToken) switch
        {
            ProcessOutput { ExitCode: 0 } => Installed(bundle),
            ProcessOutput output => Unlinked(temporaryLink, new InternalFailure($"Swapping {options.CurrentReleaseLink} failed: {output.Stderr.Trim()}")),
            RequestTimeout failure => Unlinked(temporaryLink, failure),
            Unavailable failure => Unlinked(temporaryLink, failure),
        };
    }

    private static TFailure Unlinked<TFailure>(string temporaryLink, TFailure failure)
    {
        File.Delete(temporaryLink);
        return failure;
    }

    private Result<Done, Validation, RequestTimeout, Unavailable, InternalFailure> Installed(UpgradeBundle bundle)
    {
        try
        {
            foreach (var release in Directory.EnumerateDirectories(options.ReleasesDirectory))
            {
                var name = Path.GetFileName(release);
                if (release != bundle.ReleaseDirectory && release != bundle.PreviousRelease && !name.StartsWith('.'))
                {
                    Directory.Delete(release, recursive: true);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new InternalFailure($"Agent {bundle.Version} is installed but pruning old releases failed: {exception.Message}");
        }

        AgentLog.UpgradeInstalled(logger, bundle.Version);
        return new Done();
    }

    private string? CurrentReleaseDirectory()
    {
        var link = new FileInfo(options.CurrentReleaseLink);
        return link.LinkTarget is { } target ? Path.GetFullPath(target, options.InstallDirectory) : null;
    }

    private static int SizeGiB(string path) => (int)Math.Round(new DriveInfo(path).TotalSize / (1024d * 1024d * 1024d));

    private sealed record class UpgradeBundle(string Version, string Archive, string Staging, string ReleaseDirectory, string? PreviousRelease);
}
