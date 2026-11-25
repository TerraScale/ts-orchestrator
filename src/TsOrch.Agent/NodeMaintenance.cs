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

public sealed record class MaintenanceToolTimedOut(string Message);

public sealed record class MaintenanceToolUnavailable(string Message);

public readonly union ProcessExecution(ProcessOutput, MaintenanceToolTimedOut, MaintenanceToolUnavailable);

public sealed record class VolumeGrowthRejected(string Message);

public sealed record class VolumeMountMissing(string Message);

public sealed record class VolumeGrowthFailed(string Message);

public readonly union VolumeGrowth(VolumeGrown, VolumeGrowthRejected, VolumeMountMissing, VolumeGrowthFailed, MaintenanceToolTimedOut, MaintenanceToolUnavailable);

public readonly record struct AgentUpgradeCompleted;

public readonly record struct AgentUpgradeAlreadyCurrent;

public sealed record class AgentUpgradeRejected(string Message);

public sealed record class AgentUpgradeIoFailed(string Message);

public sealed record class AgentBundleUnavailable(string Message);

public sealed record class AgentBundleDownloadTimedOut(string Message);

public readonly union AgentUpgrade(AgentUpgradeCompleted, AgentUpgradeAlreadyCurrent, AgentUpgradeRejected, AgentUpgradeIoFailed,
    AgentBundleUnavailable, AgentBundleDownloadTimedOut, MaintenanceToolTimedOut, MaintenanceToolUnavailable);

internal sealed record class GrowthDevice(MountEntry Mount, string Device, string Disk, string? Partition);

internal readonly record struct DedicatedVolumeAbsent;

internal readonly union VolumeGrowthTarget(GrowthDevice, DedicatedVolumeAbsent, VolumeGrowthRejected, VolumeGrowthFailed);

internal readonly record struct AgentBundleVerified;

internal readonly record struct AgentBundleExtracted;

internal readonly union AgentBundleDownload(AgentBundleVerified, AgentUpgradeRejected, AgentUpgradeIoFailed, AgentBundleUnavailable, AgentBundleDownloadTimedOut);

internal readonly union AgentBundleExtraction(AgentBundleExtracted, AgentUpgradeRejected, AgentUpgradeIoFailed);

public static class ProcessRunner
{
    public static async Task<ProcessExecution> RunAsync(
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
            return new MaintenanceToolUnavailable($"{fileName} could not start: {exception.Message}");
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
            return new MaintenanceToolTimedOut(string.Create(CultureInfo.InvariantCulture, $"{fileName} exceeded {timeout.TotalSeconds:0} s."));
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
    private const int MaxBundleBytes = 128 * 1024 * 1024;
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
        var outcome = await reconciler.DrainAsync(cancellationToken);
        await (outcome switch
        {
            NonStatefulContainersDrained => ReportDrainCompleteAsync(nodeId, cancellationToken),
            NodeDrainIncomplete remaining => ReportDrainFailure($"Remaining placements: {string.Join(", ", remaining.PlacementIds)}"),
            NodeDrainUnverified failure => ReportDrainFailure(failure.Message),
        });
    }

    public async Task<VolumeGrowth> GrowVolumeAsync(
        string nodeId,
        string mountPath,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeId);
        if (string.IsNullOrWhiteSpace(mountPath) || mountPath.Contains('\0', StringComparison.Ordinal)
            || !Path.IsPathFullyQualified(mountPath) || Path.GetFullPath(mountPath) != mountPath.TrimEnd('/'))
        {
            return new VolumeGrowthRejected($"Mount path {mountPath} must be an absolute normalized path.");
        }

        if (!Directory.Exists(mountPath))
        {
            return new VolumeMountMissing($"Mount path {mountPath} does not exist.");
        }

        var target = await InspectVolumeGrowthAsync(mountPath, cancellationToken);
        return target switch
        {
            GrowthDevice device => await GrowDeviceAsync(nodeId, mountPath, device, cancellationToken),
            DedicatedVolumeAbsent => SkipGrowth(nodeId, mountPath),
            VolumeGrowthRejected failure => failure,
            VolumeGrowthFailed failure => failure,
        };
    }

    private static async Task<VolumeGrowthTarget> InspectVolumeGrowthAsync(string mountPath, CancellationToken cancellationToken)
    {
        try
        {
            var mounts = await MountTable.ReadAsync(cancellationToken);
            var mount = MountTable.FindContaining(mounts, mountPath);
            if (mount is null || mount.MountPoint != mountPath || !mount.Device.StartsWith("/dev/", StringComparison.Ordinal))
            {
                return new DedicatedVolumeAbsent();
            }

            var device = new FileInfo(mount.Device).ResolveLinkTarget(returnFinalTarget: true)?.FullName ?? mount.Device;
            var disk = Path.GetFileName(device);
            var sysBlock = Path.Combine("/sys/class/block", disk);
            if (!Directory.Exists(sysBlock))
            {
                return new VolumeGrowthRejected($"Block device {device} is not visible under /sys/class/block.");
            }

            string? partition = null;
            var partitionFile = Path.Combine(sysBlock, "partition");
            if (File.Exists(partitionFile))
            {
                if (Path.GetFileName(Path.GetDirectoryName(new DirectoryInfo(sysBlock).ResolveLinkTarget(returnFinalTarget: true)?.FullName)) is not { Length: > 0 } parent)
                {
                    return new VolumeGrowthFailed($"Cannot resolve the parent disk of {device}.");
                }

                disk = parent;
                partition = (await File.ReadAllTextAsync(partitionFile, cancellationToken)).Trim();
            }

            var rescan = Path.Combine("/sys/class/block", disk, "device", "rescan");
            if (File.Exists(rescan))
            {
                await File.WriteAllTextAsync(rescan, "1", cancellationToken);
            }

            return new GrowthDevice(mount, device, disk, partition);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new VolumeGrowthFailed($"Reading or rescanning the block device for {mountPath} failed: {exception.Message}");
        }
    }

    private async Task<VolumeGrowth> GrowDeviceAsync(string nodeId, string mountPath, GrowthDevice device, CancellationToken cancellationToken)
    {
        if (device.Partition is not { } partition)
        {
            return await ResizeAsync(nodeId, mountPath, device.Mount, device.Device, cancellationToken);
        }

        var outcome = await ProcessRunner.RunAsync("growpart", [$"/dev/{device.Disk}", partition], ToolTimeout, timeProvider, cancellationToken);
        return outcome switch
        {
            ProcessOutput { ExitCode: 0 } => await ResizeAsync(nodeId, mountPath, device.Mount, device.Device, cancellationToken),
            ProcessOutput output when output.Stdout.Contains("NOCHANGE", StringComparison.Ordinal) => await ResizeAsync(nodeId, mountPath, device.Mount, device.Device, cancellationToken),
            ProcessOutput output => new VolumeGrowthFailed($"growpart failed with {output.ExitCode}: {output.Stderr.Trim()}"),
            MaintenanceToolTimedOut failure => failure,
            MaintenanceToolUnavailable failure => failure,
        };
    }

    private VolumeGrowth SkipGrowth(string nodeId, string mountPath)
    {
        AgentLog.VolumeGrowSkipped(logger, mountPath);
        return MeasureVolume(nodeId, mountPath, logGrowth: false);
    }

    public async Task<AgentUpgrade> UpgradeAgentAsync(
        string version,
        string url,
        string sha256,
        CancellationToken cancellationToken)
    {
        if (!AgentNames.IsSafeToken(version))
        {
            return new AgentUpgradeRejected($"Agent version {version} is not a safe path token.");
        }

        if (sha256.Length != 64 || !sha256.All(char.IsAsciiHexDigit))
        {
            return new AgentUpgradeRejected("Agent bundle SHA-256 must be 64 hex characters.");
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var source) || !(source.Scheme == Uri.UriSchemeHttps || (source.Scheme == Uri.UriSchemeHttp && source.IsLoopback)))
        {
            return new AgentUpgradeRejected($"Agent bundle URL {url} must be https.");
        }

        var releaseDirectory = Path.Combine(options.ReleasesDirectory, version);
        var currentTarget = CurrentReleaseDirectory();
        if (currentTarget == releaseDirectory)
        {
            AgentLog.UpgradeAlreadyCurrent(logger, version);
            return new AgentUpgradeAlreadyCurrent();
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
            var outcome = await DownloadVerifiedAsync(source, bundle.Archive, Convert.FromHexString(sha256), cancellationToken);
            return outcome switch
            {
                AgentBundleVerified => await ExtractAndActivateAsync(bundle, cancellationToken),
                AgentUpgradeRejected failure => failure,
                AgentBundleDownloadTimedOut failure => failure,
                AgentBundleUnavailable failure => failure,
                AgentUpgradeIoFailed failure => failure,
            };
        }
        finally
        {
            CleanupBundle(bundle);
        }
    }

    private void CleanupBundle(UpgradeBundle bundle)
    {
        try
        {
            File.Delete(bundle.Archive);
            if (Directory.Exists(bundle.Staging))
            {
                Directory.Delete(bundle.Staging, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            AgentLog.UpgradeCleanupFailed(logger, bundle.Version, exception.Message);
        }
    }

    private async Task<AgentUpgrade> ExtractAndActivateAsync(UpgradeBundle bundle, CancellationToken cancellationToken)
    {
        var extracted = await ExtractAsync(bundle, cancellationToken);
        return extracted switch
        {
            AgentBundleExtracted => await ActivateAsync(bundle, cancellationToken),
            AgentUpgradeRejected failure => failure,
            AgentUpgradeIoFailed failure => failure,
        };
    }

    private async Task<VolumeGrowth> ResizeAsync(
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
            return new VolumeGrowthRejected($"File system {mount.FileSystem} on {mountPath} cannot be grown online.");
        }

        var outcome = await ProcessRunner.RunAsync(tool, arguments, ToolTimeout, timeProvider, cancellationToken);
        return outcome switch
        {
            ProcessOutput { ExitCode: 0 } => MeasureVolume(nodeId, mountPath, logGrowth: true),
            ProcessOutput output => new VolumeGrowthFailed($"Resizing {mount.FileSystem} on {mountPath} failed with {output.ExitCode}: {output.Stderr.Trim()}"),
            MaintenanceToolTimedOut failure => failure,
            MaintenanceToolUnavailable failure => failure,
        };
    }

    private VolumeGrowth MeasureVolume(string nodeId, string mountPath, bool logGrowth)
    {
        try
        {
            var size = (int)Math.Round(new DriveInfo(mountPath).TotalSize / (1024d * 1024d * 1024d));
            if (logGrowth)
            {
                AgentLog.VolumeGrown(logger, mountPath, size);
            }

            return new VolumeGrown(nodeId, mountPath, size);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new VolumeGrowthFailed($"Measuring {mountPath} failed: {exception.Message}");
        }
    }

    private async Task ReportDrainCompleteAsync(string nodeId, CancellationToken cancellationToken)
    {
        await outbox.EnqueueAsync(new DrainComplete(nodeId), cancellationToken);
        AgentLog.DrainCompleted(logger);
    }

    private Task ReportDrainFailure(string reason)
    {
        AgentLog.DrainFailed(logger, reason);
        return Task.CompletedTask;
    }

    private async Task RunDrainAsync(DrainWork work, CancellationToken cancellationToken) =>
        await DrainAsync(work.NodeId, work.Reason, cancellationToken);

    private async Task RunGrowVolumeAsync(GrowVolumeWork work, CancellationToken cancellationToken)
    {
        var outcome = await GrowVolumeAsync(work.NodeId, work.MountPath, cancellationToken);
        var task = outcome switch
        {
            VolumeGrown message => outbox.EnqueueAsync(message, cancellationToken),
            VolumeGrowthRejected failure => GrowFailed(work, failure.Message),
            VolumeMountMissing failure => GrowFailed(work, failure.Message),
            MaintenanceToolTimedOut failure => GrowFailed(work, failure.Message),
            MaintenanceToolUnavailable failure => GrowFailed(work, failure.Message),
            VolumeGrowthFailed failure => GrowFailed(work, failure.Message),
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
        var outcome = await UpgradeAgentAsync(work.Version, work.Url, work.Sha256, cancellationToken);
        var (shouldRestart, failure) = outcome switch
        {
            AgentUpgradeCompleted => (true, (string?)null),
            AgentUpgradeAlreadyCurrent => (false, (string?)null),
            AgentUpgradeRejected upgradeFailure => (false, upgradeFailure.Message),
            MaintenanceToolTimedOut upgradeFailure => (false, upgradeFailure.Message),
            AgentBundleDownloadTimedOut upgradeFailure => (false, upgradeFailure.Message),
            AgentBundleUnavailable upgradeFailure => (false, upgradeFailure.Message),
            MaintenanceToolUnavailable upgradeFailure => (false, upgradeFailure.Message),
            AgentUpgradeIoFailed upgradeFailure => (false, upgradeFailure.Message),
        };
        if (failure is not null)
        {
            AgentLog.UpgradeFailed(logger, work.Version, failure);
            return;
        }

        if (shouldRestart && CurrentReleaseDirectory() == Path.Combine(options.ReleasesDirectory, work.Version))
        {
            AgentLog.UpgradeRestarting(logger, work.Version);
            Environment.ExitCode = UpgradeExitCode;
            lifetime.StopApplication();
        }
    }

    private async Task<AgentBundleDownload> DownloadVerifiedAsync(
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
                return new AgentBundleUnavailable(string.Create(CultureInfo.InvariantCulture, $"Agent bundle download returned {(int)response.StatusCode}."));
            }

            if (response.Content.Headers.ContentLength > MaxBundleBytes)
            {
                return BundleTooLarge();
            }

            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await using (var input = await response.Content.ReadAsStreamAsync(linked.Token))
            await using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
            {
                var buffer = new byte[81920];
                int read;
                while ((read = await input.ReadAsync(buffer, linked.Token)) > 0)
                {
                    if (output.Position + read > MaxBundleBytes)
                    {
                        return BundleTooLarge();
                    }

                    hash.AppendData(buffer, 0, read);
                    await output.WriteAsync(buffer.AsMemory(0, read), linked.Token);
                }

                output.Flush(flushToDisk: true);
            }

            return CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), expectedHash)
                ? new AgentBundleVerified()
                : new AgentUpgradeRejected("Agent bundle SHA-256 does not match the expected digest.");
        }
        catch (HttpRequestException exception)
        {
            return new AgentBundleUnavailable($"Agent bundle download failed: {exception.Message}");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new AgentUpgradeIoFailed($"Writing the agent bundle failed: {exception.Message}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new AgentBundleDownloadTimedOut("Agent bundle download timed out.");
        }
    }

    private static AgentUpgradeRejected BundleTooLarge() =>
        new(string.Create(CultureInfo.InvariantCulture, $"Agent bundle exceeds {MaxBundleBytes} bytes."));

    private static async Task<AgentBundleExtraction> ExtractAsync(UpgradeBundle bundle, CancellationToken cancellationToken)
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
                ? new AgentBundleExtracted()
                : new AgentUpgradeRejected($"Agent bundle {bundle.Version} is empty.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return new AgentUpgradeIoFailed($"Extracting agent bundle {bundle.Version} failed: {exception.Message}");
        }
    }

    private async Task<AgentUpgrade> ActivateAsync(UpgradeBundle bundle, CancellationToken cancellationToken)
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
            return new AgentUpgradeIoFailed($"Installing agent {bundle.Version} failed: {exception.Message}");
        }

        var outcome = await ProcessRunner.RunAsync("mv", ["-T", "-f", temporaryLink, options.CurrentReleaseLink], ToolTimeout, timeProvider, cancellationToken);
        return outcome switch
        {
            ProcessOutput { ExitCode: 0 } => await InstalledAsync(bundle, cancellationToken),
            ProcessOutput output => Unlinked(temporaryLink, new AgentUpgradeIoFailed($"Swapping {options.CurrentReleaseLink} failed: {output.Stderr.Trim()}")),
            MaintenanceToolTimedOut failure => Unlinked(temporaryLink, failure),
            MaintenanceToolUnavailable failure => Unlinked(temporaryLink, failure),
        };
    }

    private static TFailure Unlinked<TFailure>(string temporaryLink, TFailure failure)
    {
        File.Delete(temporaryLink);
        return failure;
    }

    private async Task<AgentUpgrade> InstalledAsync(UpgradeBundle bundle, CancellationToken cancellationToken)
    {
        await RefreshSystemdUnitsAsync(bundle.ReleaseDirectory, cancellationToken);
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
            return new AgentUpgradeIoFailed($"Agent {bundle.Version} is installed but pruning old releases failed: {exception.Message}");
        }

        AgentLog.UpgradeInstalled(logger, bundle.Version);
        return new AgentUpgradeCompleted();
    }

    private async Task RefreshSystemdUnitsAsync(string releaseDirectory, CancellationToken cancellationToken)
    {
        var unitsDirectory = Path.Combine(releaseDirectory, "systemd");
        if (!Environment.IsPrivilegedProcess || !Directory.Exists(unitsDirectory) || !Directory.Exists("/etc/systemd/system"))
        {
            return;
        }

        try
        {
            var copied = false;
            foreach (var pattern in new[] { "*.slice", "*.service", "*.timer" })
            {
                foreach (var source in Directory.EnumerateFiles(unitsDirectory, pattern))
                {
                    var destination = Path.Combine("/etc/systemd/system", Path.GetFileName(source));
                    var bytes = await File.ReadAllBytesAsync(source, cancellationToken);
                    var write = await UnixFiles.WriteAtomicAsync(destination, bytes, UnixFiles.WorldReadable, cancellationToken);
                    if (write is AtomicWriteFailed failed)
                    {
                        AgentLog.SystemdReloadFailed(logger, failed.Message);
                        return;
                    }

                    copied = true;
                }
            }

            if (copied)
            {
                var reload = await ProcessRunner.RunAsync("systemctl", ["daemon-reload"], ToolTimeout, timeProvider, cancellationToken);
                var error = reload switch
                {
                    ProcessOutput { ExitCode: 0 } => null,
                    ProcessOutput output => $"systemctl daemon-reload exited {output.ExitCode}: {output.Stderr.Trim()}",
                    MaintenanceToolTimedOut timedOut => timedOut.Message,
                    MaintenanceToolUnavailable unavailable => unavailable.Message,
                };
                if (error is not null)
                {
                    AgentLog.SystemdReloadFailed(logger, error);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            AgentLog.SystemdReloadFailed(logger, exception.Message);
        }
    }

    private string? CurrentReleaseDirectory()
    {
        var link = new FileInfo(options.CurrentReleaseLink);
        return link.LinkTarget is { } target ? Path.GetFullPath(target, options.InstallDirectory) : null;
    }

    private sealed record class UpgradeBundle(string Version, string Archive, string Staging, string ReleaseDirectory, string? PreviousRelease);
}
