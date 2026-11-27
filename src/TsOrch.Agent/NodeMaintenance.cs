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

public sealed record class GrowVolumeWork(
    string NodeId,
    string MountPath,
    string VolumeId,
    string AttachedDevice,
    string ExpectedVolumeIdentity,
    BlockVolumeIdentity Identity,
    CancellationToken Session) : MaintenanceWork;

public sealed record class UpgradeAgentWork(string Version, string Url, string Sha256) : MaintenanceWork;

public sealed record class ProcessOutput(int ExitCode, string Stdout, string Stderr);

public sealed record class MaintenanceToolTimedOut(string Message);

public sealed record class MaintenanceToolUnavailable(string Message);

public readonly union ProcessExecution(ProcessOutput, MaintenanceToolTimedOut, MaintenanceToolUnavailable);

public readonly record struct AgentUpgradeCompleted;

public readonly record struct AgentUpgradeAlreadyCurrent;

public sealed record class AgentUpgradeRejected(string Message);

public sealed record class AgentUpgradeIoFailed(string Message);

public sealed record class AgentBundleUnavailable(string Message);

public sealed record class AgentBundleDownloadTimedOut(string Message);

public readonly union AgentUpgrade(AgentUpgradeCompleted, AgentUpgradeAlreadyCurrent, AgentUpgradeRejected, AgentUpgradeIoFailed,
    AgentBundleUnavailable, AgentBundleDownloadTimedOut, MaintenanceToolTimedOut, MaintenanceToolUnavailable);

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
        startInfo.Environment["LC_ALL"] = "C";
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
    VolumeGrowthExecutor volumeGrowth,
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

    private readonly Lock _growGate = new();
    private readonly Dictionary<string, GrowVolumeWork> _queuedGrows = [];
    private readonly Dictionary<string, GrowVolumeWork> _runningGrows = [];

    public ValueTask EnqueueAsync(MaintenanceWork work, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(work);
        return _queue.Writer.WriteAsync(work, cancellationToken);
    }

    public async ValueTask EnqueueGrowVolumeAsync(string nodeId, GrowVolume grow, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeId);
        ArgumentNullException.ThrowIfNull(grow);
        if (!VolumeGrowthExecutor.IsNormalizedMountPath(grow.MountPath))
        {
            await GrowFailed(grow.MountPath, VolumeGrowthExecutor.MountPathRejected(grow.MountPath).Message);
            return;
        }

        if (grow is not { VolumeId: { Length: > 0 } volumeId, Device: { Length: > 0 } attachedDevice, VolumeIdentity: { Length: > 0 } volumeIdentity }
            || !MountTable.IsCanonicalVolumeIdentity(volumeIdentity))
        {
            await GrowFailed(grow.MountPath, VolumeGrowthExecutor.UnboundVolumeGrowMessage(grow.MountPath));
            return;
        }

        var target = VolumeGrowthExecutor.InspectVolumeGrowth(grow.MountPath, attachedDevice, volumeIdentity, cancellationToken);
        var queued = target switch
        {
            GrowthDevice device => QueueGrowVolumeAsync(
                new GrowVolumeWork(nodeId, grow.MountPath, volumeId, attachedDevice, volumeIdentity, device.Identity, cancellationToken),
                cancellationToken),
            VolumeGrowthRejected failure => GrowFailed(grow.MountPath, failure.Message),
            VolumeGrowthFailed failure => GrowFailed(grow.MountPath, failure.Message),
        };
        await queued;
    }

    private async ValueTask QueueGrowVolumeAsync(GrowVolumeWork work, CancellationToken cancellationToken)
    {
        lock (_growGate)
        {
            if (_queuedGrows.ContainsKey(work.MountPath))
            {
                _queuedGrows[work.MountPath] = work;
                return;
            }

            if (_runningGrows.TryGetValue(work.MountPath, out var running) && IsSameLiveGrow(running, work))
            {
                return;
            }

            _queuedGrows[work.MountPath] = work;
        }

        var written = false;
        try
        {
            await _queue.Writer.WriteAsync(work, cancellationToken);
            written = true;
        }
        finally
        {
            if (!written)
            {
                lock (_growGate)
                {
                    _queuedGrows.Remove(work.MountPath);
                }
            }
        }
    }

    private static bool IsSameLiveGrow(GrowVolumeWork running, GrowVolumeWork retry) =>
        !running.Session.IsCancellationRequested
        && running.VolumeId == retry.VolumeId
        && running.AttachedDevice == retry.AttachedDevice
        && running.ExpectedVolumeIdentity == retry.ExpectedVolumeIdentity
        && running.Identity == retry.Identity;

    private GrowVolumeWork? StartQueuedGrow(string mountPath)
    {
        lock (_growGate)
        {
            if (!_queuedGrows.Remove(mountPath, out var work))
            {
                return null;
            }

            _runningGrows[mountPath] = work;
            return work;
        }
    }

    private async Task RunQueuedGrowVolumeAsync(string mountPath, CancellationToken cancellationToken)
    {
        if (StartQueuedGrow(mountPath) is not { } work)
        {
            return;
        }

        try
        {
            await RunGrowVolumeAsync(work, cancellationToken);
        }
        finally
        {
            lock (_growGate)
            {
                _runningGrows.Remove(mountPath);
            }
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var work in _queue.Reader.ReadAllAsync(stoppingToken))
        {
            var task = work switch
            {
                DrainWork drain => RunDrainAsync(drain, stoppingToken),
                GrowVolumeWork grow => RunQueuedGrowVolumeAsync(grow.MountPath, stoppingToken),
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
        if (work.Session.IsCancellationRequested)
        {
            await GrowDropped(work.MountPath);
            return;
        }

        var outcome = await volumeGrowth.GrowVolumeAsync(work.NodeId, work.MountPath, work.AttachedDevice, work.ExpectedVolumeIdentity, work.Identity, cancellationToken);
        var task = outcome switch
        {
            VolumeGrown message => ReportVolumeGrownAsync(work, message, cancellationToken),
            VolumeGrowthRejected failure => GrowFailed(work.MountPath, failure.Message),
            MaintenanceToolTimedOut failure => GrowFailed(work.MountPath, failure.Message),
            MaintenanceToolUnavailable failure => GrowFailed(work.MountPath, failure.Message),
            VolumeGrowthFailed failure => GrowFailed(work.MountPath, failure.Message),
        };
        await task;
    }

    private async ValueTask ReportVolumeGrownAsync(GrowVolumeWork work, VolumeGrown message, CancellationToken cancellationToken)
    {
        var target = VolumeGrowthExecutor.InspectExpectedVolume(work.MountPath, work.AttachedDevice, work.ExpectedVolumeIdentity, work.Identity, cancellationToken);
        var task = target switch
        {
            GrowthDevice when work.Session.IsCancellationRequested => GrowDropped(work.MountPath),
            GrowthDevice => outbox.EnqueueAsync(message with { VolumeId = work.VolumeId }, work.Session, cancellationToken),
            VolumeGrowthRejected failure => GrowFailed(work.MountPath, failure.Message),
            VolumeGrowthFailed failure => GrowFailed(work.MountPath, failure.Message),
        };
        await task;
    }

    private ValueTask GrowFailed(string mountPath, string reason)
    {
        AgentLog.VolumeGrowFailed(logger, mountPath, reason);
        return ValueTask.CompletedTask;
    }

    private ValueTask GrowDropped(string mountPath)
    {
        AgentLog.VolumeGrowDropped(logger, mountPath);
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
