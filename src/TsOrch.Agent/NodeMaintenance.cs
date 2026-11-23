using System.ComponentModel;
using System.Diagnostics;
using System.Formats.Tar;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace TsOrch.Agent;

public closed record class MaintenanceWork;

public sealed record class DrainWork(string NodeId, string Reason) : MaintenanceWork;

public sealed record class GrowVolumeWork(string NodeId, string MountPath) : MaintenanceWork;

public sealed record class UpgradeAgentWork(string Version, string Url, string Sha256) : MaintenanceWork;

public sealed record class ProcessOutput(int ExitCode, string Stdout, string Stderr);

public static class ProcessRunner
{
    public static async Task<OrchResult<ProcessOutput>> RunAsync(
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
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            return new Unavailable(string.Create(CultureInfo.InvariantCulture, $"{fileName} exceeded {timeout.TotalSeconds:0} s."));
        }
    }
}

public sealed class NodeMaintenance(
    ContainerReconciler reconciler,
    AgentOutbox outbox,
    IHttpClientFactory httpClientFactory,
    IHostApplicationLifetime lifetime,
    IOptions<AgentOptions> options,
    TimeProvider timeProvider,
    ILogger<NodeMaintenance> logger) : BackgroundService
{
    public const string DownloadClientName = "ts-orch-download";
    public const int UpgradeExitCode = 75;
    private const int QueueCapacity = 16;
    private static readonly TimeSpan ToolTimeout = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DownloadTimeout = TimeSpan.FromMinutes(10);

    private readonly AgentOptions _options = options.Value;
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
        logger.DrainStarted(reason);
        await reconciler.DrainAsync(cancellationToken);
        await outbox.EnqueueAsync(new DrainComplete(nodeId), cancellationToken);
        logger.DrainCompleted();
    }

    public async Task<OrchResult<VolumeGrown>> GrowVolumeAsync(string nodeId, string mountPath, CancellationToken cancellationToken)
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
            logger.VolumeGrowSkipped(mountPath);
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
            ? Path.GetFileName(Path.GetDirectoryName(new DirectoryInfo(sysBlock).ResolveLinkTarget(returnFinalTarget: true)?.FullName)) ?? throw new InvalidDataException($"Cannot resolve parent disk of {device}.")
            : deviceName;
        var rescan = Path.Combine("/sys/class/block", diskName, "device", "rescan");
        if (File.Exists(rescan))
        {
            await File.WriteAllTextAsync(rescan, "1", cancellationToken);
        }

        if (isPartition)
        {
            var partitionNumber = (await File.ReadAllTextAsync(partitionFile, cancellationToken)).Trim();
            var grown = await ProcessRunner.RunAsync("growpart", [$"/dev/{diskName}", partitionNumber], ToolTimeout, timeProvider, cancellationToken);
            if (!grown.TryGetValue(out var growOutput, out var growError))
            {
                return growError;
            }

            if (growOutput.ExitCode != 0 && !growOutput.Stdout.Contains("NOCHANGE", StringComparison.Ordinal))
            {
                return new Internal($"growpart failed with {growOutput.ExitCode}: {growOutput.Stderr.Trim()}");
            }
        }

        var resize = mount.FileSystem switch
        {
            "ext2" or "ext3" or "ext4" => await ProcessRunner.RunAsync("resize2fs", [device], ToolTimeout, timeProvider, cancellationToken),
            "xfs" => await ProcessRunner.RunAsync("xfs_growfs", [mountPath], ToolTimeout, timeProvider, cancellationToken),
            var other => new Validation($"File system {other} on {mountPath} cannot be grown online."),
        };
        if (!resize.TryGetValue(out var resizeOutput, out var resizeError))
        {
            return resizeError;
        }

        if (resizeOutput.ExitCode != 0)
        {
            return new Internal($"Resizing {mount.FileSystem} on {mountPath} failed with {resizeOutput.ExitCode}: {resizeOutput.Stderr.Trim()}");
        }

        var size = SizeGiB(mountPath);
        logger.VolumeGrown(mountPath, size);
        return new VolumeGrown(nodeId, mountPath, size);
    }

    public async Task<OrchResult<Done>> UpgradeAgentAsync(string version, string url, string sha256, CancellationToken cancellationToken)
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

        var releaseDirectory = Path.Combine(_options.ReleasesDirectory, version);
        var currentTarget = CurrentReleaseDirectory();
        if (currentTarget == releaseDirectory)
        {
            logger.UpgradeAlreadyCurrent(version);
            return new Done();
        }

        Directory.CreateDirectory(_options.ReleasesDirectory);
        var token = Guid.NewGuid().ToString("N");
        var archive = Path.Combine(_options.ReleasesDirectory, $".{version}.{token}.tar.gz");
        var staging = Path.Combine(_options.ReleasesDirectory, $".{version}.{token}.staging");
        try
        {
            var downloaded = await DownloadVerifiedAsync(source, archive, Convert.FromHexString(sha256), cancellationToken);
            if (downloaded is OrchError downloadError)
            {
                return downloadError;
            }

            Directory.CreateDirectory(staging);
            await using (var file = File.OpenRead(archive))
            await using (var gzip = new GZipStream(file, CompressionMode.Decompress))
            {
                await TarFile.ExtractToDirectoryAsync(gzip, staging, overwriteFiles: false, cancellationToken);
            }

            if (!Directory.EnumerateFileSystemEntries(staging).Any())
            {
                return new Validation($"Agent bundle {version} is empty.");
            }

            if (Directory.Exists(releaseDirectory))
            {
                Directory.Delete(releaseDirectory, recursive: true);
            }

            Directory.Move(staging, releaseDirectory);
            var swapped = await SwapCurrentLinkAsync(version, cancellationToken);
            if (swapped is OrchError swapError)
            {
                return swapError;
            }

            PruneReleases(releaseDirectory, currentTarget);
            logger.UpgradeInstalled(version);
            return new Done();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException or HttpRequestException)
        {
            return new Internal($"Agent upgrade to {version} failed: {exception.Message}");
        }
        finally
        {
            File.Delete(archive);
            if (Directory.Exists(staging))
            {
                Directory.Delete(staging, recursive: true);
            }
        }
    }

    private async Task RunDrainAsync(DrainWork work, CancellationToken cancellationToken) =>
        await DrainAsync(work.NodeId, work.Reason, cancellationToken);

    private async Task RunGrowVolumeAsync(GrowVolumeWork work, CancellationToken cancellationToken)
    {
        var grown = await GrowVolumeAsync(work.NodeId, work.MountPath, cancellationToken);
        switch (grown)
        {
            case VolumeGrown message:
                await outbox.EnqueueAsync(message, cancellationToken);
                break;
            case OrchError error:
                logger.VolumeGrowFailed(work.MountPath, error.Message);
                break;
        }
    }

    private async Task RunUpgradeAsync(UpgradeAgentWork work, CancellationToken cancellationToken)
    {
        var upgraded = await UpgradeAgentAsync(work.Version, work.Url, work.Sha256, cancellationToken);
        switch (upgraded)
        {
            case Done when CurrentReleaseDirectory() == Path.Combine(_options.ReleasesDirectory, work.Version):
                logger.UpgradeRestarting(work.Version);
                Environment.ExitCode = UpgradeExitCode;
                lifetime.StopApplication();
                break;
            case Done:
                break;
            case OrchError error:
                logger.UpgradeFailed(work.Version, error.Message);
                break;
        }
    }

    private async Task<OrchResult<Done>> DownloadVerifiedAsync(Uri source, string destination, byte[] expectedHash, CancellationToken cancellationToken)
    {
        using var timeoutSource = new CancellationTokenSource(DownloadTimeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);
        using var client = httpClientFactory.CreateClient(DownloadClientName);
        try
        {
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
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new Unavailable("Agent bundle download timed out.");
        }
    }

    private async Task<OrchResult<Done>> SwapCurrentLinkAsync(string version, CancellationToken cancellationToken)
    {
        var temporaryLink = Path.Combine(_options.InstallDirectory, $".current.{Guid.NewGuid():N}");
        File.CreateSymbolicLink(temporaryLink, Path.Combine("releases", version));
        var moved = await ProcessRunner.RunAsync("mv", ["-T", "-f", temporaryLink, _options.CurrentReleaseLink], ToolTimeout, timeProvider, cancellationToken);
        if (!moved.TryGetValue(out var output, out var error))
        {
            File.Delete(temporaryLink);
            return error;
        }

        if (output.ExitCode != 0)
        {
            File.Delete(temporaryLink);
            return new Internal($"Swapping {_options.CurrentReleaseLink} failed: {output.Stderr.Trim()}");
        }

        return new Done();
    }

    private string? CurrentReleaseDirectory()
    {
        var link = new FileInfo(_options.CurrentReleaseLink);
        return link.LinkTarget is { } target ? Path.GetFullPath(target, _options.InstallDirectory) : null;
    }

    private void PruneReleases(string current, string? previous)
    {
        foreach (var release in Directory.EnumerateDirectories(_options.ReleasesDirectory))
        {
            var name = Path.GetFileName(release);
            if (release != current && release != previous && !name.StartsWith('.'))
            {
                Directory.Delete(release, recursive: true);
            }
        }
    }

    private static int SizeGiB(string path) => (int)Math.Round(new DriveInfo(path).TotalSize / (1024d * 1024d * 1024d));
}
