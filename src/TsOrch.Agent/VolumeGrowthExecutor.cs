using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

namespace TsOrch.Agent;

public sealed record class BlockVolumeIdentity(
    string Device,
    string DeviceNumber,
    string StableNames,
    string DiskByIdNames,
    ulong MountId,
    ulong MountInode,
    string DiskNodeSignature,
    string PartitionNodeSignature,
    string? OciDevice = null);

public sealed record class VolumeGrowthRejected(string Message);

public sealed record class VolumeGrowthFailed(string Message);

public readonly union VolumeGrowth(VolumeGrown, VolumeGrowthRejected, VolumeGrowthFailed, MaintenanceToolTimedOut, MaintenanceToolUnavailable);

internal sealed record class GrowthDevice(
    MountEntry Mount,
    string Disk,
    string DiskMajorMinor,
    string? Partition,
    BlockVolumeIdentity Identity);

internal readonly union VolumeGrowthTarget(GrowthDevice, VolumeGrowthRejected, VolumeGrowthFailed);

internal readonly record struct SysfsHelperInvocation(string Executable, string EntryAssembly);

internal sealed record class GrowthAliases(string DiskByIdNames, string StableNames, DirectorySnapshots Snapshots)
{
    public GrowthAliases With(DirectorySnapshots ociSnapshots) => this with { Snapshots = Snapshots.Concat(ociSnapshots) };
}

public sealed class VolumeGrowthExecutor(
    TimeProvider timeProvider,
    ILogger<VolumeGrowthExecutor> logger)
{
    private const uint PrivateMountDirectoryMode = 0x1c0;
    private const string PrivateMountStageDirectory = "/run/ts-orch-grow-stage";
    private const int PrivateMountMismatchExitCode = 65;
    private const string StatFsMarkerPrefix = "TS_ORCH_STATFS ";
    private const string DotnetHostName = "dotnet";
    private const double BytesPerGiB = 1024d * 1024d * 1024d;
    private static readonly TimeSpan ToolTimeout = TimeSpan.FromMinutes(5);

    public static bool IsNormalizedMountPath(string mountPath) =>
        MountTable.IsNormalizedMountPath(mountPath);

    public static VolumeGrowthRejected MountPathRejected(string mountPath) =>
        new($"Mount path {mountPath} must be an absolute normalized path.");

    public static string UnboundVolumeGrowMessage(string mountPath) =>
        $"grow_volume for {mountPath} does not name its OCI volume, attachment device and by-uuid filesystem volume identity, so the mounted disk cannot be verified.";

    public async Task<VolumeGrowth> GrowVolumeAsync(
        string nodeId,
        string mountPath,
        string attachedDevice,
        string expectedVolumeIdentity,
        BlockVolumeIdentity expected,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeId);
        ArgumentNullException.ThrowIfNull(expected);
        if (!IsNormalizedMountPath(mountPath))
        {
            return MountPathRejected(mountPath);
        }

        var target = InspectExpectedVolume(mountPath, attachedDevice, expectedVolumeIdentity, expected, cancellationToken);
        return target switch
        {
            GrowthDevice device => await GrowDeviceAsync(nodeId, mountPath, device, expected, cancellationToken),
            VolumeGrowthRejected failure => failure,
            VolumeGrowthFailed failure => failure,
        };
    }

    internal static VolumeGrowthTarget InspectExpectedVolume(
        string mountPath,
        string attachedDevice,
        string expectedVolumeIdentity,
        BlockVolumeIdentity expected,
        CancellationToken cancellationToken)
    {
        var target = InspectVolumeGrowth(mountPath, attachedDevice, expectedVolumeIdentity, cancellationToken);
        return target switch
        {
            GrowthDevice device when device.Identity == expected => device,
            GrowthDevice device => IdentityChanged(mountPath, expected, device.Identity),
            VolumeGrowthRejected failure => failure,
            VolumeGrowthFailed failure => failure,
        };
    }

    private static VolumeGrowthRejected IdentityChanged(string mountPath, BlockVolumeIdentity expected, BlockVolumeIdentity current) =>
        new($"The block volume behind {mountPath} changed since grow_volume arrived: expected {Describe(expected)}, found {Describe(current)}.");

    private static string Describe(BlockVolumeIdentity identity) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"{identity.Device} {identity.DeviceNumber} mnt={identity.MountId} ino={identity.MountInode} disk={identity.DiskNodeSignature} part={identity.PartitionNodeSignature} [{identity.StableNames}] disk-by-id=[{identity.DiskByIdNames}] ({identity.OciDevice ?? "none"})");

    internal static VolumeGrowthTarget InspectVolumeGrowth(
        string mountPath,
        string attachedDevice,
        string expectedVolumeIdentity,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!MountTable.IsCanonicalVolumeIdentity(expectedVolumeIdentity))
        {
            return new VolumeGrowthRejected($"Expected volume identity [{expectedVolumeIdentity}] must be a single by-uuid/ filesystem identifier.");
        }

        var read = MountTable.TryRead();
        return read switch
        {
            IReadOnlyList<MountEntry> mounts => ResolveGrowthTarget(mounts, mountPath, attachedDevice, expectedVolumeIdentity),
            MountTableReadFailed failed => new VolumeGrowthFailed($"Reading the block device for {mountPath} failed: {failed.Message}"),
        };
    }

    private static VolumeGrowthTarget ResolveGrowthTarget(
        IReadOnlyList<MountEntry> mounts,
        string mountPath,
        string attachedDevice,
        string expectedVolumeIdentity)
    {
        var pathIdentity = MountTable.TryReadMountIdentity(mountPath);
        var resolved = MountTable.ResolveDedicatedBlockMount(mounts, mountPath, pathIdentity);
        return resolved switch
        {
            DedicatedBlockMount dedicated => ReadGrowthDevice(dedicated, mountPath, attachedDevice, expectedVolumeIdentity),
            DedicatedBlockMountMissing missing => new VolumeGrowthRejected(missing.Message),
            DedicatedBlockMountInconsistent inconsistent => new VolumeGrowthRejected(inconsistent.Message),
        };
    }

    private static VolumeGrowthTarget ReadGrowthDevice(
        DedicatedBlockMount dedicated,
        string mountPath,
        string attachedDevice,
        string expectedVolumeIdentity)
    {
        if (!MountTable.IsGrowableFilesystem(dedicated.Mount.FileSystem))
        {
            return new VolumeGrowthRejected($"File system {dedicated.Mount.FileSystem} on {mountPath} cannot be grown online.");
        }

        if (dedicated.Mount.IsReadOnly)
        {
            return new VolumeGrowthRejected($"File system {dedicated.Mount.FileSystem} on {mountPath} is mounted read-only and cannot be grown online.");
        }

        return MountTable.ResolveVerifiedBlockNodes(dedicated) switch
        {
            VerifiedBlockNodes nodes => ReadDiskByIdNames(dedicated, nodes, mountPath, attachedDevice, expectedVolumeIdentity),
            BlockNodeValidationRejected rejected => new VolumeGrowthRejected(rejected.Message),
            BlockNodeValidationFailed failed => new VolumeGrowthFailed(failed.Message),
        };
    }

    private static VolumeGrowthTarget ReadDiskByIdNames(
        DedicatedBlockMount dedicated,
        VerifiedBlockNodes nodes,
        string mountPath,
        string attachedDevice,
        string expectedVolumeIdentity) =>
        MountTable.ReadByIdNames(nodes.DiskPath, nodes.DiskStatx) switch
        {
            StableAliasNames diskByIdNames => ReadDeviceStableNames(dedicated, nodes, diskByIdNames, mountPath, attachedDevice, expectedVolumeIdentity),
            DirectoryScanFailed failed => new VolumeGrowthRejected(failed.Message),
        };

    private static VolumeGrowthTarget ReadDeviceStableNames(
        DedicatedBlockMount dedicated,
        VerifiedBlockNodes nodes,
        StableAliasNames diskByIdNames,
        string mountPath,
        string attachedDevice,
        string expectedVolumeIdentity)
    {
        if (!diskByIdNames.HasById)
        {
            return new VolumeGrowthRejected($"Block disk {nodes.DiskPath} has no stable /dev/disk/by-id path, so volume growth cannot be bound to the verified volume.");
        }

        return MountTable.ReadStableNames(nodes.Device, nodes.DeviceStatx) switch
        {
            StableAliasNames stableNames => ResolveOciAttachment(dedicated, nodes, diskByIdNames, stableNames, mountPath, attachedDevice, expectedVolumeIdentity),
            DirectoryScanFailed failed => new VolumeGrowthRejected(failed.Message),
        };
    }

    private static VolumeGrowthTarget ResolveOciAttachment(
        DedicatedBlockMount dedicated,
        VerifiedBlockNodes nodes,
        StableAliasNames diskByIdAliases,
        StableAliasNames stableAliases,
        string mountPath,
        string attachedDevice,
        string expectedVolumeIdentity)
    {
        var stableNames = stableAliases.Identity;
        var aliases = new GrowthAliases(diskByIdAliases.Identity, stableNames, diskByIdAliases.Snapshots.Concat(stableAliases.Snapshots));
        if (!stableAliases.HasById)
        {
            return new VolumeGrowthRejected($"Block device {nodes.Device} identity [{stableNames}] must include a by-id/ identifier.");
        }

        if (!string.Equals(MountTable.CanonicalVolumeIdentity(stableAliases), expectedVolumeIdentity, StringComparison.Ordinal))
        {
            return new VolumeGrowthRejected($"Block device {nodes.Device} stable names [{stableNames}] do not carry the single expected volume identity [{expectedVolumeIdentity}].");
        }

        if (MountTable.IsOciDeviceAlias(attachedDevice))
        {
            if (!string.Equals(LinuxPathResolver.TryResolve(attachedDevice), nodes.DiskPath, StringComparison.Ordinal)
                || MountTable.TryReadBlockDeviceStatxIdentity(attachedDevice, followSymlinks: true) != nodes.DiskStatx)
            {
                return new VolumeGrowthRejected($"Block device {nodes.Device} on disk {nodes.Disk} is not the OCI attachment {attachedDevice}.");
            }

            return MountTable.FindOciDevice(nodes) switch
            {
                OciDeviceFound found when string.Equals(found.Path, attachedDevice, StringComparison.Ordinal) =>
                    VerifyDiscoveredOciDevice(dedicated, nodes, aliases.With(found.Snapshots), mountPath, found.Path),
                OciDeviceFound found => new VolumeGrowthRejected(
                    $"OCI attachment {attachedDevice} for {mountPath} does not match the unique OCI device alias {found.Path} of {nodes.DiskPath}."),
                OciDeviceAbsent => new VolumeGrowthRejected(
                    $"OCI attachment {attachedDevice} for {mountPath} is not a unique OCI device alias of {nodes.DiskPath}."),
                DirectoryScanFailed failed => new VolumeGrowthRejected(failed.Message),
            };
        }

        if (!string.Equals(attachedDevice, nodes.DiskPath, StringComparison.Ordinal)
            || !string.Equals(LinuxPathResolver.TryResolve(attachedDevice), nodes.DiskPath, StringComparison.Ordinal)
            || MountTable.TryReadBlockDeviceStatxIdentity(attachedDevice, followSymlinks: false) != nodes.DiskStatx)
        {
            return new VolumeGrowthRejected(
                $"OCI attachment {attachedDevice} for {mountPath} must be a /dev/oracleoci alias or the canonical block disk {nodes.DiskPath} itself.");
        }

        return MountTable.FindOciDevice(nodes) switch
        {
            OciDeviceFound found => VerifyDiscoveredOciDevice(dedicated, nodes, aliases.With(found.Snapshots), mountPath, found.Path),
            OciDeviceAbsent absent => BuildGrowthDevice(dedicated, nodes, aliases.With(absent.Snapshots), mountPath, effectiveOciDevice: null),
            DirectoryScanFailed failed => new VolumeGrowthRejected(failed.Message),
        };
    }

    private static VolumeGrowthTarget VerifyDiscoveredOciDevice(
        DedicatedBlockMount dedicated,
        VerifiedBlockNodes nodes,
        GrowthAliases aliases,
        string mountPath,
        string discoveredOciDevice)
    {
        if (!string.Equals(LinuxPathResolver.TryResolve(discoveredOciDevice), nodes.DiskPath, StringComparison.Ordinal)
            || MountTable.TryReadBlockDeviceStatxIdentity(discoveredOciDevice, followSymlinks: true) != nodes.DiskStatx)
        {
            return new VolumeGrowthRejected($"OCI attachment path {discoveredOciDevice} for {mountPath} changed while inspecting {nodes.Device}.");
        }

        return BuildGrowthDevice(dedicated, nodes, aliases, mountPath, discoveredOciDevice);
    }

    private static VolumeGrowthTarget BuildGrowthDevice(
        DedicatedBlockMount dedicated,
        VerifiedBlockNodes nodes,
        GrowthAliases aliases,
        string mountPath,
        string? effectiveOciDevice)
    {
        if (MountTable.FindChangedVolumeBinding(dedicated, nodes, mountPath, aliases.Snapshots) is { } changed)
        {
            return new VolumeGrowthRejected(changed);
        }

        var identity = new BlockVolumeIdentity(
            nodes.Device,
            nodes.DeviceMajorMinor,
            aliases.StableNames,
            aliases.DiskByIdNames,
            dedicated.MountId,
            dedicated.MountInode,
            nodes.DiskStatx.StatSignature,
            nodes.DeviceStatx.StatSignature,
            effectiveOciDevice);
        return new GrowthDevice(dedicated.Mount, nodes.Disk, nodes.DiskMajorMinor, nodes.Partition, identity);
    }

    private async Task<VolumeGrowth> GrowDeviceAsync(
        string nodeId,
        string mountPath,
        GrowthDevice device,
        BlockVolumeIdentity expected,
        CancellationToken cancellationToken)
    {
        if (!MountTable.IsGrowableFilesystem(device.Mount.FileSystem))
        {
            return new VolumeGrowthRejected($"File system {device.Mount.FileSystem} on {mountPath} cannot be grown online.");
        }

        var (mode, tool) = device.Mount.FileSystem switch
        {
            "ext2" or "ext3" or "ext4" => ("resize_device", "resize2fs"),
            "xfs" => ("resize_mount", "xfs_growfs"),
            _ => throw new UnreachableException($"Unexpected growable filesystem {device.Mount.FileSystem}."),
        };

        var outcome = await RunPrivateVolumeToolAsync(mode, mountPath, device, expected, tool, cancellationToken);
        return outcome switch
        {
            ProcessOutput { ExitCode: 0 } output => CompletePrivateResize(nodeId, mountPath, output.Stdout),
            ProcessOutput { ExitCode: PrivateMountMismatchExitCode } output => new VolumeGrowthRejected(output.Stderr.Trim()),
            ProcessOutput output => new VolumeGrowthFailed($"Growing {device.Mount.FileSystem} on {mountPath} failed with {output.ExitCode}: {output.Stderr.Trim()}"),
            MaintenanceToolTimedOut failure => failure,
            MaintenanceToolUnavailable failure => failure,
        };
    }

    private async Task<ProcessExecution> RunPrivateVolumeToolAsync(
        string mode,
        string mountPath,
        GrowthDevice device,
        BlockVolumeIdentity expected,
        string tool,
        CancellationToken cancellationToken)
    {
        if (!MountTable.TryParseMajorMinor(device.DiskMajorMinor, out _, out _)
            || !MountTable.TryParseMajorMinor(expected.DeviceNumber, out var partMajor, out var partMinor))
        {
            return new ProcessOutput(PrivateMountMismatchExitCode, string.Empty, $"Block device for {mountPath} is missing valid kernel major:minor numbers.");
        }

        var partName = Path.GetFileName(expected.Device);
        if (device.Disk.Length == 0 || partName.Length == 0)
        {
            return new ProcessOutput(PrivateMountMismatchExitCode, string.Empty, $"Block device name for {mountPath} is invalid.");
        }

        if (EnsurePrivateMountStageDirectory() is { } stageError)
        {
            return new ProcessOutput(1, string.Empty, stageError);
        }

        if (ResolveSysfsHelperInvocation() is not { } helper)
        {
            return new ProcessOutput(1, string.Empty, "The ts-orch executable for in-namespace sysfs helpers cannot be resolved.");
        }

        var attachedArgument = expected.OciDevice is { } attached ? attached : string.Empty;
        var partitionArgument = device.Partition is { } partitionNumber ? partitionNumber : string.Empty;
        string[] arguments =
        [
            "--mount",
            "--propagation",
            "private",
            "--",
            "sh",
            "-eu",
            "-c",
            VolumeGrowthScript.PrivateMountVolumeScript,
            "_",
            mode,
            mountPath,
            MountTable.EscapeMountField(mountPath),
            MountTable.EncodeLinuxDeviceId(partMajor, partMinor).ToString(CultureInfo.InvariantCulture),
            device.Mount.FileSystem,
            PrivateMountStageDirectory,
            Environment.ProcessId.ToString(CultureInfo.InvariantCulture),
            expected.MountId.ToString(CultureInfo.InvariantCulture),
            device.Disk,
            device.DiskMajorMinor,
            expected.DiskNodeSignature,
            expected.DiskByIdNames,
            partName,
            expected.DeviceNumber,
            expected.PartitionNodeSignature,
            expected.StableNames,
            attachedArgument,
            partitionArgument,
            tool,
            expected.MountInode.ToString(CultureInfo.InvariantCulture),
            helper.Executable,
            helper.EntryAssembly,
        ];
        return await ProcessRunner.RunAsync("unshare", arguments, ToolTimeout, timeProvider, cancellationToken);
    }

    private static SysfsHelperInvocation? ResolveSysfsHelperInvocation()
    {
        if (Environment.ProcessPath is not { } executable || !Path.IsPathFullyQualified(executable))
        {
            return null;
        }

        if (!string.Equals(Path.GetFileName(executable), DotnetHostName, StringComparison.Ordinal))
        {
            return new SysfsHelperInvocation(executable, string.Empty);
        }

        return Environment.GetCommandLineArgs() is [var entryAssembly, ..]
            && Path.IsPathFullyQualified(entryAssembly)
            && entryAssembly.EndsWith(".dll", StringComparison.Ordinal)
            && File.Exists(entryAssembly)
                ? new SysfsHelperInvocation(executable, entryAssembly)
                : null;
    }

    private static string? EnsurePrivateMountStageDirectory()
    {
        if (LinuxInterop.MakeDirectory(PrivateMountStageDirectory, PrivateMountDirectoryMode) != 0)
        {
            var error = Marshal.GetLastPInvokeError();
            if (error != LinuxInterop.ErrorExists)
            {
                return string.Create(CultureInfo.InvariantCulture, $"Creating private mount stage directory {PrivateMountStageDirectory} failed (errno {error}: {Marshal.GetPInvokeErrorMessage(error)}).");
            }
        }

        return MountTable.IsOwnedPrivateDirectory(PrivateMountStageDirectory, PrivateMountDirectoryMode)
            ? null
            : $"Private mount stage directory {PrivateMountStageDirectory} must be a 0700 directory owned by the agent process.";
    }

    private VolumeGrowth CompletePrivateResize(string nodeId, string mountPath, string stdout)
    {
        if (!TryParseStatFsTotalGiB(stdout, out var size))
        {
            return new VolumeGrowthFailed($"Measuring {mountPath} in private namespace failed: missing or invalid statfs output.");
        }

        AgentLog.VolumeGrown(logger, mountPath, size);
        return new VolumeGrown(nodeId, mountPath, size);
    }

    private static bool TryParseStatFsTotalGiB(string stdout, out int sizeGiB)
    {
        sizeGiB = 0;
        string? markerLine = null;
        foreach (var rawLine in stdout.Split('\n'))
        {
            var trimmed = rawLine.Trim();
            if (trimmed.Length > 0)
            {
                markerLine = trimmed;
            }
        }

        if (markerLine is null || !markerLine.StartsWith(StatFsMarkerPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        var fields = markerLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length != 4
            || !ulong.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var blocks)
            || !ulong.TryParse(fields[2], NumberStyles.None, CultureInfo.InvariantCulture, out var blockSize)
            || !ulong.TryParse(fields[3], NumberStyles.None, CultureInfo.InvariantCulture, out _)
            || blocks == 0
            || blockSize == 0)
        {
            return false;
        }

        var gib = (double)blocks * blockSize / BytesPerGiB;
        if (!double.IsFinite(gib) || gib < 0d || gib > int.MaxValue)
        {
            return false;
        }

        sizeGiB = (int)Math.Round(gib);
        return true;
    }
}
