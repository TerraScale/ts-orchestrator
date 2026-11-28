using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace TsOrch.Agent;

public readonly record struct BlockDeviceStatxIdentity(string MajorMinor, string StatSignature);

public sealed record class VerifiedBlockNodes(
    string Device,
    string DeviceMajorMinor,
    BlockDeviceStatxIdentity DeviceStatx,
    SysfsBlockBinding DeviceSysfs,
    string Disk,
    string DiskPath,
    string DiskMajorMinor,
    BlockDeviceStatxIdentity DiskStatx,
    SysfsBlockBinding DiskSysfs,
    string? Partition);

public sealed record class BlockNodeValidationRejected(string Message);

public sealed record class BlockNodeValidationFailed(string Message);

public readonly union VerifiedBlockNodeResolution(VerifiedBlockNodes, BlockNodeValidationRejected, BlockNodeValidationFailed);

public sealed record class DirectoryScanFailed(string Directory, string Message);

public sealed class DirectorySnapshots
{
    internal DirectorySnapshots(IReadOnlyList<MountTable.ScannedDirectoryState> states) => States = states;

    public static DirectorySnapshots Empty { get; } = new([]);

    internal IReadOnlyList<MountTable.ScannedDirectoryState> States { get; }

    public DirectorySnapshots Concat(DirectorySnapshots other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return new([.. States, .. other.States]);
    }
}

public sealed record class StableAliasNames(string Identity, bool HasById, DirectorySnapshots Snapshots);

public readonly union StableNamesRead(StableAliasNames, DirectoryScanFailed);

public sealed record class OciDeviceFound(string Path, DirectorySnapshots Snapshots);

public sealed record class OciDeviceAbsent(DirectorySnapshots Snapshots);

public readonly union OciDeviceScan(OciDeviceFound, OciDeviceAbsent, DirectoryScanFailed);

public sealed record class UsableVolumeIdentity(string Identity, DirectorySnapshots Snapshots);

public sealed record class NoUsableVolumeIdentity(DirectorySnapshots Snapshots);

public readonly union UsableVolumeIdentityOutcome(UsableVolumeIdentity, NoUsableVolumeIdentity, DirectoryScanFailed);

public static partial class MountTable
{
    private const string OciDeviceDirectory = "/dev/oracleoci";
    private const string OciDeviceAliasPrefix = OciDeviceDirectory + "/";
    private const string StableIdDirectory = "/dev/disk/by-id";
    private const string StableUuidDirectory = "/dev/disk/by-uuid";
    private const string StableIdPrefix = "by-id/";
    private const string StableUuidPrefix = "by-uuid/";
    private static readonly string[] StableIdDirectories = [StableIdDirectory];
    private static readonly string[] StableNameDirectories = [StableIdDirectory, StableUuidDirectory];
    private static readonly string[] StableParentDirectories = [DevDirectory, "/dev/disk"];

    internal sealed record class ScannedDirectoryState(string Directory, DirectoryNodeIdentity? Identity, DirectoryListing? Listing);

    internal sealed record class NotBlockDevice;

    internal sealed record class BlockDeviceMetadataReadFailed;

    internal readonly union BlockDeviceStatxProbe(BlockDeviceStatxIdentity, NotBlockDevice, BlockDeviceMetadataReadFailed);

    public static VerifiedBlockNodeResolution ResolveVerifiedBlockNodes(DedicatedBlockMount dedicated)
    {
        ArgumentNullException.ThrowIfNull(dedicated);
        var device = dedicated.Device;
        var mountMajorMinor = dedicated.MajorMinor;
        var devName = Path.GetFileName(device);
        var sysBlock = $"{SysClassBlockDirectory}/{devName}";
        if (!Directory.Exists(sysBlock))
        {
            return new BlockNodeValidationRejected($"Block device {device} is not visible under /sys/class/block.");
        }

        var probe = ProbePartition(sysBlock, mountMajorMinor);
        return probe switch
        {
            PartitionNumber partition => VerifyBlockNodes(device, mountMajorMinor, partition.Disk, partition.DiskMajorMinor, partition.Number),
            WholeDisk => VerifyBlockNodes(device, mountMajorMinor, devName, mountMajorMinor, partition: null),
            PartitionDevMismatch mismatch => new BlockNodeValidationRejected(
                $"Block device {device} sysfs dev {mismatch.Found ?? "missing"} does not match mounted {mountMajorMinor}."),
            PartitionProbeFailed failed => new BlockNodeValidationFailed(failed.Message),
        };
    }

    private static VerifiedBlockNodeResolution VerifyBlockNodes(string device, string mountMajorMinor, string disk, string diskMajorMinor, string? partition)
    {
        var rawDiskPath = $"/dev/{disk}";
        if (TryResolveSysfsBlock(diskMajorMinor) is not { } diskSysfs || !string.Equals(diskSysfs.Name, disk, StringComparison.Ordinal))
        {
            return new BlockNodeValidationRejected($"Block disk {rawDiskPath} could not be verified via /sys/dev/block.");
        }

        var wholeDisk = string.Equals(device, rawDiskPath, StringComparison.Ordinal);
        if ((wholeDisk ? diskSysfs : TryResolveSysfsBlock(mountMajorMinor)) is not { } deviceSysfs
            || !string.Equals($"/dev/{deviceSysfs.Name}", device, StringComparison.Ordinal))
        {
            return new BlockNodeValidationRejected($"Block device {device} could not be verified via /sys/dev/block.");
        }

        if (TryReadBlockDeviceStatxIdentity(rawDiskPath) is not { } diskStatx
            || !string.Equals(diskStatx.MajorMinor, diskMajorMinor, StringComparison.Ordinal))
        {
            return new BlockNodeValidationRejected($"Block disk {rawDiskPath} device node metadata does not match {diskMajorMinor}.");
        }

        var deviceStatx = wholeDisk
            ? diskStatx
            : TryReadBlockDeviceStatxIdentity(device);
        if (deviceStatx is not { } verifiedDeviceStatx
            || !string.Equals(verifiedDeviceStatx.MajorMinor, mountMajorMinor, StringComparison.Ordinal))
        {
            return new BlockNodeValidationRejected($"Block device {device} device node metadata does not match {mountMajorMinor}.");
        }

        return new VerifiedBlockNodes(
            device,
            mountMajorMinor,
            verifiedDeviceStatx,
            deviceSysfs,
            disk,
            rawDiskPath,
            diskMajorMinor,
            diskStatx,
            diskSysfs,
            partition);
    }

    public static bool TryParseMajorMinor(ReadOnlySpan<char> value, out uint major, out uint minor)
    {
        major = 0;
        minor = 0;
        var colon = value.IndexOf(':');
        return colon > 0
            && colon < value.Length - 1
            && uint.TryParse(value[..colon], NumberStyles.None, CultureInfo.InvariantCulture, out major)
            && uint.TryParse(value[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out minor);
    }

    public static ulong EncodeLinuxDeviceId(uint major, uint minor) =>
        ((ulong)(major & 0xfffu) << 8)
        | (minor & 0xffu)
        | ((ulong)(minor & ~0xffu) << 12)
        | ((ulong)(major & ~0xfffu) << 32);

    public static BlockDeviceStatxIdentity? TryReadBlockDeviceStatxIdentity(string path, bool followSymlinks = false) =>
        ProbeBlockDeviceStatx(path, followSymlinks) switch
        {
            BlockDeviceStatxIdentity identity => identity,
            NotBlockDevice => null,
            BlockDeviceMetadataReadFailed => null,
        };

    private static BlockDeviceStatxProbe ProbeBlockDeviceStatx(string path, bool followSymlinks)
    {
        if (!OperatingSystem.IsLinux() || string.IsNullOrEmpty(path))
        {
            return new BlockDeviceMetadataReadFailed();
        }

        Span<byte> buffer = stackalloc byte[LinuxInterop.StatxBufferSize];
        var flags = followSymlinks
            ? LinuxInterop.AtStatxDontSync
            : LinuxInterop.AtSymlinkNoFollow | LinuxInterop.AtStatxDontSync;
        if (LinuxInterop.Statx(LinuxInterop.AtFdCwd, path, flags, LinuxInterop.StatxType | LinuxInterop.StatxIno, buffer) != 0)
        {
            return new BlockDeviceMetadataReadFailed();
        }

        return ReadBlockDeviceStatxProbe(buffer);
    }

    private static BlockDeviceStatxProbe ReadBlockDeviceStatxProbe(ReadOnlySpan<byte> buffer)
    {
        var mask = MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxMaskOffset..]);
        if ((mask & (LinuxInterop.StatxType | LinuxInterop.StatxIno)) != (LinuxInterop.StatxType | LinuxInterop.StatxIno))
        {
            return new BlockDeviceMetadataReadFailed();
        }

        var mode = MemoryMarshal.Read<ushort>(buffer[LinuxInterop.StatxModeOffset..]);
        if ((mode & LinuxInterop.FileTypeMask) != LinuxInterop.BlockDeviceType)
        {
            return new NotBlockDevice();
        }

        var devId = EncodeLinuxDeviceId(
            MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxDevMajorOffset..]),
            MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxDevMinorOffset..]));
        var ino = MemoryMarshal.Read<ulong>(buffer[LinuxInterop.StatxInoOffset..]);
        var rdevMajor = MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxRdevMajorOffset..]);
        var rdevMinor = MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxRdevMinorOffset..]);
        return new BlockDeviceStatxIdentity(
            string.Create(CultureInfo.InvariantCulture, $"{rdevMajor}:{rdevMinor}"),
            string.Create(CultureInfo.InvariantCulture, $"{rdevMajor:x}|{rdevMinor:x}|{devId}|{ino}"));
    }

    public static string? FindChangedBlockNode(VerifiedBlockNodes nodes)
    {
        ArgumentNullException.ThrowIfNull(nodes);
        if (TryReadBlockDeviceStatxIdentity(nodes.Device, followSymlinks: false) != nodes.DeviceStatx)
        {
            return nodes.Device;
        }

        return TryReadBlockDeviceStatxIdentity(nodes.DiskPath, followSymlinks: false) != nodes.DiskStatx
            ? nodes.DiskPath
            : null;
    }

    public static bool IsOciDeviceAlias(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (!path.StartsWith(OciDeviceAliasPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        var name = path.AsSpan(OciDeviceAliasPrefix.Length);
        return name.Length > 0 && !name.Contains('/') && name is not "." and not "..";
    }

    public static OciDeviceScan FindOciDevice(VerifiedBlockNodes nodes)
    {
        ArgumentNullException.ThrowIfNull(nodes);
        if (!string.Equals(LinuxPathResolver.TryResolve(nodes.DiskPath), nodes.DiskPath, StringComparison.Ordinal))
        {
            return new DirectoryScanFailed(nodes.DiskPath, $"Resolving canonical path for {nodes.DiskPath} failed.");
        }

        var scan = ReadOciDirectory();
        return scan switch
        {
            OciDirectoryListing listing => MatchOciDevice(listing, nodes.DiskPath, nodes.DiskStatx),
            DirectoryScanFailed failed => failed,
        };
    }

    private static OciDeviceScan MatchOciDevice(
        OciDirectoryListing listing,
        string diskPath,
        BlockDeviceStatxIdentity expectedDiskStatx)
    {
        DirectorySnapshots snapshots = new(
        [
            new ScannedDirectoryState(DevDirectory, listing.Dev, null),
            new ScannedDirectoryState(OciDeviceDirectory, listing.Oci.Identity, listing.Oci),
        ]);
        string? matched = null;
        foreach (var entry in listing.Oci.Entries)
        {
            var link = entry.Path;
            var target = entry.Target switch
            {
                ResolvedEntryTarget resolved => resolved,
                DanglingEntryTarget => null,
            };
            if (target is null)
            {
                return new DirectoryScanFailed(
                    OciDeviceDirectory,
                    $"OCI device alias {link} could not be resolved while matching {diskPath}.");
            }

            if (!string.Equals(target.Path, diskPath, StringComparison.Ordinal))
            {
                var conflict = target.Probe switch
                {
                    BlockDeviceStatxIdentity other => string.Equals(other.MajorMinor, expectedDiskStatx.MajorMinor, StringComparison.Ordinal)
                        ? new DirectoryScanFailed(
                            OciDeviceDirectory,
                            $"Conflicting OCI device alias {link} resolves to {target.Path} with the block numbers {other.MajorMinor} of {diskPath}.")
                        : null,
                    NotBlockDevice => null,
                    BlockDeviceMetadataReadFailed => new DirectoryScanFailed(
                        OciDeviceDirectory,
                        $"OCI device alias {link} metadata could not be read while matching {diskPath}."),
                };
                if (conflict is not null)
                {
                    return conflict;
                }

                continue;
            }

            if (!IsExpectedBlockDevice(target.Probe, expectedDiskStatx))
            {
                return new DirectoryScanFailed(
                    OciDeviceDirectory,
                    $"OCI device alias {link} resolves to {diskPath} but its block identity could not be verified.");
            }

            if (matched is not null)
            {
                return new DirectoryScanFailed(
                    OciDeviceDirectory,
                    $"Multiple OCI device aliases in {OciDeviceDirectory} matched {diskPath} ({matched} and {link}).");
            }

            matched = link;
        }

        if (TryReadBlockDeviceStatxIdentity(diskPath, followSymlinks: false) != expectedDiskStatx)
        {
            return new DirectoryScanFailed(
                diskPath,
                $"Block disk {diskPath} changed while scanning {OciDeviceDirectory}.");
        }

        if (matched is not null
            && (!string.Equals(LinuxPathResolver.TryResolve(matched), diskPath, StringComparison.Ordinal)
                || TryReadBlockDeviceStatxIdentity(matched, followSymlinks: true) != expectedDiskStatx))
        {
            return new DirectoryScanFailed(
                OciDeviceDirectory,
                $"OCI device alias {matched} changed while scanning {OciDeviceDirectory} for {diskPath}.");
        }

        if (FindChangedDirectory(snapshots) is not null)
        {
            return new DirectoryScanFailed(
                OciDeviceDirectory,
                $"{OciDeviceDirectory} changed while scanning it for {diskPath}.");
        }

        if (matched is null)
        {
            return new OciDeviceAbsent(snapshots);
        }

        return new OciDeviceFound(matched, snapshots);
    }

    private static bool IsExpectedBlockDevice(BlockDeviceStatxProbe probe, BlockDeviceStatxIdentity expected) =>
        probe switch
        {
            BlockDeviceStatxIdentity identity => identity == expected,
            NotBlockDevice => false,
            BlockDeviceMetadataReadFailed => false,
        };

    public static StableNamesRead ReadStableNames(string devicePath, BlockDeviceStatxIdentity expectedStatx) =>
        ReadStableDirectoryNames(devicePath, expectedStatx, StableNameDirectories);

    public static StableNamesRead ReadByIdNames(string devicePath, BlockDeviceStatxIdentity expectedStatx) =>
        ReadStableDirectoryNames(devicePath, expectedStatx, StableIdDirectories);

    private static StableNamesRead ReadStableDirectoryNames(
        string devicePath,
        BlockDeviceStatxIdentity expectedStatx,
        string[] directories)
    {
        if (LinuxPathResolver.TryResolve(devicePath) is not { } resolved)
        {
            return new DirectoryScanFailed(devicePath, $"Resolving canonical path for {devicePath} failed.");
        }

        List<ScannedDirectoryState> states = [];
        foreach (var parent in StableParentDirectories)
        {
            var captured = CaptureDirectoryState(parent, states);
            if (captured is not null)
            {
                return captured;
            }
        }

        List<string> names = [];
        foreach (var directory in directories)
        {
            var failure = CollectDirectoryAliases(directory, resolved, expectedStatx, names, states);
            if (failure is not null)
            {
                return failure;
            }
        }

        var unchanged = VerifyStableScanUnchanged(devicePath, resolved, expectedStatx, states);
        if (unchanged is not null)
        {
            return unchanged;
        }

        var hasById = names.Exists(static name => name.StartsWith(StableIdPrefix, StringComparison.Ordinal));
        names.Sort(CompareUtf8Ordinal);
        return new StableAliasNames(string.Join(',', names), hasById, new DirectorySnapshots(states));
    }

    private static DirectoryScanFailed? CaptureDirectoryState(string directory, List<ScannedDirectoryState> states) =>
        ProbeDirectoryNode(directory) switch
        {
            DirectoryNodeIdentity identity => RecordDirectoryState(new ScannedDirectoryState(directory, identity, null), states),
            DirectoryNodeAbsent => RecordDirectoryState(new ScannedDirectoryState(directory, null, null), states),
            DirectoryScanFailed failed => failed,
        };

    private static DirectoryScanFailed? RecordDirectoryState(ScannedDirectoryState state, List<ScannedDirectoryState> states)
    {
        states.Add(state);
        return null;
    }

    private static DirectoryScanFailed? VerifyStableScanUnchanged(
        string devicePath,
        string resolved,
        BlockDeviceStatxIdentity expectedStatx,
        List<ScannedDirectoryState> states)
    {
        foreach (var state in states)
        {
            if (!IsUnchangedDirectoryState(state))
            {
                return new DirectoryScanFailed(state.Directory, $"{state.Directory} changed while collecting stable device names.");
            }
        }

        if (!string.Equals(LinuxPathResolver.TryResolve(devicePath), resolved, StringComparison.Ordinal)
            || TryReadBlockDeviceStatxIdentity(resolved, followSymlinks: false) != expectedStatx)
        {
            return new DirectoryScanFailed(devicePath, $"Block device {devicePath} changed while collecting stable device names.");
        }

        return null;
    }

    public static string? FindChangedDirectory(DirectorySnapshots snapshots)
    {
        ArgumentNullException.ThrowIfNull(snapshots);
        foreach (var state in snapshots.States)
        {
            if (!IsUnchangedDirectoryState(state))
            {
                return state.Directory;
            }
        }

        return null;
    }

    private static bool IsUnchangedDirectoryState(ScannedDirectoryState state) =>
        IsSameDirectoryNode(ProbeDirectoryNode(state.Directory), state.Identity)
        && (state.Listing is not { } listing || IsSameDirectoryListing(state.Directory, listing));

    private static int CompareUtf8Ordinal(string left, string right) =>
        Encoding.UTF8.GetBytes(left).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(right));

    private static string EncodeAliasName(string name) =>
        name.Replace("%", "%25", StringComparison.Ordinal).Replace(",", "%2C", StringComparison.Ordinal);

    private static DirectoryScanFailed? CollectDirectoryAliases(
        string directory,
        string resolved,
        BlockDeviceStatxIdentity expectedStatx,
        List<string> names,
        List<ScannedDirectoryState> states)
    {
        var scan = ReadDirectoryEntryNames(directory);
        return scan switch
        {
            DirectoryListing listing => AppendMatchingAliases(directory, listing.Entries, resolved, expectedStatx, names)
                ?? VerifyDirectoryUnchanged(directory, listing)
                ?? RecordDirectoryState(new ScannedDirectoryState(directory, listing.Identity, listing), states),
            DirectoryScanFailed failed => failed,
        };
    }

    private static DirectoryScanFailed? AppendMatchingAliases(
        string directory,
        IReadOnlyList<DirectoryEntrySnapshot> entries,
        string resolved,
        BlockDeviceStatxIdentity expectedStatx,
        List<string> names)
    {
        foreach (var entry in entries)
        {
            var failure = entry.Target switch
            {
                ResolvedEntryTarget target => ClassifyAlias(directory, entry, target, resolved, expectedStatx, names),
                DanglingEntryTarget => new DirectoryScanFailed(directory, $"Stable device name {entry.Path} could not be resolved."),
            };
            if (failure is not null)
            {
                return failure;
            }
        }

        return null;
    }

    private static DirectoryScanFailed? ClassifyAlias(
        string directory,
        DirectoryEntrySnapshot entry,
        ResolvedEntryTarget target,
        string resolved,
        BlockDeviceStatxIdentity expectedStatx,
        List<string> names) =>
        target.Probe switch
        {
            BlockDeviceStatxIdentity identity when !string.Equals(identity.MajorMinor, expectedStatx.MajorMinor, StringComparison.Ordinal) => null,
            BlockDeviceStatxIdentity identity => AppendVerifiedAlias(directory, entry.Name, entry.Path, target.Path, identity, resolved, expectedStatx, names),
            NotBlockDevice => null,
            BlockDeviceMetadataReadFailed => new DirectoryScanFailed(directory, $"Stable device name {entry.Path} metadata could not be read."),
        };

    private static DirectoryScanFailed? AppendVerifiedAlias(
        string directory,
        string name,
        string link,
        string target,
        BlockDeviceStatxIdentity identity,
        string resolved,
        BlockDeviceStatxIdentity expectedStatx,
        List<string> names)
    {
        if (!string.Equals(target, resolved, StringComparison.Ordinal) || identity != expectedStatx)
        {
            return new DirectoryScanFailed(
                directory,
                $"Conflicting stable device name {link} resolves to {target} with the block numbers {identity.MajorMinor} of {resolved}.");
        }

        if (name.Contains('\n', StringComparison.Ordinal))
        {
            return new DirectoryScanFailed(directory, $"Stable device name {link} contains a newline and cannot be verified.");
        }

        names.Add($"{Path.GetFileName(directory)}/{EncodeAliasName(name)}");
        return null;
    }

    public static bool IsCanonicalVolumeIdentity(string? identity) =>
        identity is not null
        && identity.Length > StableUuidPrefix.Length
        && identity.StartsWith(StableUuidPrefix, StringComparison.Ordinal)
        && !identity.Contains(',', StringComparison.Ordinal);

    public static string? CanonicalVolumeIdentity(StableAliasNames names)
    {
        ArgumentNullException.ThrowIfNull(names);
        string? canonical = null;
        foreach (var segment in names.Identity.Split(','))
        {
            if (!IsCanonicalVolumeIdentity(segment))
            {
                continue;
            }

            if (canonical is not null)
            {
                return null;
            }

            canonical = segment;
        }

        return canonical;
    }

    public static UsableVolumeIdentityOutcome ReadUsableVolumeIdentity(VerifiedBlockNodes nodes)
    {
        ArgumentNullException.ThrowIfNull(nodes);
        return ReadByIdNames(nodes.DiskPath, nodes.DiskStatx) switch
        {
            StableAliasNames diskNames => ReadDeviceVolumeIdentity(nodes, diskNames),
            DirectoryScanFailed failed => failed,
        };
    }

    private static UsableVolumeIdentityOutcome ReadDeviceVolumeIdentity(VerifiedBlockNodes nodes, StableAliasNames diskNames) =>
        ReadStableNames(nodes.Device, nodes.DeviceStatx) switch
        {
            StableAliasNames names when diskNames.HasById && names.HasById && CanonicalVolumeIdentity(names) is { } identity =>
                new UsableVolumeIdentity(identity, diskNames.Snapshots.Concat(names.Snapshots)),
            StableAliasNames names => new NoUsableVolumeIdentity(diskNames.Snapshots.Concat(names.Snapshots)),
            DirectoryScanFailed failed => failed,
        };
}
