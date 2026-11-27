using System.Buffers;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace TsOrch.Agent;

public readonly record struct SysfsDirectoryIdentity(uint DevMajor, uint DevMinor, ulong Inode, ulong MountId);

public readonly record struct SysfsBlockBinding(string Name, SysfsDirectoryIdentity Directory);

public static partial class MountTable
{
    private const string SysClassBlockDirectory = "/sys/class/block";
    private const string SysDevBlockDirectory = "/sys/dev/block";
    private const string SysfsMountDirectory = "/sys";
    internal const string SysfsIndexMountPoints = "/sys/block|/sys/class|/sys/class/block|/sys/dev|/sys/dev/block";
    private static readonly string[] SysfsIndexMountPointPaths = SysfsIndexMountPoints.Split('|');
    private static ReadOnlySpan<byte> PartitionAttributeName => "partition\0"u8;
    private static ReadOnlySpan<byte> DevAttributeName => "dev\0"u8;
    private const string SysfsDeviceDirectoryPrefix = "/sys/devices/";
    private const string RescanAttributeName = "rescan";
    private static ReadOnlySpan<byte> SysfsMountPath => "/sys\0"u8;
    private static ReadOnlySpan<byte> ParentDirectoryName => "..\0"u8;
    private static ReadOnlySpan<byte> RescanCommand => "1\n"u8;
    private static ReadOnlySpan<byte> DeviceDirectoryName => "device\0"u8;
    private static ReadOnlySpan<byte> RescanAttributeFileName => "rescan\0"u8;

    private sealed record class PartitionNumber(string Number, string Disk, string DiskMajorMinor);

    private sealed record class PartitionAttribute(string Number);

    private readonly union PartitionAttributeRead(PartitionAttribute, WholeDisk, PartitionProbeFailed);

    private readonly record struct SysfsAttributeLocation(string Directory, byte[] Name);

    private sealed record class WholeDisk;

    private sealed record class PartitionDevMismatch(string? Found);

    private sealed record class PartitionProbeFailed(string Message);

    private readonly union PartitionProbe(PartitionNumber, WholeDisk, PartitionDevMismatch, PartitionProbeFailed);

    private readonly record struct SysfsDirectoryDescriptor(int Descriptor);

    private sealed record class SysfsDirectoryRejected(string Message);

    private sealed record class SysfsDirectoryMissing(string Message);

    private readonly union SysfsDirectoryOpen(SysfsDirectoryDescriptor, SysfsDirectoryMissing, SysfsDirectoryRejected);

    private readonly record struct SysfsAttributeIdentity(uint DevMajor, uint DevMinor, ulong Inode, ulong MountId);

    private sealed record class SysfsAttributeText(string Text, SysfsAttributeIdentity Identity);

    private sealed record class SysfsAttributeAbsent;

    private sealed record class SysfsAttributeRejected(string Message);

    private readonly union SysfsAttributeRead(SysfsAttributeText, SysfsAttributeAbsent, SysfsAttributeRejected);

    private readonly union SysfsAttributeInspection(SysfsAttributeIdentity, SysfsAttributeRejected);

    public static string? TryResolveBlockDevice(string? majorMinor) =>
        TryResolveSysfsBlock(majorMinor) is { } binding ? $"/dev/{binding.Name}" : null;

    public static SysfsBlockBinding? TryResolveSysfsBlock(string? majorMinor)
    {
        if (string.IsNullOrEmpty(majorMinor) || !TryParseMajorMinor(majorMinor, out _, out _))
        {
            return null;
        }

        var sysDevBlock = $"{SysDevBlockDirectory}/{majorMinor}";
        var opened = OpenSysfsBlockDirectory(sysDevBlock);
        return opened switch
        {
            SysfsDirectoryDescriptor directory => ResolveSysfsBlockAndClose(sysDevBlock, directory.Descriptor, majorMinor),
            SysfsDirectoryMissing => null,
            SysfsDirectoryRejected => null,
        };
    }

    public static string? FindChangedSysfsBinding(VerifiedBlockNodes nodes)
    {
        ArgumentNullException.ThrowIfNull(nodes);
        if (TryResolveSysfsBlock(nodes.DeviceMajorMinor) != nodes.DeviceSysfs)
        {
            return $"{SysDevBlockDirectory}/{nodes.DeviceMajorMinor}";
        }

        return TryResolveSysfsBlock(nodes.DiskMajorMinor) != nodes.DiskSysfs
            ? $"{SysDevBlockDirectory}/{nodes.DiskMajorMinor}"
            : null;
    }

    public static string? FindRescanHazard(VerifiedBlockNodes nodes)
    {
        ArgumentNullException.ThrowIfNull(nodes);
        var classBlock = $"{SysClassBlockDirectory}/{nodes.DiskSysfs.Name}";
        var opened = OpenSysfsBlockDirectory(classBlock);
        return opened switch
        {
            SysfsDirectoryDescriptor directory => FindRescanHazardAndClose(classBlock, directory.Descriptor, nodes.DiskSysfs.Directory),
            SysfsDirectoryMissing missing => missing.Message,
            SysfsDirectoryRejected rejected => rejected.Message,
        };
    }

    private static string? FindRescanHazardAndClose(string classBlock, int disk, SysfsDirectoryIdentity expected)
    {
        try
        {
            if (ReadBoundSysfsDirectory(classBlock, disk) != expected || ReadCanonicalSysfsDevicePath(disk) is not { } canonical)
            {
                return $"{classBlock} is not the verified disk directory on the {SysfsMountDirectory} mount.";
            }

            return FindDeviceRescanHazard(classBlock, disk, canonical, expected.MountId)
                ?? (ReadBoundSysfsDirectory(classBlock, disk) == expected ? null : $"{classBlock} changed while inspecting its rescan attribute.");
        }
        finally
        {
            _ = LinuxInterop.Close(disk);
        }
    }

    private static string? FindDeviceRescanHazard(string classBlock, int disk, string canonical, ulong sysfsMountId)
    {
        var entry = LinuxInterop.OpenAt(disk, DeviceDirectoryName, LinuxInterop.NoFollowPathOpenFlags);
        if (entry < 0)
        {
            var error = Marshal.GetLastPInvokeError();
            return error == LinuxInterop.ErrorNotFound && AreSysfsBlockIndexesUncovered(canonical)
                ? null
                : SysfsError($"Probing {classBlock}/device on an uncovered {SysfsMountDirectory} mount", error);
        }

        _ = LinuxInterop.Close(entry);
        var device = LinuxInterop.OpenAt(
            disk,
            DeviceDirectoryName,
            LinuxInterop.OpenReadOnly | LinuxInterop.OpenNonBlock | LinuxInterop.OpenDirectoryFlag | LinuxInterop.OpenCloseOnExec);
        if (device < 0)
        {
            return SysfsError($"Opening {classBlock}/device on an uncovered {SysfsMountDirectory} mount", Marshal.GetLastPInvokeError());
        }

        try
        {
            if (!IsSysfsDescriptor(device)
                || ReadSysfsDirectoryIdentity(device, "\0"u8, LinuxInterop.AtEmptyPath) is not { } identity
                || identity.MountId != sysfsMountId
                || ReadCanonicalSysfsDevicePath(device) is not { } devicePath)
            {
                return $"{classBlock}/device is not a directory on the {SysfsMountDirectory} mount.";
            }

            if (!AreSysfsBlockIndexesUncovered(devicePath))
            {
                return $"Sysfs device directory {devicePath} of {classBlock} is covered by another mount.";
            }

            var rescan = InspectRescanAttribute(device, devicePath, canonical, sysfsMountId);
            return rescan ?? (AreSysfsBlockIndexesUncovered(devicePath) ? null : $"Sysfs device directory {devicePath} of {classBlock} became covered by another mount.");
        }
        finally
        {
            _ = LinuxInterop.Close(device);
        }
    }

    private static string? InspectRescanAttribute(int device, string devicePath, string canonical, ulong sysfsMountId)
    {
        var rescanPath = $"{devicePath}/{RescanAttributeName}";
        var pathFd = LinuxInterop.OpenAt(device, RescanAttributeFileName, LinuxInterop.NoFollowPathOpenFlags);
        if (pathFd < 0)
        {
            var error = Marshal.GetLastPInvokeError();
            return error == LinuxInterop.ErrorNotFound ? null : SysfsError($"Pinning {rescanPath}", error);
        }

        try
        {
            return InspectSysfsAttribute(rescanPath, pathFd, sysfsMountId) switch
            {
                SysfsAttributeIdentity when !string.Equals(canonical, $"{devicePath}/block/{Path.GetFileName(canonical)}", StringComparison.Ordinal) =>
                    $"{rescanPath} does not sit beside the block directory {canonical}.",
                SysfsAttributeIdentity => null,
                SysfsAttributeRejected rejected => rejected.Message,
            };
        }
        finally
        {
            _ = LinuxInterop.Close(pathFd);
        }
    }

    private static SysfsBlockBinding? ResolveSysfsBlockAndClose(string sysDevBlock, int directory, string majorMinor)
    {
        try
        {
            if (!AreSysfsBlockIndexesUncovered(null)
                || ReadBoundSysfsDirectory(sysDevBlock, directory) is not { } opened
                || ReadCanonicalSysfsDevicePath(directory) is not { } canonical
                || Path.GetFileName(canonical) is not { Length: > 0 } name)
            {
                return null;
            }

            var classBlock = $"{SysClassBlockDirectory}/{name}";
            if (ReadBoundSysfsClassDirectory(classBlock) != opened)
            {
                return null;
            }

            var dev = ReadSysfsDevAt(sysDevBlock, directory, opened.MountId);
            return string.Equals(dev, majorMinor, StringComparison.Ordinal)
                && ReadBoundSysfsDirectory(sysDevBlock, directory) == opened
                && ReadBoundSysfsClassDirectory(classBlock) == opened
                && AreSysfsBlockIndexesUncovered(canonical)
                ? new SysfsBlockBinding(name, opened)
                : null;
        }
        finally
        {
            _ = LinuxInterop.Close(directory);
        }
    }

    private static SysfsDirectoryIdentity? ReadBoundSysfsClassDirectory(string classBlock) =>
        ReadSysfsDirectoryIdentity(LinuxInterop.AtFdCwd, Encoding.UTF8.GetBytes($"{classBlock}\0"), 0) is { } identity
        && ReadSysfsDirectoryIdentity(LinuxInterop.AtFdCwd, SysfsMountPath, 0) is { } mount
        && identity.MountId == mount.MountId
        && identity.DevMajor == mount.DevMajor
        && identity.DevMinor == mount.DevMinor
            ? identity
            : null;

    private static bool AreSysfsBlockIndexesUncovered(string? deviceDirectory) =>
        ReadSysfsDirectoryIdentity(LinuxInterop.AtFdCwd, SysfsMountPath, 0) is { } mount
        && SysfsIndexMountPointPaths.All(path => IsOnSysfsMount(Encoding.UTF8.GetBytes($"{path}\0"), mount))
        && TryRead() switch
        {
            IReadOnlyList<MountEntry> mounts => SatisfiesSysfsMountPolicy(mounts, mount.MountId, deviceDirectory),
            MountTableReadFailed => false,
        };

    private static bool SatisfiesSysfsMountPolicy(IReadOnlyList<MountEntry> mounts, ulong sysfsMountId, string? deviceDirectory) =>
        mounts.Where(static entry => string.Equals(entry.MountPoint, SysfsMountDirectory, StringComparison.Ordinal)).ToList()
            is [{ FileSystem: "sysfs", FsRoot: "/" } root]
        && root.MountId == sysfsMountId
        && !mounts.Any(entry => SysfsIndexMountPointPaths.Contains(entry.MountPoint, StringComparer.Ordinal)
            || CoversSysfsDevice(entry.MountPoint, deviceDirectory));

    private static bool CoversSysfsDevice(string mountPoint, string? deviceDirectory) =>
        deviceDirectory is not null
        && mountPoint.StartsWith($"{SysfsMountDirectory}/", StringComparison.Ordinal)
        && (string.Equals(mountPoint, deviceDirectory, StringComparison.Ordinal)
            || deviceDirectory.StartsWith($"{mountPoint}/", StringComparison.Ordinal)
            || mountPoint.StartsWith($"{deviceDirectory}/", StringComparison.Ordinal));

    private static bool IsOnSysfsMount(ReadOnlySpan<byte> path, SysfsDirectoryIdentity mount) =>
        ReadSysfsDirectoryIdentity(LinuxInterop.AtFdCwd, path, LinuxInterop.AtSymlinkNoFollow) is { } identity
        && identity.MountId == mount.MountId
        && identity.DevMajor == mount.DevMajor
        && identity.DevMinor == mount.DevMinor;

    private static string? ReadSysfsDevAt(string sysBlock, int directory, ulong directoryMountId)
    {
        var read = ReadSysfsAttribute(directory, directoryMountId, $"{sysBlock}/dev", DevAttributeName);
        return read switch
        {
            SysfsAttributeText value when value.Text.Length > 0 => value.Text,
            SysfsAttributeText => null,
            SysfsAttributeAbsent => null,
            SysfsAttributeRejected => null,
        };
    }

    private static PartitionProbe ProbePartition(string sysBlock, string expectedMajorMinor)
    {
        var opened = OpenSysfsBlockDirectory(sysBlock);
        return opened switch
        {
            SysfsDirectoryDescriptor directory => ProbeOpenedPartition(sysBlock, directory.Descriptor, expectedMajorMinor),
            SysfsDirectoryMissing missing => new PartitionProbeFailed(missing.Message),
            SysfsDirectoryRejected rejected => new PartitionProbeFailed(rejected.Message),
        };
    }

    private static PartitionProbe ProbeOpenedPartition(string sysBlock, int directory, string expectedMajorMinor)
    {
        try
        {
            var bound = ReadBoundSysfsDirectory(sysBlock, directory);
            if (bound is not { } opened)
            {
                return new PartitionProbeFailed($"{sysBlock} is not bound to one directory on the {SysfsMountDirectory} mount.");
            }

            var devBefore = ReadSysfsDevAt(sysBlock, directory, opened.MountId);
            if (!string.Equals(devBefore, expectedMajorMinor, StringComparison.Ordinal))
            {
                return new PartitionDevMismatch(devBefore);
            }

            var probe = ReadPartitionAt(sysBlock, directory, opened.MountId) switch
            {
                PartitionAttribute partition => ResolvePartitionParent(sysBlock, directory, opened, partition.Number),
                WholeDisk whole => whole,
                PartitionProbeFailed failed => failed,
            };
            var devAfter = ReadSysfsDevAt(sysBlock, directory, opened.MountId);
            if (!string.Equals(devAfter, expectedMajorMinor, StringComparison.Ordinal))
            {
                return new PartitionDevMismatch(devAfter);
            }

            return ReadBoundSysfsDirectory(sysBlock, directory) == opened
                ? probe
                : new PartitionProbeFailed($"{sysBlock} changed while probing its partition attribute.");
        }
        finally
        {
            _ = LinuxInterop.Close(directory);
        }
    }

    private static PartitionProbe ResolvePartitionParent(string sysBlock, int partitionDirectory, SysfsDirectoryIdentity partition, string number)
    {
        var parent = LinuxInterop.OpenAt(
            partitionDirectory,
            ParentDirectoryName,
            LinuxInterop.OpenReadOnly | LinuxInterop.OpenNonBlock | LinuxInterop.OpenDirectoryFlag | LinuxInterop.OpenCloseOnExec);
        if (parent < 0)
        {
            return new PartitionProbeFailed(SysfsError($"Opening the parent directory of {sysBlock}", Marshal.GetLastPInvokeError()));
        }

        try
        {
            return ProbePartitionParent(sysBlock, parent, partition, number);
        }
        finally
        {
            _ = LinuxInterop.Close(parent);
        }
    }

    private static PartitionProbe ProbePartitionParent(string sysBlock, int parent, SysfsDirectoryIdentity partition, string number)
    {
        if (!IsSysfsDescriptor(parent)
            || ReadSysfsDirectoryIdentity(parent, "\0"u8, LinuxInterop.AtEmptyPath) is not { } parentIdentity
            || parentIdentity.MountId != partition.MountId
            || parentIdentity.DevMajor != partition.DevMajor
            || parentIdentity.DevMinor != partition.DevMinor)
        {
            return new PartitionProbeFailed($"The parent directory of {sysBlock} is not on the {SysfsMountDirectory} mount.");
        }

        var partitionName = Encoding.UTF8.GetBytes($"{Path.GetFileName(sysBlock)}\0");
        if (ReadSysfsDirectoryIdentity(parent, partitionName, LinuxInterop.AtSymlinkNoFollow) != partition)
        {
            return new PartitionProbeFailed($"The parent directory of {sysBlock} does not hold the probed partition directory.");
        }

        if (ReadCanonicalSysfsDevicePath(parent) is not { } parentPath
            || Path.GetFileName(parentPath) is not { Length: > 0 } disk
            || ReadSysfsDirectoryIdentity(LinuxInterop.AtFdCwd, Encoding.UTF8.GetBytes($"{SysClassBlockDirectory}/{disk}\0"), 0) != parentIdentity)
        {
            return new PartitionProbeFailed($"The parent directory of {sysBlock} is not a {SysClassBlockDirectory} disk.");
        }

        var wholeDisk = ReadPartitionAt(parentPath, parent, parentIdentity.MountId) switch
        {
            WholeDisk => true,
            PartitionAttribute => false,
            PartitionProbeFailed => false,
        };
        var diskDev = ReadSysfsDevAt(parentPath, parent, parentIdentity.MountId);
        return wholeDisk && diskDev is { } verifiedDev && ReadSysfsDirectoryIdentity(parent, partitionName, LinuxInterop.AtSymlinkNoFollow) == partition
            ? new PartitionNumber(number, disk, verifiedDev)
            : new PartitionProbeFailed($"The parent disk {parentPath} of {sysBlock} could not be verified.");
    }

    private static PartitionAttributeRead ReadPartitionAt(string sysBlock, int directory, ulong directoryMountId)
    {
        var path = $"{sysBlock}/partition";
        var read = ReadSysfsAttribute(directory, directoryMountId, path, PartitionAttributeName);
        return read switch
        {
            SysfsAttributeText value when uint.TryParse(value.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed > 0 =>
                new PartitionAttribute(value.Text),
            SysfsAttributeText => new PartitionProbeFailed($"Cannot read the partition number from {path}."),
            SysfsAttributeAbsent => new WholeDisk(),
            SysfsAttributeRejected rejected => new PartitionProbeFailed(rejected.Message),
        };
    }

    private static SysfsDirectoryIdentity? ReadBoundSysfsDirectory(string sysBlock, int directory)
    {
        if (!IsSysfsDescriptor(directory)
            || ReadSysfsDirectoryIdentity(directory, "\0"u8, LinuxInterop.AtEmptyPath) is not { } opened
            || ReadSysfsDirectoryIdentity(LinuxInterop.AtFdCwd, Encoding.UTF8.GetBytes($"{sysBlock}\0"), 0) is not { } live
            || ReadSysfsDirectoryIdentity(LinuxInterop.AtFdCwd, SysfsMountPath, 0) is not { } mount)
        {
            return null;
        }

        return opened == live && opened.MountId == mount.MountId && opened.DevMajor == mount.DevMajor && opened.DevMinor == mount.DevMinor
            ? opened
            : null;
    }

    private static SysfsDirectoryIdentity? ReadSysfsDirectoryIdentity(int directory, ReadOnlySpan<byte> path, int flags)
    {
        Span<byte> buffer = stackalloc byte[LinuxInterop.StatxBufferSize];
        const uint mask = LinuxInterop.StatxType | LinuxInterop.StatxIno | LinuxInterop.StatxMountId;
        if (LinuxInterop.StatxAt(directory, path, flags | LinuxInterop.AtStatxDontSync, mask, buffer) != 0
            || (MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxMaskOffset..]) & mask) != mask
            || (MemoryMarshal.Read<ushort>(buffer[LinuxInterop.StatxModeOffset..]) & LinuxInterop.FileTypeMask) != LinuxInterop.DirectoryType)
        {
            return null;
        }

        return new SysfsDirectoryIdentity(
            MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxDevMajorOffset..]),
            MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxDevMinorOffset..]),
            MemoryMarshal.Read<ulong>(buffer[LinuxInterop.StatxInoOffset..]),
            MemoryMarshal.Read<ulong>(buffer[LinuxInterop.StatxMountIdOffset..]));
    }

    private static SysfsDirectoryOpen OpenSysfsBlockDirectory(string path)
    {
        if (!OperatingSystem.IsLinux())
        {
            return new SysfsDirectoryRejected($"Sysfs block directory {path} can only be opened on Linux.");
        }

        var directory = LinuxInterop.Open(
            path,
            LinuxInterop.OpenReadOnly | LinuxInterop.OpenNonBlock | LinuxInterop.OpenDirectoryFlag | LinuxInterop.OpenCloseOnExec);
        if (directory < 0)
        {
            var error = Marshal.GetLastPInvokeError();
            var message = SysfsError($"Opening {path}", error);
            return error == LinuxInterop.ErrorNotFound ? new SysfsDirectoryMissing(message) : new SysfsDirectoryRejected(message);
        }

        if (IsSysfsDescriptor(directory))
        {
            return new SysfsDirectoryDescriptor(directory);
        }

        _ = LinuxInterop.Close(directory);
        return new SysfsDirectoryRejected($"{path} is not a sysfs directory.");
    }

    private static SysfsAttributeRead ReadSysfsAttribute(int directory, ulong directoryMountId, string path, ReadOnlySpan<byte> name)
    {
        var pathFd = LinuxInterop.OpenAt(directory, name, LinuxInterop.NoFollowPathOpenFlags);
        if (pathFd < 0)
        {
            var error = Marshal.GetLastPInvokeError();
            return error == LinuxInterop.ErrorNotFound
                ? new SysfsAttributeAbsent()
                : new SysfsAttributeRejected(SysfsError($"Pinning {path}", error));
        }

        try
        {
            var pinned = InspectSysfsAttribute(path, pathFd, directoryMountId);
            return pinned switch
            {
                SysfsAttributeIdentity identity => ReadPinnedSysfsAttribute(path, pathFd, identity, directoryMountId),
                SysfsAttributeRejected rejected => rejected,
            };
        }
        finally
        {
            _ = LinuxInterop.Close(pathFd);
        }
    }

    private static SysfsAttributeRead ReadPinnedSysfsAttribute(string path, int pathFd, SysfsAttributeIdentity pinned, ulong directoryMountId)
    {
        var fd = LinuxInterop.Open(
            string.Create(CultureInfo.InvariantCulture, $"/proc/self/fd/{pathFd}"),
            LinuxInterop.OpenReadOnly | LinuxInterop.OpenNonBlock | LinuxInterop.OpenCloseOnExec);
        if (fd < 0)
        {
            return new SysfsAttributeRejected(SysfsError($"Opening pinned {path}", Marshal.GetLastPInvokeError()));
        }

        try
        {
            var opened = InspectSysfsAttribute(path, fd, directoryMountId);
            return opened switch
            {
                SysfsAttributeIdentity identity when identity == pinned => TryReadTrimmedFd(fd) is { } text
                    ? new SysfsAttributeText(text, identity)
                    : new SysfsAttributeRejected($"Reading {path} failed."),
                SysfsAttributeIdentity => new SysfsAttributeRejected($"{path} changed between pinning and opening."),
                SysfsAttributeRejected rejected => rejected,
            };
        }
        finally
        {
            _ = LinuxInterop.Close(fd);
        }
    }

    private static SysfsAttributeInspection InspectSysfsAttribute(string path, int fd, ulong directoryMountId)
    {
        Span<byte> buffer = stackalloc byte[LinuxInterop.StatxBufferSize];
        const uint mask = LinuxInterop.StatxType | LinuxInterop.StatxIno | LinuxInterop.StatxMountId;
        if (LinuxInterop.StatxAt(fd, "\0"u8, LinuxInterop.AtEmptyPath | LinuxInterop.AtStatxDontSync, mask, buffer) != 0)
        {
            return new SysfsAttributeRejected(SysfsError($"Inspecting {path}", Marshal.GetLastPInvokeError()));
        }

        if ((MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxMaskOffset..]) & mask) != mask
            || (MemoryMarshal.Read<ushort>(buffer[LinuxInterop.StatxModeOffset..]) & LinuxInterop.FileTypeMask) != LinuxInterop.RegularFileType)
        {
            return new SysfsAttributeRejected($"{path} is not a regular file.");
        }

        if (!IsSysfsDescriptor(fd))
        {
            return new SysfsAttributeRejected($"{path} is not a sysfs attribute.");
        }

        var mountId = MemoryMarshal.Read<ulong>(buffer[LinuxInterop.StatxMountIdOffset..]);
        if (mountId != directoryMountId)
        {
            return new SysfsAttributeRejected($"{path} is not on the mount of its sysfs block directory.");
        }

        return new SysfsAttributeIdentity(
            MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxDevMajorOffset..]),
            MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxDevMinorOffset..]),
            MemoryMarshal.Read<ulong>(buffer[LinuxInterop.StatxInoOffset..]),
            mountId);
    }

    private static bool IsSysfsDescriptor(int fd)
    {
        Span<byte> buffer = stackalloc byte[LinuxInterop.StatFsBufferSize];
        return LinuxInterop.FStatFs(fd, buffer) == 0
            && MemoryMarshal.Read<long>(buffer[LinuxInterop.StatFsTypeOffset..]) == LinuxInterop.SysfsMagic;
    }

    private static string? TryReadTrimmedFd(int fd)
    {
        Span<byte> buffer = stackalloc byte[128];
        var read = LinuxInterop.Read(fd, buffer, (nuint)buffer.Length);
        return read > 0 ? Encoding.UTF8.GetString(buffer[..(int)read]).Trim() : null;
    }

    private static string? ReadCanonicalSysfsDevicePath(int fd)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(LinuxInterop.PathMax);
        try
        {
            var length = LinuxInterop.ReadLink(string.Create(CultureInfo.InvariantCulture, $"/proc/self/fd/{fd}"), buffer, LinuxInterop.PathMax);
            if (length <= 0 || length >= LinuxInterop.PathMax)
            {
                return null;
            }

            var path = Encoding.UTF8.GetString(buffer, 0, (int)length);
            return path.StartsWith(SysfsDeviceDirectoryPrefix, StringComparison.Ordinal) && IsCanonicalAbsolutePath(path) ? path : null;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static bool IsCanonicalAbsolutePath(string path) =>
        path.Length > 1
        && path[0] == '/'
        && !path.EndsWith('/')
        && !path.Contains("//", StringComparison.Ordinal)
        && !path.Contains("/./", StringComparison.Ordinal)
        && !path.Contains("/../", StringComparison.Ordinal)
        && !path.EndsWith("/.", StringComparison.Ordinal)
        && !path.EndsWith("/..", StringComparison.Ordinal)
        && path.All(static character => character > ' ' && character != '\x7f');

    private static SysfsAttributeLocation? LocateSysfsAttribute(string path)
    {
        if (!path.StartsWith($"{SysfsMountDirectory}/", StringComparison.Ordinal) || !IsCanonicalAbsolutePath(path))
        {
            return null;
        }

        var slash = path.LastIndexOf('/');
        return new SysfsAttributeLocation(path[..slash], Encoding.UTF8.GetBytes($"{path[(slash + 1)..]}\0"));
    }

    private static string FormatSysfsIdentity(SysfsAttributeIdentity identity) =>
        string.Create(CultureInfo.InvariantCulture, $"{identity.DevMajor}:{identity.DevMinor}|{identity.Inode}|{identity.MountId}");

    public static SysfsHelperRead ReadSysfsAttributePath(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (LocateSysfsAttribute(path) is not { } location)
        {
            return new SysfsHelperRejected($"{path} is not a canonical absolute {SysfsMountDirectory} attribute path.");
        }

        var opened = OpenSysfsBlockDirectory(location.Directory);
        return opened switch
        {
            SysfsDirectoryDescriptor directory => ReadSysfsAttributePathAndClose(path, location, directory.Descriptor),
            SysfsDirectoryMissing => new SysfsHelperAbsent(),
            SysfsDirectoryRejected rejected => new SysfsHelperRejected(rejected.Message),
        };
    }

    private static SysfsHelperRead ReadSysfsAttributePathAndClose(string path, SysfsAttributeLocation location, int directory)
    {
        try
        {
            if (ReadBoundSysfsDirectory(location.Directory, directory) is not { } opened || ReadCanonicalSysfsDevicePath(directory) is null)
            {
                return new SysfsHelperRejected($"{location.Directory} is not one {SysfsDeviceDirectoryPrefix} directory on the {SysfsMountDirectory} mount.");
            }

            var result = ToHelperRead(path, ReadSysfsAttribute(directory, opened.MountId, path, location.Name));
            return ReadBoundSysfsDirectory(location.Directory, directory) == opened
                ? result
                : new SysfsHelperRejected($"{location.Directory} changed while reading {path}.");
        }
        finally
        {
            _ = LinuxInterop.Close(directory);
        }
    }

    private static SysfsHelperRead ToHelperRead(string path, SysfsAttributeRead read) =>
        read switch
        {
            SysfsAttributeText value when value.Text.All(static character => character > ' ' && character != '\x7f') =>
                new SysfsHelperValue(FormatSysfsIdentity(value.Identity), value.Text),
            SysfsAttributeText => new SysfsHelperRejected($"{path} does not hold one token."),
            SysfsAttributeAbsent => new SysfsHelperAbsent(),
            SysfsAttributeRejected rejected => new SysfsHelperRejected(rejected.Message),
        };

    public static SysfsRescanWrite WriteSysfsRescan(string path, SysfsRescanTarget target)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (LocateSysfsAttribute(path) is not { } location || !path.EndsWith($"/{RescanAttributeName}", StringComparison.Ordinal))
        {
            return new SysfsHelperRejected($"{path} is not a canonical absolute {SysfsMountDirectory} rescan attribute path.");
        }

        var opened = OpenSysfsBlockDirectory(location.Directory);
        return opened switch
        {
            SysfsDirectoryDescriptor directory => WriteSysfsRescanAndClose(path, target, location, directory.Descriptor),
            SysfsDirectoryMissing missing => new SysfsHelperRejected(missing.Message),
            SysfsDirectoryRejected rejected => new SysfsHelperRejected(rejected.Message),
        };
    }

    private static SysfsRescanWrite WriteSysfsRescanAndClose(string path, SysfsRescanTarget target, SysfsAttributeLocation location, int directory)
    {
        try
        {
            if (ReadBoundSysfsDirectory(location.Directory, directory) is not { } opened
                || ReadCanonicalSysfsDevicePath(directory) is not { } canonical
                || !string.Equals($"{canonical}/{RescanAttributeName}", target.CanonicalPath, StringComparison.Ordinal))
            {
                return new SysfsHelperRejected($"{location.Directory} is not the {SysfsMountDirectory} directory of {target.CanonicalPath}.");
            }

            var written = WriteRescanAt(path, target, directory, opened.MountId, location.Name);
            return ReadBoundSysfsDirectory(location.Directory, directory) == opened
                ? written
                : new SysfsHelperRejected($"{location.Directory} changed while writing {path}.");
        }
        finally
        {
            _ = LinuxInterop.Close(directory);
        }
    }

    private static SysfsRescanWrite WriteRescanAt(string path, SysfsRescanTarget target, int directory, ulong directoryMountId, byte[] name)
    {
        var pathFd = LinuxInterop.OpenAt(directory, name, LinuxInterop.NoFollowPathOpenFlags);
        if (pathFd < 0)
        {
            return new SysfsHelperRejected(SysfsError($"Pinning {path}", Marshal.GetLastPInvokeError()));
        }

        try
        {
            var pinned = InspectSysfsAttribute(path, pathFd, directoryMountId);
            return pinned switch
            {
                SysfsAttributeIdentity identity when !IsRescanTarget(identity, target) => new SysfsHelperRejected(
                    string.Create(CultureInfo.InvariantCulture, $"{path} is {FormatSysfsIdentity(identity)}, not the verified rescan attribute dev={target.Device} ino={target.Inode}.")),
                SysfsAttributeIdentity when !string.Equals(ReadCanonicalSysfsDevicePath(pathFd), target.CanonicalPath, StringComparison.Ordinal) =>
                    new SysfsHelperRejected($"{path} does not resolve to {target.CanonicalPath}."),
                SysfsAttributeIdentity identity => WritePinnedRescan(path, pathFd, identity, directoryMountId),
                SysfsAttributeRejected rejected => new SysfsHelperRejected(rejected.Message),
            };
        }
        finally
        {
            _ = LinuxInterop.Close(pathFd);
        }
    }

    private static bool IsRescanTarget(SysfsAttributeIdentity identity, SysfsRescanTarget target) =>
        identity.Inode == target.Inode && EncodeDevice(identity.DevMajor, identity.DevMinor) == target.Device;

    private static ulong EncodeDevice(uint major, uint minor) =>
        ((ulong)(major & 0xfffff000u) << 32)
        | ((ulong)(major & 0xfffu) << 8)
        | ((ulong)(minor & 0xffffff00u) << 12)
        | (minor & 0xffu);

    private static SysfsRescanWrite WritePinnedRescan(string path, int pathFd, SysfsAttributeIdentity pinned, ulong directoryMountId)
    {
        var fd = LinuxInterop.Open(
            string.Create(CultureInfo.InvariantCulture, $"/proc/self/fd/{pathFd}"),
            LinuxInterop.OpenWriteOnly | LinuxInterop.OpenNonBlock | LinuxInterop.OpenCloseOnExec);
        if (fd < 0)
        {
            return new SysfsHelperRejected(SysfsError($"Opening pinned {path} for writing", Marshal.GetLastPInvokeError()));
        }

        try
        {
            var opened = InspectSysfsAttribute(path, fd, directoryMountId);
            return opened switch
            {
                SysfsAttributeIdentity identity when identity == pinned => WriteRescanCommand(path, fd),
                SysfsAttributeIdentity => new SysfsHelperRejected($"{path} changed between pinning and opening."),
                SysfsAttributeRejected rejected => new SysfsHelperRejected(rejected.Message),
            };
        }
        finally
        {
            _ = LinuxInterop.Close(fd);
        }
    }

    private static SysfsRescanWrite WriteRescanCommand(string path, int fd)
    {
        var written = LinuxInterop.Write(fd, RescanCommand, (nuint)RescanCommand.Length);
        if (written < 0)
        {
            return new SysfsHelperRejected(SysfsError($"Writing {path}", Marshal.GetLastPInvokeError()));
        }

        return written == RescanCommand.Length ? new SysfsRescanWritten() : new SysfsHelperRejected($"Writing {path} was short.");
    }

    private static string SysfsError(string action, int error) =>
        string.Create(CultureInfo.InvariantCulture, $"{action} failed (errno {error}: {Marshal.GetPInvokeErrorMessage(error)}).");
}
