using System.Buffers;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace TsOrch.Agent;

public sealed record class MountEntry(
    string Device,
    string MountPoint,
    string FileSystem,
    string? MajorMinor = null,
    ulong? MountId = null,
    string? FsRoot = null,
    bool IsReadOnly = false);

public sealed record class MountTableReadFailed(string Message);

public readonly union MountTableRead(IReadOnlyList<MountEntry>, MountTableReadFailed);

public sealed record class DedicatedBlockMount(MountEntry Mount, ulong MountId, ulong MountInode, string MajorMinor, string Device);

public sealed record class DedicatedBlockMountMissing(string Message);

public sealed record class DedicatedBlockMountInconsistent(string Message);

public readonly union DedicatedBlockMountResolution(DedicatedBlockMount, DedicatedBlockMountMissing, DedicatedBlockMountInconsistent);

public sealed record class DirectoryMissing;

public sealed record class DirectoryOpenFailed(string Message);

public readonly union DirectoryOpenResult(SafeFileHandle, DirectoryMissing, DirectoryOpenFailed);

public readonly record struct PathMountIdentity(string MajorMinor, ulong? MountId, ulong? Inode = null);

public readonly record struct DirectoryMountSnapshot(PathMountIdentity Identity, ulong TotalBlocks, ulong AvailableBlocks, ulong BlockSize)
{
    public double TotalBytes => (double)TotalBlocks * BlockSize;

    public double UsedPct =>
        TotalBlocks == 0 || AvailableBlocks >= TotalBlocks
            ? 0d
            : 100d * (TotalBlocks - AvailableBlocks) / TotalBlocks;
}

public static partial class MountTable
{
    public const string MountInfoFile = "/proc/self/mountinfo";
    private const int ProcReadBufferSize = 8192;

    private readonly union ProcFileRead(string, MountTableReadFailed);

    public static bool IsGrowableFilesystem(string fileSystem) =>
        fileSystem is "ext2" or "ext3" or "ext4" or "xfs";

    public static bool IsNormalizedMountPath(string mountPath) =>
        !string.IsNullOrWhiteSpace(mountPath) && !mountPath.Contains('\0', StringComparison.Ordinal)
        && Path.IsPathFullyQualified(mountPath) && Path.GetFullPath(mountPath) == mountPath.TrimEnd('/');

    public static DedicatedBlockMountResolution ResolveDedicatedBlockMount(
        IReadOnlyList<MountEntry> mounts,
        string mountPath,
        PathMountIdentity? pathIdentity)
    {
        ArgumentNullException.ThrowIfNull(mounts);
        if (!IsNormalizedMountPath(mountPath))
        {
            return new DedicatedBlockMountMissing($"No dedicated block device is mounted at {mountPath}.");
        }

        if (ReadNoFollowMountWalk(mountPath) is not { Identity: { MountId: not null, Inode: not null } snapshot } walk)
        {
            return SymlinkedMountPath(mountPath);
        }

        if (snapshot != pathIdentity)
        {
            return new DedicatedBlockMountInconsistent($"Mount path {mountPath} changed before inspecting {MountInfoFile}.");
        }

        return ResolveSymlinkFreeBlockMount(mounts, mountPath, snapshot) switch
        {
            DedicatedBlockMountMissing when !walk.IsUnchanged(ReadNoFollowMountWalk(mountPath)) =>
                new DedicatedBlockMountInconsistent($"Mount path {mountPath} or one of its ancestors changed while confirming it has no dedicated block mount."),
            DedicatedBlockMountMissing missing => missing,
            DedicatedBlockMount dedicated => dedicated,
            DedicatedBlockMountInconsistent inconsistent => inconsistent,
        };
    }

    private sealed record class NoFollowMountWalk(PathMountIdentity Identity, IReadOnlyList<DirectoryNodeIdentity> Ancestors)
    {
        public bool IsUnchanged(NoFollowMountWalk? live) =>
            live is not null && live.Identity == Identity && live.Ancestors.SequenceEqual(Ancestors);
    }

    private static NoFollowMountWalk? ReadNoFollowMountWalk(string mountPath)
    {
        if (!OperatingSystem.IsLinux())
        {
            return null;
        }

        var opened = OpenDirectoryNoFollow(mountPath);
        return opened switch
        {
            NoFollowDirectoryDescriptor directory => ReadDescriptorMountIdentity(directory.Descriptor) is { } identity
                ? new NoFollowMountWalk(identity, directory.Ancestors)
                : null,
            DirectoryNodeAbsent => null,
            DirectoryScanFailed => null,
        };
    }

    private static PathMountIdentity? ReadDescriptorMountIdentity(int descriptor)
    {
        Span<byte> buffer = stackalloc byte[LinuxInterop.StatxBufferSize];
        var read = LinuxInterop.Statx(
            descriptor,
            string.Empty,
            LinuxInterop.AtEmptyPath | LinuxInterop.AtStatxDontSync,
            LinuxInterop.StatxType | LinuxInterop.StatxIno | LinuxInterop.StatxMountId,
            buffer);
        _ = LinuxInterop.Close(descriptor);
        return read == 0
            ? ReadMountIdentityFromBuffer(buffer, MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxMaskOffset..]))
            : null;
    }

    private static DedicatedBlockMountInconsistent SymlinkedMountPath(string mountPath) =>
        new($"Mount path {mountPath} is missing, has a symbolic link or non-directory path component, or lacks statx mount id and inode metadata.");

    private static DedicatedBlockMountResolution ResolveSymlinkFreeBlockMount(
        IReadOnlyList<MountEntry> mounts,
        string mountPath,
        PathMountIdentity? pathIdentity)
    {
        if (pathIdentity is not { MountId: { } pathMountId, Inode: { } mountInode } identity)
        {
            return new DedicatedBlockMountInconsistent($"Mount path {mountPath} is missing kernel mount id or inode metadata from statx.");
        }

        if (TryReadMountIdentity(mountPath) is not { } liveIdentity
            || liveIdentity.MountId != pathMountId
            || liveIdentity.Inode != mountInode
            || !string.Equals(liveIdentity.MajorMinor, identity.MajorMinor, StringComparison.Ordinal))
        {
            return new DedicatedBlockMountInconsistent($"Mount path {mountPath} changed while inspecting {MountInfoFile}.");
        }

        var mount = FindContaining(mounts, pathMountId);
        if (mount is null)
        {
            return new DedicatedBlockMountInconsistent($"Mount table changed while inspecting {mountPath}.");
        }

        if (mount.MountId is not { } mountId)
        {
            return new DedicatedBlockMountInconsistent($"Mount entry for {mountPath} is missing kernel mount id from {MountInfoFile}.");
        }

        if (mountId != pathMountId)
        {
            return new DedicatedBlockMountInconsistent(string.Create(CultureInfo.InvariantCulture, $"Mount path {mountPath} reports mount id {pathMountId} instead of {mountId}."));
        }

        if (mount.MountPoint != mountPath || !mount.Device.StartsWith("/dev/", StringComparison.Ordinal))
        {
            return new DedicatedBlockMountMissing($"No dedicated block device is mounted at {mountPath}.");
        }

        if (!string.Equals(mount.FsRoot, "/", StringComparison.Ordinal))
        {
            return new DedicatedBlockMountMissing($"Mount entry for {mountPath} mounts filesystem subpath {mount.FsRoot ?? "unknown"} instead of /.");
        }

        if (mount.MajorMinor is not { } mountMajorMinor)
        {
            return new DedicatedBlockMountInconsistent($"Mount entry for {mountPath} is missing kernel major:minor from {MountInfoFile}.");
        }

        if (!string.Equals(identity.MajorMinor, mountMajorMinor, StringComparison.Ordinal))
        {
            return new DedicatedBlockMountInconsistent($"Mount path {mountPath} reports device {identity.MajorMinor} instead of {mountMajorMinor}.");
        }

        if (TryResolveBlockDevice(mountMajorMinor) is not { } device)
        {
            return new DedicatedBlockMountInconsistent($"Mounted block device {mountMajorMinor} for {mountPath} could not be resolved via /sys/dev/block.");
        }

        var parentPath = Path.GetDirectoryName(mountPath);
        if (string.IsNullOrEmpty(parentPath))
        {
            return new DedicatedBlockMountMissing($"Mount path {mountPath} has no parent directory.");
        }

        if (TryReadMountIdentity(parentPath) is not { } parentIdentity)
        {
            return new DedicatedBlockMountInconsistent($"Inspecting parent mount path {parentPath} for {mountPath} failed.");
        }

        if (string.Equals(parentIdentity.MajorMinor, mountMajorMinor, StringComparison.Ordinal))
        {
            return new DedicatedBlockMountMissing($"Mount path {mountPath} shares its block device {mountMajorMinor} with parent {parentPath}.");
        }

        return new DedicatedBlockMount(mount, mountId, mountInode, mountMajorMinor, device);
    }

    public static string? FindChangedLiveBinding(DedicatedBlockMount dedicated, VerifiedBlockNodes nodes, string mountPath)
    {
        ArgumentNullException.ThrowIfNull(dedicated);
        ArgumentNullException.ThrowIfNull(nodes);
        if (!IsExactLiveMount(dedicated, mountPath)
            || !HasExactMountInfoEntry(dedicated, mountPath)
            || !IsExactLiveMount(dedicated, mountPath))
        {
            return $"Mount path {mountPath} changed while inspecting its block volume.";
        }

        if (FindChangedBlockNode(nodes) is { } changedNode)
        {
            return $"Block device node {changedNode} changed or disappeared while inspecting the block volume behind {mountPath}.";
        }

        if (FindChangedSysfsBinding(nodes) is { } changedSysfs)
        {
            return $"Sysfs block directory {changedSysfs} changed or disappeared while inspecting the block volume behind {mountPath}.";
        }

        return FindRescanHazard(nodes) is { } rescanHazard
            ? $"The rescan attribute of the block volume behind {mountPath} cannot be written safely: {rescanHazard}"
            : null;
    }

    public static string? FindChangedVolumeBinding(
        DedicatedBlockMount dedicated,
        VerifiedBlockNodes nodes,
        string mountPath,
        DirectorySnapshots directories)
    {
        if (FindChangedDirectory(directories) is { } changedBefore)
        {
            return $"{changedBefore} changed while inspecting the block volume behind {mountPath}.";
        }

        if (FindChangedLiveBinding(dedicated, nodes, mountPath) is { } changedBeforeScan)
        {
            return changedBeforeScan;
        }

        if (FindChangedDirectory(directories) is { } changedAfter)
        {
            return $"{changedAfter} changed while inspecting the block volume behind {mountPath}.";
        }

        return FindChangedLiveBinding(dedicated, nodes, mountPath);
    }

    private static bool IsExactLiveMount(DedicatedBlockMount dedicated, string mountPath) =>
        string.Equals(LinuxPathResolver.TryResolve(mountPath), mountPath, StringComparison.Ordinal)
        && ReadMountIdentity(mountPath, LinuxInterop.AtSymlinkNoFollow | LinuxInterop.AtStatxDontSync) is { } live
        && live.MountId == dedicated.MountId
        && live.Inode == dedicated.MountInode
        && string.Equals(live.MajorMinor, dedicated.MajorMinor, StringComparison.Ordinal);

    private static bool HasExactMountInfoEntry(DedicatedBlockMount dedicated, string mountPath) =>
        TryRead() switch
        {
            IReadOnlyList<MountEntry> mounts => mounts.Count(entry => entry.MountId == dedicated.MountId) == 1
                && mounts.Any(entry => entry.MountId == dedicated.MountId
                    && string.Equals(entry.MountPoint, mountPath, StringComparison.Ordinal)
                    && string.Equals(entry.MajorMinor, dedicated.MajorMinor, StringComparison.Ordinal)
                    && string.Equals(entry.FsRoot, "/", StringComparison.Ordinal)
                    && entry.IsReadOnly == dedicated.Mount.IsReadOnly
                    && string.Equals(entry.Device, dedicated.Mount.Device, StringComparison.Ordinal)),
            MountTableReadFailed => false,
        };

    public static bool IsOwnedPrivateDirectory(string path, uint expectedMode)
    {
        if (!OperatingSystem.IsLinux() || string.IsNullOrEmpty(path))
        {
            return false;
        }

        Span<byte> buffer = stackalloc byte[LinuxInterop.StatxBufferSize];
        if (LinuxInterop.Statx(
                LinuxInterop.AtFdCwd,
                path,
                LinuxInterop.AtSymlinkNoFollow | LinuxInterop.AtStatxDontSync,
                LinuxInterop.StatxType | LinuxInterop.StatxMode | LinuxInterop.StatxUid,
                buffer) != 0)
        {
            return false;
        }

        var mask = MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxMaskOffset..]);
        var mode = MemoryMarshal.Read<ushort>(buffer[LinuxInterop.StatxModeOffset..]);
        var uid = MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxUidOffset..]);
        return (mask & (LinuxInterop.StatxType | LinuxInterop.StatxMode | LinuxInterop.StatxUid))
                == (LinuxInterop.StatxType | LinuxInterop.StatxMode | LinuxInterop.StatxUid)
            && (mode & LinuxInterop.FileTypeMask) == LinuxInterop.DirectoryType
            && (mode & LinuxInterop.PermissionModeMask) == expectedMode
            && uid == LinuxInterop.GetEffectiveUid();
    }

    public static DirectoryOpenResult OpenDirectoryReadOnly(string path)
    {
        if (!OperatingSystem.IsLinux())
        {
            return new DirectoryOpenFailed("Linux directory inspection requires Linux.");
        }

        if (string.IsNullOrEmpty(path))
        {
            return new DirectoryMissing();
        }

        while (true)
        {
            var fd = LinuxInterop.Open(
                path,
                LinuxInterop.OpenReadOnly | LinuxInterop.OpenCloseOnExec | LinuxInterop.OpenNonBlock | LinuxInterop.OpenDirectoryFlag);
            if (fd >= 0)
            {
                return new SafeFileHandle((nint)fd, ownsHandle: true);
            }

            var openError = Marshal.GetLastPInvokeError();
            if (openError == LinuxInterop.ErrorInterrupted)
            {
                continue;
            }

            return openError == LinuxInterop.ErrorNotFound && IsConfirmedAbsentDirectory(path)
                ? new DirectoryMissing()
                : new DirectoryOpenFailed(string.Create(CultureInfo.InvariantCulture, $"Opening {path} failed (errno {openError}: {Marshal.GetPInvokeErrorMessage(openError)})."));
        }
    }

    public static DirectoryMountSnapshot? TryReadDirectoryMountSnapshot(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (!OperatingSystem.IsLinux())
        {
            return null;
        }

        Span<byte> statxBuffer = stackalloc byte[LinuxInterop.StatxBufferSize];
        if (LinuxInterop.StatxHandle(
                handle,
                string.Empty,
                LinuxInterop.AtEmptyPath,
                LinuxInterop.StatxType | LinuxInterop.StatxIno | LinuxInterop.StatxMountId,
                statxBuffer) != 0)
        {
            return null;
        }

        var mask = MemoryMarshal.Read<uint>(statxBuffer[LinuxInterop.StatxMaskOffset..]);
        var mode = MemoryMarshal.Read<ushort>(statxBuffer[LinuxInterop.StatxModeOffset..]);
        if ((mask & LinuxInterop.StatxType) == 0 || (mode & LinuxInterop.FileTypeMask) != LinuxInterop.DirectoryType)
        {
            return null;
        }

        Span<byte> vfsBuffer = stackalloc byte[LinuxInterop.StatVfsBufferSize];
        if (LinuxInterop.FStatVfs(handle, vfsBuffer) != 0)
        {
            return null;
        }

        var bsize = MemoryMarshal.Read<ulong>(vfsBuffer[LinuxInterop.StatVfsBlockSizeOffset..]);
        var frsize = MemoryMarshal.Read<ulong>(vfsBuffer[LinuxInterop.StatVfsFragmentSizeOffset..]);
        var identity = ReadMountIdentityFromBuffer(statxBuffer, mask);
        return new DirectoryMountSnapshot(
            identity,
            MemoryMarshal.Read<ulong>(vfsBuffer[LinuxInterop.StatVfsBlocksOffset..]),
            MemoryMarshal.Read<ulong>(vfsBuffer[LinuxInterop.StatVfsBlocksAvailableOffset..]),
            frsize != 0 ? frsize : bsize);
    }

    public static PathMountIdentity? TryReadMountIdentity(string path) =>
        ReadMountIdentity(path, LinuxInterop.AtStatxDontSync);

    private static PathMountIdentity? ReadMountIdentity(string path, int flags)
    {
        if (!OperatingSystem.IsLinux() || string.IsNullOrEmpty(path))
        {
            return null;
        }

        Span<byte> buffer = stackalloc byte[LinuxInterop.StatxBufferSize];
        if (LinuxInterop.Statx(
                LinuxInterop.AtFdCwd,
                path,
                flags,
                LinuxInterop.StatxType | LinuxInterop.StatxIno | LinuxInterop.StatxMountId,
                buffer) != 0)
        {
            return null;
        }

        return ReadMountIdentityFromBuffer(buffer, MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxMaskOffset..]));
    }

    private static PathMountIdentity ReadMountIdentityFromBuffer(ReadOnlySpan<byte> buffer, uint mask)
    {
        var major = MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxDevMajorOffset..]);
        var minor = MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxDevMinorOffset..]);
        ulong? mountId = (mask & LinuxInterop.StatxMountId) != 0 ? MemoryMarshal.Read<ulong>(buffer[LinuxInterop.StatxMountIdOffset..]) : null;
        ulong? inode = (mask & LinuxInterop.StatxIno) != 0 ? MemoryMarshal.Read<ulong>(buffer[LinuxInterop.StatxInoOffset..]) : null;
        return new PathMountIdentity(string.Create(CultureInfo.InvariantCulture, $"{major}:{minor}"), mountId, inode);
    }

    public static string EscapeMountField(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            builder.Append(ch switch
            {
                ' ' => "\\040",
                '\t' => "\\011",
                '\n' => "\\012",
                '\\' => "\\134",
                _ => ch.ToString(),
            });
        }

        return builder.ToString();
    }

    public static MountTableRead TryRead()
    {
        if (!OperatingSystem.IsLinux())
        {
            return new MountTableReadFailed("Linux mount table inspection requires Linux.");
        }

        return ReadProcFile(MountInfoFile) switch
        {
            string content => ParseMountInfo(content.Split('\n')),
            MountTableReadFailed failed => failed,
        };
    }

    private static ProcFileRead ReadProcFile(string path)
    {
        int fd;
        while (true)
        {
            fd = LinuxInterop.Open(path, LinuxInterop.OpenReadOnly | LinuxInterop.OpenCloseOnExec);
            if (fd >= 0)
            {
                break;
            }

            var openError = Marshal.GetLastPInvokeError();
            if (openError == LinuxInterop.ErrorInterrupted)
            {
                continue;
            }

            return new MountTableReadFailed(string.Create(CultureInfo.InvariantCulture, $"Opening {path} failed (errno {openError}: {Marshal.GetPInvokeErrorMessage(openError)})."));
        }

        var buffer = ArrayPool<byte>.Shared.Rent(ProcReadBufferSize);
        try
        {
            using var stream = new MemoryStream();
            while (true)
            {
                var read = LinuxInterop.Read(fd, buffer.AsSpan(0, ProcReadBufferSize), (nuint)ProcReadBufferSize);
                if (read > 0)
                {
                    stream.Write(buffer, 0, (int)read);
                    continue;
                }

                if (read == 0)
                {
                    return Encoding.UTF8.GetString(stream.GetBuffer(), 0, (int)stream.Length);
                }

                var readError = Marshal.GetLastPInvokeError();
                if (readError == LinuxInterop.ErrorInterrupted)
                {
                    continue;
                }

                return new MountTableReadFailed(string.Create(CultureInfo.InvariantCulture, $"Reading {path} failed (errno {readError}: {Marshal.GetPInvokeErrorMessage(readError)})."));
            }
        }
        finally
        {
            _ = LinuxInterop.Close(fd);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static List<MountEntry> ParseMountInfo(string[] lines)
    {
        List<MountEntry> entries = [];
        foreach (var line in lines)
        {
            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 9)
            {
                continue;
            }

            var separator = Array.IndexOf(fields, "-", 6);
            if (separator < 6 || separator + 2 >= fields.Length)
            {
                continue;
            }

            ulong? mountId = ulong.TryParse(fields[0], NumberStyles.None, CultureInfo.InvariantCulture, out var parsedMountId)
                ? parsedMountId
                : null;
            var majorMinor = TryParseMajorMinor(fields[2], out _, out _) ? fields[2] : null;
            var isReadOnly = HasReadOnlyOption(fields[5])
                || (separator + 3 < fields.Length && HasReadOnlyOption(fields[separator + 3]));
            entries.Add(new MountEntry(
                Unescape(fields[separator + 2]),
                Unescape(fields[4]),
                Unescape(fields[separator + 1]),
                majorMinor,
                mountId,
                Unescape(fields[3]),
                isReadOnly));
        }

        return entries;
    }

    private static bool HasReadOnlyOption(string options) =>
        options.Split(',').Contains("ro", StringComparer.Ordinal);

    public static MountEntry? FindContaining(IReadOnlyList<MountEntry> entries, ulong mountId)
    {
        ArgumentNullException.ThrowIfNull(entries);
        return entries.FirstOrDefault(entry => entry.MountId == mountId);
    }

    private static string Unescape(string value)
    {
        if (!value.Contains('\\', StringComparison.Ordinal))
        {
            return value;
        }

        var builder = new StringBuilder(value.Length);
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '\\' && i + 3 < value.Length)
            {
                var decoded = value.AsSpan(i, 4) switch
                {
                    "\\040" => ' ',
                    "\\011" => '\t',
                    "\\012" => '\n',
                    "\\134" => '\\',
                    _ => '\0',
                };
                if (decoded != '\0')
                {
                    builder.Append(decoded);
                    i += 3;
                    continue;
                }
            }

            builder.Append(value[i]);
        }

        return builder.ToString();
    }
}
