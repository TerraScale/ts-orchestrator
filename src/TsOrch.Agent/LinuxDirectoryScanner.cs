using System.Buffers;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Unicode;

namespace TsOrch.Agent;

public static partial class MountTable
{
    private const string DevDirectory = "/dev";
    private const int DirentNameCapacity = 256;
    private const uint DirectoryIdentityMask = LinuxInterop.StatxType | LinuxInterop.StatxIno | LinuxInterop.StatxMountId;
    private static readonly IReadOnlyList<DirectoryEntrySnapshot> EmptyDirectoryEntries = [];

    internal readonly record struct DirectoryNodeIdentity(uint DevMajor, uint DevMinor, ulong Inode, ulong MountId);

    private sealed record class DirectoryNodeAbsent;

    private readonly union DirectoryNodeProbe(DirectoryNodeIdentity, DirectoryNodeAbsent, DirectoryScanFailed);

    internal sealed record class ResolvedEntryTarget(string Path, BlockDeviceStatxProbe Probe);

    internal sealed record class DanglingEntryTarget;

    internal readonly union DirectoryEntryTarget(ResolvedEntryTarget, DanglingEntryTarget);

    internal sealed record class DirectoryEntrySnapshot(string Name, string Path, DirectoryEntryTarget Target);

    internal sealed record class DirectoryListing(DirectoryNodeIdentity? Identity, IReadOnlyList<DirectoryEntrySnapshot> Entries, string EntrySignature);

    private sealed record class CapturedDirectoryEntry(DirectoryEntrySnapshot Snapshot, string Signature);

    private sealed record class CapturedLinkTarget(string Signature, DirectoryEntryTarget Target);

    private readonly union DirectoryEntryScan(DirectoryListing, DirectoryScanFailed);

    private sealed record class OciDirectoryListing(DirectoryNodeIdentity Dev, DirectoryListing Oci);

    private readonly union OciDirectoryScan(OciDirectoryListing, DirectoryScanFailed);

    private readonly record struct NoFollowDirectoryDescriptor(int Descriptor, IReadOnlyList<DirectoryNodeIdentity> Ancestors);

    private readonly union NoFollowDirectoryOpen(NoFollowDirectoryDescriptor, DirectoryNodeAbsent, DirectoryScanFailed);

    private static DirectoryEntryScan ReadDirectoryEntryNames(string directory)
    {
        if (!OperatingSystem.IsLinux())
        {
            return new DirectoryListing(null, EmptyDirectoryEntries, string.Empty);
        }

        return OpenDirectoryNoFollow(directory) switch
        {
            NoFollowDirectoryDescriptor opened => ReadOpenedDescriptor(directory, opened.Descriptor),
            DirectoryNodeAbsent => new DirectoryListing(null, EmptyDirectoryEntries, string.Empty),
            DirectoryScanFailed failed => failed,
        };
    }

    private static NoFollowDirectoryOpen OpenDirectoryNoFollow(string directory)
    {
        if (!directory.StartsWith('/'))
        {
            return new DirectoryScanFailed(directory, $"{directory} is not an absolute path.");
        }

        var components = directory.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (components.Any(static component => component is "." or ".."))
        {
            return new DirectoryScanFailed(directory, $"{directory} contains a relative path component.");
        }

        var flags = LinuxInterop.NoFollowDirectoryOpenFlags;
        var descriptor = OpenAtComponent(LinuxInterop.AtFdCwd, "/\0"u8, flags);
        if (descriptor < 0)
        {
            return OpenComponentFailed(directory, "/", Marshal.GetLastPInvokeError());
        }

        List<DirectoryNodeIdentity> ancestors = [with(capacity: components.Length)];
        foreach (var component in components)
        {
            if (ReadDescriptorIdentity(descriptor) is not { } ancestor)
            {
                _ = LinuxInterop.Close(descriptor);
                return new DirectoryScanFailed(directory, $"Inspecting an ancestor directory of {directory} failed.");
            }

            ancestors.Add(ancestor);
            var next = OpenAtComponent(descriptor, NullTerminated(Encoding.UTF8.GetBytes(component)), flags);
            var error = Marshal.GetLastPInvokeError();
            _ = LinuxInterop.Close(descriptor);
            if (next < 0)
            {
                return error == LinuxInterop.ErrorNotFound
                    ? ConfirmComponentMissing(directory, components, ancestors, flags)
                    : OpenComponentFailed(directory, component, error);
            }

            descriptor = next;
        }

        return new NoFollowDirectoryDescriptor(descriptor, ancestors);
    }

    private static NoFollowDirectoryOpen ConfirmComponentMissing(
        string directory,
        string[] components,
        List<DirectoryNodeIdentity> ancestors,
        int flags)
    {
        var descriptor = OpenAtComponent(LinuxInterop.AtFdCwd, "/\0"u8, flags);
        if (descriptor < 0)
        {
            return OpenComponentFailed(directory, "/", Marshal.GetLastPInvokeError());
        }

        var missing = ancestors.Count - 1;
        for (var index = 0; ; index++)
        {
            var unchanged = ReadDescriptorIdentity(descriptor) == ancestors[index];
            var next = unchanged ? OpenAtComponent(descriptor, NullTerminated(Encoding.UTF8.GetBytes(components[index])), flags) : -1;
            var error = Marshal.GetLastPInvokeError();
            _ = LinuxInterop.Close(descriptor);
            if (index == missing && unchanged && next < 0 && error == LinuxInterop.ErrorNotFound)
            {
                return new DirectoryNodeAbsent();
            }

            if (index == missing || !unchanged || next < 0)
            {
                if (next >= 0)
                {
                    _ = LinuxInterop.Close(next);
                }

                return new DirectoryScanFailed(directory, $"An ancestor of {directory} changed while confirming that {components[missing]} is missing.");
            }

            descriptor = next;
        }
    }

    private static int OpenAtComponent(int directoryDescriptor, ReadOnlySpan<byte> component, int flags)
    {
        while (true)
        {
            var descriptor = LinuxInterop.OpenAt(directoryDescriptor, component, flags);
            if (descriptor >= 0 || Marshal.GetLastPInvokeError() != LinuxInterop.ErrorInterrupted)
            {
                return descriptor;
            }
        }
    }

    private static DirectoryScanFailed OpenComponentFailed(string directory, string component, int error) =>
        new(
            directory,
            string.Create(
                CultureInfo.InvariantCulture,
                $"Opening {directory} at component {component} without following symlinks failed (errno {error}: {Marshal.GetPInvokeErrorMessage(error)})."));

    private static byte[] NullTerminated(ReadOnlySpan<byte> raw) => [.. raw, 0];

    private static DirectoryEntryScan ReadOpenedDescriptor(string directory, int descriptor)
    {
        var handle = LinuxInterop.FdOpenDir(descriptor);
        if (handle == 0)
        {
            var error = Marshal.GetLastPInvokeError();
            _ = LinuxInterop.Close(descriptor);
            return new DirectoryScanFailed(
                directory,
                string.Create(CultureInfo.InvariantCulture, $"Opening a directory stream for {directory} failed (errno {error}: {Marshal.GetPInvokeErrorMessage(error)})."));
        }

        try
        {
            return ReadOpenedDirectory(directory, handle);
        }
        finally
        {
            _ = LinuxInterop.CloseDir(handle);
        }
    }

    private static DirectoryScanFailed? VerifyDirectoryUnchanged(string directory, DirectoryListing listing) =>
        IsSameDirectoryListing(directory, listing)
            ? null
            : new DirectoryScanFailed(directory, $"{directory} changed while collecting stable device names.");

    private static bool IsSameDirectoryListing(string directory, DirectoryListing expected) =>
        ReadDirectoryEntryNames(directory) switch
        {
            DirectoryListing current => current.Identity == expected.Identity
                && string.Equals(current.EntrySignature, expected.EntrySignature, StringComparison.Ordinal),
            DirectoryScanFailed => false,
        };

    private static OciDirectoryScan ReadOciDirectory()
    {
        if (!OperatingSystem.IsLinux())
        {
            return new DirectoryScanFailed(OciDeviceDirectory, $"{OciDeviceDirectory} can only be scanned on Linux.");
        }

        var dev = ProbeDirectoryNode(DevDirectory);
        return dev switch
        {
            DirectoryNodeIdentity identity => BindOciListing(identity, ReadDirectoryEntryNames(OciDeviceDirectory)),
            DirectoryNodeAbsent => new DirectoryScanFailed(DevDirectory, $"{DevDirectory} is missing."),
            DirectoryScanFailed failed => failed,
        };
    }

    private static OciDirectoryScan BindOciListing(DirectoryNodeIdentity dev, DirectoryEntryScan scan) =>
        scan switch
        {
            DirectoryListing listing => new OciDirectoryListing(dev, listing),
            DirectoryScanFailed failed => failed,
        };

    private static bool IsSameDirectoryNode(DirectoryNodeProbe probe, DirectoryNodeIdentity? expected) =>
        probe switch
        {
            DirectoryNodeIdentity identity => identity == expected,
            DirectoryNodeAbsent => expected is null,
            DirectoryScanFailed => false,
        };

    private static DirectoryNodeProbe ProbeDirectoryNode(string directory) =>
        OpenDirectoryNoFollow(directory) switch
        {
            NoFollowDirectoryDescriptor opened => ProbeOpenedDirectoryNode(directory, opened.Descriptor),
            DirectoryNodeAbsent absent => absent,
            DirectoryScanFailed failed => failed,
        };

    private static DirectoryNodeProbe ProbeOpenedDirectoryNode(string directory, int descriptor)
    {
        try
        {
            return ReadDescriptorIdentity(descriptor) is { } identity
                ? identity
                : new DirectoryScanFailed(directory, $"Inspecting the opened directory {directory} failed.");
        }
        finally
        {
            _ = LinuxInterop.Close(descriptor);
        }
    }

    private static DirectoryNodeIdentity? ReadDescriptorIdentity(int descriptor)
    {
        Span<byte> buffer = stackalloc byte[LinuxInterop.StatxBufferSize];
        return LinuxInterop.Statx(
                descriptor,
                string.Empty,
                LinuxInterop.AtEmptyPath | LinuxInterop.AtStatxDontSync,
                DirectoryIdentityMask,
                buffer) == 0
            ? ReadDirectoryNodeIdentity(buffer)
            : null;
    }

    private static DirectoryNodeIdentity? ReadDirectoryNodeIdentity(ReadOnlySpan<byte> buffer)
    {
        var mask = MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxMaskOffset..]);
        if ((mask & DirectoryIdentityMask) != DirectoryIdentityMask
            || (MemoryMarshal.Read<ushort>(buffer[LinuxInterop.StatxModeOffset..]) & LinuxInterop.FileTypeMask) != LinuxInterop.DirectoryType)
        {
            return null;
        }

        return new DirectoryNodeIdentity(
            MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxDevMajorOffset..]),
            MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxDevMinorOffset..]),
            MemoryMarshal.Read<ulong>(buffer[LinuxInterop.StatxInoOffset..]),
            MemoryMarshal.Read<ulong>(buffer[LinuxInterop.StatxMountIdOffset..]));
    }

    private static DirectoryEntryScan ReadOpenedDirectory(string directory, nint handle)
    {
        var descriptor = LinuxInterop.DirFd(handle);
        if (ReadDescriptorIdentity(descriptor) is not { } identity)
        {
            return new DirectoryScanFailed(directory, $"Inspecting the opened directory {directory} failed.");
        }

        List<DirectoryEntrySnapshot> entries = [];
        List<string> entrySignatures = [];
        while (true)
        {
            Marshal.SetLastSystemError(0);
            var entry = LinuxInterop.ReadDir(handle);
            if (entry == 0)
            {
                var readError = Marshal.GetLastPInvokeError();
                if (readError != 0)
                {
                    return new DirectoryScanFailed(
                        directory,
                        string.Create(CultureInfo.InvariantCulture, $"Reading {directory} failed (errno {readError}: {Marshal.GetPInvokeErrorMessage(readError)})."));
                }

                break;
            }

            var raw = ReadDirentName(entry + LinuxInterop.DirentNameOffset);
            if (raw is not { Length: > 0 } or [(byte)'.'] or [(byte)'.', (byte)'.'])
            {
                continue;
            }

            if (!Utf8.IsValid(raw))
            {
                return new DirectoryScanFailed(directory, $"{directory} contains an entry whose name is not valid UTF-8 ({Convert.ToHexString(raw)}).");
            }

            if (CaptureDirectoryEntry(directory, descriptor, raw) is not { } captured)
            {
                return new DirectoryScanFailed(
                    directory,
                    $"Entry {Encoding.UTF8.GetString(raw)} in {directory} could not be inspected without following symlinks.");
            }

            entries.Add(captured.Snapshot);
            entrySignatures.Add(captured.Signature);
        }

        entrySignatures.Sort(StringComparer.Ordinal);
        var live = ProbeDirectoryNode(directory);
        return live switch
        {
            DirectoryNodeIdentity liveIdentity when liveIdentity == identity => new DirectoryListing(identity, entries, string.Join('/', entrySignatures)),
            DirectoryNodeIdentity => new DirectoryScanFailed(directory, $"{directory} was replaced while it was being enumerated."),
            DirectoryNodeAbsent => new DirectoryScanFailed(directory, $"{directory} disappeared while it was being enumerated."),
            DirectoryScanFailed failed => failed,
        };
    }

    private static CapturedDirectoryEntry? CaptureDirectoryEntry(string directory, int directoryDescriptor, byte[] raw)
    {
        var name = NullTerminated(raw);
        Span<byte> buffer = stackalloc byte[LinuxInterop.StatxBufferSize];
        const uint required = LinuxInterop.StatxType | LinuxInterop.StatxMode | LinuxInterop.StatxIno;
        if (LinuxInterop.StatxAt(
                directoryDescriptor,
                name,
                LinuxInterop.AtSymlinkNoFollow | LinuxInterop.AtStatxDontSync,
                required,
                buffer) != 0
            || (MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxMaskOffset..]) & required) != required)
        {
            return null;
        }

        var entryName = Encoding.UTF8.GetString(raw);
        var path = $"{directory}/{entryName}";
        var mode = MemoryMarshal.Read<ushort>(buffer[LinuxInterop.StatxModeOffset..]);
        var isLink = (mode & LinuxInterop.FileTypeMask) == LinuxInterop.SymbolicLinkType;
        var target = isLink ? ReadEntryLinkTarget(directoryDescriptor, name) : "-";
        var resolved = isLink
            ? CaptureLinkTarget(path)
            : new CapturedLinkTarget("-", new ResolvedEntryTarget(path, ReadBlockDeviceStatxProbe(buffer)));
        return target is null || resolved is null
            ? null
            : new CapturedDirectoryEntry(
                new DirectoryEntrySnapshot(entryName, path, resolved.Target),
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{Convert.ToHexString(raw)}:{FormatNodeMetadata(buffer)}:{target}:{resolved.Signature}"));
    }

    private static CapturedLinkTarget? CaptureLinkTarget(string link) =>
        LinuxPathResolver.Resolve(link) switch
        {
            ResolvedLinuxPath resolved => CaptureResolvedNode(resolved.Path),
            MissingLinuxPath => new CapturedLinkTarget("dangling", new DanglingEntryTarget()),
            UnresolvableLinuxPath => null,
        };

    private static CapturedLinkTarget? CaptureResolvedNode(string path)
    {
        Span<byte> buffer = stackalloc byte[LinuxInterop.StatxBufferSize];
        const uint required = LinuxInterop.StatxType | LinuxInterop.StatxMode | LinuxInterop.StatxIno;
        if (LinuxInterop.Statx(
                LinuxInterop.AtFdCwd,
                path,
                LinuxInterop.AtSymlinkNoFollow | LinuxInterop.AtStatxDontSync,
                required,
                buffer) != 0
            || (MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxMaskOffset..]) & required) != required)
        {
            return null;
        }

        return new CapturedLinkTarget(
            $"{Convert.ToHexString(Encoding.UTF8.GetBytes(path))}:{FormatNodeMetadata(buffer)}",
            new ResolvedEntryTarget(path, ReadBlockDeviceStatxProbe(buffer)));
    }

    private static string FormatNodeMetadata(ReadOnlySpan<byte> buffer) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"{MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxDevMajorOffset..])}:{MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxDevMinorOffset..])}:{MemoryMarshal.Read<ulong>(buffer[LinuxInterop.StatxInoOffset..])}:{MemoryMarshal.Read<ushort>(buffer[LinuxInterop.StatxModeOffset..]):x}:{MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxRdevMajorOffset..])}:{MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxRdevMinorOffset..])}");

    private static string? ReadEntryLinkTarget(int directoryDescriptor, byte[] name)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(LinuxInterop.PathMax);
        try
        {
            var length = LinuxInterop.ReadLinkAt(directoryDescriptor, name, buffer.AsSpan(0, LinuxInterop.PathMax), LinuxInterop.PathMax);
            if (length <= 0 || length >= LinuxInterop.PathMax)
            {
                return null;
            }

            var target = buffer.AsSpan(0, (int)length);
            return Utf8.IsValid(target) ? Convert.ToHexString(target) : null;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static byte[] ReadDirentName(nint name)
    {
        var length = 0;
        while (length < DirentNameCapacity && Marshal.ReadByte(name, length) != 0)
        {
            length++;
        }

        var raw = new byte[length];
        Marshal.Copy(name, raw, 0, length);
        return raw;
    }

    private static bool IsConfirmedAbsentDirectory(string directory) =>
        OpenDirectoryNoFollow(directory) switch
        {
            NoFollowDirectoryDescriptor opened => CloseExistingDirectory(opened.Descriptor),
            DirectoryNodeAbsent => true,
            DirectoryScanFailed => false,
        };

    private static bool CloseExistingDirectory(int descriptor)
    {
        _ = LinuxInterop.Close(descriptor);
        return false;
    }
}
