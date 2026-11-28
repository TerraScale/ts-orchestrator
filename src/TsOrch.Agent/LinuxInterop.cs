using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace TsOrch.Agent;

internal static partial class LinuxInterop
{
    public const int PathMax = 4096;
    public const int ErrorNotFound = 2;
    public const int ErrorInterrupted = 4;
    public const int ErrorExists = 17;
    public const int DirentNameOffset = 19;
    public const int OpenReadOnly = 0;
    public const int OpenWriteOnly = 1;
    public const int OpenNonBlock = 0x800;
    public const int OpenDirectoryArm64 = 0x4000;
    public const int OpenDirectoryX64 = 0x10000;
    public const int OpenNoFollowArm64 = 0x8000;
    public const int OpenNoFollowX64 = 0x20000;
    public const int OpenCloseOnExec = 0x80000;
    public const int OpenPath = 0x200000;
    public const int AtFdCwd = -100;
    public const int AtSymlinkNoFollow = 0x100;
    public const int AtEmptyPath = 0x1000;
    public const int AtStatxDontSync = 0x4000;
    public const uint StatxType = 0x1u;
    public const uint StatxMode = 0x2u;
    public const uint StatxUid = 0x8u;
    public const uint StatxIno = 0x100u;
    public const uint StatxMountId = 0x1000u;
    public const int StatxBufferSize = 256;
    public const int StatxMaskOffset = 0;
    public const int StatxUidOffset = 20;
    public const int StatxModeOffset = 28;
    public const int StatxInoOffset = 32;
    public const int StatxRdevMajorOffset = 128;
    public const int StatxRdevMinorOffset = 132;
    public const int StatxDevMajorOffset = 136;
    public const int StatxDevMinorOffset = 140;
    public const int StatxMountIdOffset = 144;
    public const int StatVfsBufferSize = 256;
    public const int StatVfsBlockSizeOffset = 0;
    public const int StatVfsFragmentSizeOffset = 8;
    public const int StatVfsBlocksOffset = 16;
    public const int StatVfsBlocksAvailableOffset = 32;
    public const int StatFsBufferSize = 256;
    public const int StatFsTypeOffset = 0;
    public const long SysfsMagic = 0x62656572;
    public const ushort FileTypeMask = 0xf000;
    public const ushort PermissionModeMask = 0x0fff;
    public const ushort DirectoryType = 0x4000;
    public const ushort BlockDeviceType = 0x6000;
    public const ushort RegularFileType = 0x8000;
    public const ushort SymbolicLinkType = 0xa000;

    public static int OpenDirectoryFlag => CurrentOpenFlags.Directory;

    public static int NoFollowDirectoryOpenFlags =>
        OpenReadOnly | CurrentOpenFlags.Directory | CurrentOpenFlags.NoFollow | OpenCloseOnExec;

    public static int NoFollowPathOpenFlags => OpenPath | CurrentOpenFlags.NoFollow | OpenCloseOnExec;

    private static (int Directory, int NoFollow) CurrentOpenFlags =>
        RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.Arm64 => (OpenDirectoryArm64, OpenNoFollowArm64),
            Architecture.X64 => (OpenDirectoryX64, OpenNoFollowX64),
            Architecture.X86 or Architecture.Arm or Architecture.Armv6 or Architecture.Wasm or Architecture.S390x
                or Architecture.LoongArch64 or Architecture.Ppc64le or Architecture.RiscV64 =>
                throw new PlatformNotSupportedException($"ts-orch agent does not support {RuntimeInformation.ProcessArchitecture}."),
            _ => throw new UnreachableException(),
        };

    [LibraryImport("libc", EntryPoint = "readlink", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    public static partial nint ReadLink(string path, Span<byte> buffer, nuint size);

    [LibraryImport("libc", EntryPoint = "geteuid")]
    public static partial uint GetEffectiveUid();

    [LibraryImport("libc", EntryPoint = "readlinkat", SetLastError = true)]
    public static partial nint ReadLinkAt(int dirfd, ReadOnlySpan<byte> path, Span<byte> buffer, nuint size);

    [LibraryImport("libc", EntryPoint = "openat", SetLastError = true)]
    public static partial int OpenAt(int dirfd, ReadOnlySpan<byte> path, int flags);

    [LibraryImport("libc", EntryPoint = "fdopendir", SetLastError = true)]
    public static partial nint FdOpenDir(int fd);

    [LibraryImport("libc", EntryPoint = "readdir", SetLastError = true)]
    public static partial nint ReadDir(nint dir);

    [LibraryImport("libc", EntryPoint = "dirfd", SetLastError = true)]
    public static partial int DirFd(nint dir);

    [LibraryImport("libc", EntryPoint = "closedir")]
    public static partial int CloseDir(nint dir);

    [LibraryImport("libc", EntryPoint = "open", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    public static partial int Open(string path, int flags);

    [LibraryImport("libc", EntryPoint = "read", SetLastError = true)]
    public static partial nint Read(int fd, Span<byte> buffer, nuint count);

    [LibraryImport("libc", EntryPoint = "write", SetLastError = true)]
    public static partial nint Write(int fd, ReadOnlySpan<byte> buffer, nuint count);

    [LibraryImport("libc", EntryPoint = "close")]
    public static partial int Close(int fd);

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    public static partial int Statx(int dirfd, string path, int flags, uint mask, Span<byte> buffer);

    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true)]
    public static partial int StatxAt(int dirfd, ReadOnlySpan<byte> path, int flags, uint mask, Span<byte> buffer);

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int StatxHandle(SafeFileHandle dirfd, string path, int flags, uint mask, Span<byte> buffer);

    [LibraryImport("libc", EntryPoint = "fstatvfs")]
    public static partial int FStatVfs(SafeFileHandle fd, Span<byte> buffer);

    [LibraryImport("libc", EntryPoint = "fstatfs", SetLastError = true)]
    public static partial int FStatFs(int fd, Span<byte> buffer);

    [LibraryImport("libc", EntryPoint = "mkdir", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    public static partial int MakeDirectory(string path, uint mode);
}
