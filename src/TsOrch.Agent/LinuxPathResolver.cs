using System.Buffers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Unicode;

namespace TsOrch.Agent;

internal sealed record class ResolvedLinuxPath(string Path);

internal sealed record class MissingLinuxPath;

internal sealed record class UnresolvableLinuxPath;

internal readonly union LinuxPathResolution(ResolvedLinuxPath, MissingLinuxPath, UnresolvableLinuxPath);

internal static class LinuxPathResolver
{
    private const int MaxSymlinkHops = 16;

    private readonly record struct FileTypeProbe(ushort? Type, bool Missing);

    public static string? TryResolve(string path) =>
        Resolve(path) switch
        {
            ResolvedLinuxPath resolved => resolved.Path,
            MissingLinuxPath => null,
            UnresolvableLinuxPath => null,
        };

    public static LinuxPathResolution Resolve(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (!OperatingSystem.IsLinux() || !path.StartsWith('/'))
        {
            return new UnresolvableLinuxPath();
        }

        var rest = path[1..];
        var current = string.Empty;
        var hops = 0;
        while (rest.Length > 0)
        {
            var slash = rest.IndexOf('/', StringComparison.Ordinal);
            var more = slash >= 0;
            var segment = more ? rest[..slash] : rest;
            rest = more ? rest[(slash + 1)..] : string.Empty;
            if (segment is "" or ".")
            {
                continue;
            }

            if (segment == "..")
            {
                if (current.Length > 0)
                {
                    if (ReadFileType(current).Type != LinuxInterop.DirectoryType)
                    {
                        return new UnresolvableLinuxPath();
                    }

                    current = current[..current.LastIndexOf('/')];
                }

                continue;
            }

            var next = $"{current}/{segment}";
            var probe = ReadFileType(next);
            var type = probe.Type;
            if (more)
            {
                if (type != LinuxInterop.DirectoryType)
                {
                    return probe.Missing ? new MissingLinuxPath() : new UnresolvableLinuxPath();
                }

                current = next;
                continue;
            }

            if (type == LinuxInterop.SymbolicLinkType)
            {
                hops++;
                if (hops > MaxSymlinkHops || ReadLinkTarget(next) is not { } target)
                {
                    return new UnresolvableLinuxPath();
                }

                if (target.StartsWith('/'))
                {
                    current = string.Empty;
                    rest = target[1..];
                }
                else
                {
                    rest = target;
                }

                continue;
            }

            return type is not null
                ? new ResolvedLinuxPath(next)
                : probe.Missing ? new MissingLinuxPath() : new UnresolvableLinuxPath();
        }

        return new UnresolvableLinuxPath();
    }

    private static FileTypeProbe ReadFileType(string path)
    {
        Span<byte> buffer = stackalloc byte[LinuxInterop.StatxBufferSize];
        if (LinuxInterop.Statx(
                LinuxInterop.AtFdCwd,
                path,
                LinuxInterop.AtSymlinkNoFollow | LinuxInterop.AtStatxDontSync,
                LinuxInterop.StatxType,
                buffer) != 0)
        {
            return new FileTypeProbe(null, Marshal.GetLastPInvokeError() == LinuxInterop.ErrorNotFound);
        }

        return (MemoryMarshal.Read<uint>(buffer[LinuxInterop.StatxMaskOffset..]) & LinuxInterop.StatxType) == 0
            ? new FileTypeProbe(null, false)
            : new FileTypeProbe((ushort)(MemoryMarshal.Read<ushort>(buffer[LinuxInterop.StatxModeOffset..]) & LinuxInterop.FileTypeMask), false);
    }

    private static string? ReadLinkTarget(string path)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(LinuxInterop.PathMax);
        try
        {
            var length = LinuxInterop.ReadLink(path, buffer.AsSpan(0, LinuxInterop.PathMax), LinuxInterop.PathMax);
            if (length <= 0 || length >= LinuxInterop.PathMax)
            {
                return null;
            }

            if (!Utf8.IsValid(buffer.AsSpan(0, (int)length)))
            {
                return null;
            }

            var target = Encoding.UTF8.GetString(buffer, 0, (int)length);
            return target.Contains('\n', StringComparison.Ordinal) ? null : target;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
