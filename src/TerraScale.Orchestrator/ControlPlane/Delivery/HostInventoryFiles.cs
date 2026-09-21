using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>Linux file type and owner checks; FileInfo alone cannot exclude FIFOs or sockets.</summary>
internal static class HostInventoryFiles
{
    internal readonly record struct Identity(uint Major, uint Minor, ulong Inode);

    internal static Identity Require(string path, bool directory = false, bool optional = false)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        if (Statx(-100, path, 0x100, 0x7ff, out var stat) != 0)
        {
            if (optional && Marshal.GetLastPInvokeError() == 2) return default;
            throw new IOException("Cannot inspect host inventory storage.");
        }
        if ((stat.Mask & 0x11f) != 0x11f || stat.UserId != GetEffectiveUserId() ||
            stat.Mode != (directory ? 0x41c0 : 0x8180) || (!directory && stat.Links != 1))
            throw new InvalidDataException("Host inventory storage must be private, owned, and free of file links or special files.");
        return new(stat.DeviceMajor, stat.DeviceMinor, stat.Inode);
    }

    internal static Identity Of(SafeFileHandle handle)
    {
        if (Statx(handle.DangerousGetHandle().ToInt32(), "", 0x1000, 0x7ff, out var stat) != 0)
            throw new IOException("Cannot inspect the host ownership descriptor.");
        return new(stat.DeviceMajor, stat.DeviceMinor, stat.Inode);
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct LinuxStat
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(16)] public uint Links;
        [FieldOffset(20)] public uint UserId;
        [FieldOffset(28)] public ushort Mode;
        [FieldOffset(32)] public ulong Inode;
        [FieldOffset(136)] public uint DeviceMajor;
        [FieldOffset(140)] public uint DeviceMinor;
    }

    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Statx(int directory, string path, int flags, uint mask, out LinuxStat stat);
    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();
}
