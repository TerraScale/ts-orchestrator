using System.Globalization;

namespace TsOrch.Agent;

public sealed record class SysfsHelperValue(string Identity, string Text);

public sealed record class SysfsHelperAbsent;

public sealed record class SysfsHelperRejected(string Message);

public readonly union SysfsHelperRead(SysfsHelperValue, SysfsHelperAbsent, SysfsHelperRejected);

public sealed record class SysfsRescanWritten;

public readonly record struct SysfsRescanTarget(string CanonicalPath, ulong Device, ulong Inode);

public readonly union SysfsRescanWrite(SysfsRescanWritten, SysfsHelperRejected);

public static class SysfsHelperCommand
{
    public const string ReadAttribute = "--sysfs-read-attr";
    public const string RescanWrite = "--sysfs-rescan-write";
    private const int AbsentExitCode = 1;
    private const int RejectedExitCode = 2;
    private const int UsageExitCode = 64;

    public static bool Handles(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        return args is [ReadAttribute or RescanWrite, ..];
    }

    public static int Run(IReadOnlyList<string> args, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        return args switch
        {
            [ReadAttribute, var path] => ReportRead(MountTable.ReadSysfsAttributePath(path), output, error),
            [RescanWrite, var path, var expectedCanonicalPath, var device, var inode] => ReportWrite(WriteRescan(path, expectedCanonicalPath, device, inode), error),
            _ => Usage(error),
        };
    }

    private static SysfsRescanWrite WriteRescan(string path, string expectedCanonicalPath, string device, string inode) =>
        ulong.TryParse(device, NumberStyles.None, CultureInfo.InvariantCulture, out var expectedDevice)
        && ulong.TryParse(inode, NumberStyles.None, CultureInfo.InvariantCulture, out var expectedInode)
            ? MountTable.WriteSysfsRescan(path, new SysfsRescanTarget(expectedCanonicalPath, expectedDevice, expectedInode))
            : new SysfsHelperRejected($"Rescan attribute identity dev={device} ino={inode} is not a pair of decimal numbers.");

    private static int ReportRead(SysfsHelperRead read, TextWriter output, TextWriter error) =>
        read switch
        {
            SysfsHelperValue value => Emit(output, $"{value.Identity} {value.Text}", 0),
            SysfsHelperAbsent => AbsentExitCode,
            SysfsHelperRejected rejected => Emit(error, rejected.Message, RejectedExitCode),
        };

    private static int ReportWrite(SysfsRescanWrite write, TextWriter error) =>
        write switch
        {
            SysfsRescanWritten => 0,
            SysfsHelperRejected rejected => Emit(error, rejected.Message, RejectedExitCode),
        };

    private static int Emit(TextWriter writer, string line, int exitCode)
    {
        writer.Write($"{line}\n");
        return exitCode;
    }

    private static int Usage(TextWriter error) =>
        Emit(error, $"usage: ts-orch {ReadAttribute} PATH | ts-orch {RescanWrite} PATH CANONICAL_PATH DEV INO", UsageExitCode);
}
