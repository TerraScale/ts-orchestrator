namespace TsOrch.Cli;

internal sealed record class CliConsole(TextReader In, TextWriter Out, TextWriter Error, bool OutputIsTerminal);
