using System.Runtime.InteropServices;
using TsOrch.Cli;

using var shutdown = new CancellationTokenSource();
using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, RequestShutdown);
using var terminate = PosixSignalRegistration.Create(PosixSignal.SIGTERM, RequestShutdown);

try
{
    return await CliApp.RunAsync(args, new CliConsole(Console.In, Console.Out, Console.Error, !Console.IsOutputRedirected), TimeProvider.System, shutdown.Token);
}
catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
{
    return ExitCodes.Interrupted;
}

void RequestShutdown(PosixSignalContext context)
{
    if (shutdown.IsCancellationRequested)
    {
        return;
    }

    context.Cancel = true;
    shutdown.Cancel();
}
