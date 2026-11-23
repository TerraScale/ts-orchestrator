using System.Runtime.InteropServices;
using TsOrch.AppHost;

using var shutdown = new CancellationTokenSource();
using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, Stop);
using var terminate = PosixSignalRegistration.Create(PosixSignal.SIGTERM, Stop);

if (AppHostArguments.Has(args, OciMockOptions.Flag))
{
    return OciMockOptions.Parse(args) switch
    {
        OciMockOptions options => await OciMockServer.RunAsync(options, shutdown.Token),
        InvalidArguments invalid => Usage(invalid),
    };
}

if (AppHostArguments.Has(args, LocalSeederOptions.Flag))
{
    return LocalSeederOptions.Parse(args) switch
    {
        LocalSeederOptions options => await LocalSeeder.RunAsync(options, shutdown.Token),
        InvalidArguments invalid => Usage(invalid),
    };
}

await using var fleet = LocalFleet.Build(args);
await fleet.RunAsync(shutdown.Token);
return 0;

void Stop(PosixSignalContext context)
{
    context.Cancel = true;
    shutdown.Cancel();
}

static int Usage(InvalidArguments invalid)
{
    Console.Error.WriteLine($"TsOrch.AppHost: {invalid.Message}");
    Console.Error.WriteLine("usage: TsOrch.AppHost [--oci-mock --port <port> [--seed-secret NAME=VALUE]... [--seed-services <dir>]...] [--seed --worker-url <url> --repo-root <dir> [--local-region <label> --edge-url <url>]]");
    return 64;
}
