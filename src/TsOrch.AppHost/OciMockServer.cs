using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace TsOrch.AppHost;

internal sealed record class OciMockOptions(int Port, IReadOnlyDictionary<string, string> Secrets)
{
    public const string Flag = "--oci-mock";

    public static Parsed<OciMockOptions> Parse(IReadOnlyList<string> args) =>
        AppHostArguments.Port(args, "--port") switch
        {
            int port => ServiceSecrets(AppHostArguments.Values(args, "--seed-services")) switch
            {
                IReadOnlyDictionary<string, string> serviceSecrets => WithSeedSecrets(port, serviceSecrets, args),
                InvalidArguments invalid => invalid,
            },
            InvalidArguments invalid => invalid,
        };

    private static Parsed<OciMockOptions> WithSeedSecrets(int port, IReadOnlyDictionary<string, string> serviceSecrets, IReadOnlyList<string> args)
    {
        Dictionary<string, string> secrets = new(serviceSecrets, StringComparer.Ordinal);
        foreach (var pair in AppHostArguments.Values(args, "--seed-secret"))
        {
            var separator = pair.IndexOf('=', StringComparison.Ordinal);
            if (separator <= 0 || separator == pair.Length - 1)
            {
                return new InvalidArguments($"--seed-secret expects NAME=VALUE, got '{pair}'.");
            }

            secrets[pair[..separator]] = pair[(separator + 1)..];
        }

        return new OciMockOptions(port, secrets);
    }

    private static Parsed<IReadOnlyDictionary<string, string>> ServiceSecrets(IReadOnlyList<string> directories)
    {
        Dictionary<string, string> secrets = new(StringComparer.Ordinal);
        try
        {
            foreach (var directory in directories)
            {
                foreach (var file in Directory.EnumerateFiles(directory, "*.json").Order(StringComparer.Ordinal))
                {
                    if (JsonNode.Parse(File.ReadAllText(file)) is not JsonObject service || service["secrets"] is not JsonObject references)
                    {
                        continue;
                    }

                    foreach (var (_, reference) in references)
                    {
                        if (reference is JsonObject entry && entry["name"] is JsonValue value && value.TryGetValue<string>(out var name) && name.Length > 0)
                        {
                            secrets[name] = $"local-{name}";
                        }
                    }
                }
            }

            return secrets;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new InvalidArguments($"--seed-services could not be read: {exception.Message}");
        }
    }
}

internal static class OciMockServer
{
    public static async Task<int> RunAsync(OciMockOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, options.Port));
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<OciMockState>();
        builder.Services.AddSingleton(static services => OciMockIdentity.Create(services.GetRequiredService<TimeProvider>()));
        builder.Services.AddSingleton<OciMockRouter>();

        await using var app = builder.Build();
        var state = app.Services.GetRequiredService<OciMockState>();
        foreach (var (name, value) in options.Secrets)
        {
            state.SeedSecret(name, value);
        }

        app.Run(app.Services.GetRequiredService<OciMockRouter>().HandleAsync);
        await app.StartAsync(cancellationToken);
        await app.WaitForShutdownAsync(cancellationToken);
        return 0;
    }
}
