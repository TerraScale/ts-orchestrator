using System.Text.Json;
using NATS.Client.Core;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Operations;

public static class OperatorCli
{
    private static readonly JsonSerializerOptions OutputOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public static async Task<int> ExecuteAsync(
        IReadOnlyList<string> arguments,
        Func<string, string?> environment,
        CancellationToken cancellationToken)
    {
        if (arguments.Count == 0 || arguments[0] != "status")
        {
            throw new ArgumentException("operator requires 'status'.");
        }
        var values = ParseValues(arguments.Skip(1).ToArray());
        var cell = Value(values, "--cell", environment("TS_ORCH_CELL") ?? "local");
        var url = Value(values, "--nats-url", environment("TS_ORCH_NATS_URL") ?? "nats://127.0.0.1:4222");
        var nkeyFile = ValueOrNull(
            values,
            "--nkey-file",
            environment("TS_ORCH_NATS_NKEY_FILE"));
        nkeyFile = NatsCredentialFile.Resolve(nkeyFile, "operator --nkey-file");
        var tls = NatsTlsFiles.Resolve(
            ValueOrNull(values, "--tls-ca-file", environment("TS_ORCH_NATS_TLS_CA_FILE")),
            ValueOrNull(values, "--tls-cert-file", environment("TS_ORCH_NATS_TLS_CERT_FILE")),
            ValueOrNull(values, "--tls-key-file", environment("TS_ORCH_NATS_TLS_KEY_FILE")),
            "operator TLS");
        if (!Uri.TryCreate(url, UriKind.Absolute, out var endpoint) || endpoint.Scheme != "tls" ||
            nkeyFile is null || tls is null)
        {
            throw new ArgumentException(
                "operator status requires a tls:// NATS URL, a private NKey seed, and complete mTLS credentials.");
        }
        _ = OrchestratorOptions.Parse(
            ["check"],
            key => key switch
            {
                "TS_ORCH_CELL" => cell,
                "TS_ORCH_NATS_URL" => url,
                "TS_ORCH_REPLICAS" => "1",
                _ => null
            });

        var clientOptions = new NatsOpts
        {
            Url = url,
            RetryOnInitialConnect = false,
            RequestTimeout = TimeSpan.FromSeconds(10)
        };
        if (nkeyFile is not null)
        {
            clientOptions = clientOptions with
            {
                AuthOpts = new NatsAuthOpts { NKeyFile = nkeyFile }
            };
        }
        if (tls is not null)
        {
            clientOptions = clientOptions with
            {
                TlsOpts = new NatsTlsOpts
                {
                    Mode = TlsMode.Require,
                    CaFile = tls.CaFile,
                    CertFile = tls.CertificateFile,
                    KeyFile = tls.KeyFile
                }
            };
        }
        await using var client = new NatsClient(clientOptions);
        await client.ConnectAsync();
        var response = await client.RequestAsync<string, string>(
            new NatsTopology(cell, 1).StatusSubject,
            "status",
            cancellationToken: cancellationToken);
        var status = JsonSerializer.Deserialize(
            response.Data ?? throw new InvalidOperationException("The regional controller returned no status."),
            RegionalControllerStatusJsonContext.Default.RegionalControllerStatus)
            ?? throw new InvalidOperationException("The regional controller returned no status.");
        status.Validate(cell);
        Console.WriteLine(JsonSerializer.Serialize(status, OutputOptions));
        return 0;
    }

    internal static IReadOnlyDictionary<string, string> ParseValues(IReadOnlyList<string> arguments)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < arguments.Count; index += 2)
        {
            if (index + 1 >= arguments.Count ||
                arguments[index] is not ("--cell" or "--nats-url" or "--nkey-file" or
                    "--tls-ca-file" or "--tls-cert-file" or "--tls-key-file") ||
                !values.TryAdd(arguments[index], arguments[index + 1]))
            {
                throw new ArgumentException(
                    "operator status accepts [--cell <cell>] [--nats-url <nats-url>] " +
                    "[--nkey-file <seed-file>] [--tls-ca-file <pem>] " +
                    "[--tls-cert-file <pem>] [--tls-key-file <pem>].");
            }
        }
        return values;
    }

    private static string Value(IReadOnlyDictionary<string, string> values, string key, string fallback) =>
        values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : fallback;

    private static string? ValueOrNull(
        IReadOnlyDictionary<string, string> values,
        string key,
        string? fallback) =>
        values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : string.IsNullOrWhiteSpace(fallback) ? null : fallback;
}
