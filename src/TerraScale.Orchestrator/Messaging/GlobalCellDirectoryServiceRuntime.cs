using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.Services;
using NATS.Net;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Read-only NATS service for the global cell projection. It owns a distinct
/// service identity and only observes the standalone directory runtime.
/// </summary>
internal sealed class GlobalCellDirectoryServiceRuntime : IGlobalCellDirectoryServiceRuntimeInstance
{
    private readonly NatsClient client;
    private readonly INatsSvcServer service;
    private int disposed;

    private GlobalCellDirectoryServiceRuntime(NatsClient client, INatsSvcServer service)
    {
        this.client = client;
        this.service = service;
    }

    internal static async Task<GlobalCellDirectoryServiceRuntime> StartAsync(
        GlobalDirectoryServiceNatsConfiguration configuration,
        Func<GlobalCellDirectorySnapshot> snapshot,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(snapshot);
        if (configuration.Cell != "gru")
            throw new ArgumentException("The global cell directory service is GRU-only.", nameof(configuration));

        var client = new NatsClient(new NatsOpts
        {
            Url = configuration.Url,
            RetryOnInitialConnect = false,
            RequestTimeout = TimeSpan.FromSeconds(15),
            AuthOpts = new NatsAuthOpts { NKeyFile = configuration.NKeyFile },
            TlsOpts = new NatsTlsOpts
            {
                Mode = TlsMode.Require,
                CaFile = configuration.Tls.CaFile,
                CertFile = configuration.Tls.CertificateFile,
                KeyFile = configuration.Tls.KeyFile,
            },
        });

        INatsSvcServer? service = null;
        try
        {
            await client.ConnectAsync();
            var services = client.CreateServicesContext();
            service = await services.AddServiceAsync(
                new NatsSvcConfig("terrascale-global-cell-directory-gru", "1.0.0")
                {
                    Description = "TerraScale read-only global cell directory",
                    Metadata = new Dictionary<string, string>
                    {
                        ["cell"] = "gru",
                        ["readOnly"] = "true"
                    },
                    QueueGroup = "ts-orch-global-cell-directory"
                },
                cancellationToken);
            await service.AddEndpointAsync<string>(
                message => message.ReplyAsync(
                    JsonSerializer.Serialize(
                        snapshot(),
                        GlobalCellDirectoryJsonContext.Default.GlobalCellDirectorySnapshot),
                    cancellationToken: cancellationToken),
                name: "cells",
                subject: GlobalNatsTopology.CellDirectorySubject,
                metadata: new Dictionary<string, string>
                {
                    ["protocol"] = "1",
                    ["readOnly"] = "true",
                    ["source"] = GlobalNatsTopology.CellsBucket
                },
                cancellationToken: cancellationToken);
            return new(client, service);
        }
        catch
        {
            try
            {
                if (service is not null)
                    await service.DisposeAsync();
            }
            finally
            {
                await client.DisposeAsync();
            }
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        try
        {
            await service.DisposeAsync();
        }
        finally
        {
            await client.DisposeAsync();
        }
    }
}
