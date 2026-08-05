using System.Text;
using NATS.Client.KeyValueStore;
using NATS.Client.Services;
using NATS.Net;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>Private typed mutation boundary; only this service holds journal KV write credentials.</summary>
internal sealed class NatsOperationJournalMutationService : IAsyncDisposable
{
    private const int MaximumValueBytes = 16 * 1024;
    private readonly INatsSvcServer service;

    private NatsOperationJournalMutationService(INatsSvcServer service) => this.service = service;

    internal static async Task<NatsOperationJournalMutationService> StartAsync(
        NatsClient writer,
        INatsKVStore store,
        NatsTopology topology,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(topology);
        var service = await writer.CreateServicesContext().AddServiceAsync(
            new NatsSvcConfig($"terrascale_orchestrator_journal_writer_{topology.Cell}", "1.0.0")
            {
                Description = "Private typed CreateNode journal mutation service",
            },
            cancellationToken);
        await service.AddEndpointAsync<NatsOperationJournalCreateRequest>(
            message => CreateAsync(message, store, cancellationToken),
            name: "create",
            subject: topology.OperationJournalCreateSubject,
            metadata: new Dictionary<string, string> { ["private"] = "true" },
            cancellationToken: cancellationToken);
        await service.AddEndpointAsync<NatsOperationJournalUpdateRequest>(
            message => UpdateAsync(message, store, cancellationToken),
            name: "update",
            subject: topology.OperationJournalUpdateSubject,
            metadata: new Dictionary<string, string> { ["private"] = "true" },
            cancellationToken: cancellationToken);
        return new(service);
    }

    public ValueTask DisposeAsync() => service.DisposeAsync();

    private static async ValueTask CreateAsync(
        NatsSvcMsg<NatsOperationJournalCreateRequest> message,
        INatsKVStore store,
        CancellationToken cancellationToken)
    {
        var request = message.Data;
        if (request is null || !IsValid(request.Key, request.Value))
        {
            await message.ReplyAsync(new NatsOperationJournalMutationReply(false, 0), cancellationToken: cancellationToken);
            return;
        }
        try
        {
            var revision = await store.CreateAsync(request.Key, request.Value, cancellationToken: cancellationToken);
            await message.ReplyAsync(new NatsOperationJournalMutationReply(true, revision), cancellationToken: cancellationToken);
        }
        catch (NatsKVCreateException)
        {
            await message.ReplyAsync(new NatsOperationJournalMutationReply(false, 0), cancellationToken: cancellationToken);
        }
    }

    private static async ValueTask UpdateAsync(
        NatsSvcMsg<NatsOperationJournalUpdateRequest> message,
        INatsKVStore store,
        CancellationToken cancellationToken)
    {
        var request = message.Data;
        if (request is null || !IsValid(request.Key, request.Value) || request.Revision == 0)
        {
            await message.ReplyAsync(new NatsOperationJournalMutationReply(false, 0), cancellationToken: cancellationToken);
            return;
        }
        try
        {
            var revision = await store.UpdateAsync(request.Key, request.Value, request.Revision, cancellationToken: cancellationToken);
            await message.ReplyAsync(new NatsOperationJournalMutationReply(true, revision), cancellationToken: cancellationToken);
        }
        catch (NatsKVWrongLastRevisionException)
        {
            await message.ReplyAsync(new NatsOperationJournalMutationReply(false, 0), cancellationToken: cancellationToken);
        }
    }

    private static bool IsValid(string? key, string? value) =>
        key is { Length: 74 } && key.StartsWith("operation.", StringComparison.Ordinal) &&
        key.AsSpan(10).ToString().All(Uri.IsHexDigit) && value is not null &&
        Encoding.UTF8.GetByteCount(value) <= MaximumValueBytes;
}

internal sealed class NatsOperationJournalMutationClient(NatsClient client, NatsTopology topology)
{
    internal Task<NatsOperationJournalMutationReply> CreateAsync(
        string key,
        string value,
        CancellationToken cancellationToken = default) =>
        RequestAsync(topology.OperationJournalCreateSubject, new NatsOperationJournalCreateRequest(key, value), cancellationToken);

    internal Task<NatsOperationJournalMutationReply> UpdateAsync(
        string key,
        string value,
        ulong revision,
        CancellationToken cancellationToken = default) =>
        RequestAsync(topology.OperationJournalUpdateSubject, new NatsOperationJournalUpdateRequest(key, value, revision), cancellationToken);

    private async Task<NatsOperationJournalMutationReply> RequestAsync<TRequest>(
        string subject,
        TRequest request,
        CancellationToken cancellationToken)
    {
        var response = await client.RequestAsync<TRequest, NatsOperationJournalMutationReply>(
            subject,
            request,
            cancellationToken: cancellationToken);
        response.EnsureSuccess();
        return response.Data ?? throw new InvalidOperationException("The private journal mutation service returned no reply.");
    }
}

internal sealed record NatsOperationJournalCreateRequest(string Key, string Value);

internal sealed record NatsOperationJournalUpdateRequest(string Key, string Value, ulong Revision);

internal sealed record NatsOperationJournalMutationReply(bool Succeeded, ulong Revision);
