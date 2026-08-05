using System.Text;
using System.Security.Cryptography;
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
        NatsOperationJournalMutationAuthorityVerifier authority,
        string controllerIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(topology);
        ArgumentNullException.ThrowIfNull(authority);
        if (string.IsNullOrWhiteSpace(controllerIdentity)) throw new ArgumentException("Controller identity is required.", nameof(controllerIdentity));
        var service = await writer.CreateServicesContext().AddServiceAsync(
            new NatsSvcConfig($"terrascale_orchestrator_journal_writer_{topology.Cell}", "1.0.0")
            {
                Description = "Private typed CreateNode journal mutation service",
            },
            cancellationToken);
        await service.AddEndpointAsync<NatsOperationJournalCreateRequest>(
            message => CreateAsync(message, store, topology.Cell, authority, controllerIdentity, cancellationToken),
            name: "create",
            subject: topology.OperationJournalCreateSubject,
            metadata: new Dictionary<string, string> { ["private"] = "true" },
            cancellationToken: cancellationToken);
        await service.AddEndpointAsync<NatsOperationJournalUpdateRequest>(
            message => UpdateAsync(message, store, topology.Cell, authority, controllerIdentity, cancellationToken),
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
        string cell,
        NatsOperationJournalMutationAuthorityVerifier authority,
        string controllerIdentity,
        CancellationToken cancellationToken)
    {
        var request = message.Data;
        if (request is null || !IsValid(request.Key, request.Value) ||
            !authority.Verify(request.Authority, cell, controllerIdentity, "create", request.Key, 0, request.Value))
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
        string cell,
        NatsOperationJournalMutationAuthorityVerifier authority,
        string controllerIdentity,
        CancellationToken cancellationToken)
    {
        var request = message.Data;
        if (request is null || !IsValid(request.Key, request.Value) || request.Revision == 0 ||
            !authority.Verify(request.Authority, cell, controllerIdentity, "update", request.Key, request.Revision, request.Value))
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

internal sealed class NatsOperationJournalMutationClient(
    NatsClient client,
    NatsTopology topology,
    NatsOperationJournalMutationAuthoritySigner authority)
{
    internal Task<NatsOperationJournalMutationReply> CreateAsync(
        string key,
        string value,
        CancellationToken cancellationToken = default) =>
        RequestAsync(topology.OperationJournalCreateSubject, new NatsOperationJournalCreateRequest(key, value,
            authority.Issue(topology.Cell, "create", key, 0, value)), cancellationToken);

    internal Task<NatsOperationJournalMutationReply> UpdateAsync(
        string key,
        string value,
        ulong revision,
        CancellationToken cancellationToken = default) =>
        RequestAsync(topology.OperationJournalUpdateSubject, new NatsOperationJournalUpdateRequest(key, value, revision,
            authority.Issue(topology.Cell, "update", key, revision, value)), cancellationToken);

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

internal sealed record NatsOperationJournalCreateRequest(string Key, string Value, NatsOperationJournalMutationAuthorityProof Authority);

internal sealed record NatsOperationJournalUpdateRequest(string Key, string Value, ulong Revision, NatsOperationJournalMutationAuthorityProof Authority);

internal sealed record NatsOperationJournalMutationReply(bool Succeeded, ulong Revision);

internal sealed record NatsOperationJournalMutationAuthorityProof(
    string Cell,
    string CallerIdentity,
    string Action,
    string Key,
    ulong Revision,
    string CiphertextDigest,
    string Lease,
    DateTimeOffset ExpiresAt,
    string Nonce,
    string Signature)
{
    internal string Payload() => string.Join('|', Cell, CallerIdentity, Action, Key, Revision, CiphertextDigest, Lease,
        ExpiresAt.UtcTicks, Nonce);
}

internal sealed class NatsOperationJournalMutationAuthoritySigner(string callerIdentity, ECDsa key)
{
    internal NatsOperationJournalMutationAuthorityProof Issue(string cell, string action, string keyName, ulong revision, string value)
    {
        var proof = new NatsOperationJournalMutationAuthorityProof(cell, callerIdentity, action, keyName, revision,
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value))), Guid.NewGuid().ToString("N"),
            DateTimeOffset.UtcNow.AddMinutes(2), Guid.NewGuid().ToString("N"), string.Empty);
        return proof with { Signature = Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(proof.Payload()), HashAlgorithmName.SHA256)) };
    }
}

internal sealed class NatsOperationJournalMutationAuthorityVerifier(byte[] publicKey)
{
    private readonly byte[] publicKey = publicKey.ToArray();
    internal bool Verify(NatsOperationJournalMutationAuthorityProof? proof, string cell, string caller, string action, string keyName, ulong revision, string value)
    {
        try
        {
            if (proof is null || proof.Cell != cell || proof.CallerIdentity != caller || proof.Action != action ||
                proof.Key != keyName || proof.Revision != revision || proof.CiphertextDigest != Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value))) ||
                string.IsNullOrWhiteSpace(proof.Lease) || string.IsNullOrWhiteSpace(proof.Nonce) ||
                proof.ExpiresAt <= DateTimeOffset.UtcNow || proof.ExpiresAt > DateTimeOffset.UtcNow.AddMinutes(5)) return false;
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            return key.VerifyData(Encoding.UTF8.GetBytes(proof.Payload()), Convert.FromBase64String(proof.Signature), HashAlgorithmName.SHA256);
        }
        catch (CryptographicException) { return false; }
        catch (FormatException) { return false; }
    }
}
