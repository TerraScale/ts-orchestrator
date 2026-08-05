using System.Text;
using System.Security.Cryptography;
using System.Buffers.Binary;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using NATS.Client.Services;
using NATS.Net;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>Private typed mutation boundary; only this service holds journal KV write credentials.</summary>
internal sealed class NatsOperationJournalMutationService : IAsyncDisposable
{
    private const int MaximumValueBytes = 16 * 1024;
    private readonly INatsSvcServer service;
    private readonly NatsOperationJournalMutationReplySigner replies;
    private readonly CancellationTokenSource lifetime;
    private int disposed;

    private NatsOperationJournalMutationService(
        INatsSvcServer service,
        NatsOperationJournalMutationReplySigner replies,
        CancellationTokenSource lifetime)
    {
        this.service = service;
        this.replies = replies;
        this.lifetime = lifetime;
    }

    internal static async Task<NatsOperationJournalMutationService> StartAsync(
        NatsClient writer,
        INatsKVStore store,
        INatsKVStore proofConsumptions,
        NatsTopology topology,
        NatsOperationJournalMutationAuthorityVerifier authority,
        IReadOnlySet<string> controllerIdentities,
        NatsOperationJournalMutationReplySigner replies,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(proofConsumptions);
        ArgumentNullException.ThrowIfNull(topology);
        ArgumentNullException.ThrowIfNull(authority);
        if (controllerIdentities is null || controllerIdentities.Count == 0 || controllerIdentities.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("At least one controller identity is required.", nameof(controllerIdentities));
        ArgumentNullException.ThrowIfNull(replies);
        var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = lifetime.Token;
        INatsSvcServer? service = null;
        try
        {
            service = await writer.CreateServicesContext().AddServiceAsync(
                new NatsSvcConfig($"terrascale_orchestrator_journal_writer_{topology.Cell}", "1.0.0")
                {
                    Description = "Private typed CreateNode journal mutation service",
                    QueueGroup = topology.OperationJournalWriterQueueGroup,
                },
                cancellationToken);
            await service.AddEndpointAsync<NatsOperationJournalCreateRequest>(
                message => CreateAsync(message, store, proofConsumptions, topology.Cell, authority, controllerIdentities, replies, token),
                name: "create",
                subject: topology.OperationJournalCreateSubject,
                metadata: new Dictionary<string, string> { ["private"] = "true" },
                cancellationToken: token);
            await service.AddEndpointAsync<NatsOperationJournalUpdateRequest>(
                message => UpdateAsync(message, store, proofConsumptions, topology.Cell, authority, controllerIdentities, replies, token),
                name: "update",
                subject: topology.OperationJournalUpdateSubject,
                metadata: new Dictionary<string, string> { ["private"] = "true" },
                cancellationToken: token);
            return new(service, replies, lifetime);
        }
        catch
        {
            lifetime.Cancel();
            if (service is not null)
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                try
                {
                    await service.StopAsync(cleanup.Token).AsTask().WaitAsync(cleanup.Token);
                }
                catch
                {
                }
                try
                {
                    await service.DisposeAsync().AsTask().WaitAsync(cleanup.Token);
                }
                catch
                {
                }
            }
            lifetime.Dispose();
            replies.Dispose();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        lifetime.Cancel();
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try
        {
            await service.StopAsync(shutdown.Token).AsTask().WaitAsync(shutdown.Token);
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
        {
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                await service.DisposeAsync().AsTask().WaitAsync(cleanup.Token);
            }
            catch (OperationCanceledException) when (cleanup.IsCancellationRequested)
            {
            }
            finally
            {
                lifetime.Dispose();
                replies.Dispose();
            }
        }
    }

    private static async ValueTask CreateAsync(
        NatsSvcMsg<NatsOperationJournalCreateRequest> message,
        INatsKVStore store,
        INatsKVStore proofConsumptions,
        string cell,
        NatsOperationJournalMutationAuthorityVerifier authority,
        IReadOnlySet<string> controllerIdentities,
        NatsOperationJournalMutationReplySigner replies,
        CancellationToken cancellationToken)
    {
        var request = message.Data;
        if (request is null || !IsValid(request.Key, request.Value) ||
            !authority.Verify(request.Authority, cell, controllerIdentities, "create", request.Key, 0, request.Value))
        {
            if (request is not null)
                await ReplyAsync(message, request.Authority, false, 0, replies, cancellationToken);
            return;
        }
        if (!await NatsOperationJournalMutationProofConsumption.TryConsumeAsync(proofConsumptions, request.Authority, cancellationToken))
        {
            await ReplyAsync(message, request.Authority, false, 0, replies, cancellationToken);
            return;
        }
        try
        {
            var revision = await store.CreateAsync(request.Key, request.Value, cancellationToken: cancellationToken);
            await ReplyAsync(message, request.Authority, true, revision, replies, cancellationToken);
        }
        catch (NatsKVCreateException)
        {
            await ReplyAsync(message, request.Authority, false, 0, replies, cancellationToken);
        }
    }

    private static async ValueTask UpdateAsync(
        NatsSvcMsg<NatsOperationJournalUpdateRequest> message,
        INatsKVStore store,
        INatsKVStore proofConsumptions,
        string cell,
        NatsOperationJournalMutationAuthorityVerifier authority,
        IReadOnlySet<string> controllerIdentities,
        NatsOperationJournalMutationReplySigner replies,
        CancellationToken cancellationToken)
    {
        var request = message.Data;
        if (request is null || !IsValid(request.Key, request.Value) || request.Revision == 0 ||
            !authority.Verify(request.Authority, cell, controllerIdentities, "update", request.Key, request.Revision, request.Value))
        {
            if (request is not null)
                await ReplyAsync(message, request.Authority, false, 0, replies, cancellationToken);
            return;
        }
        if (!await NatsOperationJournalMutationProofConsumption.TryConsumeAsync(proofConsumptions, request.Authority, cancellationToken))
        {
            await ReplyAsync(message, request.Authority, false, 0, replies, cancellationToken);
            return;
        }
        try
        {
            var revision = await store.UpdateAsync(request.Key, request.Value, request.Revision, cancellationToken: cancellationToken);
            await ReplyAsync(message, request.Authority, true, revision, replies, cancellationToken);
        }
        catch (NatsKVWrongLastRevisionException)
        {
            await ReplyAsync(message, request.Authority, false, 0, replies, cancellationToken);
        }
    }

    private static bool IsValid(string? key, string? value) =>
        key is { Length: 74 } && key.StartsWith("operation.", StringComparison.Ordinal) &&
        key.AsSpan(10).ToString().All(Uri.IsHexDigit) && value is not null &&
        Encoding.UTF8.GetByteCount(value) <= MaximumValueBytes;

    private static ValueTask ReplyAsync<TRequest>(
        NatsSvcMsg<TRequest> message,
        NatsOperationJournalMutationAuthorityProof authority,
        bool succeeded,
        ulong revision,
        NatsOperationJournalMutationReplySigner replies,
        CancellationToken cancellationToken)
    {
        var digest = NatsOperationJournalMutationRequestDigest.Create(authority);
        return message.ReplyAsync(replies.Sign(succeeded, revision, digest), cancellationToken: cancellationToken);
    }
}

/// <summary>R3 create-only proof ledger. Entries expire within the maximum accepted proof lifetime.</summary>
internal static class NatsOperationJournalMutationProofConsumption
{
    private const string MarkerValue = "consumed";

    internal static async ValueTask<bool> TryConsumeAsync(
        INatsKVStore store,
        NatsOperationJournalMutationAuthorityProof proof,
        CancellationToken cancellationToken)
    {
        try
        {
            await store.CreateAsync(Key(proof), MarkerValue, cancellationToken: cancellationToken);
            return true;
        }
        catch (NatsKVCreateException)
        {
            return false;
        }
        catch (NatsKVWrongLastRevisionException)
        {
            return false;
        }
        // A failed proof-ledger write must fail closed before the operation KV is
        // touched; providers never receive a mutation reply that authorizes reuse.
        catch (NatsException)
        {
            return false;
        }
    }

    internal static string Key(NatsOperationJournalMutationAuthorityProof proof)
    {
        ArgumentNullException.ThrowIfNull(proof);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[sizeof(int)];
        foreach (var value in new[] { proof.Cell, proof.CallerIdentity, proof.Lease, proof.Nonce })
        {
            var bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
            BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
            hash.AppendData(length);
            hash.AppendData(bytes);
        }
        return "proof." + Convert.ToHexStringLower(hash.GetHashAndReset());
    }
}

internal sealed class NatsOperationJournalMutationClient(
    NatsClient client,
    NatsTopology topology,
    NatsOperationJournalMutationAuthoritySigner authority,
    NatsOperationJournalMutationReplyVerifier replies)
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
        CancellationToken cancellationToken) where TRequest : INatsOperationJournalMutationRequest
    {
        var replySubject = topology.OperationJournalReplySubject(authority.CallerIdentity, Guid.NewGuid().ToString("N"));
        using var responseTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        responseTimeout.CancelAfter(TimeSpan.FromSeconds(15));
        await using var subscription = await client.Connection.SubscribeCoreAsync<NatsOperationJournalMutationReply>(
            replySubject,
            opts: new NatsSubOpts { MaxMsgs = 1, Timeout = TimeSpan.FromSeconds(15) },
            cancellationToken: responseTimeout.Token);
        await client.PingAsync(responseTimeout.Token);
        await client.PublishAsync(subject, request, replyTo: replySubject, cancellationToken: responseTimeout.Token);
        var response = (await subscription.Msgs.ReadAsync(responseTimeout.Token)).Data
            ?? throw new InvalidOperationException("The private journal mutation service returned no reply.");
        if (!replies.Verify(response, NatsOperationJournalMutationRequestDigest.Create(((INatsOperationJournalMutationRequest)request).Authority)))
            throw new InvalidOperationException("The private journal mutation service reply failed authority verification.");
        return response;
    }
}

internal interface INatsOperationJournalMutationRequest
{
    NatsOperationJournalMutationAuthorityProof Authority { get; }
}

internal sealed record NatsOperationJournalCreateRequest(string Key, string Value, NatsOperationJournalMutationAuthorityProof Authority) : INatsOperationJournalMutationRequest;

internal sealed record NatsOperationJournalUpdateRequest(string Key, string Value, ulong Revision, NatsOperationJournalMutationAuthorityProof Authority) : INatsOperationJournalMutationRequest;

internal sealed record NatsOperationJournalMutationReply(bool Succeeded, ulong Revision, string RequestDigest, string Signature)
{
    internal string Payload() => string.Join('|', Succeeded, Revision, RequestDigest);
}

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
    internal string CallerIdentity { get; } = callerIdentity;
    internal NatsOperationJournalMutationAuthorityProof Issue(string cell, string action, string keyName, ulong revision, string value)
    {
        var proof = new NatsOperationJournalMutationAuthorityProof(cell, CallerIdentity, action, keyName, revision,
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value))), Guid.NewGuid().ToString("N"),
            DateTimeOffset.UtcNow.AddMinutes(2), Guid.NewGuid().ToString("N"), string.Empty);
        return proof with { Signature = Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(proof.Payload()), HashAlgorithmName.SHA256)) };
    }
}

internal sealed class NatsOperationJournalMutationAuthorityVerifier(byte[] publicKey)
{
    private readonly byte[] publicKey = publicKey.ToArray();
    internal bool Verify(NatsOperationJournalMutationAuthorityProof? proof, string cell, IReadOnlySet<string> callers, string action, string keyName, ulong revision, string value)
    {
        try
        {
            if (proof is null || proof.Cell != cell || !callers.Contains(proof.CallerIdentity) || proof.Action != action ||
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

internal static class NatsOperationJournalMutationRequestDigest
{
    internal static string Create(NatsOperationJournalMutationAuthorityProof proof) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{proof.Payload()}|{proof.Signature}")));
}

internal sealed class NatsOperationJournalMutationReplySigner(ECDsa key) : IDisposable
{
    internal static NatsOperationJournalMutationReplySigner Load(string path)
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(File.ReadAllText(path));
            return new(key);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }
    internal NatsOperationJournalMutationReply Sign(bool succeeded, ulong revision, string requestDigest)
    {
        var reply = new NatsOperationJournalMutationReply(succeeded, revision, requestDigest, string.Empty);
        return reply with { Signature = Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(reply.Payload()), HashAlgorithmName.SHA256)) };
    }

    internal byte[] ExportPublicKey() => key.ExportSubjectPublicKeyInfo();
    public void Dispose() => key.Dispose();
}

internal sealed class NatsOperationJournalMutationReplyVerifier(byte[] publicKey)
{
    private readonly byte[] publicKey = publicKey.ToArray();

    internal bool Verify(NatsOperationJournalMutationReply? reply, string requestDigest)
    {
        try
        {
            if (reply is null || reply.RequestDigest != requestDigest || string.IsNullOrWhiteSpace(reply.Signature)) return false;
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            return key.VerifyData(Encoding.UTF8.GetBytes(reply.Payload()), Convert.FromBase64String(reply.Signature), HashAlgorithmName.SHA256);
        }
        catch (CryptographicException) { return false; }
        catch (FormatException) { return false; }
    }
}
