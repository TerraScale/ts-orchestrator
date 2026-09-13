using TerraScale.Orchestrator.ControlPlane.Operations;

namespace TerraScale.Orchestrator.ControlPlane.Providers;

public sealed record CreateNodeProviderRequest(ProviderOperationContext Context, CreateNodeProviderParameters Parameters,
    CreateNodeReceiptBinding Binding, CreateNodeHandoffReceipt Receipt, CreateNodeRecoveryLookupAuthority RecoveryAuthority,
    CreateNodeAuthoritativeInvocationCapability? InvocationCapability = null);
public sealed record CreateNodeProviderResponse(ProviderResourceId NodeId, ProviderWorkRequestId WorkRequestId);
public sealed record CreateNodeProviderReconciliationProof(string Algorithm, string KeyId, CreateNodeReceiptBinding Binding,
    ProviderResourceId NodeId, ProviderWorkRequestId WorkRequestId, string Signature)
{ internal byte[] Payload() => System.Text.Encoding.UTF8.GetBytes(CreateNodeHandoffReceipt.Canonical("create-node-provider-proof-v2", Algorithm, KeyId, Binding.Digest, NodeId.Value, WorkRequestId.Value)); }
public sealed class CreateNodeProviderProofSigner(string keyId, System.Security.Cryptography.ECDsa key)
{ private readonly System.Security.Cryptography.ECDsa key = CreateNodeHandoffReceiptSigner.RequireP256(key); public string KeyId { get; } = keyId; public CreateNodeProviderReconciliationProof Sign(CreateNodeReceiptBinding binding, CreateNodeProviderResponse response) { var unsigned = new CreateNodeProviderReconciliationProof(CreateNodeHandoffReceiptSigner.Algorithm, KeyId, binding, response.NodeId, response.WorkRequestId, string.Empty); return unsigned with { Signature = Convert.ToBase64String(key.SignData(unsigned.Payload(), System.Security.Cryptography.HashAlgorithmName.SHA256)) }; } }
public static class CreateNodeProviderProofVerifier
{ public static bool Verify(CreateNodeProviderReconciliationProof proof, ICreateNodeProviderAttestationKeyResolver keys, CreateNodeReceiptBinding expected) { try { if (proof.Algorithm != CreateNodeHandoffReceiptSigner.Algorithm || proof.Binding != expected || proof.Binding.Digest != expected.Digest || !keys.TryResolve(proof.KeyId, proof.Algorithm, out var bytes)) return false; using var key = System.Security.Cryptography.ECDsa.Create(); key.ImportSubjectPublicKeyInfo(bytes, out _); CreateNodeHandoffReceiptSigner.RequireP256(key); return key.VerifyData(proof.Payload(), Convert.FromBase64String(proof.Signature), System.Security.Cryptography.HashAlgorithmName.SHA256); } catch (System.Security.Cryptography.CryptographicException) { return false; } catch (FormatException) { return false; } catch (ArgumentException) { return false; } } }
public enum CreateNodeReconciliationStatus { Found = 1, NotFound = 2, Unknown = 3 }
public sealed record CreateNodeReconciliation(CreateNodeReconciliationStatus Status, CreateNodeProviderResponse? Response, CreateNodeProviderReconciliationProof? Proof)
{
    public static CreateNodeReconciliation Found(CreateNodeProviderResponse response, CreateNodeProviderReconciliationProof proof) => new(CreateNodeReconciliationStatus.Found, response, proof);
}

/// <summary>A provider must reconcile a recorded create key; the coordinator never retries a CreateNode mutation.</summary>
public interface ICreateNodeProvider
{
    bool IsExternalMutationProvider => false;
    ICreateNodeOperationJournal? InvocationJournal => null;
    ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken);
    ValueTask<CreateNodeReconciliation> ReconcileCreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken);
}

public sealed class DeterministicCreateNodeProvider(ICreateNodeReceiptKeyResolver keys, ICreateNodeRecoveryLookupKeyResolver recoveryKeys, CreateNodeProviderProofSigner proofSigner, TimeProvider clock) : ICreateNodeProvider
{
    private readonly ICreateNodeReceiptKeyResolver keys = keys ?? throw new ArgumentNullException(nameof(keys));
    private readonly TimeProvider clock = clock ?? throw new ArgumentNullException(nameof(clock));
    private readonly CreateNodeProviderProofSigner proofSigner = proofSigner ?? throw new ArgumentNullException(nameof(proofSigner));
    private readonly ICreateNodeRecoveryLookupKeyResolver recoveryKeys = recoveryKeys ?? throw new ArgumentNullException(nameof(recoveryKeys));
    private readonly Dictionary<string, CreateNodeProviderResponse> results = new(StringComparer.Ordinal);
    public bool IsExternalMutationProvider => false;
    public int CreateCallCount { get; private set; }
    public ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); Validate(request, keys, clock.GetUtcNow());
        // Deliberately not idempotent: tests prove the coordinator never issues a second call.
        CreateCallCount++;
        var response = new CreateNodeProviderResponse(new($"fake-node-{request.Context.OperationId.Value}"), new($"fake-work-{request.Context.OperationId.Value}"));
        results.Add(request.Binding.CreateKey, response); return ValueTask.FromResult(response);
    }
    public ValueTask<CreateNodeReconciliation> ReconcileCreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); ValidateRecovery(request, keys, recoveryKeys, clock.GetUtcNow());
        return ValueTask.FromResult(results.TryGetValue(request.Binding.CreateKey, out var response)
            ? CreateNodeReconciliation.Found(response, proofSigner.Sign(request.Binding, response)) : new(CreateNodeReconciliationStatus.NotFound, null, null));
    }
    internal static void Validate(CreateNodeProviderRequest request, ICreateNodeReceiptKeyResolver keys, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(request.Context); ArgumentNullException.ThrowIfNull(request.Parameters);
        if (request.Context.Action != ProviderAction.CreateNode || request.Context.ResourceKind != ProviderResourceKind.Node ||
            request.Context.ActionParameters != request.Parameters || request.Context.Target is not IdempotentProviderCreate create ||
            create.Key.Value != request.Binding.CreateKey || request.Context.OperationId.Value != request.Binding.OperationId ||
            request.Context.IdempotencyKey.Value != request.Binding.IdempotencyKey || request.Context.CellId.Value != request.Binding.CellId ||
            request.Context.CompartmentId.Value != request.Binding.CompartmentId || request.Context.ExpectedGeneration.Value != request.Binding.Generation ||
            request.Context.ControllerEpoch.Value != request.Binding.Epoch || request.Parameters.TemplateId.Value != request.Binding.TemplateId ||
            request.Parameters.PlacementId.Value != request.Binding.PlacementId || request.Parameters.BootstrapEnvelopeDigest.Sha256 != request.Binding.BootstrapEnvelopeDigest || request.Context.Fingerprint != request.Binding.ProviderContextFingerprint ||
            !CreateNodeHandoffReceiptVerifier.Verify(request.Receipt, keys, request.Binding, now))
            throw new InvalidOperationException("CreateNode provider request is not the exact signed authorized handoff.");
    }
    internal static void ValidateRecovery(CreateNodeProviderRequest request, ICreateNodeReceiptKeyResolver keys, ICreateNodeRecoveryLookupKeyResolver recoveryKeys, DateTimeOffset now)
    { if (!CreateNodeRecoveryLookupVerifier.Verify(request.RecoveryAuthority, recoveryKeys, request.Binding, now)) throw new InvalidOperationException("CreateNode recovery authority is invalid."); if (request.Context.Fingerprint != request.Binding.ProviderContextFingerprint) throw new InvalidOperationException("CreateNode recovery context differs."); }
}

public sealed record OciCreateNodeProviderOptions(bool Enabled);
public interface IOciCreateNodeClient
{
    ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken);
    ValueTask<CreateNodeReconciliation> ReconcileCreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken);
}
/// <summary>Disabled by default; no production OCI mutation client is wired in this slice.</summary>
public sealed class OciCreateNodeProvider(OciCreateNodeProviderOptions options, IOciCreateNodeClient client,
    ICreateNodeReceiptKeyResolver keys, ICreateNodeRecoveryLookupKeyResolver recoveryKeys, ICreateNodeAuthoritativeInvocationCapabilityKeyResolver invocationCapabilityKeys, ICreateNodeOperationJournal invocationJournal, TimeProvider clock) : ICreateNodeProvider
{
    private readonly OciCreateNodeProviderOptions options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly IOciCreateNodeClient client = client ?? throw new ArgumentNullException(nameof(client));
    private readonly ICreateNodeReceiptKeyResolver keys = keys ?? throw new ArgumentNullException(nameof(keys));
    private readonly ICreateNodeRecoveryLookupKeyResolver recoveryKeys = recoveryKeys ?? throw new ArgumentNullException(nameof(recoveryKeys));
    private readonly ICreateNodeAuthoritativeInvocationCapabilityKeyResolver invocationCapabilityKeys = invocationCapabilityKeys ?? throw new ArgumentNullException(nameof(invocationCapabilityKeys));
    private readonly ICreateNodeOperationJournal invocationJournal = invocationJournal ?? throw new ArgumentNullException(nameof(invocationJournal));
    private readonly TimeProvider clock = clock ?? throw new ArgumentNullException(nameof(clock));
    private readonly bool distinctKeyDomains = ValidateKeyDomains(keys, recoveryKeys, invocationCapabilityKeys);
    public bool IsExternalMutationProvider => true;
    public ICreateNodeOperationJournal InvocationJournal => invocationJournal;
    public async ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken)
    { if (!options.Enabled) throw new InvalidOperationException("OCI CreateNode is disabled."); DeterministicCreateNodeProvider.Validate(request, keys, clock.GetUtcNow()); var now = clock.GetUtcNow(); if (invocationJournal.Durability != CreateNodeJournalDurability.AuthoritativeCrashDurable || !CreateNodeAuthoritativeInvocationCapabilityVerifier.Verify(request.InvocationCapability, invocationCapabilityKeys, request.Binding, now) || !await invocationJournal.TryConsumeInvocationCapabilityAsync(request.InvocationCapability!, request.Binding, now, cancellationToken)) throw new InvalidOperationException("OCI CreateNode requires an unconsumed authoritative invocation capability."); return await client.CreateNodeAsync(request, cancellationToken); }
    public ValueTask<CreateNodeReconciliation> ReconcileCreateNodeAsync(CreateNodeProviderRequest request, CancellationToken cancellationToken)
    { if (!options.Enabled) throw new InvalidOperationException("OCI CreateNode is disabled."); DeterministicCreateNodeProvider.ValidateRecovery(request, keys, recoveryKeys, clock.GetUtcNow()); return client.ReconcileCreateNodeAsync(request, cancellationToken); }
    private static bool ValidateKeyDomains(ICreateNodeReceiptKeyResolver receiptKeys, ICreateNodeRecoveryLookupKeyResolver recoveryKeys, ICreateNodeAuthoritativeInvocationCapabilityKeyResolver invocationCapabilityKeys)
    { CreateNodeKeyDomainValidator.EnsureDistinct(receiptKeys, recoveryKeys, invocationCapabilityKeys); return true; }
}

