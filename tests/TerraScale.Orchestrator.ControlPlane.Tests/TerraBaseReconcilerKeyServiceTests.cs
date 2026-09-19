using System.Security.Cryptography;
using TerraScale.Orchestrator.ControlPlane;
using TerraScale.Orchestrator.ControlPlane.Operations;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class TerraBaseReconcilerKeyServiceTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 9, 19, 12, 0, 0, TimeSpan.Zero);
    private readonly List<ECDsa> keys = [];
    private readonly string directory = Path.Combine(Path.GetTempPath(), $"terrabase-keys-{Guid.NewGuid():N}");

    [Test]
    public async Task Configuration_is_all_five_distinct_key_files_or_none()
    {
        var none = TerraBaseReconcilerKeyConfiguration.Resolve(static _ => null);
        await Assert.That(none).IsNull();

        var paths = new[]
        {
            TerraBaseReconcilerKeyConfiguration.ReceiptKeyFileVariable,
            TerraBaseReconcilerKeyConfiguration.TenantKeyFileVariable,
            TerraBaseReconcilerKeyConfiguration.ProviderKeyFileVariable,
            TerraBaseReconcilerKeyConfiguration.RecoveryKeyFileVariable,
            TerraBaseReconcilerKeyConfiguration.InvocationKeyFileVariable,
        };
        await Assert.That(() => TerraBaseReconcilerKeyConfiguration.Resolve(
                variable => paths[0] == variable ? "a.pem" : null))
            .Throws<ArgumentException>();
        await Assert.That(() => TerraBaseReconcilerKeyConfiguration.Resolve(
                variable => paths.Contains(variable) ? "shared.pem" : null))
            .Throws<ArgumentException>();
        await Assert.That(TerraBaseReconcilerKeyConfiguration.Resolve(
            variable => paths.Contains(variable) ? $"{variable.ToLowerInvariant()}.pem" : null))
            .IsNotNull();
    }

    [Test]
    public async Task Every_domain_signs_and_verifies_through_its_own_material()
    {
        var (service, _) = OpenService();
        using var owned = service;
        var binding = Binding();

        var receipt = service.ReceiptSigner.Sign(binding, Now, Now.AddMinutes(5));
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt, service.ReceiptKeys, binding, Now))
            .IsTrue();

        var tenant = service.TenantSigner.Sign("tenant-a", "op-1", "digest-1", Now.AddDays(1));
        await Assert.That(CreateNodeTenantAuthorizationVerifier.Verify(
            tenant, service.TenantKeys, "op-1", "digest-1", Now, out var tenantId)).IsTrue();
        await Assert.That(tenantId).IsEqualTo("tenant-a");

        var recovery = service.RecoverySigner.Sign(binding, Now, Now.AddDays(1));
        await Assert.That(CreateNodeRecoveryLookupVerifier.Verify(recovery, service.RecoveryKeys, binding, Now))
            .IsTrue();

        var response = new CreateNodeProviderResponse(new("ocid1.instance.oc1..i"), new("work-1"));
        var proof = service.ProofSigner.Sign(binding, response);
        await Assert.That(CreateNodeProviderProofVerifier.Verify(proof, service.ProviderKeys, binding)).IsTrue();

        var checkpoint = new CreateNodeOperationJournalEntry(
            1, "fingerprint", binding, receipt, recovery, CreateNodeJournalStage.ProviderCallStarted,
            Now, 1, null, "lease-owner", "lease-token", "nonce", Now.AddMinutes(5));
        var capability = service.InvocationCapabilitySigner.Sign(checkpoint, Now, Now.AddMinutes(5));
        await Assert.That(CreateNodeAuthoritativeInvocationCapabilityVerifier.Verify(
            capability, service.InvocationCapabilityKeys, binding, Now)).IsTrue();
    }

    [Test]
    public async Task Shared_material_between_two_domains_fails_closed()
    {
        var shared = PrivatePem();
        var files = Files(shared, PrivatePem(), shared, PrivatePem(), PrivatePem());
        await Assert.That(() => TerraBaseReconcilerKeyService.Open(
                TerraBaseReconcilerKeyConfiguration.Resolve(Files(files))!))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task Key_files_must_be_owner_private_p256_material()
    {
        var (service, files) = OpenService();
        using var owned = service;

        // A group-readable key file is exactly the credential the composition must refuse.
        var permissive = Path.Combine(directory, "permissive.pem");
        await File.WriteAllTextAsync(permissive, PrivatePem());
        OwnerPrivate(permissive,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        files[TerraBaseReconcilerKeyConfiguration.ReceiptKeyFileVariable] = permissive;
        await Assert.That(() => TerraBaseReconcilerKeyService.Open(
                TerraBaseReconcilerKeyConfiguration.Resolve(Files(files))!))
            .Throws<ArgumentException>();

        var notAKey = Path.Combine(directory, "not-a-key.pem");
        await File.WriteAllTextAsync(notAKey, "not a pem key");
        OwnerPrivate(notAKey, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        files[TerraBaseReconcilerKeyConfiguration.ReceiptKeyFileVariable] = notAKey;
        await Assert.That(() => TerraBaseReconcilerKeyService.Open(
                TerraBaseReconcilerKeyConfiguration.Resolve(Files(files))!))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task The_reconciler_composition_executes_a_create_end_to_end()
    {
        var (service, _) = OpenService();
        using var owned = service;
        var client = new RecordingClient();
        var clock = new MutableTime(Now);
        var journal = new AuthoritativeJournal(service.InvocationCapabilitySigner);

        var coordinator = OciCreateNodeComposition.ForReconciler(client, journal, service, clock);
        var result = await coordinator.ExecuteAsync(Dispatch(service.TenantSigner));

        await Assert.That(result.Disposition).IsEqualTo(CreateNodeCoordinationDisposition.Completed);
        await Assert.That(result.Entry.Stage).IsEqualTo(CreateNodeJournalStage.Completed);
        await Assert.That(client.Creates).IsEqualTo(1);
        await Assert.That(result.Entry.Response!.NodeId.Value).IsEqualTo("ocid1.instance.oc1..i");
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(directory, true);
        }
        catch (DirectoryNotFoundException)
        {
        }

        foreach (var key in keys) key.Dispose();
    }

    private static CreateNodeReceiptBinding Binding() => new(
        "op-1", "tenant-a", "node-request-1", "idempotency-1", "create-key-1",
        "cell-a", "ocid1.compartment.oc1..member", 7, 12, "template-member-gru", "placement-a",
        new string('a', 64), 1, "auth-digest-1", "fingerprint-1");

    private string PrivatePem()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        keys.Add(key);
        return key.ExportPkcs8PrivateKeyPem();
    }

    private Dictionary<string, string> Files(
        string receipt, string tenant, string provider, string recovery, string invocation)
    {
        Directory.CreateDirectory(directory);
        var files = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, pem) in new[]
        {
            (TerraBaseReconcilerKeyConfiguration.ReceiptKeyFileVariable, receipt),
            (TerraBaseReconcilerKeyConfiguration.TenantKeyFileVariable, tenant),
            (TerraBaseReconcilerKeyConfiguration.ProviderKeyFileVariable, provider),
            (TerraBaseReconcilerKeyConfiguration.RecoveryKeyFileVariable, recovery),
            (TerraBaseReconcilerKeyConfiguration.InvocationKeyFileVariable, invocation),
        })
        {
            var path = Path.Combine(directory, $"{name.ToLowerInvariant()}-{Guid.NewGuid():N}.pem");
            File.WriteAllText(path, pem);
            OwnerPrivate(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            files[name] = path;
        }

        return files;
    }

    private static void OwnerPrivate(string path, UnixFileMode mode)
    {
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, mode);
    }

    private (TerraBaseReconcilerKeyService Service, Dictionary<string, string> Files) OpenService()
    {
        var files = Files(PrivatePem(), PrivatePem(), PrivatePem(), PrivatePem(), PrivatePem());
        return (TerraBaseReconcilerKeyService.Open(
            TerraBaseReconcilerKeyConfiguration.Resolve(Files(files))!), files);
    }

    private static Func<string, string?> Files(Dictionary<string, string> files) =>
        variable => files.GetValueOrDefault(variable);

    /// <summary>The exact authorized dispatch the reconciler assembles for one member-host create.</summary>
    private static CreateNodeDispatch Dispatch(CreateNodeTenantAuthorizationSigner tenantSigner)
    {
        var desired = new DesiredOperation(
            "aggregate", 7, "rv", "create-node", "node-request-1", "present", "payload", "idempotency-1",
            Now.AddMinutes(5));
        var observed = new ObservedResource("aggregate", 7, "rv-1", "obs-1", "node-request-1", "absent", true);
        var history = OperationEngine.Decide([], new PrepareOperation("op-1", 10, Now, desired, observed, ["observe"]))
            .EventsToAppend.ToList();
        var evidence = new AuthorizationEvidence(
            new("aggregate", 7, "rv-2", "obs-2", "node-request-1", "absent", true),
            "approval", "evidence", true, true, true, true) { TenantId = "tenant-a" };
        history.AddRange(OperationEngine.Decide(
            history, new AuthorizeOperation("op-1", 11, Now.AddMinutes(1), evidence)).EventsToAppend);
        var authorization = (OperationAuthorized)history.Last();
        var intent = (DispatchProviderIntent)OperationEngine.Decide(
            history, new RecordDispatch("op-1", 12, Now.AddMinutes(2), "executor", 1)).Intents.Single();
        var context = new ProviderOperationContext(
            new("op-1"), new("cell-a"), new("ocid1.compartment.oc1..member"), new(12),
            ProviderResourceKind.Node, ProviderAction.CreateNode,
            new IdempotentProviderCreate(new("create-key-1")), new(7),
            ProviderObservedState.Absent, ProviderTerminalState.Present, [ProviderApproval.RegionalAuthority],
            new(DeadlineEvidenceStatus.Valid, new(7)), new("idempotency-1"), [ProviderCompensation.ObserveOnly],
            new CreateNodeProviderParameters(new("template-member-gru"), new("placement-a"), new(new string('a', 64))));
        var provider = (CreateNodeProviderIntent)ProviderOwnershipEngine.Authorize(new ProviderAuthorizationRequest(
            context,
            new(new("cell-a"), new("ocid1.compartment.oc1..member"), new(12)),
            [], [], ProviderObservationCompleteness.Complete, [],
            [new ProviderCreateObservation(
                new("create-key-1"), new("cell-a"), new("ocid1.compartment.oc1..member"), new(7),
                ProviderObservedState.Absent, null)],
            [ProviderApproval.RegionalAuthority], null, new(context, ProviderCallStatus.NotCalled, null))).Intents.Single();
        return new(intent, authorization, provider, "node-request-1",
            tenantSigner.Sign("tenant-a", intent.OperationId, intent.AuthorizationDigest, Now.AddDays(1)));
    }

    private sealed class AuthoritativeJournal(
        CreateNodeAuthoritativeInvocationCapabilitySigner signer) : ICreateNodeOperationJournal
    {
        private readonly InMemoryCreateNodeOperationJournal inner = new();

        public CreateNodeJournalDurability Durability => CreateNodeJournalDurability.AuthoritativeCrashDurable;

        public ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string id, CancellationToken token) =>
            inner.ReadAsync(id, token);

        public ValueTask<bool> CompareExchangeAsync(
            CreateNodeOperationJournalEntry? expected, CreateNodeOperationJournalEntry replacement,
            CancellationToken token) => inner.CompareExchangeAsync(expected, replacement, token);

        public async ValueTask<CreateNodeAuthoritativeInvocationCapability> MintInvocationCapabilityAsync(
            CreateNodeOperationJournalEntry checkpoint, DateTimeOffset now, CancellationToken token)
        {
            var current = await inner.ReadAsync(checkpoint.Binding.OperationId, token);
            if (current != checkpoint)
                throw new InvalidOperationException("Invocation checkpoint is not current.");
            return signer.Sign(current, now, now.AddMinutes(10));
        }

        public async ValueTask<bool> TryConsumeInvocationCapabilityAsync(
            CreateNodeAuthoritativeInvocationCapability capability, CreateNodeReceiptBinding binding,
            DateTimeOffset now, CancellationToken token)
        {
            var current = await inner.ReadAsync(capability.OperationId, token);
            if (current is null || current.Stage != CreateNodeJournalStage.ProviderCallStarted ||
                current.InvocationConsumedAt is not null || now >= capability.LeaseExpiresAt ||
                now >= capability.ExpiresAt || current.Binding != binding ||
                current.Version != capability.JournalVersion ||
                current.InvocationLeaseOwner != capability.LeaseOwner ||
                current.InvocationLeaseToken != capability.LeaseToken ||
                current.InvocationCapabilityNonce != capability.Nonce)
                return false;
            return await inner.CompareExchangeAsync(current, current with { InvocationConsumedAt = now }, token);
        }
    }

    private sealed class MutableTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class RecordingClient : IOciCreateNodeClient
    {
        public int Creates { get; private set; }

        public ValueTask<CreateNodeProviderResponse> CreateNodeAsync(
            CreateNodeProviderRequest request, CancellationToken cancellationToken)
        {
            Creates++;
            return ValueTask.FromResult(new CreateNodeProviderResponse(
                new("ocid1.instance.oc1..i"), new("work-1")));
        }

        public ValueTask<CreateNodeReconciliation> ReconcileCreateNodeAsync(
            CreateNodeProviderRequest request, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new CreateNodeReconciliation(CreateNodeReconciliationStatus.NotFound, null, null));
    }
}
