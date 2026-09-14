using System.Security.Cryptography;
using System.Diagnostics;
using TerraScale.Orchestrator.ControlPlane.Operations;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class CreateNodeCoordinatorTests
{
    private static readonly DateTimeOffset Start = new(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ReceiptBindsEveryImmutableProviderAndAuthorizationFieldAndSupportsRetainedOldKey()
    {
        using var old = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var current = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var oldSigner = new CreateNodeHandoffReceiptSigner("old", old); var signer = new CreateNodeHandoffReceiptSigner("current", current);
        var keys = new CreateNodeReceiptKeyRing(new Dictionary<string, byte[]> { ["old"] = oldSigner.ExportPublicKey(), ["current"] = signer.ExportPublicKey() });
        var binding = Binding(); var receipt = oldSigner.Sign(binding, Start, Start.AddMinutes(5));
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt, keys, binding, Start.AddMinutes(1))).IsTrue();
        foreach (var changed in Variants(binding)) await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt, keys, changed, Start.AddMinutes(1))).IsFalse();
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt with { KeyId = "missing" }, keys, binding, Start.AddMinutes(1))).IsFalse();
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt with { Algorithm = "RSA" }, keys, binding, Start.AddMinutes(1))).IsFalse();
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(receipt, keys, binding, Start.AddMinutes(5))).IsFalse();
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        await Assert.That(() => new CreateNodeHandoffReceiptSigner("p384", p384)).Throws<ArgumentException>();
        using var tenantKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var tenantSigner = new CreateNodeTenantAuthorizationSigner("tenant", tenantKey);
        var tenantKeys = new CreateNodeTenantAuthorityKeyRing(new Dictionary<string, byte[]> { ["tenant"] = tenantKey.ExportSubjectPublicKeyInfo() });
        var receiptDomainSigner = new CreateNodeTenantAuthorizationSigner("old", old);
        var receiptDomainProof = receiptDomainSigner.Sign("tenant-a", "op-1", "authorization-digest", Start.AddMinutes(5));
        await Assert.That(CreateNodeTenantAuthorizationVerifier.Verify(receiptDomainProof, tenantKeys, "op-1", "authorization-digest", Start, out _)).IsFalse();
        await Assert.That(CreateNodeTenantAuthorizationVerifier.Verify(tenantSigner.Sign("tenant-a", "op-1", "authorization-digest", Start.AddMinutes(5)), tenantKeys, "op-1", "authorization-digest", Start, out _)).IsTrue();
    }

    [Test]
    public async Task CrashAfterProviderSuccessReconcilesWithoutSecondCreateAgainstNonDeduplicatingProvider()
    {
        var clock = new MutableTime(Start); using var trust = new CreateNodeTrust(); var signer = trust.ReceiptSigner;
        var provider = new NonDeduplicatingProvider(trust.ReceiptKeys, trust.RecoveryKeys, trust.ProviderProofSigner, clock); var journal = new DropCompletionJournal(new InMemoryCreateNodeOperationJournal());
        var coordinator = new CreateNodeCoordinator(journal, provider, signer, trust.ReceiptKeys, trust.TenantKeys, trust.ProviderKeys, trust.RecoverySigner, trust.RecoveryKeys, trust.InvocationCapabilityKeys, clock); var first = await coordinator.ExecuteAsync(Dispatch(signer, trust.TenantSigner));
        await Assert.That(first.Disposition).IsEqualTo(CreateNodeCoordinationDisposition.InProgress);
        clock.Advance(TimeSpan.FromMinutes(6));
        var persisted = (await journal.ReadAsync("op-1", default))!;
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(persisted.Receipt, trust.ReceiptKeys, persisted.Binding, clock.GetUtcNow())).IsFalse();
        await Assert.That(CreateNodeRecoveryLookupVerifier.Verify(persisted.RecoveryAuthority, trust.RecoveryKeys, persisted.Binding, clock.GetUtcNow())).IsTrue();
        var recovered = await coordinator.ExecuteAsync(Dispatch(signer, trust.TenantSigner));
        await Assert.That(recovered.Disposition).IsEqualTo(CreateNodeCoordinationDisposition.Completed);
        await Assert.That(provider.CreateCalls).IsEqualTo(1); await Assert.That(provider.ReconcileCalls).IsEqualTo(1);
    }

    [Test]
    public async Task ExpiredInFlightLeaseNotFoundRequiresManualRecoveryAndNeverCreatesAgain()
    {
        var clock = new MutableTime(Start); using var trust = new CreateNodeTrust(); var signer = trust.ReceiptSigner;
        var provider = new NonDeduplicatingProvider(trust.ReceiptKeys, trust.RecoveryKeys, trust.ProviderProofSigner, clock) { ReturnNotFound = true }; var journal = new DropCompletionJournal(new InMemoryCreateNodeOperationJournal());
        var coordinator = new CreateNodeCoordinator(journal, provider, signer, trust.ReceiptKeys, trust.TenantKeys, trust.ProviderKeys, trust.RecoverySigner, trust.RecoveryKeys, trust.InvocationCapabilityKeys, clock); await coordinator.ExecuteAsync(Dispatch(signer, trust.TenantSigner));
        clock.Advance(TimeSpan.FromMinutes(2)); var held = await coordinator.ExecuteAsync(Dispatch(signer, trust.TenantSigner));
        await Assert.That(held.Disposition).IsEqualTo(CreateNodeCoordinationDisposition.RequiresManualRecovery);
        await Assert.That(provider.CreateCalls).IsEqualTo(1); await Assert.That(provider.ReconcileCalls).IsEqualTo(1);
    }

    [Test]
    public async Task ForgedTenantAndMismatchedProviderProofRequireManualRecovery()
    {
        var clock = new MutableTime(Start); using var trust = new CreateNodeTrust(); var signer = trust.ReceiptSigner;
        var provider = new NonDeduplicatingProvider(trust.ReceiptKeys, trust.RecoveryKeys, trust.ProviderProofSigner, clock) { TamperProof = true };
        var journal = new DropCompletionJournal(new InMemoryCreateNodeOperationJournal()); var coordinator = new CreateNodeCoordinator(journal, provider, signer, trust.ReceiptKeys, trust.TenantKeys, trust.ProviderKeys, trust.RecoverySigner, trust.RecoveryKeys, trust.InvocationCapabilityKeys, clock);
        await coordinator.ExecuteAsync(Dispatch(signer, trust.TenantSigner)); clock.Advance(TimeSpan.FromMinutes(2));
        await Assert.That((await coordinator.ExecuteAsync(Dispatch(signer, trust.TenantSigner))).Disposition).IsEqualTo(CreateNodeCoordinationDisposition.RequiresManualRecovery);
        var forged = Dispatch(signer, trust.TenantSigner) with { TenantProof = trust.TenantSigner.Sign("tenant-b", "op-1", "wrong-digest", Start.AddMinutes(5)) };
        Func<Task> executeForged = async () => { await coordinator.ExecuteAsync(forged); };
        await Assert.That(executeForged).Throws<ArgumentException>();
    }

    [Test]
    public async Task TenantProofMustMatchAuthenticatedAuthorizationTenant()
    {
        var clock = new MutableTime(Start); using var trust = new CreateNodeTrust(); var signer = trust.ReceiptSigner; var provider = new NonDeduplicatingProvider(trust.ReceiptKeys, trust.RecoveryKeys, trust.ProviderProofSigner, clock);
        var coordinator = new CreateNodeCoordinator(new InMemoryCreateNodeOperationJournal(), provider, signer, trust.ReceiptKeys, trust.TenantKeys, trust.ProviderKeys, trust.RecoverySigner, trust.RecoveryKeys, trust.InvocationCapabilityKeys, clock); var dispatch = Dispatch(signer, trust.TenantSigner);
        var mismatched = dispatch with { TenantProof = trust.TenantSigner.Sign("tenant-b", dispatch.OperationIntent.OperationId, dispatch.OperationIntent.AuthorizationDigest, Start.AddDays(1)) };
        Func<Task> execute = async () => { await coordinator.ExecuteAsync(mismatched); };
        await Assert.That(execute).Throws<ArgumentException>();
    }

    [Test]
    public async Task FileJournalRejectsTamperedFullRecord()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"create-node-{Guid.NewGuid():N}"); var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            var keys = new CreateNodeJournalTagKeyRing(new Dictionary<string, byte[]> { ["journal"] = key });
            var journal = new TestFileCreateNodeOperationJournal(directory, "journal", key, keys);
            var signerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); var signer = new CreateNodeHandoffReceiptSigner("receipt", signerKey);
            var binding = Binding(); var entry = new CreateNodeOperationJournalEntry(0, "fingerprint", binding, signer.Sign(binding, Start, Start.AddMinutes(5)), new CreateNodeRecoveryLookupSigner("receipt", signerKey).Sign(binding, Start, Start.AddDays(1)), CreateNodeJournalStage.Prepared, null, 0, null);
            await journal.CompareExchangeAsync(null, entry, default);
            var file = Directory.EnumerateFiles(directory, "*.json").Single(); var bytes = await File.ReadAllBytesAsync(file); bytes[^1] ^= 1; await File.WriteAllBytesAsync(file, bytes);
            await Assert.That(() => journal.ReadAsync(binding.OperationId, default).AsTask()).Throws<InvalidDataException>();
            signerKey.Dispose();
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }

    [Test]
    public async Task ExpiredRecoveryAuthorityHoldsEvenWhileMutationReceiptIsStillValid()
    {
        var clock = new MutableTime(Start); using var trust = new CreateNodeTrust(); var signer = trust.ReceiptSigner;
        var provider = new NonDeduplicatingProvider(trust.ReceiptKeys, trust.RecoveryKeys, trust.ProviderProofSigner, clock); var journal = new DropCompletionJournal(new ExpiringRecoveryJournal(new InMemoryCreateNodeOperationJournal(), trust.RecoverySigner, Start.AddMinutes(1)));
        var coordinator = new CreateNodeCoordinator(journal, provider, signer, trust.ReceiptKeys, trust.TenantKeys, trust.ProviderKeys, trust.RecoverySigner, trust.RecoveryKeys, trust.InvocationCapabilityKeys, clock);
        await coordinator.ExecuteAsync(Dispatch(signer, trust.TenantSigner)); clock.Advance(TimeSpan.FromMinutes(2));
        var persisted = (await journal.ReadAsync("op-1", default))!;
        await Assert.That(CreateNodeHandoffReceiptVerifier.Verify(persisted.Receipt, trust.ReceiptKeys, persisted.Binding, clock.GetUtcNow())).IsTrue();
        await Assert.That(CreateNodeRecoveryLookupVerifier.Verify(persisted.RecoveryAuthority, trust.RecoveryKeys, persisted.Binding, clock.GetUtcNow())).IsFalse();
        await Assert.That((await coordinator.ExecuteAsync(Dispatch(signer, trust.TenantSigner))).Disposition).IsEqualTo(CreateNodeCoordinationDisposition.RequiresManualRecovery);
        await Assert.That(provider.ReconcileCalls).IsEqualTo(0);
    }

    [Test]
    public async Task MissingRecoveryAuthorityRequiresManualRecoveryWithoutLookup()
    {
        var clock = new MutableTime(Start); using var trust = new CreateNodeTrust(); var signer = trust.ReceiptSigner;
        var provider = new NonDeduplicatingProvider(trust.ReceiptKeys, trust.RecoveryKeys, trust.ProviderProofSigner, clock); var corrupted = new CorruptingRecoveryJournal(new InMemoryCreateNodeOperationJournal()); var journal = new DropCompletionJournal(corrupted);
        var coordinator = new CreateNodeCoordinator(journal, provider, signer, trust.ReceiptKeys, trust.TenantKeys, trust.ProviderKeys, trust.RecoverySigner, trust.RecoveryKeys, trust.InvocationCapabilityKeys, clock);
        await coordinator.ExecuteAsync(Dispatch(signer, trust.TenantSigner)); corrupted.ReturnMissingRecovery = true; clock.Advance(TimeSpan.FromMinutes(2));
        await Assert.That((await coordinator.ExecuteAsync(Dispatch(signer, trust.TenantSigner))).Disposition).IsEqualTo(CreateNodeCoordinationDisposition.RequiresManualRecovery);
        await Assert.That(provider.ReconcileCalls).IsEqualTo(0);
    }

    [Test]
    public async Task ExternalProviderIsRejectedWithNonCrashDurableJournal()
    {
        var clock = new MutableTime(Start); using var trust = new CreateNodeTrust(); var signer = trust.ReceiptSigner; var client = new OciClient(); var provider = new OciCreateNodeProvider(new(true), client, trust.ReceiptKeys, trust.RecoveryKeys, trust.InvocationCapabilityKeys, new InMemoryCreateNodeOperationJournal(), clock);
        var coordinator = new CreateNodeCoordinator(new InMemoryCreateNodeOperationJournal(), provider, signer, trust.ReceiptKeys, trust.TenantKeys, trust.ProviderKeys, trust.RecoverySigner, trust.RecoveryKeys, trust.InvocationCapabilityKeys, clock);
        Func<Task> execute = async () => { await coordinator.ExecuteAsync(Dispatch(signer, trust.TenantSigner)); };
        await Assert.That(execute).Throws<InvalidOperationException>(); await Assert.That(client.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task OciReconciliationRejectsWrongRecoveryBindingBeforeClientLookup()
    {
        var clock = new MutableTime(Start); using var trust = new CreateNodeTrust(); var signer = trust.ReceiptSigner; var client = new OciClient(); var dispatch = Dispatch(signer, trust.TenantSigner); var binding = Binding();
        var provider = new OciCreateNodeProvider(new(true), client, trust.ReceiptKeys, trust.RecoveryKeys, trust.InvocationCapabilityKeys, new InMemoryCreateNodeOperationJournal(), clock); var request = new CreateNodeProviderRequest(dispatch.ProviderIntent.Context, dispatch.ProviderIntent.Parameters, binding, signer.Sign(binding, Start, Start.AddMinutes(5)), trust.RecoverySigner.Sign(binding with { TenantId = "tenant-b" }, Start, Start.AddDays(1)));
        Func<Task> reconcile = async () => { await provider.ReconcileCreateNodeAsync(request, default); };
        await Assert.That(reconcile).Throws<InvalidOperationException>(); await Assert.That(client.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task DirectEnabledOciCreateRequiresAnAuthoritativeInvocationPermit()
    {
        var clock = new MutableTime(Start); using var trust = new CreateNodeTrust(); var signer = trust.ReceiptSigner; var client = new OciClient(); var dispatch = Dispatch(signer, trust.TenantSigner); var binding = Binding();
        var provider = new OciCreateNodeProvider(new(true), client, trust.ReceiptKeys, trust.RecoveryKeys, trust.InvocationCapabilityKeys, new InMemoryCreateNodeOperationJournal(), clock); var request = new CreateNodeProviderRequest(dispatch.ProviderIntent.Context, dispatch.ProviderIntent.Parameters, binding, signer.Sign(binding, Start, Start.AddMinutes(5)), trust.RecoverySigner.Sign(binding, Start, Start.AddDays(1)));
        Func<Task> create = async () => { await provider.CreateNodeAsync(request, default); };
        await Assert.That(create).Throws<InvalidOperationException>(); await Assert.That(client.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task AuthoritativeInvocationCapabilityConsumesOnlyOnceAndAtItsCheckpointVersion()
    {
        var clock = new MutableTime(Start); using var trust = new CreateNodeTrust(); var authority = new AuthoritativeJournal(trust.InvocationCapabilitySigner); var journal = new DropCompletionJournal(authority); var provider = new NonDeduplicatingProvider(trust.ReceiptKeys, trust.RecoveryKeys, trust.ProviderProofSigner, clock);
        var coordinator = new CreateNodeCoordinator(journal, provider, trust.ReceiptSigner, trust.ReceiptKeys, trust.TenantKeys, trust.ProviderKeys, trust.RecoverySigner, trust.RecoveryKeys, trust.InvocationCapabilityKeys, clock); await coordinator.ExecuteAsync(Dispatch(trust.ReceiptSigner, trust.TenantSigner));
        var checkpoint = (await authority.ReadAsync("op-1", default))!; var capability = await authority.MintInvocationCapabilityAsync(checkpoint, clock.GetUtcNow(), default);
        await Assert.That(await authority.TryConsumeInvocationCapabilityAsync(capability with { JournalVersion = capability.JournalVersion + 1 }, checkpoint.Binding, clock.GetUtcNow(), default)).IsFalse();
        await Assert.That(await authority.TryConsumeInvocationCapabilityAsync(capability, checkpoint.Binding, clock.GetUtcNow(), default)).IsTrue();
        await Assert.That(await authority.TryConsumeInvocationCapabilityAsync(capability, checkpoint.Binding, clock.GetUtcNow(), default)).IsFalse();
        clock.Advance(TimeSpan.FromMinutes(2));
        await Assert.That((await coordinator.ExecuteAsync(Dispatch(trust.ReceiptSigner, trust.TenantSigner))).Disposition).IsEqualTo(CreateNodeCoordinationDisposition.Completed);
        await Assert.That(provider.CreateCalls).IsEqualTo(1); await Assert.That(provider.ReconcileCalls).IsEqualTo(1);
    }

    [Test]
    public async Task DelayedExpiredFirstOwnerCannotInvokeOciAfterPostLeaseRecoveryFinalizes()
    {
        var clock = new MutableTime(Start); using var trust = new CreateNodeTrust(); var authority = new AuthoritativeJournal(trust.InvocationCapabilitySigner); var journal = new DropCompletionJournal(authority); var provider = new NonDeduplicatingProvider(trust.ReceiptKeys, trust.RecoveryKeys, trust.ProviderProofSigner, clock);
        var coordinator = new CreateNodeCoordinator(journal, provider, trust.ReceiptSigner, trust.ReceiptKeys, trust.TenantKeys, trust.ProviderKeys, trust.RecoverySigner, trust.RecoveryKeys, trust.InvocationCapabilityKeys, clock); var dispatch = Dispatch(trust.ReceiptSigner, trust.TenantSigner); await coordinator.ExecuteAsync(dispatch);
        var checkpoint = (await authority.ReadAsync("op-1", default))!; var capability = await authority.MintInvocationCapabilityAsync(checkpoint, clock.GetUtcNow(), default); clock.Advance(TimeSpan.FromMinutes(2));
        await Assert.That((await coordinator.ExecuteAsync(dispatch)).Disposition).IsEqualTo(CreateNodeCoordinationDisposition.Completed);
        var client = new OciClient(); var oci = new OciCreateNodeProvider(new(true), client, trust.ReceiptKeys, trust.RecoveryKeys, trust.InvocationCapabilityKeys, authority, clock); var request = new CreateNodeProviderRequest(dispatch.ProviderIntent.Context, dispatch.ProviderIntent.Parameters, checkpoint.Binding, checkpoint.Receipt, checkpoint.RecoveryAuthority, capability);
        Func<Task> create = async () => { await oci.CreateNodeAsync(request, default); };
        await Assert.That(create).Throws<InvalidOperationException>(); await Assert.That(client.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task CoordinatorRejectsSharedTrustDomainMaterial()
    {
        using var shared = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var providerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var recoveryKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var invocationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var receipt = new CreateNodeHandoffReceiptSigner("shared", shared); var tenant = new CreateNodeTenantAuthorityKeyRing(new Dictionary<string, byte[]> { ["tenant"] = shared.ExportSubjectPublicKeyInfo() });
        Func<CreateNodeCoordinator> compose = () => new CreateNodeCoordinator(new InMemoryCreateNodeOperationJournal(), new NonDeduplicatingProvider(new CreateNodeReceiptKeyRing(new Dictionary<string, byte[]> { ["shared"] = receipt.ExportPublicKey() }), new CreateNodeRecoveryLookupKeyRing(new Dictionary<string, byte[]> { ["recovery"] = recoveryKey.ExportSubjectPublicKeyInfo() }), new CreateNodeProviderProofSigner("provider", providerKey), TimeProvider.System), receipt, new CreateNodeReceiptKeyRing(new Dictionary<string, byte[]> { ["shared"] = receipt.ExportPublicKey() }), tenant, new CreateNodeProviderAttestationKeyRing(new Dictionary<string, byte[]> { ["provider"] = providerKey.ExportSubjectPublicKeyInfo() }), new CreateNodeRecoveryLookupSigner("recovery", recoveryKey), new CreateNodeRecoveryLookupKeyRing(new Dictionary<string, byte[]> { ["recovery"] = recoveryKey.ExportSubjectPublicKeyInfo() }), new CreateNodeAuthoritativeInvocationCapabilityKeyRing(new Dictionary<string, byte[]> { ["invocation"] = invocationKey.ExportSubjectPublicKeyInfo() }), TimeProvider.System);
        await Assert.That(compose).Throws<ArgumentException>();
    }

    [Test]
    [NotInParallel]
    public async Task FileJournalUsesFilesystemCasAcrossTwoProcesses()
    {
        var root = Path.Combine(Path.GetTempPath(), $"create-node-process-{Guid.NewGuid():N}"); Directory.CreateDirectory(root);
        try
        {
            var project = Path.Combine(RepositoryRoot(), "tests", "TerraScale.Orchestrator.ControlPlane.JournalChild", "TerraScale.Orchestrator.ControlPlane.JournalChild.csproj");
            await Run("dotnet", ["build", project], TimeSpan.FromSeconds(120));
            var child = Path.Combine(Path.GetDirectoryName(project)!, "bin", "Debug", "net11.0", "linux-x64", "TerraScale.Orchestrator.ControlPlane.JournalChild.dll");
            var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)); var barrier = Path.Combine(root, "go"); var one = Path.Combine(root, "one"); var two = Path.Combine(root, "two");
            using var first = StartChild(child, root, key, barrier, one, "one"); var firstOutput = CaptureOutputAsync(first);
            using var second = StartChild(child, root, key, barrier, two, "two"); var secondOutput = CaptureOutputAsync(second);
            await WaitForFiles([one + ".ready", two + ".ready"], TimeSpan.FromSeconds(60)); await File.WriteAllTextAsync(barrier, "go");
            await first.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(60)); await second.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(60));
            // The CAS winner exits 0 and the loser exits 1; any other pair means a
            // child failed before writing its verdict, so surface why instead of a
            // bare missing-file error.
            if ((first.ExitCode, second.ExitCode) is not ((0, 1) or (1, 0)))
                throw new InvalidOperationException($"Journal children exited with {first.ExitCode} and {second.ExitCode}; one: {await firstOutput}; two: {await secondOutput}");
            var results = new[] { await File.ReadAllTextAsync(one), await File.ReadAllTextAsync(two) };
            await Assert.That(results.Count(static value => value.Contains("|True|1|op-contention", StringComparison.Ordinal))).IsEqualTo(1);
            await Assert.That(results.Count(static value => value.Contains("|False|1|op-contention", StringComparison.Ordinal))).IsEqualTo(1);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    private static async Task<string> CaptureOutputAsync(Process process) =>
        $"{await process.StandardOutput.ReadToEndAsync()} {await process.StandardError.ReadToEndAsync()}".Trim();

    private static Process StartChild(string child, params string[] arguments)
    { var info = new ProcessStartInfo("dotnet") { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false }; info.ArgumentList.Add(child); foreach (var argument in arguments) info.ArgumentList.Add(argument); return Process.Start(info) ?? throw new InvalidOperationException("Child process did not start."); }
    private static async Task Run(string executable, IEnumerable<string> arguments, TimeSpan timeout)
    { var info = new ProcessStartInfo(executable) { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false }; foreach (var argument in arguments) info.ArgumentList.Add(argument); using var process = Process.Start(info) ?? throw new InvalidOperationException("Build process did not start."); await process.WaitForExitAsync().WaitAsync(timeout); if (process.ExitCode != 0) throw new InvalidOperationException((await process.StandardOutput.ReadToEndAsync()) + (await process.StandardError.ReadToEndAsync())); }
    private static async Task WaitForFiles(IEnumerable<string> paths, TimeSpan timeout)
    { var deadline = DateTime.UtcNow + timeout; while (paths.Any(static path => !File.Exists(path))) { if (DateTime.UtcNow >= deadline) throw new TimeoutException("Journal child did not signal readiness."); await Task.Delay(10); } }
    private static string RepositoryRoot()
    { for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent) if (File.Exists(Path.Combine(directory.FullName, "TerraScale.Orchestrator.slnx"))) return directory.FullName; throw new DirectoryNotFoundException("Repository root not found."); }

    [Test]
    public async Task OciAdapterIsDisabledBeforeAnyClientCall()
    {
        var clock = new MutableTime(Start); using var trust = new CreateNodeTrust(); var signer = trust.ReceiptSigner; var client = new OciClient();
        var provider = new OciCreateNodeProvider(new(false), client, trust.ReceiptKeys, trust.RecoveryKeys, trust.InvocationCapabilityKeys, new InMemoryCreateNodeOperationJournal(), clock); var dispatch = Dispatch(signer, trust.TenantSigner); var binding = Binding(); var request = new CreateNodeProviderRequest(dispatch.ProviderIntent.Context, dispatch.ProviderIntent.Parameters, binding, signer.Sign(binding, Start, Start.AddMinutes(5)), trust.RecoverySigner.Sign(binding, Start, Start.AddDays(1)));
        Func<Task> call = async () => { await provider.CreateNodeAsync(request, default); }; await Assert.That(call).Throws<InvalidOperationException>(); await Assert.That(client.Calls).IsEqualTo(0);
    }

    private static CreateNodeReceiptBinding Binding() => new("op-1", "tenant-a", "node-request-1", "idempotency-1", "create-key-1", "cell-a", "compartment-a", 7, 12, "template-a", "placement-a", new string('a', 64), 2, "authorization-digest", "context-fingerprint");
    private static IEnumerable<CreateNodeReceiptBinding> Variants(CreateNodeReceiptBinding value) => [value with { OperationId = "op-2" }, value with { TenantId = "tenant-b" }, value with { NodeRequestId = "node-2" }, value with { IdempotencyKey = "idempotency-2" }, value with { CreateKey = "create-key-2" }, value with { CellId = "cell-b" }, value with { CompartmentId = "compartment-b" }, value with { Generation = 8 }, value with { Epoch = 13 }, value with { TemplateId = "template-b" }, value with { PlacementId = "placement-b" }, value with { BootstrapEnvelopeDigest = new string('b', 64) }, value with { AuthorizationSequence = 3 }, value with { AuthorizationDigest = "other-digest" }, value with { ProviderContextFingerprint = "other-context" }];
    private static CreateNodeDispatch Dispatch(CreateNodeHandoffReceiptSigner signer, CreateNodeTenantAuthorizationSigner tenantSigner)
    {
        var desired = new DesiredOperation("aggregate", 7, "rv", "create-node", "node-request-1", "present", "payload", "idempotency-1", Start.AddMinutes(5)); var observed = new ObservedResource("aggregate", 7, "rv-1", "obs-1", "node-request-1", "absent", true);
        var history = OperationEngine.Decide([], new PrepareOperation("op-1", 10, Start, desired, observed, ["observe"])).EventsToAppend.ToList(); var evidence = new AuthorizationEvidence(new("aggregate", 7, "rv-2", "obs-2", "node-request-1", "absent", true), "approval", "evidence", true, true, true, true) { TenantId = "tenant-a" };
        history.AddRange(OperationEngine.Decide(history, new AuthorizeOperation("op-1", 11, Start.AddMinutes(1), evidence)).EventsToAppend); var authorization = (OperationAuthorized)history.Last(); var intent = (DispatchProviderIntent)OperationEngine.Decide(history, new RecordDispatch("op-1", 12, Start.AddMinutes(2), "executor", 1)).Intents.Single();
        var context = new ProviderOperationContext(new("op-1"), new("cell-a"), new("compartment-a"), new(12), ProviderResourceKind.Node, ProviderAction.CreateNode, new IdempotentProviderCreate(new("create-key-1")), new(7), ProviderObservedState.Absent, ProviderTerminalState.Present, [ProviderApproval.RegionalAuthority], new(DeadlineEvidenceStatus.Valid, new(7)), new("idempotency-1"), [ProviderCompensation.ObserveOnly], new CreateNodeProviderParameters(new("template-a"), new("placement-a"), new(new string('a', 64))));
        var provider = (CreateNodeProviderIntent)ProviderOwnershipEngine.Authorize(new ProviderAuthorizationRequest(context, new(new("cell-a"), new("compartment-a"), new(12)), [], [], ProviderObservationCompleteness.Complete, [], [new ProviderCreateObservation(new("create-key-1"), new("cell-a"), new("compartment-a"), new(7), ProviderObservedState.Absent, null)], [ProviderApproval.RegionalAuthority], null, new(context, ProviderCallStatus.NotCalled, null))).Intents.Single(); return new(intent, authorization, provider, "node-request-1", tenantSigner.Sign("tenant-a", intent.OperationId, intent.AuthorizationDigest, Start.AddDays(1)));
    }
    private sealed class MutableTime(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; public void Advance(TimeSpan value) => now += value; }
    private sealed class CreateNodeTrust : IDisposable
    {
        private readonly ECDsa receiptKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); private readonly ECDsa tenantKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); private readonly ECDsa providerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); private readonly ECDsa recoveryKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); private readonly ECDsa invocationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public CreateNodeHandoffReceiptSigner ReceiptSigner { get; }
        public CreateNodeTenantAuthorizationSigner TenantSigner { get; }
        public CreateNodeProviderProofSigner ProviderProofSigner { get; }
        public CreateNodeRecoveryLookupSigner RecoverySigner { get; }
        public CreateNodeAuthoritativeInvocationCapabilitySigner InvocationCapabilitySigner { get; }
        public ICreateNodeReceiptKeyResolver ReceiptKeys { get; }
        public ICreateNodeTenantAuthorityKeyResolver TenantKeys { get; }
        public ICreateNodeProviderAttestationKeyResolver ProviderKeys { get; }
        public ICreateNodeRecoveryLookupKeyResolver RecoveryKeys { get; }
        public ICreateNodeAuthoritativeInvocationCapabilityKeyResolver InvocationCapabilityKeys { get; }
        public CreateNodeTrust()
        {
            ReceiptSigner = new("receipt", receiptKey); TenantSigner = new("tenant", tenantKey); ProviderProofSigner = new("provider", providerKey); RecoverySigner = new("recovery", recoveryKey); InvocationCapabilitySigner = new("invocation", invocationKey);
            ReceiptKeys = new CreateNodeReceiptKeyRing(new Dictionary<string, byte[]> { [ReceiptSigner.KeyId] = receiptKey.ExportSubjectPublicKeyInfo() }); TenantKeys = new CreateNodeTenantAuthorityKeyRing(new Dictionary<string, byte[]> { [TenantSigner.KeyId] = tenantKey.ExportSubjectPublicKeyInfo() }); ProviderKeys = new CreateNodeProviderAttestationKeyRing(new Dictionary<string, byte[]> { [ProviderProofSigner.KeyId] = providerKey.ExportSubjectPublicKeyInfo() }); RecoveryKeys = new CreateNodeRecoveryLookupKeyRing(new Dictionary<string, byte[]> { [RecoverySigner.KeyId] = recoveryKey.ExportSubjectPublicKeyInfo() }); InvocationCapabilityKeys = new CreateNodeAuthoritativeInvocationCapabilityKeyRing(new Dictionary<string, byte[]> { ["invocation"] = invocationKey.ExportSubjectPublicKeyInfo() });
        }
        public void Dispose() { receiptKey.Dispose(); tenantKey.Dispose(); providerKey.Dispose(); recoveryKey.Dispose(); invocationKey.Dispose(); }
    }
    private sealed class NonDeduplicatingProvider(ICreateNodeReceiptKeyResolver keys, ICreateNodeRecoveryLookupKeyResolver recoveryKeys, CreateNodeProviderProofSigner proofSigner, TimeProvider clock) : ICreateNodeProvider { private CreateNodeProviderResponse? response; public int CreateCalls { get; private set; } public int ReconcileCalls { get; private set; } public bool ReturnNotFound { get; init; } public bool TamperProof { get; init; } public ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest request, CancellationToken token) { DeterministicCreateNodeProvider.Validate(request, keys, clock.GetUtcNow()); CreateCalls++; return ValueTask.FromResult(response = new(new("node-1"), new("work-1"))); } public ValueTask<CreateNodeReconciliation> ReconcileCreateNodeAsync(CreateNodeProviderRequest request, CancellationToken token) { DeterministicCreateNodeProvider.ValidateRecovery(request, keys, recoveryKeys, clock.GetUtcNow()); ReconcileCalls++; if (ReturnNotFound) return ValueTask.FromResult(new CreateNodeReconciliation(CreateNodeReconciliationStatus.NotFound, null, null)); var proof = proofSigner.Sign(TamperProof ? request.Binding with { TenantId = "tenant-b" } : request.Binding, response!); return ValueTask.FromResult(CreateNodeReconciliation.Found(response!, proof)); } }
    private sealed class DropCompletionJournal(ICreateNodeOperationJournal inner) : ICreateNodeOperationJournal { private bool drop = true; public ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string id, CancellationToken token) => inner.ReadAsync(id, token); public ValueTask<bool> CompareExchangeAsync(CreateNodeOperationJournalEntry? expected, CreateNodeOperationJournalEntry replacement, CancellationToken token) { if (drop && replacement.Stage == CreateNodeJournalStage.Completed) { drop = false; return ValueTask.FromResult(false); } return inner.CompareExchangeAsync(expected, replacement, token); } }
    private sealed class CorruptingRecoveryJournal(ICreateNodeOperationJournal inner) : ICreateNodeOperationJournal
    {
        public bool ReturnMissingRecovery { get; set; }
        public async ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string id, CancellationToken token) { var entry = await inner.ReadAsync(id, token); return ReturnMissingRecovery && entry?.Stage == CreateNodeJournalStage.ProviderCallStarted ? entry with { RecoveryAuthority = null! } : entry; }
        public async ValueTask<bool> CompareExchangeAsync(CreateNodeOperationJournalEntry? expected, CreateNodeOperationJournalEntry replacement, CancellationToken token)
        {
            if (!ReturnMissingRecovery || expected?.Stage != CreateNodeJournalStage.ProviderCallStarted || expected.RecoveryAuthority is not null) return await inner.CompareExchangeAsync(expected, replacement, token);
            var actual = await inner.ReadAsync(expected.Binding.OperationId, token); return actual is not null && await inner.CompareExchangeAsync(actual, replacement with { RecoveryAuthority = actual.RecoveryAuthority }, token);
        }
    }
    private sealed class AuthoritativeJournal(CreateNodeAuthoritativeInvocationCapabilitySigner signer) : ICreateNodeOperationJournal
    {
        private readonly InMemoryCreateNodeOperationJournal inner = new();
        public CreateNodeJournalDurability Durability => CreateNodeJournalDurability.AuthoritativeCrashDurable;
        public ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string id, CancellationToken token) => inner.ReadAsync(id, token);
        public ValueTask<bool> CompareExchangeAsync(CreateNodeOperationJournalEntry? expected, CreateNodeOperationJournalEntry replacement, CancellationToken token) => inner.CompareExchangeAsync(expected, replacement, token);
        public async ValueTask<CreateNodeAuthoritativeInvocationCapability> MintInvocationCapabilityAsync(CreateNodeOperationJournalEntry checkpoint, DateTimeOffset now, CancellationToken token)
        {
            var current = await inner.ReadAsync(checkpoint.Binding.OperationId, token); if (current != checkpoint) throw new InvalidOperationException("Invocation checkpoint is not current.");
            return signer.Sign(current, now, now.AddMinutes(10));
        }
        public async ValueTask<bool> TryConsumeInvocationCapabilityAsync(CreateNodeAuthoritativeInvocationCapability capability, CreateNodeReceiptBinding binding, DateTimeOffset now, CancellationToken token)
        {
            var current = await inner.ReadAsync(capability.OperationId, token);
            if (current is null || current.Stage != CreateNodeJournalStage.ProviderCallStarted || current.InvocationConsumedAt is not null || now >= capability.LeaseExpiresAt || now >= capability.ExpiresAt || current.Binding != binding || current.Version != capability.JournalVersion || current.InvocationLeaseOwner != capability.LeaseOwner || current.InvocationLeaseToken != capability.LeaseToken || current.InvocationCapabilityNonce != capability.Nonce) return false;
            return await inner.CompareExchangeAsync(current, current with { InvocationConsumedAt = now }, token);
        }
    }
    private sealed class ExpiringRecoveryJournal(ICreateNodeOperationJournal inner, CreateNodeRecoveryLookupSigner signer, DateTimeOffset expiry) : ICreateNodeOperationJournal { public ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string id, CancellationToken token) => inner.ReadAsync(id, token); public ValueTask<bool> CompareExchangeAsync(CreateNodeOperationJournalEntry? expected, CreateNodeOperationJournalEntry replacement, CancellationToken token) => inner.CompareExchangeAsync(expected, replacement.Stage == CreateNodeJournalStage.ProviderCallStarted ? replacement with { RecoveryAuthority = signer.Sign(replacement.Binding, replacement.RecoveryAuthority.IssuedAt, expiry) } : replacement, token); }
    private sealed class OciClient : IOciCreateNodeClient { public int Calls { get; private set; } public ValueTask<CreateNodeProviderResponse> CreateNodeAsync(CreateNodeProviderRequest r, CancellationToken t) { Calls++; throw new InvalidOperationException(); } public ValueTask<CreateNodeReconciliation> ReconcileCreateNodeAsync(CreateNodeProviderRequest r, CancellationToken t) { Calls++; throw new InvalidOperationException(); } }
}

