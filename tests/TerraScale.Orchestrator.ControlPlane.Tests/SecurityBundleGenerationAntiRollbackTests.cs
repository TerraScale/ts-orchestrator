using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Security;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class SecurityBundleGenerationAntiRollbackTests
{
    [Test]
    public async Task Lower_survival_bundle_generation_is_rejected_after_a_higher_generation_was_accepted()
    {
        var decision = SecurityDecisionEngine.EvaluateSurvivalSecrets(Request(candidate: 6, current: 7));

        await Assert.That(decision.Authorized).IsFalse();
        await Assert.That(decision.Intent).IsTypeOf<HoldSecurityOperationIntent>();
        await Assert.That(decision.Trace.Select(reason => reason.Code).SequenceEqual(new[]
        {
            SecurityDecisionCode.EvidenceUnique,
            SecurityDecisionCode.SurvivalReferencesExact,
            SecurityDecisionCode.BundleGenerationNotRollback,
        })).IsTrue();
        await Assert.That(decision.Trace[2].Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(decision.Trace[2].Observed).IsEqualTo(6UL);
        await Assert.That(decision.Trace[2].Required).IsEqualTo(7UL);
    }

    [Test]
    public async Task Equal_retry_and_non_contiguous_forward_generation_are_accepted()
    {
        foreach (var request in new[] { Request(candidate: 7, current: 7), Request(candidate: 12, current: 7) })
        {
            var decision = SecurityDecisionEngine.EvaluateSurvivalSecrets(request);

            await Assert.That(decision.Authorized).IsTrue();
            await Assert.That(decision.Intent).IsTypeOf<AcceptSurvivalSecretReferencesIntent>();
            await Assert.That(ReferenceEquals(((AcceptSurvivalSecretReferencesIntent)decision.Intent).Request, request)).IsTrue();
            await Assert.That(decision.Trace.Count).IsEqualTo(3);
            await Assert.That(decision.Trace.All(reason => reason.Outcome == SecurityDecisionOutcome.Passed)).IsTrue();
        }
    }

    [Test]
    public async Task Bundle_high_water_is_required_get_only_culture_stable_and_code_ids_are_append_only()
    {
        await Assert.That(Throws<ArgumentNullException>(() => new SurvivalSecretRequest(
            Operation,
            Cell,
            new(7),
            null!,
            PolicyGeneration,
            [Reference],
            [Metadata],
            [Policy]))).IsTrue();

        var property = typeof(SurvivalSecretRequest).GetProperty(nameof(SurvivalSecretRequest.CurrentAcceptedBundleGeneration));
        await Assert.That(property).IsNotNull();
        await Assert.That(property!.SetMethod).IsNull();
        await Assert.That(Enum.GetValues<SecurityDecisionCode>().Select(value => (int)value).ToArray())
            .IsEquivalentTo(Enumerable.Range(1, 28).ToArray());

        string? baseline = null;
        foreach (var cultureName in new[] { "en-US", "tr-TR", "ar-SA", "ja-JP" })
        {
            var original = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
                var decision = SecurityDecisionEngine.EvaluateSurvivalSecrets(Request(candidate: 6, current: 7));
                var fingerprint = string.Join(';', decision.Trace.Select(reason =>
                    $"{reason.Code}:{reason.Outcome}:{reason.Observed}:{reason.Required}"));
                baseline ??= fingerprint;
                await Assert.That(fingerprint).IsEqualTo(baseline);
            }
            finally
            {
                CultureInfo.CurrentCulture = original;
            }
        }
    }

    private static SurvivalSecretRequest Request(ulong candidate, ulong current) => new(
        Operation,
        Cell,
        new(candidate),
        new(current),
        PolicyGeneration,
        [Reference],
        [Metadata],
        [Policy]);

    private static readonly SecurityOperationId Operation = new("survival-operation");
    private static readonly SecurityCellId Cell = new("gru");
    private static readonly SecurityGeneration PolicyGeneration = new(3);
    private static readonly SecuritySecretId SecretId = new("database-credential");
    private static readonly SecretVersion Version = new(4);
    private static readonly SecurityDigest CiphertextDigest = new(new string('a', 64));
    private static readonly SurvivalSecretReference Reference = new(
        SecretId,
        Version,
        Cell,
        SecurityEnvironment.Recovery,
        SecretPurpose.Database,
        CiphertextDigest);
    private static readonly EncryptedSecretMetadata Metadata = new(
        SecretId,
        Version,
        Cell,
        SecurityEnvironment.Recovery,
        SecretPurpose.Database,
        new SecurityKeyId("regional-wrapping-key"),
        CiphertextDigest,
        SecretAvailability.Available);
    private static readonly SecretRetentionPolicy Policy = new(
        PolicyGeneration,
        SecretId,
        Cell,
        SecurityEnvironment.Recovery,
        SecretPurpose.Database,
        [Version],
        new SecurityDurationSeconds(300),
        EvidenceStatus.Valid);

    private static bool Throws<T>(Action action) where T : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (T)
        {
            return true;
        }
    }
}
