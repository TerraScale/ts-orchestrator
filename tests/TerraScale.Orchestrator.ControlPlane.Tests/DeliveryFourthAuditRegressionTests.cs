using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class DeliveryFourthAuditRegressionTests
{
    [Test]
    public async Task Accepted_stage_retains_exact_inputs_and_preserves_compatibility_getters()
    {
        var cells = new[] { new DeliveryCellId("sfo"), new DeliveryCellId("fra") };
        var release = Release(cells: cells);
        var selected = Availability(release, cells[0]);
        var unselected = Availability(release, cells[1]);

        var stage = Stage(release, [unselected, selected]);
        cells[0] = new("mutated-after-construction");

        await Assert.That(ReferenceEquals(stage.ReleaseSpec, release)).IsTrue();
        await Assert.That(ReferenceEquals(stage.Availability, selected)).IsTrue();
        await Assert.That(stage.Release).IsEqualTo(release.Release);
        await Assert.That(stage.Operation).IsEqualTo(release.Operation);
        await Assert.That(stage.Cell).IsEqualTo(selected.Cell);
        await Assert.That(stage.Generation).IsEqualTo(release.Generation);
        await Assert.That(stage.Artifact).IsEqualTo(release.Artifact);
        await Assert.That(stage.Digest).IsEqualTo(release.Digest);
        await Assert.That(stage.SigningIdentity).IsEqualTo(release.SigningIdentity);
        await Assert.That(stage.Signature).IsEqualTo(release.Signature);
        await Assert.That(stage.Architecture).IsEqualTo(release.Architecture);
        await Assert.That(stage.RollbackArtifact).IsEqualTo(release.RollbackArtifact);
        await Assert.That(stage.RollbackDigest).IsEqualTo(release.RollbackDigest);
        await Assert.That(stage.RollbackSigningIdentity).IsEqualTo(release.RollbackSigningIdentity);
        await Assert.That(stage.RollbackSignature).IsEqualTo(release.RollbackSignature);
        await Assert.That(stage.RollbackArchitecture).IsEqualTo(release.RollbackArchitecture);
        await Assert.That(stage.ReleaseSpec.OrderedCells[0].Value).IsEqualTo("sfo");
    }

    [Test]
    public async Task Stage_provenance_distinguishes_all_strategies_rollback_policies_and_cell_order()
    {
        var strategies = Enum.GetValues<RolloutStrategy>().Where(value => value != RolloutStrategy.Unspecified).ToArray();
        var strategyFingerprints = strategies.Select(strategy => DeliveryStageFingerprint.Create(Stage(Release(strategy: strategy)))).ToArray();
        var policies = Enum.GetValues<RollbackPolicy>().Where(value => value != RollbackPolicy.Unspecified).ToArray();
        var policyFingerprints = policies
            .Select(policy => DeliveryStageFingerprint.Create(Stage(Release(policy: policy)))).ToArray();
        var reversed = DeliveryStageFingerprint.Create(Stage(Release(cells: [new("fra"), new("sfo")])));
        var baseline = DeliveryStageFingerprint.Create(Stage(Release()));

        await Assert.That(strategies.Length).IsEqualTo(4);
        await Assert.That(strategyFingerprints.Distinct(StringComparer.Ordinal).Count()).IsEqualTo(4);
        await Assert.That(policyFingerprints.Distinct(StringComparer.Ordinal).Count()).IsEqualTo(policyFingerprints.Length);
        await Assert.That(reversed).IsNotEqualTo(baseline);
    }

    [Test]
    public async Task Stage_fingerprint_changes_for_every_release_and_availability_field()
    {
        var values = ReleaseValues.Default;
        var release = values.Create();
        var availability = Availability(release, release.OrderedCells[0]);
        var baseline = DeliveryStageFingerprint.Create(release, availability);
        var releaseVariants = new[]
        {
            values with { Release = new("release-other") },
            values with { Operation = new("operation-other") },
            values with { Generation = 8 },
            values with { Artifact = new("artifact-other") },
            values with { Digest = new("digest-other") },
            values with { SigningIdentity = new("signer-other") },
            values with { Signature = new("signature-other") },
            values with { Architecture = DeliveryArchitecture.LinuxX64 },
            values with { RollbackArtifact = new("rollback-artifact-other") },
            values with { RollbackDigest = new("rollback-digest-other") },
            values with { RollbackSigningIdentity = new("rollback-signer-other") },
            values with { RollbackSignature = new("rollback-signature-other") },
            values with { RollbackArchitecture = DeliveryArchitecture.LinuxX64 },
            values with { Strategy = RolloutStrategy.BlueGreen },
            values with { RollbackPolicy = RollbackPolicy.HoldForApproval },
            values with { OrderedCells = [new("sfo")] },
            values with { OrderedCells = [new("fra"), new("sfo")] },
            values with { OrderedCells = [new("other"), new("fra")] },
        };
        var availabilityVariants = new[]
        {
            availability with { Release = new("release-other") },
            availability with { Operation = new("operation-other") },
            availability with { Generation = 8 },
            availability with { Cell = new("fra") },
            availability with { ForwardArtifact = new("artifact-other") },
            availability with { ForwardDigest = new("digest-other") },
            availability with { ForwardSigningIdentity = new("signer-other") },
            availability with { ForwardSignature = new("signature-other") },
            availability with { ForwardArchitecture = DeliveryArchitecture.LinuxX64 },
            availability with { RollbackArtifact = new("rollback-artifact-other") },
            availability with { RollbackDigest = new("rollback-digest-other") },
            availability with { RollbackSigningIdentity = new("rollback-signer-other") },
            availability with { RollbackSignature = new("rollback-signature-other") },
            availability with { RollbackArchitecture = DeliveryArchitecture.LinuxX64 },
            availability with { ForwardAvailable = false },
            availability with { RollbackAvailable = false },
        };

        foreach (var variant in releaseVariants)
            await Assert.That(DeliveryStageFingerprint.Create(variant.Create(), availability)).IsNotEqualTo(baseline);
        foreach (var variant in availabilityVariants)
            await Assert.That(DeliveryStageFingerprint.Create(release, variant)).IsNotEqualTo(baseline);
    }

    [Test]
    public async Task Complete_stage_fingerprint_is_semantic_replay_and_culture_stable_for_1000_cases()
    {
        var before = CultureInfo.CurrentCulture;
        var beforeUi = CultureInfo.CurrentUICulture;
        try
        {
            for (var index = 0; index < 1_000; index++)
            {
                var strategy = (RolloutStrategy)((index % 4) + 1);
                var policy = (RollbackPolicy)((index % 2) + 1);
                var release = Release(index, index + 1, strategy, policy,
                    index % 2 == 0 ? [new("sfo"), new("fra")] : [new("fra"), new("sfo")]);
                var first = DeliveryStageFingerprint.Create(Stage(release));
                var replay = Release(index, index + 1, strategy, policy, release.OrderedCells.ToArray());

                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(index % 2 == 0 ? "ar-SA" : "tr-TR");
                CultureInfo.CurrentUICulture = CultureInfo.CurrentCulture;
                await Assert.That(DeliveryStageFingerprint.Create(Stage(replay))).IsEqualTo(first);
            }
        }
        finally
        {
            CultureInfo.CurrentCulture = before;
            CultureInfo.CurrentUICulture = beforeUi;
        }
    }

    [Test]
    public async Task Unavailable_stage_evidence_has_only_a_hold_intent()
    {
        var release = Release();
        foreach (var availability in new[]
        {
            Availability(release, release.OrderedCells[0]) with { ForwardAvailable = false },
            Availability(release, release.OrderedCells[0]) with { RollbackAvailable = false },
            Availability(release, release.OrderedCells[0]) with { ForwardDigest = new("wrong") },
        })
        {
            var decision = DeliveryEngine.DecideRollout(new(release, [], [availability], null, 96));
            await Assert.That(decision.Intents).HasSingleItem();
            await Assert.That(decision.Intents.Single()).IsTypeOf<HoldDeliveryIntent>();
        }
    }

    [Test]
    public async Task Stage_intent_has_no_public_construction_or_deconstruction_route()
    {
        var type = typeof(StageReleaseIntent);
        var exportedTypes = type.Assembly.GetExportedTypes();
        var externallyReturning = exportedTypes
            .SelectMany(candidate => candidate.GetMethods(BindingFlags.Public | BindingFlags.Static |
                BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(method => method.ReturnType == type)
            .Select(method => $"{method.DeclaringType!.FullName}.{method.Name}")
            .Order(StringComparer.Ordinal)
            .ToArray();
        var rolloutDecisionRoutes = typeof(DeliveryEngine)
            .GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(method => method.ReturnType == typeof(DeliveryDecision) &&
                method.GetParameters().Select(parameter => parameter.ParameterType).SequenceEqual([typeof(RolloutRequest)]))
            .Select(method => method.Name)
            .ToArray();

        await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Instance).Any(method => method.Name == "Deconstruct")).IsFalse();
        await Assert.That(type.GetProperties(BindingFlags.Public | BindingFlags.Instance).Any(property => property.SetMethod?.IsPublic == true)).IsFalse();
        await Assert.That(externallyReturning).IsEmpty();
        await Assert.That(rolloutDecisionRoutes).IsEquivalentTo([nameof(DeliveryEngine.DecideRollout)]);
    }

    private static StageReleaseIntent Stage(ReleaseSpec release, IEnumerable<CellArtifactAvailability>? availability = null)
    {
        availability ??= release.OrderedCells.Select(cell => Availability(release, cell));
        var decision = DeliveryEngine.DecideRollout(new(release, [], availability, null, 96));
        return (StageReleaseIntent)decision.Intents.Single();
    }

    private static ReleaseSpec Release(int index = 0, long generation = 7,
        RolloutStrategy strategy = RolloutStrategy.Canary,
        RollbackPolicy policy = RollbackPolicy.AutomaticOnFailedHealth,
        IReadOnlyList<DeliveryCellId>? cells = null) => new(new($"release-{index}"), new($"operation-{index}"), generation,
        new($"artifact-{index}"), new($"digest-{index}"), new($"signer-{index}"), new($"signature-{index}"), DeliveryArchitecture.LinuxArm64,
        new($"rollback-artifact-{index}"), new($"rollback-digest-{index}"), new($"rollback-signer-{index}"), new($"rollback-signature-{index}"),
        DeliveryArchitecture.LinuxArm64, strategy, policy, cells ?? [new("sfo"), new("fra")]);

    private static CellArtifactAvailability Availability(ReleaseSpec release, DeliveryCellId cell) => new(release.Release,
        release.Operation, release.Generation, cell, release.Artifact, release.Digest, release.SigningIdentity, release.Signature,
        release.Architecture, release.RollbackArtifact, release.RollbackDigest, release.RollbackSigningIdentity,
        release.RollbackSignature, release.RollbackArchitecture, true, true);

    private sealed record ReleaseValues(ReleaseId Release, DeliveryOperationId Operation, long Generation,
        ArtifactId Artifact, DigestId Digest, SigningIdentityId SigningIdentity, SignatureId Signature,
        DeliveryArchitecture Architecture, ArtifactId RollbackArtifact, DigestId RollbackDigest,
        SigningIdentityId RollbackSigningIdentity, SignatureId RollbackSignature,
        DeliveryArchitecture RollbackArchitecture, RolloutStrategy Strategy, RollbackPolicy RollbackPolicy,
        IReadOnlyList<DeliveryCellId> OrderedCells)
    {
        internal static ReleaseValues Default { get; } = new(new("release-0"), new("operation-0"), 7,
            new("artifact-0"), new("digest-0"), new("signer-0"), new("signature-0"), DeliveryArchitecture.LinuxArm64,
            new("rollback-artifact-0"), new("rollback-digest-0"), new("rollback-signer-0"), new("rollback-signature-0"),
            DeliveryArchitecture.LinuxArm64, RolloutStrategy.Canary, RollbackPolicy.AutomaticOnFailedHealth,
            [new("sfo"), new("fra")]);

        internal ReleaseSpec Create() => new(Release, Operation, Generation, Artifact, Digest, SigningIdentity,
            Signature, Architecture, RollbackArtifact, RollbackDigest, RollbackSigningIdentity, RollbackSignature,
            RollbackArchitecture, Strategy, RollbackPolicy, OrderedCells);
    }
}
