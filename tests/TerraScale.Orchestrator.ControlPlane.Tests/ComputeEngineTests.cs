using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Compute;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class ComputeEngineTests
{
    [Test]
    public async Task ScaleOutTransitionsPreserveExactAuthorityAndCompleteOnlyAfterHealth()
    {
        var binding = Binding();
        var plan = ComputeEngine.DecideScaleOut(Out(ScaleOutState.DemandObserved));
        var persisted = (PersistScalePlanIntent)plan.Intents.Single();
        await Assert.That(persisted.Binding).IsEqualTo(binding);
        await Assert.That(persisted.Resources).IsEqualTo(Authorization().Resources);
        await Assert.That(persisted.DesiredNodes).IsEqualTo(1);
        await Assert.That(persisted.PlanIdentity.Value).IsEqualTo("plan-identity");

        var authorize = (AuthorizeCapacityIntent)ComputeEngine.DecideScaleOut(Out(ScaleOutState.PlanPersisted)).Intents.Single();
        await Assert.That(authorize.PersistedPlan.PersistenceProof.Value).IsEqualTo("plan-persistence-proof");
        await Assert.That(authorize.PersistedPlan.Plan).IsEqualTo(Plan());
        var create = (RequestCreateIntent)ComputeEngine.DecideScaleOut(Out(ScaleOutState.Authorized)).Intents.Single();
        await Assert.That(create.Binding).IsEqualTo(binding);
        await Assert.That(create.CreateKey.Value).IsEqualTo("create-key");
        await Assert.That(create.PersistedPlan).IsEqualTo(Persisted());
        await Assert.That(create.Authorization).IsEqualTo(Authorization());
        await Assert.That(create.CreateEvidence).IsEqualTo(Create(ProviderCreateStatus.ProvenAbsent));
        await Assert.That(create.CreateKey).IsEqualTo(create.CreateEvidence.CreateKey);

        var enroll = (EnrollNodeIntent)ComputeEngine.DecideScaleOut(Out(ScaleOutState.InstanceCreated)).Intents.Single();
        await Assert.That(enroll.Resource.Value).IsEqualTo("instance-1");
        await Assert.That(enroll.Node.Value).IsEqualTo("node-1");
        var ready = (ReadyNodeIntent)ComputeEngine.DecideScaleOut(Out(ScaleOutState.Enrolled)).Intents.Single();
        await Assert.That(ready.Binding).IsEqualTo(binding);
        await Assert.That(ready.PlacementProof.Value).IsEqualTo("placement-proof");
        await Assert.That(ComputeEngine.DecideScaleOut(Out(ScaleOutState.Ready)).Intents).IsEmpty();
    }

    [Test]
    public async Task CreateIntentRetainsTheExactValidatedPlanAuthorizationAndAbsenceEvidence()
    {
        var firstPlan = Plan();
        var firstPersisted = Persisted(firstPlan);
        var firstAuthorization = Authorization();
        var firstEvidence = Create(ProviderCreateStatus.ProvenAbsent);
        var first = (RequestCreateIntent)ComputeEngine.DecideScaleOut(Out(ScaleOutState.Authorized,
            plan: firstPlan, persisted: firstPersisted, authorization: firstAuthorization,
            create: firstEvidence)).Intents.Single();

        var secondResources = new ResourceEnvelope(8, 32_768, 200, 240_000);
        var secondPlan = firstPlan with { Resources = secondResources, PlanIdentity = new("other-plan") };
        var secondPersisted = new PersistedScaleOutPlan(secondPlan, new("other-persistence"));
        var secondAuthorization = firstAuthorization with
        {
            Resources = secondResources,
            BudgetProof = new("other-budget"),
            QuotaProof = new("other-quota"),
            CapacityProof = new("other-capacity"),
            CostProof = new("other-cost"),
            PlacementProof = new("other-placement"),
        };
        var secondEvidence = firstEvidence with { ObservationProof = new("other-absence-observation") };
        var second = (RequestCreateIntent)ComputeEngine.DecideScaleOut(Out(ScaleOutState.Authorized,
            plan: secondPlan, persisted: secondPersisted, authorization: secondAuthorization,
            create: secondEvidence)).Intents.Single();

        await Assert.That(ReferenceEquals(first.PersistedPlan, firstPersisted)).IsTrue();
        await Assert.That(ReferenceEquals(first.Authorization, firstAuthorization)).IsTrue();
        await Assert.That(ReferenceEquals(first.CreateEvidence, firstEvidence)).IsTrue();
        await Assert.That(ReferenceEquals(second.PersistedPlan, secondPersisted)).IsTrue();
        await Assert.That(ReferenceEquals(second.Authorization, secondAuthorization)).IsTrue();
        await Assert.That(ReferenceEquals(second.CreateEvidence, secondEvidence)).IsTrue();
        await Assert.That(first.CreateKey).IsEqualTo(first.CreateEvidence.CreateKey);
        await Assert.That(second.CreateKey).IsEqualTo(second.CreateEvidence.CreateKey);
        await Assert.That(first.Authorization).IsNotEqualTo(second.Authorization);
        await Assert.That(first.CreateEvidence).IsNotEqualTo(second.CreateEvidence);
    }

    [Test]
    public async Task ScaleOutCheckpointsRequireTheEntireExactProofPrefix()
    {
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.Enrolled,
            progress: OutProgress(ScaleOutState.Enrolled) with { Resource = null })), ComputeErrorCode.MissingProof);
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.Enrolled,
            progress: OutProgress(ScaleOutState.Enrolled) with { IdentityAttested = false })), ComputeErrorCode.MissingProof);
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.InstanceCreated,
            progress: OutProgress(ScaleOutState.Ready))), ComputeErrorCode.MissingProof);
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.InstanceCreated,
            progress: OutProgress(ScaleOutState.InstanceCreated) with
            { EnrollmentProof = new("future-enrollment-proof") })), ComputeErrorCode.MissingProof);
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.Ready,
            authorization: Authorization(Binding() with { Operation = new("replayed-operation") }))),
            ComputeErrorCode.MissingProof);
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.Authorized,
            authorization: Authorization() with { AuthorizedNodes = 2 })), ComputeErrorCode.EvidenceMismatch);
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.Authorized,
            authorization: Authorization() with { Resources = new(8, 24576, 100, 120000) })),
            ComputeErrorCode.EvidenceMismatch);
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.Ready,
            create: Create(ProviderCreateStatus.Created) with
            { Binding = Binding() with { ProviderFingerprint = new("replayed-provider") } })),
            ComputeErrorCode.MissingProof);
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.Completed,
            progress: OutProgress(ScaleOutState.InstanceCreated))), ComputeErrorCode.MissingProof);
    }

    [Test]
    public async Task LostProviderResponseOnlyObservesTheRecordedCreateKey()
    {
        var request = Out(ScaleOutState.RequestRecorded, create: Create(ProviderCreateStatus.OutcomeUnknown));
        var first = (ObserveCreateIntent)ComputeEngine.DecideScaleOut(request).Intents.Single();
        var replay = (ObserveCreateIntent)ComputeEngine.DecideScaleOut(request).Intents.Single();
        await Assert.That(first.CreateKey).IsEqualTo(replay.CreateKey);
        await Assert.That(first.Binding).IsEqualTo(replay.Binding);
        await Assert.That(ComputeEngine.DecideScaleOut(request).Intents.Any(static value => value is RequestCreateIntent)).IsFalse();
    }

    [Test]
    public async Task ScaleOutProofsCannotReplayAcrossAnyAuthorityDimension()
    {
        var binding = Binding();
        var changed = new[]
        {
            binding with { Cell = new("sfo") },
            binding with { NodeClass = new("other-class") },
            binding with { Template = new("other-template") },
            binding with { Shape = new("other-shape") },
            binding with { Domain = new("other-domain") },
            binding with { Artifact = new("other-artifact") },
            binding with { ArtifactDigest = new("other-digest") },
            binding with { Demand = new("other-demand") },
            binding with { Operation = new("other-operation") },
            binding with { ProviderFingerprint = new("other-provider") },
            binding with { Generation = 8 },
            binding with { ControllerEpoch = 4 },
        };
        foreach (var replay in changed)
            await AssertHeld(ComputeEngine.DecideScaleOut(new(binding, ScaleOutState.Authorized, Demand(),
                Plan(), Persisted(), Authorization(replay), Create(ProviderCreateStatus.ProvenAbsent), null, 50, 64)),
                ComputeErrorCode.MissingProof);
    }

    [Test]
    public async Task EveryCapacityAndCostGateFailsClosed()
    {
        var baseline = Authorization();
        var cases = new[]
        {
            (baseline with { BudgetAllowed = false }, ComputeErrorCode.BudgetDenied),
            (baseline with { QuotaAllowed = false }, ComputeErrorCode.QuotaDenied),
            (baseline with { CapacityAvailable = false }, ComputeErrorCode.CapacityDenied),
            (baseline with { CostAllowed = false }, ComputeErrorCode.CostDenied),
            (baseline with { PlacementAllowed = false }, ComputeErrorCode.PlacementDenied),
        };
        foreach (var (authorization, error) in cases)
            await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.Authorized, authorization: authorization)), error);
    }

    [Test]
    public async Task StaleDemandAllowsOnlyExplicitBoundedSafetyScaleOut()
    {
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.DemandObserved,
            demand: Demand() with { ObservationSequence = 35, FreshThroughSequence = 40 })), ComputeErrorCode.EvidenceStale);
        var safety = Demand() with
        {
            Trigger = ComputeTrigger.FailedHostReplacement,
            ObservationSequence = 35,
            FreshThroughSequence = 40,
            SafetyBounded = true,
            Sustained = false,
        };
        await Assert.That(ComputeEngine.DecideScaleOut(Out(ScaleOutState.DemandObserved, demand: safety)).Intents.Single())
            .IsTypeOf<PersistScalePlanIntent>();
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.DemandObserved,
            demand: safety with { ObservationSequence = 51, FreshThroughSequence = 60 })),
            ComputeErrorCode.EvidenceStale);
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.DemandObserved,
            demand: safety with { ObservationSequence = 45, FreshThroughSequence = 44 })),
            ComputeErrorCode.InvalidInput);
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.DemandObserved,
            demand: safety with { ExplicitDemand = false })), ComputeErrorCode.EvidenceStale);
    }

    [Test]
    public async Task ScaleInCrashResumeEmitsOnlyTheNextExactNodeStep()
    {
        var cases = new (ScaleInState State, ScaleInProgress Progress, Type Intent)[]
        {
            (ScaleInState.CandidateSelected, InProgress(ScaleInState.CandidateSelected), typeof(CordonNodeIntent)),
            (ScaleInState.Cordoned, InProgress(ScaleInState.Cordoned), typeof(DrainNodeIntent)),
            (ScaleInState.Drained, InProgress(ScaleInState.Drained), typeof(DeregisterNodeIntent)),
            (ScaleInState.Deregistered, InProgress(ScaleInState.Deregistered), typeof(DetachVolumeIntent)),
            (ScaleInState.StorageHandled, InProgress(ScaleInState.StorageHandled), typeof(RevokeNodeIntent)),
            (ScaleInState.Revoked, InProgress(ScaleInState.Revoked), typeof(TerminateNodeIntent)),
            (ScaleInState.Terminated, InProgress(ScaleInState.Terminated), typeof(AuditOrphansIntent)),
        };
        foreach (var (state, progress, type) in cases)
        {
            var first = ComputeEngine.DecideScaleIn(In(state, progress: progress));
            var replay = ComputeEngine.DecideScaleIn(In(state, progress: progress));
            await Assert.That(first.Intents.Single().GetType()).IsEqualTo(type);
            await Assert.That(replay.Intents.Single().GetType()).IsEqualTo(type);
            await Assert.That(IntentBinding(first.Intents.Single())).IsEqualTo(InBinding());
        }
    }

    [Test]
    public async Task ScaleInCannotSkipDrainStorageRevocationTerminationOrAuditProofs()
    {
        var skipped = new[]
        {
            In(ScaleInState.Drained, progress: InProgress(ScaleInState.Drained) with { Cordoned = false }),
            In(ScaleInState.Deregistered, progress: InProgress(ScaleInState.Deregistered) with { Drained = false }),
            In(ScaleInState.Revoked, progress: InProgress(ScaleInState.Revoked) with { VolumeHandled = false }),
            In(ScaleInState.Terminated, progress: InProgress(ScaleInState.Terminated) with { Revoked = false }),
            In(ScaleInState.Completed, progress: InProgress(ScaleInState.CandidateSelected)),
            In(ScaleInState.CandidateSelected, progress: InProgress(ScaleInState.CandidateSelected) with
            { CordonProof = new("future-cordon-proof") }),
            In(ScaleInState.Cordoned, progress: InProgress(ScaleInState.Cordoned) with { CordonProof = null }),
        };
        foreach (var request in skipped)
            await AssertHeld(ComputeEngine.DecideScaleIn(request), ComputeErrorCode.MissingProof);
    }

    [Test]
    public async Task TerminationIntentRetainsExactValidatedAuthorizationAndRevokedPrefix()
    {
        var binding = InBinding(ComputeNodeRole.ElasticStateful);
        var firstAuthorization = InAuthorization(binding) with
        { StatefulDisposition = StatefulDisposition.Approved, StatefulApproved = true };
        var firstProgress = InProgress(ScaleInState.Revoked, binding, VolumeDisposition.RetainedStateful);
        var first = (TerminateNodeIntent)ComputeEngine.DecideScaleIn(In(ScaleInState.Revoked, binding,
            firstAuthorization, firstProgress)).Intents.Single();

        var secondAuthorization = firstAuthorization with
        {
            LowUseProof = new("other-low-use"),
            AvailabilityProof = new("other-availability"),
            StatefulProof = new("other-stateful-approval"),
        };
        var secondProgress = firstProgress with
        {
            VolumeProof = new("other-volume-proof"),
            RevocationProof = new("other-revocation-proof"),
            StatefulOwner = new("other-stateful-controller"),
        };
        var second = (TerminateNodeIntent)ComputeEngine.DecideScaleIn(In(ScaleInState.Revoked, binding,
            secondAuthorization, secondProgress)).Intents.Single();

        await Assert.That(ReferenceEquals(first.Authorization, firstAuthorization)).IsTrue();
        await Assert.That(ReferenceEquals(first.Progress, firstProgress)).IsTrue();
        await Assert.That(ReferenceEquals(second.Authorization, secondAuthorization)).IsTrue();
        await Assert.That(ReferenceEquals(second.Progress, secondProgress)).IsTrue();
        await Assert.That(first.RevocationProof).IsEqualTo(first.Progress.RevocationProof);
        await Assert.That(second.RevocationProof).IsEqualTo(second.Progress.RevocationProof);
        await Assert.That(first.Authorization).IsNotEqualTo(second.Authorization);
        await Assert.That(first.Progress).IsNotEqualTo(second.Progress);
    }

    [Test]
    public async Task ScaleInProofsCannotReplayAcrossLbVolumeResourceOrOperation()
    {
        var binding = InBinding();
        foreach (var replay in new[]
        {
            binding with { Resource = new("other-instance") },
            binding with { LoadBalancerRegistration = new("other-lb") },
            binding with { Volume = new("other-volume") },
            binding with { Compute = binding.Compute with { Operation = new("other-operation") } },
        })
            await AssertHeld(ComputeEngine.DecideScaleIn(In(ScaleInState.Deregistered, binding: binding,
                authorization: InAuthorization(binding), progress: InProgress(ScaleInState.Deregistered, replay))),
                ComputeErrorCode.InvalidInput);
    }

    [Test]
    public async Task ScaleInAlwaysHoldsStaleConflictAvailabilityAndStatefulVeto()
    {
        var authorization = InAuthorization();
        var cases = new[]
        {
            (authorization with { FreshThroughSequence = 40 }, ComputeErrorCode.EvidenceStale),
            (authorization with { ConflictingOperation = true }, ComputeErrorCode.ConflictingOperation),
            (authorization with { ReplacementCapacity = 0 }, ComputeErrorCode.AvailabilityDenied),
            (authorization with { NatsHealthy = false }, ComputeErrorCode.AvailabilityDenied),
            (authorization with { CostBenefitPassed = false }, ComputeErrorCode.CostDenied),
        };
        foreach (var (evidence, error) in cases)
            await AssertHeld(ComputeEngine.DecideScaleIn(In(ScaleInState.CandidateSelected, authorization: evidence)), error);

        var stateful = InBinding(ComputeNodeRole.ElasticStateful);
        await AssertHeld(ComputeEngine.DecideScaleIn(In(ScaleInState.CandidateSelected, binding: stateful,
            authorization: InAuthorization(stateful) with { StatefulDisposition = StatefulDisposition.Vetoed, StatefulApproved = false },
            progress: InProgress(ScaleInState.CandidateSelected, stateful, VolumeDisposition.RetainedStateful))), ComputeErrorCode.StatefulVeto);
    }

    [Test]
    public async Task CriticalFloorsNeverFallBelowThreeAndRetainedVolumesKeepTheirOwner()
    {
        var binding = InBinding(ComputeNodeRole.TerraBase);
        await AssertHeld(ComputeEngine.DecideScaleIn(In(ScaleInState.CandidateSelected, binding: binding,
            authorization: InAuthorization(binding, 3, 3),
            progress: InProgress(ScaleInState.CandidateSelected, binding, VolumeDisposition.RetainedStateful))),
            ComputeErrorCode.FloorDenied);

        var authorization = InAuthorization(binding, 4, 3) with
        { StatefulDisposition = StatefulDisposition.Approved, StatefulApproved = true };
        var progress = InProgress(ScaleInState.Deregistered, binding, VolumeDisposition.RetainedStateful);
        var intent = (DetachVolumeIntent)ComputeEngine.DecideScaleIn(In(ScaleInState.Deregistered, binding,
            authorization, progress)).Intents.Single();
        await Assert.That(intent.Disposition).IsEqualTo(VolumeDisposition.RetainedStateful);
        await Assert.That(intent.StatefulOwner!.Value).IsEqualTo("terrabase-controller");
        await Assert.That(intent.Binding.Resource.Value).IsEqualTo("instance-1");
        await Assert.That(intent.Binding.Volume.Value).IsEqualTo("volume-1");
        await Assert.That(intent.Binding.LoadBalancerRegistration.Value).IsEqualTo("lb-registration-1");
    }

    [Test]
    public async Task VolumeDispositionIsClosedByStatefulStoreRole()
    {
        foreach (var role in new[] { ComputeNodeRole.ControlNats, ComputeNodeRole.ProductNats, ComputeNodeRole.TerraBase })
        {
            var binding = InBinding(role);
            var authorization = InAuthorization(binding, 4, 3) with
            { StatefulDisposition = StatefulDisposition.Approved, StatefulApproved = true };
            await AssertHeld(ComputeEngine.DecideScaleIn(In(ScaleInState.CandidateSelected, binding,
                authorization, InProgress(ScaleInState.CandidateSelected, binding))), ComputeErrorCode.StatefulVeto);
            await Assert.That(ComputeEngine.DecideScaleIn(In(ScaleInState.CandidateSelected, binding,
                authorization, InProgress(ScaleInState.CandidateSelected, binding,
                    VolumeDisposition.RetainedStateful))).Intents.Single()).IsTypeOf<CordonNodeIntent>();
        }

        var stateless = InBinding(ComputeNodeRole.ElasticStateless);
        await AssertHeld(ComputeEngine.DecideScaleIn(In(ScaleInState.CandidateSelected, stateless,
            InAuthorization(stateless), InProgress(ScaleInState.CandidateSelected, stateless,
                VolumeDisposition.RetainedStateful))), ComputeErrorCode.StatefulVeto);
    }

    [Test]
    public async Task TerminationRequiresExactInstanceBootAbsenceAndCleanOrphanAudit()
    {
        await AssertHeld(ComputeEngine.DecideScaleIn(In(ScaleInState.Terminated,
            progress: InProgress(ScaleInState.Terminated) with { ExactInstanceTerminated = false })),
            ComputeErrorCode.UnsafeTermination);
        await AssertHeld(ComputeEngine.DecideScaleIn(In(ScaleInState.Terminated,
            progress: InProgress(ScaleInState.Terminated) with { BootVolumeAbsent = false })),
            ComputeErrorCode.UnsafeTermination);
        await AssertHeld(ComputeEngine.DecideScaleIn(In(ScaleInState.Audited,
            progress: InProgress(ScaleInState.Audited) with { OrphanAuditPassed = false })), ComputeErrorCode.OrphanDenied);
        await Assert.That(ComputeEngine.DecideScaleIn(In(ScaleInState.Audited,
            progress: InProgress(ScaleInState.Audited))).Intents).IsEmpty();
    }

    [Test]
    public async Task RegionalSurvivalBindsCompleteEncryptedForwardAndRollbackState()
    {
        var request = Survival();
        await Assert.That(ComputeEngine.DecideSurvival(request).Intents.Single()).IsTypeOf<ReadySurvivalIntent>();
        var disconnected = request with
        { DisconnectedReplacementRequested = true, ReplacementTarget = Target(request.Required) };
        var intent = (AuthorizeSurvivalIntent)ComputeEngine.DecideSurvival(disconnected).Intents.Single();
        await Assert.That(intent.Bundle.Bundle.Value).IsEqualTo("bundle-1");
        await Assert.That(intent.Authority.AuthorityEpoch).IsEqualTo(7);
        await Assert.That(intent.Target.Operation.Value).IsEqualTo("replacement-operation");
        await Assert.That(intent.Target.CreateKey.Value).IsEqualTo("replacement-create-key");
        await Assert.That(intent.Target.Template.Value).IsEqualTo("template-1");
    }

    [Test]
    public async Task BundleMissingExpiredRollbackAndAuthorityGapsHold()
    {
        var request = Survival();
        await AssertHeld(ComputeEngine.DecideSurvival(request with
        { Evidence = request.Evidence with { MetadataEncrypted = false } }), ComputeErrorCode.BundleIncomplete);
        await AssertHeld(ComputeEngine.DecideSurvival(request with { EvaluationPosition = 201 }), ComputeErrorCode.BundleExpired);
        await AssertHeld(ComputeEngine.DecideSurvival(request with
        { Evidence = request.Evidence with { ArtifactsLocal = false } }), ComputeErrorCode.BundleIncomplete);
        await AssertHeld(ComputeEngine.DecideSurvival(request with
        { Authority = request.Authority with { AuthorityEpoch = 8 } }), ComputeErrorCode.AuthorityDenied);
        foreach (var inverted in new[]
        {
            Bundle(snapshotPosition: 91, journalPosition: 90),
            Bundle(journalPosition: 151, freshThroughPosition: 150),
            Bundle(freshThroughPosition: 201, expiresAfterPosition: 200),
        })
            await AssertHeld(ComputeEngine.DecideSurvival(Survival(inverted)), ComputeErrorCode.InvalidInput);
    }

    [Test]
    public async Task BundleEvidenceCannotReplayAcrossMetadataOrSecretVersions()
    {
        var required = Bundle();
        foreach (var observed in new[]
        {
            Bundle(provider: "other-provider"),
            Bundle(generation: 3),
            Bundle(rollbackDigest: "other-rollback"),
            Bundle(secrets: [new("secret-v1")]),
            Bundle(templates: [Template("template-2")]),
            Bundle(authorityEpoch: 8),
        })
        {
            var request = Survival(required, observed);
            await AssertHeld(ComputeEngine.DecideSurvival(request), ComputeErrorCode.EvidenceMismatch);
        }
    }

    [Test]
    public async Task DisconnectedReplacementTargetCannotReplayAcrossCreateSubject()
    {
        var ready = Survival();
        await Assert.That(ComputeEngine.DecideSurvival(ready).Intents.Single()).IsTypeOf<ReadySurvivalIntent>();
        await AssertHeld(ComputeEngine.DecideSurvival(ready with { ReplacementTarget = Target(ready.Required) }),
            ComputeErrorCode.EvidenceMismatch);
        await AssertHeld(ComputeEngine.DecideSurvival(ready with { DisconnectedReplacementRequested = true }),
            ComputeErrorCode.MissingProof);

        var request = ready with
        { DisconnectedReplacementRequested = true, ReplacementTarget = Target(ready.Required) };
        foreach (var target in new[]
        {
            request.ReplacementTarget! with { Cell = new("sfo") },
            request.ReplacementTarget! with { Template = new("template-other") },
            request.ReplacementTarget! with { Shape = new("other-shape") },
            request.ReplacementTarget! with { Domain = new("other-domain") },
            request.ReplacementTarget! with { ArtifactDigest = new("other-digest") },
            request.ReplacementTarget! with { ProviderFingerprint = new("other-provider") },
            request.ReplacementTarget! with { BundleGeneration = 3 },
            request.ReplacementTarget! with { ControllerEpoch = 8 },
        })
            await AssertHeld(ComputeEngine.DecideSurvival(request with { ReplacementTarget = target }),
                ComputeErrorCode.InvalidInput);
    }

    [Test]
    public async Task CollectionsAreCopiedAndBundleOrderingIsCultureAndPermutationInvariant()
    {
        var secrets = new List<SecretVersionId> { new("secret-v2"), new("secret-v1") };
        var templates = new List<SurvivalNodeTemplate> { Template("template-1"), Template("template-2") };
        var bundle = Bundle(secrets: secrets, templates: templates);
        secrets.Clear(); templates.Clear();
        await Assert.That(bundle.EncryptedSecretVersions.Count).IsEqualTo(2);
        await Assert.That(bundle.Templates.Count).IsEqualTo(2);

        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new("tr-TR");
            var first = ComputeEngine.DecideSurvival(Survival(bundle, Bundle(secrets: bundle.EncryptedSecretVersions.Reverse(),
                templates: bundle.Templates.Reverse())));
            CultureInfo.CurrentCulture = new("en-US");
            var second = ComputeEngine.DecideSurvival(Survival(bundle, bundle));
            await Assert.That(first.Intents.Single().GetType()).IsEqualTo(second.Intents.Single().GetType());
        }
        finally { CultureInfo.CurrentCulture = original; }
    }

    [Test]
    public async Task OutputsCannotBeForgedAndExposeNoExecutableOrPlaintextSurface()
    {
        var assembly = typeof(ComputeIntent).Assembly;
        var outputs = assembly.GetTypes().Where(type => type.Namespace == typeof(ComputeIntent).Namespace &&
            (type == typeof(ComputeDecision) || type == typeof(ComputeError) || type == typeof(ComputeTrace) ||
             typeof(ComputeIntent).IsAssignableFrom(type))).ToArray();
        await Assert.That(outputs.All(static type => type.GetConstructors().Length == 0)).IsTrue();
        var forbidden = new[] { "command", "script", "query", "plaintext", "privatekey", "callback", "sdk", "process", "network" };
        var properties = assembly.GetTypes().Where(type => type.Namespace == typeof(ComputeIntent).Namespace)
            .SelectMany(static type => type.GetProperties()).Select(static value => value.Name).ToArray();
        await Assert.That(properties.Any(name => forbidden.Any(value => name.Contains(value,
            StringComparison.OrdinalIgnoreCase)))).IsFalse();
        await Assert.That(outputs.Any(static type => type.Name.Contains("Adopt", StringComparison.Ordinal))).IsFalse();
        await Assert.That(outputs.Any(static type => type.Name.Contains("Delete", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task EveryComputeIntentKeepsItsReviewedExactPublicShape()
    {
        var expected = new Dictionary<Type, string[]>
        {
            [typeof(ObserveCreateIntent)] = ["Binding", "CreateKey"],
            [typeof(PersistScalePlanIntent)] = ["Binding", "DesiredNodes", "PlanIdentity", "Resources"],
            [typeof(AuthorizeCapacityIntent)] = ["Binding", "PersistedPlan"],
            [typeof(RequestCreateIntent)] = ["Authorization", "Binding", "CreateEvidence", "CreateKey", "PersistedPlan"],
            [typeof(EnrollNodeIntent)] = ["Binding", "IdentityProof", "Node", "Resource"],
            [typeof(ReadyNodeIntent)] = ["Binding", "BootstrapProof", "DiskProof", "Node", "PlacementProof", "Resource"],
            [typeof(CordonNodeIntent)] = ["Binding"],
            [typeof(DrainNodeIntent)] = ["Binding", "CordonProof"],
            [typeof(DeregisterNodeIntent)] = ["Binding", "StatefulProof"],
            [typeof(DetachVolumeIntent)] = ["Binding", "Disposition", "StatefulOwner"],
            [typeof(RevokeNodeIntent)] = ["Binding", "VolumeProof"],
            [typeof(TerminateNodeIntent)] = ["Authorization", "Binding", "Progress", "RevocationProof"],
            [typeof(AuditOrphansIntent)] = ["Binding", "BootAbsenceProof", "TerminationProof"],
            [typeof(AuthorizeSurvivalIntent)] = ["Authority", "Bundle", "Target"],
            [typeof(ReadySurvivalIntent)] = ["Bundle"],
            [typeof(HoldComputeIntent)] = ["Operation", "Reason"],
        };
        var concrete = typeof(ComputeIntent).Assembly.GetTypes()
            .Where(type => !type.IsAbstract && typeof(ComputeIntent).IsAssignableFrom(type))
            .ToArray();
        await Assert.That(concrete.Length).IsEqualTo(expected.Count);
        foreach (var (type, names) in expected)
        {
            var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
            await Assert.That(properties.Select(static property => property.Name).Order(StringComparer.Ordinal))
                .IsEquivalentTo(names);
            await Assert.That(properties.All(static property => property.SetMethod?.IsPublic != true)).IsTrue();
            await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        }
    }

    [Test]
    public async Task InvalidEnumsScalarsCountsAndResourcesFailClosed()
    {
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.DemandObserved,
            demand: Demand() with { Trigger = ComputeTrigger.Unspecified })), ComputeErrorCode.InvalidInput);
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.DemandObserved,
            plan: Plan() with { DesiredNodes = 0 })), ComputeErrorCode.InvalidInput);
        await AssertHeld(ComputeEngine.DecideScaleOut(Out(ScaleOutState.Authorized,
            authorization: Authorization() with { Resources = new(0, 24576, 100, 120000) })),
            ComputeErrorCode.MissingProof);

        var invalidBinding = Binding() with { Generation = 0 };
        await AssertHeld(ComputeEngine.DecideScaleOut(new(invalidBinding, ScaleOutState.DemandObserved,
            Demand() with { Binding = invalidBinding }, Plan(invalidBinding), null, null,
            null, null, 50, 64)), ComputeErrorCode.InvalidInput);

        var invalidIn = InBinding() with { Role = ComputeNodeRole.Unspecified };
        await AssertHeld(ComputeEngine.DecideScaleIn(new(invalidIn, ScaleInState.CandidateSelected,
            InAuthorization(invalidIn), InProgress(ScaleInState.CandidateSelected, invalidIn), 50, 64)),
            ComputeErrorCode.InvalidInput);
        await AssertHeld(ComputeEngine.DecideSurvival(Survival(Bundle(generation: 0))), ComputeErrorCode.InvalidInput);
    }

    private static ComputeBinding Binding() => new(new("gru"), new("app"), new("template-1"), new("a1-flex"),
        new("fault-domain-1"), new("node-image"), new("image-digest"), new("demand-1"), new("operation-1"),
        new("provider-fingerprint"), 7, 3);
    private static DemandEvidence Demand() => new(Binding(), ComputeTrigger.Unschedulable, 45, 60, 1, true, true, false);
    private static CapacityAuthorization Authorization(ComputeBinding? binding = null) => new(binding ?? Binding(),
        new(4, 24576, 100, 120000), 1, new("budget-proof"), new("quota-proof"), new("capacity-proof"),
        new("cost-proof"), new("placement-proof"), true, true, true, true, true);
    private static ScaleOutPlan Plan(ComputeBinding? binding = null) => new(binding ?? Binding(),
        new(4, 24576, 100, 120000), 1, new("plan-identity"));
    private static PersistedScaleOutPlan Persisted(ScaleOutPlan? plan = null) => new(plan ?? Plan(),
        new("plan-persistence-proof"));
    private static ProviderCreateEvidence Create(ProviderCreateStatus status) => new(Binding(), new("create-key"), status,
        status == ProviderCreateStatus.Created ? new("instance-1") : null,
        status == ProviderCreateStatus.Created ? new("work-request-1") : null, new("provider-observation"));
    private static ScaleOutProgress OutProgress(ScaleOutState state) => new(Binding(), new("instance-1"), new("node-1"),
        state >= ScaleOutState.InstanceCreated ? new("identity-proof") : null,
        state >= ScaleOutState.Enrolled ? new("enrollment-proof") : null,
        state >= ScaleOutState.Enrolled ? new("bootstrap-proof") : null,
        state >= ScaleOutState.Enrolled ? new("disk-proof") : null,
        state >= ScaleOutState.Ready ? new("placement-proof") : null,
        state >= ScaleOutState.Ready ? new("health-proof") : null, state >= ScaleOutState.InstanceCreated,
        state >= ScaleOutState.Enrolled, state >= ScaleOutState.Enrolled, state >= ScaleOutState.Enrolled,
        state >= ScaleOutState.Ready, state >= ScaleOutState.Ready);
    private static ScaleOutRequest Out(ScaleOutState state, DemandEvidence? demand = null,
        ScaleOutPlan? plan = null, PersistedScaleOutPlan? persisted = null,
        CapacityAuthorization? authorization = null, ProviderCreateEvidence? create = null,
        ScaleOutProgress? progress = null)
    {
        var proposal = plan ?? Plan();
        var createEvidence = create ?? (state == ScaleOutState.Authorized ? Create(ProviderCreateStatus.ProvenAbsent) :
            state >= ScaleOutState.RequestRecorded ? Create(ProviderCreateStatus.Created) : null);
        return new(Binding(), state, demand ?? Demand(), proposal,
            state == ScaleOutState.DemandObserved ? null : persisted ?? Persisted(proposal),
            state < ScaleOutState.Authorized ? null : authorization ?? Authorization(),
            createEvidence,
            progress ?? (state == ScaleOutState.RequestRecorded && createEvidence?.Status == ProviderCreateStatus.Created
                ? OutProgress(ScaleOutState.InstanceCreated) : state is ScaleOutState.InstanceCreated or ScaleOutState.Enrolled or
                ScaleOutState.Ready or ScaleOutState.Completed ? OutProgress(state) : null), 50, 64);
    }

    private static ScaleInBinding InBinding(ComputeNodeRole role = ComputeNodeRole.ElasticStateless) =>
        new(Binding(), new("node-1"), new("instance-1"), new("lb-registration-1"), new("volume-1"), role);
    private static ScaleInAuthorization InAuthorization(ScaleInBinding? binding = null, int current = 5, int minimum = 1) =>
        new(binding ?? InBinding(), new("low-use"), 45, 60, current, minimum, 2, 1, new("low-use-proof"),
            new("cooldown-proof"), new("lifetime-proof"), new("cost-benefit-proof"), new("control-proof"),
            new("nats-proof"), new("availability-proof"), StatefulDisposition.NotStateful, new("stateful-proof"),
            true, true, true, true, true, true, false, false);
    private static ScaleInProgress InProgress(ScaleInState state, ScaleInBinding? binding = null,
        VolumeDisposition disposition = VolumeDisposition.DetachedEphemeral) => new(binding ?? InBinding(),
        state >= ScaleInState.Cordoned ? new("cordon-proof") : null,
        state >= ScaleInState.Drained ? new("drain-proof") : null,
        state >= ScaleInState.Deregistered ? new("deregister-proof") : null,
        state >= ScaleInState.StorageHandled ? new("volume-proof") : null,
        state >= ScaleInState.Revoked ? new("revoke-proof") : null,
        state >= ScaleInState.Terminated ? new("terminate-proof") : null,
        state >= ScaleInState.Terminated ? new("boot-absence-proof") : null,
        state >= ScaleInState.Audited ? new("orphan-proof") : null, disposition,
        disposition == VolumeDisposition.RetainedStateful ? new("terrabase-controller") : null,
        state >= ScaleInState.Cordoned, state >= ScaleInState.Drained, state >= ScaleInState.Deregistered,
        state >= ScaleInState.StorageHandled, state >= ScaleInState.Revoked, state >= ScaleInState.Terminated,
        state >= ScaleInState.Terminated, state >= ScaleInState.Audited);
    private static ScaleInRequest In(ScaleInState state, ScaleInBinding? binding = null,
        ScaleInAuthorization? authorization = null, ScaleInProgress? progress = null)
    {
        var exact = binding ?? InBinding();
        return new(exact, state, authorization ?? InAuthorization(exact), progress ?? InProgress(state, exact), 50, 64);
    }
    private static ScaleInBinding IntentBinding(ComputeIntent intent) => intent switch
    {
        CordonNodeIntent value => value.Binding,
        DrainNodeIntent value => value.Binding,
        DeregisterNodeIntent value => value.Binding,
        DetachVolumeIntent value => value.Binding,
        RevokeNodeIntent value => value.Binding,
        TerminateNodeIntent value => value.Binding,
        AuditOrphansIntent value => value.Binding,
        _ => throw new InvalidOperationException(),
    };

    private static RegionalSurvivalBundle Bundle(string provider = "provider-fingerprint", long generation = 2,
        string rollbackDigest = "rollback-digest", IEnumerable<SecretVersionId>? secrets = null,
        IEnumerable<SurvivalNodeTemplate>? templates = null, long authorityEpoch = 7, long journalPosition = 90,
        long snapshotPosition = 80, long freshThroughPosition = 150, long expiresAfterPosition = 200) =>
        new(new("bundle-1"), new("gru"),
        generation, new(provider), new("orchestrator-n"), new("accepted-digest"), new("accepted-signature"),
        new("orchestrator-n-1"), new(rollbackDigest), new("rollback-signature"),
        secrets ?? [new("secret-v2"), new("secret-v1")], templates ?? [Template("template-2"), Template("template-1")],
        new("trust-ref"), new("nats-ref"), new("dns-ref"), new("backup-ref"), authorityEpoch, journalPosition,
        snapshotPosition, freshThroughPosition, expiresAfterPosition);
    private static SurvivalRequest Survival(RegionalSurvivalBundle? required = null, RegionalSurvivalBundle? observed = null)
    {
        var exact = required ?? Bundle();
        var evidence = new SurvivalBundleEvidence(observed ?? exact, new("bundle-signature"), new("encryption-proof"),
            true, true, true, true, true, true, true, true, true);
        return new(exact, evidence, new(exact.Cell, exact.AuthorityEpoch, exact.JournalPosition,
            new("authority-proof"), true), 100, false, null, 64);
    }
    private static SurvivalReplacementTarget Target(RegionalSurvivalBundle exact) => new(exact.Cell, new("control"),
            new("template-1"), new("a1-flex"),
            new("fault-domain-1"), exact.AcceptedArtifact, exact.AcceptedDigest, new("replacement-operation"),
            exact.ProviderFingerprint, new("replacement-create-key"), exact.Generation, exact.AuthorityEpoch);
    private static SurvivalNodeTemplate Template(string id) => new(new("control"), new(id), new("a1-flex"),
        new("fault-domain-1"));

    private static async Task AssertHeld(ComputeDecision decision, ComputeErrorCode code)
    {
        await Assert.That(decision.Errors.Any(error => error.Code == code)).IsTrue();
        await Assert.That(decision.Intents.Single()).IsTypeOf<HoldComputeIntent>();
    }
}
