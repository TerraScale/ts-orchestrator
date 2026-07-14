using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Compute;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class ComputePolicyCompletenessPropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task Generated_scale_out_authorization_denials_follow_the_closed_precedence()
    {
        var failures = new List<int>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var binding = Binding(seed);
            var mask = seed % 32;
            var authorization = Authorization(binding) with
            {
                BudgetAllowed = (mask & 1) == 0,
                QuotaAllowed = (mask & 2) == 0,
                CapacityAvailable = (mask & 4) == 0,
                CostAllowed = (mask & 8) == 0,
                PlacementAllowed = (mask & 16) == 0,
            };
            var expected = (mask & 1) != 0 ? ComputeErrorCode.BudgetDenied :
                (mask & 2) != 0 ? ComputeErrorCode.QuotaDenied :
                (mask & 4) != 0 ? ComputeErrorCode.CapacityDenied :
                (mask & 8) != 0 ? ComputeErrorCode.CostDenied :
                (mask & 16) != 0 ? ComputeErrorCode.PlacementDenied : ComputeErrorCode.Unspecified;
            var decision = ComputeEngine.DecideScaleOut(ScaleOut(binding, ScaleOutState.Authorized,
                authorization: authorization));
            if (expected == ComputeErrorCode.Unspecified)
            {
                if (decision.Errors.Count != 0 || decision.Intents.Count != 1 ||
                    decision.Intents[0] is not RequestCreateIntent create || create.Action != ComputeAction.RequestCreate ||
                    create.Binding != binding || create.CreateKey.Value != $"create-{seed}" ||
                    !ExactTrace(decision, ComputeTraceCode.CreateReady, ComputeAction.RequestCreate)) failures.Add(seed);
            }
            else if (!ExactHeld(decision, expected, binding.Operation)) failures.Add(seed);
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Generated_scale_out_checkpoints_emit_only_the_next_exact_subject()
    {
        var failures = new List<int>();
        var original = CultureInfo.CurrentCulture;
        var originalUi = CultureInfo.CurrentUICulture;
        try
        {
            for (var seed = 1; seed <= Cases; seed++)
            {
                var binding = Binding(seed);
                var state = (ScaleOutState)(1 + seed % 8);
                var unknown = state == ScaleOutState.RequestRecorded && seed / 8 % 2 != 0;
                var request = ScaleOut(binding, state, unknownCreateOutcome: unknown);
                CultureInfo.CurrentCulture = CultureInfo.CurrentUICulture = new("en-US");
                var baseline = ComputeEngine.DecideScaleOut(request);
                var expected = Signature(baseline);
                foreach (var cultureName in new[] { "tr-TR", "ar-SA", "ja-JP" })
                {
                    CultureInfo.CurrentCulture = CultureInfo.CurrentUICulture = new(cultureName);
                    if (!StringComparer.Ordinal.Equals(expected, Signature(ComputeEngine.DecideScaleOut(request))))
                    { failures.Add(seed); break; }
                }
                if (!ExactScaleOutOutcome(baseline, request)) failures.Add(seed);
            }
        }
        finally { CultureInfo.CurrentCulture = original; CultureInfo.CurrentUICulture = originalUi; }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Generated_early_scale_out_states_reject_every_future_evidence_shape()
    {
        var failures = new List<int>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var binding = Binding(seed);
            var variant = seed % 7;
            var state = variant < 2 ? ScaleOutState.DemandObserved :
                variant < 4 ? ScaleOutState.PlanPersisted :
                variant < 6 ? ScaleOutState.Authorized : ScaleOutState.RequestRecorded;
            var baseline = ScaleOut(binding, state, unknownCreateOutcome: state == ScaleOutState.RequestRecorded);
            var futureProgress = Progress(binding, ScaleOutState.InstanceCreated);
            var request = variant switch
            {
                0 => baseline with { CreateEvidence = Create(binding, ProviderCreateStatus.ProvenAbsent) },
                1 => baseline with { Progress = futureProgress },
                2 => baseline with { CreateEvidence = Create(binding, ProviderCreateStatus.ProvenAbsent) },
                3 => baseline with { Progress = futureProgress },
                4 or 5 => baseline with { Progress = futureProgress },
                _ => baseline with { Progress = futureProgress },
            };
            var decision = ComputeEngine.DecideScaleOut(request);
            if (!ExactHeld(decision, ComputeErrorCode.EvidenceMismatch, binding.Operation)) failures.Add(seed);
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Generated_scale_in_denials_follow_safety_precedence_and_n_plus_one_floors()
    {
        var failures = new List<int>();
        var roles = Enum.GetValues<ComputeNodeRole>().Where(static role => role != ComputeNodeRole.Unspecified).ToArray();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var role = roles[seed % roles.Length];
            var binding = ScaleInBinding(seed, role);
            var stateful = IsStateful(role);
            var critical = IsCritical(role);
            var current = 2 + seed % 6;
            var minimum = seed % 5;
            var mask = seed % 128;
            var authorization = ScaleInAuthorization(binding, current, minimum, stateful) with
            {
                FreshThroughSequence = (mask & 1) != 0 ? 40 : 60,
                ConflictingOperation = (mask & 2) != 0,
                SustainedLowUse = (mask & 4) == 0,
                CostBenefitPassed = (mask & 8) == 0,
                ReplacementCapacity = (mask & 16) != 0 ? 0 : 1,
                AvailabilityHeadroom = (mask & 16) != 0 ? 0 : 1,
                StatefulDisposition = stateful && (mask & 64) != 0 ? StatefulDisposition.Vetoed :
                    stateful ? StatefulDisposition.Approved : StatefulDisposition.NotStateful,
                StatefulApproved = stateful && (mask & 64) == 0,
            };
            var expected = (mask & 1) != 0 ? ComputeErrorCode.EvidenceStale :
                (mask & 2) != 0 ? ComputeErrorCode.ConflictingOperation :
                (mask & 4) != 0 ? ComputeErrorCode.MissingProof :
                (mask & 8) != 0 ? ComputeErrorCode.CostDenied :
                (mask & 16) != 0 ? ComputeErrorCode.AvailabilityDenied :
                current <= minimum || current <= 1 || critical && (minimum < 3 || (long)current - 1 < 3)
                    ? ComputeErrorCode.FloorDenied :
                stateful && (mask & 64) != 0 ? ComputeErrorCode.StatefulVeto : ComputeErrorCode.Unspecified;
            var decision = ComputeEngine.DecideScaleIn(new(binding, ScaleInState.CandidateSelected, authorization,
                ScaleInProgress(binding, ScaleInState.CandidateSelected, stateful), 50, 128));
            if (expected == ComputeErrorCode.Unspecified)
            {
                if (decision.Errors.Count != 0 || decision.Intents.Count != 1 ||
                    decision.Intents[0] is not CordonNodeIntent intent || intent.Action != ComputeAction.Cordon ||
                    intent.Binding != binding || !ExactTrace(decision, ComputeTraceCode.CordonReady, ComputeAction.Cordon))
                    failures.Add(seed);
            }
            else if (!ExactHeld(decision, expected, binding.Compute.Operation)) failures.Add(seed);
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Generated_scale_in_drain_reclaim_transitions_preserve_exact_ownership_subjects()
    {
        var failures = new List<int>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var state = (ScaleInState)(1 + seed % 9);
            var stateful = seed % 2 == 0;
            var role = stateful ? ComputeNodeRole.ElasticStateful : ComputeNodeRole.ElasticStateless;
            var binding = ScaleInBinding(seed, role);
            var request = new ScaleInRequest(binding, state, ScaleInAuthorization(binding, 5, 1, stateful),
                ScaleInProgress(binding, state, stateful), 50, 128);
            var decision = ComputeEngine.DecideScaleIn(request);
            if (!ExactScaleInOutcome(decision, request, stateful)) failures.Add(seed);
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Generated_survival_completeness_authority_and_replacement_gates_match_precedence()
    {
        var failures = new List<int>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var bundle = Bundle(seed);
            var mask = seed % 32;
            var incomplete = (mask & 2) != 0;
            var mismatched = (mask & 1) != 0;
            var observed = mismatched ? Bundle(seed + 10_000) : bundle;
            var evidence = Evidence(bundle) with
            {
                Observed = observed,
                SignatureValid = !incomplete || seed % 9 != 0,
                MetadataEncrypted = !incomplete || seed % 9 != 1,
                ArtifactsLocal = !incomplete || seed % 9 != 2,
                SecretsLocal = !incomplete || seed % 9 != 3,
                ProviderReady = !incomplete || seed % 9 != 4,
                TrustReady = !incomplete || seed % 9 != 5,
                NatsReady = !incomplete || seed % 9 != 6,
                DnsReady = !incomplete || seed % 9 != 7,
                BackupReady = !incomplete || seed % 9 != 8,
            };
            var authority = Authority(bundle) with
            {
                AuthorityEpoch = (mask & 8) != 0 ? bundle.AuthorityEpoch + 1 : bundle.AuthorityEpoch,
                QuorumAuthoritative = (mask & 8) == 0,
            };
            var disconnected = true;
            var target = (mask & 16) != 0 ? null : Target(bundle, seed);
            var evaluation = (mask & 4) != 0 ? bundle.ExpiresAfterPosition + 1 : 100;
            var decision = ComputeEngine.DecideSurvival(new(bundle, evidence, authority, bundle.Generation,
                evaluation, disconnected, target, 128));
            var expected = mismatched ? ComputeErrorCode.EvidenceMismatch : incomplete ? ComputeErrorCode.BundleIncomplete :
                (mask & 4) != 0 ? ComputeErrorCode.BundleExpired : (mask & 8) != 0 ? ComputeErrorCode.AuthorityDenied :
                (mask & 16) != 0 ? ComputeErrorCode.MissingProof : ComputeErrorCode.Unspecified;
            if (expected == ComputeErrorCode.Unspecified)
            {
                if (decision.Errors.Count != 0 || decision.Intents.Count != 1 ||
                    decision.Intents[0] is not AuthorizeSurvivalIntent intent || intent.Action != ComputeAction.Authorize ||
                    intent.Bundle != bundle || intent.Authority != authority || intent.Target != target ||
                    !ExactTrace(decision, ComputeTraceCode.AuthorizationReady, ComputeAction.Authorize)) failures.Add(seed);
            }
            else if (!ExactHeld(decision, expected, target?.Operation)) failures.Add(seed);
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Generated_survival_generation_high_water_is_exact_culture_and_replay_stable()
    {
        var failures = new List<int>();
        var original = CultureInfo.CurrentCulture;
        try
        {
            for (var seed = 1; seed <= Cases; seed++)
            {
                var bundle = Bundle(seed);
                var relation = seed % 3;
                var current = relation switch
                {
                    0 => bundle.Generation + 1,
                    1 => bundle.Generation,
                    _ => bundle.Generation - 1,
                };
                var request = new SurvivalRequest(bundle, Evidence(bundle), Authority(bundle), current, 100, true,
                    Target(bundle, seed), 128);
                CultureInfo.CurrentCulture = new("tr-TR");
                var first = ComputeEngine.DecideSurvival(request);
                CultureInfo.CurrentCulture = new("ar-SA");
                var replay = ComputeEngine.DecideSurvival(request);
                var expected = relation switch
                {
                    0 => ComputeErrorCode.EvidenceStale,
                    1 => ComputeErrorCode.Unspecified,
                    _ => ComputeErrorCode.EvidenceMismatch,
                };
                var exact = expected == ComputeErrorCode.Unspecified
                    ? first.Errors.Count == 0 && first.Intents.Count == 1 &&
                      first.Intents[0] is AuthorizeSurvivalIntent authorized && authorized.Bundle == bundle &&
                      authorized.Target == request.ReplacementTarget
                    : ExactHeld(first, expected, request.ReplacementTarget!.Operation) &&
                      first.Intents.All(static intent => intent is not AuthorizeSurvivalIntent and not ReadySurvivalIntent);
                if (!exact || !StringComparer.Ordinal.Equals(Signature(first), Signature(replay))) failures.Add(seed);
            }
        }
        finally { CultureInfo.CurrentCulture = original; }
        await Assert.That(failures).IsEmpty();
    }

    private static bool ExactScaleOutOutcome(ComputeDecision decision, ScaleOutRequest request)
    {
        if (decision.Errors.Count != 0) return false;
        return request.State switch
        {
        ScaleOutState.DemandObserved => ExactTrace(decision, ComputeTraceCode.PlanRequired, ComputeAction.PersistPlan) &&
            decision.Intents.Count == 1 && decision.Intents[0] is PersistScalePlanIntent value &&
            value.Action == ComputeAction.PersistPlan &&
            value.Binding == request.Binding && value.Resources == request.Plan.Resources &&
            value.DesiredNodes == request.Plan.DesiredNodes && value.PlanIdentity == request.Plan.PlanIdentity,
        ScaleOutState.PlanPersisted => ExactTrace(decision, ComputeTraceCode.AuthorizationReady, ComputeAction.Authorize) &&
            decision.Intents.Count == 1 && decision.Intents[0] is AuthorizeCapacityIntent value &&
            value.Action == ComputeAction.Authorize &&
            value.Binding == request.Binding && value.PersistedPlan == request.PersistedPlan,
        ScaleOutState.Authorized => ExactTrace(decision, ComputeTraceCode.CreateReady, ComputeAction.RequestCreate) &&
            decision.Intents.Count == 1 && decision.Intents[0] is RequestCreateIntent value &&
            value.Action == ComputeAction.RequestCreate &&
            value.Binding == request.Binding && value.CreateKey == request.CreateEvidence!.CreateKey &&
            value.PersistedPlan == request.PersistedPlan && value.Authorization == request.Authorization &&
            value.CreateEvidence == request.CreateEvidence && value.CreateKey == value.CreateEvidence.CreateKey,
        ScaleOutState.RequestRecorded when request.CreateEvidence!.Status == ProviderCreateStatus.OutcomeUnknown =>
            ExactTrace(decision, ComputeTraceCode.ObservationRequired, ComputeAction.Observe) &&
            decision.Intents.Count == 1 && decision.Intents[0] is ObserveCreateIntent value &&
            value.Action == ComputeAction.Observe && value.Binding == request.Binding &&
            value.CreateKey == request.CreateEvidence.CreateKey,
        ScaleOutState.RequestRecorded or ScaleOutState.InstanceCreated =>
            ExactTrace(decision, ComputeTraceCode.EnrollmentReady, ComputeAction.Enroll) &&
            decision.Intents.Count == 1 && decision.Intents[0] is EnrollNodeIntent value &&
            value.Action == ComputeAction.Enroll && value.Binding == request.Binding &&
            value.Resource == request.CreateEvidence!.Resource && value.Node == request.Progress!.Node &&
            value.IdentityProof == request.Progress.IdentityProof,
        ScaleOutState.Enrolled => ExactTrace(decision, ComputeTraceCode.ReadinessReady, ComputeAction.Ready) &&
            decision.Intents.Count == 1 && decision.Intents[0] is ReadyNodeIntent value && value.Action == ComputeAction.Ready &&
            value.Binding == request.Binding && value.Resource == request.Progress!.Resource &&
            value.Node == request.Progress.Node && value.BootstrapProof == request.Progress.BootstrapProof &&
            value.DiskProof == request.Progress.DiskProof && value.PlacementProof == request.Authorization!.PlacementProof,
        ScaleOutState.Ready or ScaleOutState.Completed => decision.Intents.Count == 0 && decision.Errors.Count == 0 &&
            ExactTrace(decision, ComputeTraceCode.Completed, ComputeAction.Ready),
        _ => false,
        };
    }

    private static bool ExactScaleInOutcome(ComputeDecision decision, ScaleInRequest request, bool stateful)
    {
        if (request.State is ScaleInState.Audited or ScaleInState.Completed)
            return decision.Intents.Count == 0 && decision.Errors.Count == 0 &&
                ExactTrace(decision, ComputeTraceCode.Completed, ComputeAction.Ready);
        if (decision.Errors.Count != 0 || decision.Intents.Count != 1) return false;
        var intent = decision.Intents[0];
        if (IntentBinding(intent) != request.Binding) return false;
        var expectedTrace = request.State switch
        {
            ScaleInState.CandidateSelected => (ComputeTraceCode.CordonReady, ComputeAction.Cordon),
            ScaleInState.Cordoned => (ComputeTraceCode.DrainReady, ComputeAction.Drain),
            ScaleInState.Drained => (ComputeTraceCode.DeregistrationReady, ComputeAction.Deregister),
            ScaleInState.Deregistered => (ComputeTraceCode.VolumeReady, ComputeAction.Detach),
            ScaleInState.StorageHandled => (ComputeTraceCode.RevocationReady, ComputeAction.Revoke),
            ScaleInState.Revoked => (ComputeTraceCode.TerminationReady, ComputeAction.Terminate),
            ScaleInState.Terminated => (ComputeTraceCode.AuditReady, ComputeAction.Audit),
            _ => (ComputeTraceCode.Unspecified, ComputeAction.Unspecified),
        };
        if (!ExactTrace(decision, expectedTrace.Item1, expectedTrace.Item2)) return false;
        return request.State switch
        {
            ScaleInState.CandidateSelected => intent is CordonNodeIntent && intent.Action == ComputeAction.Cordon,
            ScaleInState.Cordoned => intent is DrainNodeIntent value && value.Action == ComputeAction.Drain &&
                value.CordonProof == request.Progress.CordonProof,
            ScaleInState.Drained => intent is DeregisterNodeIntent value && value.Action == ComputeAction.Deregister &&
                value.StatefulProof == request.Authorization.StatefulProof,
            ScaleInState.Deregistered => intent is DetachVolumeIntent value &&
                value.Action == ComputeAction.Detach &&
                value.Disposition == (stateful ? VolumeDisposition.RetainedStateful : VolumeDisposition.DetachedEphemeral) &&
                value.StatefulOwner == request.Progress.StatefulOwner,
            ScaleInState.StorageHandled => intent is RevokeNodeIntent value && value.Action == ComputeAction.Revoke &&
                value.VolumeProof == request.Progress.VolumeProof,
            ScaleInState.Revoked => intent is TerminateNodeIntent value && value.Action == ComputeAction.Terminate &&
                value.RevocationProof == request.Progress.RevocationProof && value.Authorization == request.Authorization &&
                value.Progress == request.Progress && value.RevocationProof == value.Progress.RevocationProof,
            ScaleInState.Terminated => intent is AuditOrphansIntent value && value.Action == ComputeAction.Audit &&
                value.TerminationProof == request.Progress.TerminationProof &&
                value.BootAbsenceProof == request.Progress.BootAbsenceProof,
            _ => false,
        };
    }

    private static ComputeBinding Binding(int seed) => new(new($"cell-{seed}"), new($"class-{seed}"),
        new($"template-{seed}"), new($"shape-{seed}"), new($"domain-{seed}"), new($"artifact-{seed}"),
        new($"digest-{seed}"), new($"demand-{seed}"), new($"operation-{seed}"), new($"provider-{seed}"),
        10_000 + seed, 20_000 + seed);
    private static ResourceEnvelope Resources(int seed) => new((ulong)(1 + seed % 8), (ulong)(4_096 + seed),
        (ulong)(50 + seed % 200), (ulong)(100_000 + seed));
    private static DemandEvidence Demand(ComputeBinding binding) => new(binding, ComputeTrigger.Unschedulable, 45, 60,
        1 + (int)(binding.Generation % 3), true, true, false);
    private static ScaleOutPlan Plan(ComputeBinding binding) => new(binding, Resources((int)(binding.Generation - 10_000)),
        Demand(binding).RequiredNodes, new($"plan-{binding.Generation}"));
    private static CapacityAuthorization Authorization(ComputeBinding binding)
    {
        var plan = Plan(binding);
        return new(binding, plan.Resources, plan.DesiredNodes, new($"budget-{binding.Generation}"),
            new($"quota-{binding.Generation}"), new($"capacity-{binding.Generation}"), new($"cost-{binding.Generation}"),
            new($"placement-{binding.Generation}"), true, true, true, true, true);
    }
    private static ProviderCreateEvidence Create(ComputeBinding binding, ProviderCreateStatus status) => new(binding,
        new($"create-{binding.Generation - 10_000}"), status, status == ProviderCreateStatus.Created
            ? new ProviderResourceId($"resource-{binding.Generation}") : null, status == ProviderCreateStatus.Created
            ? new WorkRequestId($"work-{binding.Generation}") : null, new($"observation-{binding.Generation}"));
    private static ScaleOutProgress Progress(ComputeBinding binding, ScaleOutState state) => new(binding,
        new($"resource-{binding.Generation}"), new($"node-{binding.Generation}"), state >= ScaleOutState.InstanceCreated
            ? new($"identity-{binding.Generation}") : null, state >= ScaleOutState.Enrolled ? new($"enroll-{binding.Generation}") : null,
        state >= ScaleOutState.Enrolled ? new($"bootstrap-{binding.Generation}") : null,
        state >= ScaleOutState.Enrolled ? new($"disk-{binding.Generation}") : null,
        state >= ScaleOutState.Ready ? new($"placed-{binding.Generation}") : null,
        state >= ScaleOutState.Ready ? new($"health-{binding.Generation}") : null,
        state >= ScaleOutState.InstanceCreated, state >= ScaleOutState.Enrolled, state >= ScaleOutState.Enrolled,
        state >= ScaleOutState.Enrolled, state >= ScaleOutState.Ready, state >= ScaleOutState.Ready);
    private static ScaleOutRequest ScaleOut(ComputeBinding binding, ScaleOutState state,
        CapacityAuthorization? authorization = null, bool unknownCreateOutcome = false)
    {
        var plan = Plan(binding);
        var created = Create(binding, ProviderCreateStatus.Created);
        return new(binding, state, Demand(binding), plan, state == ScaleOutState.DemandObserved ? null : new(plan,
            new($"persisted-{binding.Generation}")), state < ScaleOutState.Authorized ? null : authorization ?? Authorization(binding),
            state < ScaleOutState.Authorized ? null : state == ScaleOutState.Authorized
                ? Create(binding, ProviderCreateStatus.ProvenAbsent) : unknownCreateOutcome
                    ? Create(binding, ProviderCreateStatus.OutcomeUnknown) : created,
            state is ScaleOutState.RequestRecorded && !unknownCreateOutcome ? Progress(binding, ScaleOutState.InstanceCreated) :
                state >= ScaleOutState.InstanceCreated ? Progress(binding, state) : null, 50, 128);
    }

    private static ScaleInBinding ScaleInBinding(int seed, ComputeNodeRole role) => new(Binding(seed), new($"node-{seed}"),
        new($"resource-{seed}"), new($"lb-{seed}"), new($"volume-{seed}"), role);
    private static ScaleInAuthorization ScaleInAuthorization(ScaleInBinding binding, int current, int minimum, bool stateful) =>
        new(binding, new($"low-{binding.Compute.Generation}"), 45, 60, current, minimum, 1, 1,
            new($"low-proof-{binding.Compute.Generation}"), new($"cooldown-{binding.Compute.Generation}"),
            new($"lifetime-{binding.Compute.Generation}"), new($"benefit-{binding.Compute.Generation}"),
            new($"control-{binding.Compute.Generation}"), new($"nats-{binding.Compute.Generation}"),
            new($"availability-{binding.Compute.Generation}"), stateful ? StatefulDisposition.Approved : StatefulDisposition.NotStateful,
            new($"stateful-{binding.Compute.Generation}"), true, true, true, true, true, true, false, stateful);
    private static ScaleInProgress ScaleInProgress(ScaleInBinding binding, ScaleInState state, bool stateful) => new(binding,
        state >= ScaleInState.Cordoned ? new($"cordon-{binding.Compute.Generation}") : null,
        state >= ScaleInState.Drained ? new($"drain-{binding.Compute.Generation}") : null,
        state >= ScaleInState.Deregistered ? new($"deregister-{binding.Compute.Generation}") : null,
        state >= ScaleInState.StorageHandled ? new($"volume-{binding.Compute.Generation}") : null,
        state >= ScaleInState.Revoked ? new($"revoke-{binding.Compute.Generation}") : null,
        state >= ScaleInState.Terminated ? new($"terminate-{binding.Compute.Generation}") : null,
        state >= ScaleInState.Terminated ? new($"boot-{binding.Compute.Generation}") : null,
        state >= ScaleInState.Audited ? new($"orphan-{binding.Compute.Generation}") : null,
        stateful ? VolumeDisposition.RetainedStateful : VolumeDisposition.DetachedEphemeral,
        stateful ? new($"owner-{binding.Compute.Generation}") : null, state >= ScaleInState.Cordoned,
        state >= ScaleInState.Drained, state >= ScaleInState.Deregistered, state >= ScaleInState.StorageHandled,
        state >= ScaleInState.Revoked, state >= ScaleInState.Terminated, state >= ScaleInState.Terminated,
        state >= ScaleInState.Audited);
    private static bool IsStateful(ComputeNodeRole role) => role is ComputeNodeRole.ElasticStateful or
        ComputeNodeRole.ControlNats or ComputeNodeRole.ProductNats or ComputeNodeRole.TerraBase;
    private static bool IsCritical(ComputeNodeRole role) => role is ComputeNodeRole.SeedController or
        ComputeNodeRole.ControlNats or ComputeNodeRole.ProductNats or ComputeNodeRole.TerraBase;
    private static ScaleInBinding IntentBinding(ComputeIntent intent) => intent switch
    {
        CordonNodeIntent value => value.Binding, DrainNodeIntent value => value.Binding,
        DeregisterNodeIntent value => value.Binding, DetachVolumeIntent value => value.Binding,
        RevokeNodeIntent value => value.Binding, TerminateNodeIntent value => value.Binding,
        AuditOrphansIntent value => value.Binding, _ => throw new InvalidOperationException(),
    };

    private static RegionalSurvivalBundle Bundle(int seed) => new(new($"bundle-{seed}"), new($"cell-{seed}"), seed + 1,
        new($"provider-{seed}"), new($"accepted-{seed}"), new($"accepted-digest-{seed}"), new($"accepted-signature-{seed}"),
        new($"rollback-{seed}"), new($"rollback-digest-{seed}"), new($"rollback-signature-{seed}"),
        [new($"secret-a-{seed}"), new($"secret-b-{seed}")],
        [new(new($"class-{seed}"), new($"template-{seed}"), new($"shape-{seed}"), new($"domain-{seed}"))],
        new($"trust-{seed}"), new($"nats-{seed}"), new($"dns-{seed}"), new($"backup-{seed}"), seed + 10, 90, 80, 150, 200);
    private static SurvivalBundleEvidence Evidence(RegionalSurvivalBundle bundle) => new(bundle, new("signature"),
        new("encryption"), true, true, true, true, true, true, true, true, true);
    private static RegionalAuthorityProof Authority(RegionalSurvivalBundle bundle) => new(bundle.Cell,
        bundle.AuthorityEpoch, bundle.JournalPosition, new("authority"), true);
    private static SurvivalReplacementTarget Target(RegionalSurvivalBundle bundle, int seed)
    {
        var template = bundle.Templates.Single();
        return new(bundle.Cell, template.NodeClass, template.Template, template.Shape, template.Domain,
            bundle.AcceptedArtifact, bundle.AcceptedDigest, new($"replacement-{seed}"), bundle.ProviderFingerprint,
            new($"replacement-create-{seed}"), bundle.Generation, bundle.AuthorityEpoch);
    }
    private static string Signature(ComputeDecision decision) => string.Join('|',
        decision.Intents.Select(IntentSignature).Concat(decision.Errors.Select(static error =>
            $"e:{(int)error.Code}:{(int)error.Requirement}:{error.Operation?.Value}")).Concat(decision.Trace.Select(static trace =>
            $"t:{trace.Sequence}:{(int)trace.Code}:{(int)trace.Action}")));
    private static string IntentSignature(ComputeIntent intent) => intent switch
    {
        PersistScalePlanIntent value => $"plan:{(int)value.Action}:{BindingSignature(value.Binding)}:{ResourceSignature(value.Resources)}:{value.DesiredNodes}:{value.PlanIdentity.Value}",
        AuthorizeCapacityIntent value => $"authorize:{(int)value.Action}:{BindingSignature(value.Binding)}:{BindingSignature(value.PersistedPlan.Plan.Binding)}:{ResourceSignature(value.PersistedPlan.Plan.Resources)}:{value.PersistedPlan.Plan.DesiredNodes}:{value.PersistedPlan.Plan.PlanIdentity.Value}:{value.PersistedPlan.PersistenceProof.Value}",
        RequestCreateIntent value => $"create:{(int)value.Action}:{BindingSignature(value.Binding)}:{value.CreateKey.Value}",
        ObserveCreateIntent value => $"observe:{(int)value.Action}:{BindingSignature(value.Binding)}:{value.CreateKey.Value}",
        EnrollNodeIntent value => $"enroll:{(int)value.Action}:{BindingSignature(value.Binding)}:{value.Resource.Value}:{value.Node.Value}:{value.IdentityProof.Value}",
        ReadyNodeIntent value => $"ready:{(int)value.Action}:{BindingSignature(value.Binding)}:{value.Resource.Value}:{value.Node.Value}:{value.BootstrapProof.Value}:{value.DiskProof.Value}:{value.PlacementProof.Value}",
        HoldComputeIntent value => $"hold:{(int)value.Action}:{(int)value.Reason}:{value.Operation?.Value}",
        _ => $"{intent.GetType().Name}:{(int)intent.Action}",
    };
    private static string BindingSignature(ComputeBinding value) => string.Join(':', value.Cell.Value, value.NodeClass.Value,
        value.Template.Value, value.Shape.Value, value.Domain.Value, value.Artifact.Value, value.ArtifactDigest.Value,
        value.Demand.Value, value.Operation.Value, value.ProviderFingerprint.Value,
        value.Generation.ToString(CultureInfo.InvariantCulture), value.ControllerEpoch.ToString(CultureInfo.InvariantCulture));
    private static string ResourceSignature(ResourceEnvelope value) => string.Join(':',
        value.Ocpus.ToString(CultureInfo.InvariantCulture), value.MemoryMib.ToString(CultureInfo.InvariantCulture),
        value.StorageGib.ToString(CultureInfo.InvariantCulture), value.EstimatedHourlyCostMicros.ToString(CultureInfo.InvariantCulture));
    private static bool ExactHeld(ComputeDecision decision, ComputeErrorCode code, ComputeOperationId? operation) =>
        decision.Errors.Count == 1 && decision.Errors[0].Code == code &&
        decision.Errors[0].Requirement == ComputeRequirementCode.ReqO011 && decision.Errors[0].Operation == operation &&
        decision.Intents.Count == 1 && decision.Intents[0] is HoldComputeIntent hold &&
        hold.Action == ComputeAction.Hold && hold.Reason == code && hold.Operation == operation &&
        ExactTrace(decision, ComputeTraceCode.Held, ComputeAction.Hold);
    private static bool ExactTrace(ComputeDecision decision, ComputeTraceCode code, ComputeAction action) =>
        decision.Trace.Count == 1 && decision.Trace[0].Sequence == 1 && decision.Trace[0].Code == code &&
        decision.Trace[0].Action == action;
}
