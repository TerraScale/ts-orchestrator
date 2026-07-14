using System.Collections;
using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Compute;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class ComputePropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task Generated_capacity_gates_match_an_independent_ordered_oracle()
    {
        var failures = new List<int>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var failedGate = seed % 5;
            var authorization = Authorization() with
            {
                BudgetAllowed = failedGate != 0,
                QuotaAllowed = failedGate != 1,
                CapacityAvailable = failedGate != 2,
                CostAllowed = failedGate != 3,
                PlacementAllowed = failedGate != 4,
            };
            var expected = failedGate switch
            {
                0 => ComputeErrorCode.BudgetDenied,
                1 => ComputeErrorCode.QuotaDenied,
                2 => ComputeErrorCode.CapacityDenied,
                3 => ComputeErrorCode.CostDenied,
                _ => ComputeErrorCode.PlacementDenied,
            };
            var decision = ComputeEngine.DecideScaleOut(Out(authorization));
            if (decision.Errors.Single().Code != expected || decision.Intents.Single() is not HoldComputeIntent)
                failures.Add(seed);
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Generated_generation_and_controller_fences_cannot_replay_capacity_proofs()
    {
        var failures = new List<int>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var baseline = Binding(seed);
            var replay = seed % 2 == 0
                ? baseline with { Generation = baseline.Generation + 1 }
                : baseline with { ControllerEpoch = baseline.ControllerEpoch + 1 };
            var decision = ComputeEngine.DecideScaleOut(Out(Authorization(replay), baseline));
            if (decision.Errors.Single().Code != ComputeErrorCode.MissingProof ||
                decision.Intents.Any(static intent => intent is RequestCreateIntent)) failures.Add(seed);
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Generated_scale_in_floors_match_independent_subtraction_without_underflow()
    {
        var failures = new List<int>();
        var roles = Enum.GetValues<ComputeNodeRole>().Where(static role => role != ComputeNodeRole.Unspecified).ToArray();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var role = roles[seed % roles.Length];
            var current = 1 + seed % 7;
            var minimum = seed % 4;
            var stateful = role is ComputeNodeRole.ElasticStateful or ComputeNodeRole.ControlNats or
                ComputeNodeRole.ProductNats or ComputeNodeRole.TerraBase;
            var critical = role is ComputeNodeRole.SeedController or ComputeNodeRole.ControlNats or
                ComputeNodeRole.ProductNats or ComputeNodeRole.TerraBase;
            var independentFloor = current <= minimum || current <= 1 ||
                (critical && (minimum < 3 || (long)current - 1 < 3));
            var binding = InBinding(seed, role);
            var decision = ComputeEngine.DecideScaleIn(In(binding, current, minimum, stateful));
            var actualFloor = decision.Errors.Any(static error => error.Code == ComputeErrorCode.FloorDenied);
            if (actualFloor != independentFloor || (!independentFloor && decision.Intents.Single() is not CordonNodeIntent))
                failures.Add(seed);
        }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Generated_decisions_replay_identically_across_supported_cultures()
    {
        var failures = new List<int>();
        var original = CultureInfo.CurrentCulture;
        try
        {
            for (var seed = 1; seed <= Cases; seed++)
            {
                var binding = Binding(seed);
                CultureInfo.CurrentCulture = new("tr-TR");
                var first = Signature(ComputeEngine.DecideScaleOut(Out(Authorization(binding), binding)));
                CultureInfo.CurrentCulture = new("ar-SA");
                var replay = Signature(ComputeEngine.DecideScaleOut(Out(Authorization(binding), binding)));
                if (!StringComparer.Ordinal.Equals(first, replay)) failures.Add(seed);
            }
        }
        finally { CultureInfo.CurrentCulture = original; }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Generated_survival_bundle_permutations_are_exact_and_culture_deterministic()
    {
        var failures = new List<int>();
        var original = CultureInfo.CurrentCulture;
        try
        {
            for (var seed = 1; seed <= Cases; seed++)
            {
                var secrets = new[] { new SecretVersionId($"secret-a-{seed}"), new SecretVersionId($"secret-b-{seed}") };
                var templates = new[] { Template(seed * 2), Template(seed * 2 + 1) };
                var required = Bundle(secrets, templates);
                var observed = Bundle(secrets.Reverse(), templates.Reverse());
                CultureInfo.CurrentCulture = new("tr-TR");
                var first = ComputeEngine.DecideSurvival(Survival(required, observed));
                CultureInfo.CurrentCulture = new("ar-SA");
                var replay = ComputeEngine.DecideSurvival(Survival(required, required));
                if (first.Intents.Single() is not ReadySurvivalIntent || Signature(first) != Signature(replay)) failures.Add(seed);
            }
        }
        finally { CultureInfo.CurrentCulture = original; }
        await Assert.That(failures).IsEmpty();
    }

    [Test]
    public async Task Survival_bundle_snapshot_accepts_exact_limits_and_is_defensive_after_dispose_mutation()
    {
        var secrets = Enumerable.Range(0, ComputeTechnicalInputLimits.MaximumSurvivalSecretVersionCount)
            .Select(index => new SecretVersionId($"secret-{index}")).ToList();
        var source = new DisposeMutatingEnumerable<SecretVersionId>(secrets);
        var templates = Enumerable.Range(0, ComputeTechnicalInputLimits.MaximumSurvivalNodeTemplateCount)
            .Select(index => Template(index)).ToArray();
        var bundle = Bundle(source, templates);
        await Assert.That(bundle.EncryptedSecretVersions.Count).IsEqualTo(ComputeTechnicalInputLimits.MaximumSurvivalSecretVersionCount);
        await Assert.That(bundle.Templates.Count).IsEqualTo(ComputeTechnicalInputLimits.MaximumSurvivalNodeTemplateCount);
        await Assert.That(secrets).IsEmpty();
    }

    [Test]
    public async Task Survival_bundle_snapshot_rejects_maximum_plus_one_infinite_and_extra_Current_without_reading_it()
    {
        var oversized = Capture(() => Bundle(Enumerable.Range(0,
            ComputeTechnicalInputLimits.MaximumSurvivalSecretVersionCount + 1).Select(index => new SecretVersionId($"s-{index}")),
            [Template(1)]));
        var oversizedTemplates = Capture(() => Bundle([new("secret")], Enumerable.Range(0,
            ComputeTechnicalInputLimits.MaximumSurvivalNodeTemplateCount + 1).Select(Template)));
        var infinite = Capture(() => Bundle(InfiniteSecrets(), [Template(1)]));
        var infiniteTemplates = Capture(() => Bundle([new("secret")], InfiniteTemplates()));
        var trap = new ExtraCurrentTrapSecrets();
        var trapped = Capture(() => Bundle(trap, [Template(1)]));
        await Assert.That(oversized).IsTypeOf<ArgumentException>();
        await Assert.That(oversizedTemplates).IsTypeOf<ArgumentException>();
        await Assert.That(infinite).IsTypeOf<ArgumentException>();
        await Assert.That(infiniteTemplates).IsTypeOf<ArgumentException>();
        await Assert.That(trapped).IsTypeOf<ArgumentException>();
        await Assert.That(trap.ExtraCurrentRead).IsFalse();
    }

    [Test]
    public async Task Survival_bundle_snapshot_translates_ordinary_iterator_failures_secret_safely_and_propagates_fatal()
    {
        const string secret = "plaintext-must-not-escape";
        foreach (var mode in Enum.GetValues<ThrowMode>())
        {
            var failure = Capture(() => Bundle(new ThrowingEnumerable<SecretVersionId>([new("s-1")], mode,
                new InvalidOperationException(secret)), [Template(1)]));
            await Assert.That(failure).IsTypeOf<ArgumentException>();
            await Assert.That(failure!.Message).DoesNotContain(secret);
        }
        foreach (var mode in Enum.GetValues<ThrowMode>())
        {
            var fatal = Capture(() => Bundle(new ThrowingEnumerable<SecretVersionId>([new("s-1")], mode,
                new OutOfMemoryException("fatal")), [Template(1)]));
            await Assert.That(fatal).IsTypeOf<OutOfMemoryException>();
        }
    }

    [Test]
    public async Task Compute_authorizing_outputs_and_observable_catalogs_are_construction_closed()
    {
        var outputs = typeof(ComputeIntent).Assembly.GetTypes().Where(type => type.Namespace == typeof(ComputeIntent).Namespace &&
            (typeof(ComputeIntent).IsAssignableFrom(type) || type == typeof(ComputeDecision))).ToArray();
        await Assert.That(outputs.All(static type => type.GetConstructors().Length == 0)).IsTrue();
        foreach (var type in new[] { typeof(ComputeAction), typeof(ComputeErrorCode), typeof(ComputeTrigger),
                     typeof(ComputeNodeRole), typeof(ScaleOutState), typeof(ScaleInState) })
            await Assert.That(Enum.GetValues(type).Cast<object>().All(value => Enum.IsDefined(type, value))).IsTrue();
    }

    private static ComputeBinding Binding(int seed = 1) => new(new($"cell-{seed}"), new("class"), new("template"),
        new("shape"), new("domain"), new("artifact"), new("digest"), new("demand"), new("operation"),
        new("provider"), 7, 3);
    private static DemandEvidence Demand(ComputeBinding binding) => new(binding, ComputeTrigger.Unschedulable, 45, 60, 1, true, true, false);
    private static ScaleOutPlan Plan(ComputeBinding binding) => new(binding, new(4, 24_576, 100, 120_000), 1, new("plan"));
    private static CapacityAuthorization Authorization(ComputeBinding? binding = null) => new(binding ?? Binding(),
        new(4, 24_576, 100, 120_000), 1, new("budget"), new("quota"), new("capacity"), new("cost"),
        new("placement"), true, true, true, true, true);
    private static ScaleOutRequest Out(CapacityAuthorization authorization, ComputeBinding? binding = null)
    {
        var exact = binding ?? Binding();
        var plan = Plan(exact);
        return new(exact, ScaleOutState.Authorized, Demand(exact), plan, new(plan, new("persisted")), authorization,
            new(exact, new("create"), ProviderCreateStatus.ProvenAbsent, null, null, new("observation")), null, 50, 64);
    }
    private static ScaleInBinding InBinding(int seed, ComputeNodeRole role) => new(Binding(seed), new("node"),
        new("instance"), new("lb"), new("volume"), role);
    private static ScaleInRequest In(ScaleInBinding binding, int current, int minimum, bool stateful)
    {
        var authorization = new ScaleInAuthorization(binding, new("low-use"), 45, 60, current, minimum, 1, 1,
            new("low"), new("cooldown"), new("lifetime"), new("benefit"), new("control"), new("nats"),
            new("availability"), stateful ? StatefulDisposition.Approved : StatefulDisposition.NotStateful,
            new("stateful"), true, true, true, true, true, true, false, stateful);
        var progress = new ScaleInProgress(binding, null, null, null, null, null, null, null, null,
            stateful ? VolumeDisposition.RetainedStateful : VolumeDisposition.DetachedEphemeral,
            stateful ? new StatefulOwnerId("owner") : null, false, false, false, false, false, false, false, false);
        return new(binding, ScaleInState.CandidateSelected, authorization, progress, 50, 64);
    }
    private static string Signature(ComputeDecision decision) => string.Join('|',
        decision.Intents.Select(static value => $"i:{(int)value.Action}:{value.GetType().Name}")
            .Concat(decision.Errors.Select(static value => $"e:{(int)value.Code}:{(int)value.Requirement}"))
            .Concat(decision.Trace.Select(static value => $"t:{value.Sequence}:{(int)value.Code}:{(int)value.Action}")));
    private static RegionalSurvivalBundle Bundle(IEnumerable<SecretVersionId> secrets,
        IEnumerable<SurvivalNodeTemplate> templates) => new(new("bundle"), new("cell"), 2, new("provider"),
        new("accepted"), new("accepted-digest"), new("accepted-signature"), new("rollback"),
        new("rollback-digest"), new("rollback-signature"), secrets, templates, new("trust"), new("nats"),
        new("dns"), new("backup"), 7, 90, 80, 150, 200);
    private static SurvivalRequest Survival(RegionalSurvivalBundle required, RegionalSurvivalBundle observed) => new(required,
        new(observed, new("signature"), new("encryption"), true, true, true, true, true, true, true, true, true),
        new(required.Cell, required.AuthorityEpoch, required.JournalPosition, new("authority"), true), 100, false, null, 64);
    private static SurvivalNodeTemplate Template(int index) => new(new($"class-{index}"), new($"template-{index}"),
        new("shape"), new($"domain-{index}"));
    private static IEnumerable<SecretVersionId> InfiniteSecrets()
    { var index = 0; while (true) yield return new($"secret-{index++}"); }
    private static IEnumerable<SurvivalNodeTemplate> InfiniteTemplates()
    { var index = 0; while (true) yield return Template(index++); }
    private static Exception? Capture(Action action) { try { action(); return null; } catch (Exception exception) { return exception; } }

    private enum ThrowMode { GetEnumerator, MoveNext, Current, Dispose }
    private sealed class ThrowingEnumerable<T>(T[] values, ThrowMode mode, Exception failure) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() => mode == ThrowMode.GetEnumerator ? throw failure : new Enumerator(values, mode, failure);
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Enumerator(T[] values, ThrowMode mode, Exception failure) : IEnumerator<T>
        {
            private int _index = -1;
            public T Current => mode == ThrowMode.Current ? throw failure : values[_index];
            object IEnumerator.Current => Current!;
            public bool MoveNext() { if (mode == ThrowMode.MoveNext) throw failure; return ++_index < values.Length; }
            public void Reset() => throw new NotSupportedException();
            public void Dispose() { if (mode == ThrowMode.Dispose) throw failure; }
        }
    }
    private sealed class DisposeMutatingEnumerable<T>(List<T> values) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() => new Enumerator(values);
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Enumerator(List<T> values) : IEnumerator<T>
        {
            private readonly IEnumerator<T> _inner = values.GetEnumerator();
            public T Current => _inner.Current; object IEnumerator.Current => Current!;
            public bool MoveNext() => _inner.MoveNext(); public void Reset() => _inner.Reset();
            public void Dispose() { _inner.Dispose(); values.Clear(); }
        }
    }
    private sealed class ExtraCurrentTrapSecrets : IEnumerable<SecretVersionId>
    {
        public bool ExtraCurrentRead { get; private set; }
        public IEnumerator<SecretVersionId> GetEnumerator() => new Enumerator(this);
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Enumerator(ExtraCurrentTrapSecrets owner) : IEnumerator<SecretVersionId>
        {
            private int _index = -1;
            public SecretVersionId Current
            {
                get
                {
                    if (_index == ComputeTechnicalInputLimits.MaximumSurvivalSecretVersionCount)
                    { owner.ExtraCurrentRead = true; throw new InvalidOperationException("must-not-read"); }
                    return new($"secret-{_index}");
                }
            }
            object IEnumerator.Current => Current;
            public bool MoveNext() => ++_index <= ComputeTechnicalInputLimits.MaximumSurvivalSecretVersionCount;
            public void Reset() => throw new NotSupportedException(); public void Dispose() { }
        }
    }
}
