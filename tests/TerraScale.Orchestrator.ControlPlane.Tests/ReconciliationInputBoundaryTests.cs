using System.Collections;
using TerraScale.Orchestrator.ControlPlane.Reconciliation;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class ReconciliationInputBoundaryTests
{
    private const int Limit = ReconciliationTechnicalInputLimits.MaximumCapturedItems;

    [Test]
    public async Task Every_reconciliation_capture_site_accepts_the_exact_technical_bound()
    {
        var dependencies = Enumerable.Range(0, Limit).Select(index => Id($"dependency-{index}")).ToArray();
        var allowedKinds = Enumerable.Range(0, Limit).Select(index => $"kind-{index}").ToArray();
        var floors = Enumerable.Range(0, Limit).ToDictionary(index => Id($"floor-{index}"), index => (long)index);
        var desired = Enumerable.Range(0, Limit).Select(index => Desired($"desired-{index}")).ToArray();
        var observed = Enumerable.Range(0, Limit).Select(index => Observed($"observed-{index}")).ToArray();

        await Assert.That(new DesiredResource(Id("root"), "kind", 1, "digest", dependencies).Dependencies.Count).IsEqualTo(Limit);
        var policy = new ReconciliationPolicy(allowedKinds, floors, 1, 1, 1, 1, 1, 1, 1);
        await Assert.That(policy.AllowedKinds.Count).IsEqualTo(Limit);
        await Assert.That(policy.GenerationFloors.Count).IsEqualTo(Limit);
        var request = new ReconciliationRequest(desired, observed, policy);
        await Assert.That(request.Desired.Count).IsEqualTo(Limit);
        await Assert.That(request.Observed.Count).IsEqualTo(Limit);
    }

    [Test]
    public async Task Every_reconciliation_capture_site_rejects_max_plus_one()
    {
        var tooManyDependencies = Enumerable.Range(0, Limit + 1).Select(index => Id($"dependency-{index}"));
        var tooManyKinds = Enumerable.Range(0, Limit + 1).Select(index => $"kind-{index}");
        var tooManyFloors = Enumerable.Range(0, Limit + 1).ToDictionary(index => Id($"floor-{index}"), index => (long)index);
        var tooManyDesired = Enumerable.Range(0, Limit + 1).Select(index => Desired($"desired-{index}"));
        var tooManyObserved = Enumerable.Range(0, Limit + 1).Select(index => Observed($"observed-{index}"));

        await Assert.That(Capture(() => new DesiredResource(Id("root"), "kind", 1, "digest", tooManyDependencies))).IsTypeOf<ArgumentException>();
        await Assert.That(Capture(() => new ReconciliationPolicy(tooManyKinds, EmptyFloors(), 1, 1, 1, 1, 1, 1, 1))).IsTypeOf<ArgumentException>();
        await Assert.That(Capture(() => new ReconciliationPolicy([], tooManyFloors, 1, 1, 1, 1, 1, 1, 1))).IsTypeOf<ArgumentException>();
        await Assert.That(Capture(() => new ReconciliationRequest(tooManyDesired, [], Policy()))).IsTypeOf<ArgumentException>();
        await Assert.That(Capture(() => new ReconciliationRequest([], tooManyObserved, Policy()))).IsTypeOf<ArgumentException>();
    }

    [Test]
    public async Task Endless_input_is_bounded_before_an_extra_Current_read()
    {
        var trap = new ExtraCurrentTrapEnumerable();
        var trapped = Capture(() => new DesiredResource(Id("root"), "kind", 1, "digest", trap));
        var endlessDependencies = Capture(() => new DesiredResource(Id("root"), "kind", 1, "digest", InfiniteDependencies()));
        var endless = Capture(() => new ReconciliationRequest(InfiniteDesired(), [], Policy()));

        await Assert.That(trapped).IsTypeOf<ArgumentException>();
        await Assert.That(trap.ExtraCurrentRead).IsFalse();
        await Assert.That(endlessDependencies).IsTypeOf<ArgumentException>();
        await Assert.That(endless).IsTypeOf<ArgumentException>();
    }

    [Test]
    public async Task Ordinary_iterator_failures_are_secret_safe_in_every_phase()
    {
        foreach (var phase in Enum.GetValues<ThrowPhase>())
        {
            var failure = Capture(() => new DesiredResource(Id("root"), "kind", 1, "digest",
                new ThrowingEnumerable<ResourceIdentity>([Id("dependency")], phase,
                    new InvalidOperationException("credential-looking-secret"))));
            await Assert.That(failure).IsTypeOf<ArgumentException>();
            await Assert.That(failure!.Message.Contains("credential-looking-secret", StringComparison.Ordinal)).IsFalse();
            await Assert.That(failure.InnerException).IsNull();
        }
    }

    [Test]
    public async Task Fatal_iterator_failures_propagate_in_every_phase()
    {
        foreach (var phase in Enum.GetValues<ThrowPhase>())
        foreach (var fatal in new Exception[] { new OutOfMemoryException(), new StackOverflowException(), new AccessViolationException() })
        {
            var failure = Capture(() => new DesiredResource(Id("root"), "kind", 1, "digest",
                new ThrowingEnumerable<ResourceIdentity>([Id("dependency")], phase, fatal)));
            await Assert.That(failure!.GetType()).IsEqualTo(fatal.GetType());
        }
    }

    [Test]
    public async Task Dispose_side_effects_cannot_mutate_the_captured_snapshot()
    {
        var source = new List<ResourceIdentity> { Id("one"), Id("two") };
        var resource = new DesiredResource(Id("root"), "kind", 1, "digest", new DisposeMutatingEnumerable<ResourceIdentity>(source));

        await Assert.That(source).IsEmpty();
        await Assert.That(resource.Dependencies.Select(identity => identity.Value)).IsEquivalentTo(["one", "two"]);
    }

    private static ResourceIdentity Id(string value) => new(value);
    private static DesiredResource Desired(string value) => new(Id(value), "kind", 1, "digest", []);
    private static ObservedResourceState Observed(string value) => new(Id(value), "kind", 1, "digest", "observation", 1, ObservedCondition.Ready);
    private static IReadOnlyDictionary<ResourceIdentity, long> EmptyFloors() => new Dictionary<ResourceIdentity, long>();
    private static ReconciliationPolicy Policy() => new(["kind"], EmptyFloors(), 10, 100, 100, 100, 100, 10, 1);
    private static IEnumerable<ResourceIdentity> InfiniteDependencies()
    { var index = 0; while (true) yield return Id($"dependency-{index++}"); }
    private static IEnumerable<DesiredResource> InfiniteDesired()
    { var index = 0; while (true) yield return Desired($"desired-{index++}"); }
    private static Exception? Capture(Action action) { try { action(); return null; } catch (Exception exception) { return exception; } }

    private enum ThrowPhase { GetEnumerator, MoveNext, Current, Dispose }

    private sealed class ThrowingEnumerable<T>(T[] values, ThrowPhase phase, Exception failure) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() => phase == ThrowPhase.GetEnumerator ? throw failure : new Enumerator(values, phase, failure);
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        private sealed class Enumerator(T[] values, ThrowPhase phase, Exception failure) : IEnumerator<T>
        {
            private int _index = -1;
            public T Current => phase == ThrowPhase.Current ? throw failure : values[_index];
            object IEnumerator.Current => Current!;
            public bool MoveNext() { if (phase == ThrowPhase.MoveNext) throw failure; return ++_index < values.Length; }
            public void Reset() => throw new NotSupportedException();
            public void Dispose() { if (phase == ThrowPhase.Dispose) throw failure; }
        }
    }

    private sealed class DisposeMutatingEnumerable<T>(List<T> values) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() => new Enumerator(values);
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        private sealed class Enumerator(List<T> values) : IEnumerator<T>
        {
            private readonly IEnumerator<T> _inner = values.GetEnumerator();
            public T Current => _inner.Current;
            object IEnumerator.Current => Current!;
            public bool MoveNext() => _inner.MoveNext();
            public void Reset() => _inner.Reset();
            public void Dispose() { _inner.Dispose(); values.Clear(); }
        }
    }

    private sealed class ExtraCurrentTrapEnumerable : IEnumerable<ResourceIdentity>
    {
        public bool ExtraCurrentRead { get; private set; }
        public IEnumerator<ResourceIdentity> GetEnumerator() => new Enumerator(this);
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        private sealed class Enumerator(ExtraCurrentTrapEnumerable owner) : IEnumerator<ResourceIdentity>
        {
            private int _index = -1;
            public ResourceIdentity Current
            {
                get
                {
                    if (_index == Limit)
                    {
                        owner.ExtraCurrentRead = true;
                        throw new InvalidOperationException("must-not-read");
                    }
                    return Id($"dependency-{_index}");
                }
            }
            object IEnumerator.Current => Current;
            public bool MoveNext() => ++_index <= Limit;
            public void Reset() => throw new NotSupportedException();
            public void Dispose() { }
        }
    }
}

