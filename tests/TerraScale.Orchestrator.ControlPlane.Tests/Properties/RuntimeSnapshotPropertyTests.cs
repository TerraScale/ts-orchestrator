using System.Collections;
using TerraScale.Orchestrator.ControlPlane.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class RuntimeSnapshotPropertyTests
{
    private const int Limit = RuntimeTechnicalLimits.MaximumCapturedItems;

    [Test]
    public async Task Runtime_capture_accepts_exact_limit_and_rejects_max_plus_one_and_infinite_before_extra_Current()
    {
        var exact = RuntimeUpgradeData.Update(1, 0, suppliedHealth: Enumerable.Range(0, Limit).Select(i => Health(i)));
        await Assert.That(exact.Health.Count).IsEqualTo(Limit);
        var finite = new HostileEnumerable<RuntimeHealthEvidence>(Limit + 1, () => Health(0), throwOnCurrentIndex: Limit);
        await Assert.That(Throws<ArgumentException>(() => RuntimeUpgradeData.Update(2, 0, suppliedHealth: finite))).IsTrue();
        await Assert.That(finite.CurrentCalls).IsEqualTo(Limit);
        var endless = new EndlessEnumerable<RuntimeHealthEvidence>(() => Health(0));
        await Assert.That(Throws<ArgumentException>(() => RuntimeUpgradeData.Update(2, 0, suppliedHealth: endless))).IsTrue();
        await Assert.That(endless.CurrentCalls).IsEqualTo(Limit);
    }

    [Test]
    public async Task Runtime_iterator_failures_are_secret_safe_and_fatal_exceptions_propagate_at_every_phase()
    {
        foreach (var phase in new[] { Phase.GetEnumerator, Phase.MoveNext, Phase.Current, Phase.Dispose })
        {
            var error = Capture<ArgumentException>(() => RuntimeUpgradeData.Update(3, 0, suppliedHealth:
                new HostileEnumerable<RuntimeHealthEvidence>(1, () => Health(0), failure: phase)));
            await Assert.That(error.Message).DoesNotContain("sentinel-secret"); await Assert.That(error.InnerException).IsNull();
            foreach (var fatal in new Func<Exception>[] { () => new OutOfMemoryException("sentinel-secret"),
                         () => new StackOverflowException("sentinel-secret"), () => new AccessViolationException("sentinel-secret") })
                await Assert.That(ThrowsExact(() => RuntimeUpgradeData.Update(4, 0, suppliedHealth:
                    new HostileEnumerable<RuntimeHealthEvidence>(1, () => Health(0), failure: phase, fatal: fatal)), fatal().GetType())).IsTrue();
        }
    }

    [Test]
    public async Task Dispose_mutation_cannot_change_runtime_snapshot()
    {
        var source = new List<RuntimeHealthEvidence> { Health(0) };
        var request = RuntimeUpgradeData.Update(5, 0, suppliedHealth: new DisposeMutationEnumerable<RuntimeHealthEvidence>(source));
        await Assert.That(source.Count).IsEqualTo(0); await Assert.That(request.Health.Count).IsEqualTo(1);
    }

    private static RuntimeHealthEvidence Health(int index) => new(new($"health-{index}"), new("operation-1"), new("allocation-1"), new(1), HealthDimension.Liveness, HealthStatus.Ready);
    private static bool Throws<T>(Action action) where T : Exception { try { action(); return false; } catch (T) { return true; } }
    private static bool ThrowsExact(Action action, Type expected) { try { action(); return false; } catch (Exception error) { return error.GetType() == expected; } }
    private static T Capture<T>(Action action) where T : Exception { try { action(); } catch (T error) { return error; } throw new InvalidOperationException(); }
    private enum Phase { None, GetEnumerator, MoveNext, Current, Dispose }

    private sealed class HostileEnumerable<T> : IEnumerable<T>
    {
        private readonly int _count; private readonly Func<T> _factory; private readonly int _throwOnCurrentIndex; private readonly Phase _failure; private readonly Func<Exception>? _fatal;
        public HostileEnumerable(int count, Func<T> factory, int throwOnCurrentIndex = -1, Phase failure = Phase.None, Func<Exception>? fatal = null)
        { _count = count; _factory = factory; _throwOnCurrentIndex = throwOnCurrentIndex; _failure = failure; _fatal = fatal; }
        public int CurrentCalls { get; private set; }
        public IEnumerator<T> GetEnumerator() { if (_failure == Phase.GetEnumerator) Throw(); return new Iterator(this); }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private void Throw() { if (_fatal is not null) throw _fatal(); throw new InvalidOperationException("sentinel-secret"); }
        private sealed class Iterator(HostileEnumerable<T> owner) : IEnumerator<T>
        {
            private int _index = -1;
            public T Current { get { owner.CurrentCalls++; if (owner._failure == Phase.Current || _index == owner._throwOnCurrentIndex) owner.Throw(); return owner._factory(); } }
            object? IEnumerator.Current => Current;
            public bool MoveNext() { if (owner._failure == Phase.MoveNext) owner.Throw(); return ++_index < owner._count; }
            public void Reset() => throw new NotSupportedException();
            public void Dispose() { if (owner._failure == Phase.Dispose) owner.Throw(); }
        }
    }

    private sealed class DisposeMutationEnumerable<T>(List<T> source) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() => new Iterator(source); IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Iterator(List<T> source) : IEnumerator<T>
        {
            private int _index = -1; public T Current => source[_index]; object? IEnumerator.Current => Current;
            public bool MoveNext() => ++_index < source.Count; public void Reset() => throw new NotSupportedException(); public void Dispose() => source.Clear();
        }
    }

    private sealed class EndlessEnumerable<T>(Func<T> factory) : IEnumerable<T>, IEnumerator<T>
    {
        public int CurrentCalls { get; private set; }
        public T Current { get { CurrentCalls++; return factory(); } } object? IEnumerator.Current => Current;
        public IEnumerator<T> GetEnumerator() => this; IEnumerator IEnumerable.GetEnumerator() => this;
        public bool MoveNext() => true; public void Reset() { } public void Dispose() { }
    }
}

