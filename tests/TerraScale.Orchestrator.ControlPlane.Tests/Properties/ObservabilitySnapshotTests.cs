using System.Collections;
using TerraScale.Orchestrator.ControlPlane.Observability;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class ObservabilitySnapshotTests
{
    private const int Limit = (int)ObservabilityTechnicalLimits.MaximumCapturedItems;

    [Test]
    public async Task Exact_max_max_plus_one_and_literal_endless_stop_before_extra_Current()
    {
        var exact = Spec(Enumerable.Range(0, Limit).Select(Label)); await Assert.That(exact.Labels.Count).IsEqualTo(Limit);
        var plus = new Hostile<TelemetryLabel>(Limit + 1, () => Label(0), Limit);
        await Assert.That(Throws<ArgumentException>(() => Spec(plus))).IsTrue(); await Assert.That(plus.CurrentCalls).IsEqualTo(Limit);
        var endless = new Endless<TelemetryLabel>(() => Label(0)); await Assert.That(Throws<ArgumentException>(() => Spec(endless))).IsTrue(); await Assert.That(endless.CurrentCalls).IsEqualTo(Limit);
    }

    [Test]
    public async Task Every_iterator_phase_is_secret_safe_and_all_fatal_classes_propagate()
    {
        foreach (var phase in new[] { Phase.GetEnumerator, Phase.MoveNext, Phase.Current, Phase.Dispose })
        {
            var error = Capture<ArgumentException>(() => Spec(new Hostile<TelemetryLabel>(1, () => Label(0), failure: phase)));
            await Assert.That(error.Message).DoesNotContain("sentinel-secret"); await Assert.That(error.InnerException).IsNull();
            foreach (var fatal in new Func<Exception>[] { () => new OutOfMemoryException(), () => new StackOverflowException(), () => new AccessViolationException() })
                await Assert.That(ThrowsExact(() => Spec(new Hostile<TelemetryLabel>(1, () => Label(0), failure: phase, fatal: fatal)), fatal().GetType())).IsTrue();
        }
    }

    [Test]
    public async Task Dispose_mutation_cannot_change_snapshot_and_caller_limit_remains_effective()
    {
        var source = new List<TelemetryLabel> { Label(0) }; var spec = Spec(new Mutating<TelemetryLabel>(source));
        await Assert.That(source.Count).IsEqualTo(0); await Assert.That(spec.Labels.Count).IsEqualTo(1);
        await Assert.That(Throws<ArgumentException>(() => Spec([Label(0), Label(1)], 1))).IsTrue();
    }

    private static TelemetryAdmissionSpec Spec(IEnumerable<TelemetryLabel> labels, ulong limit = ObservabilityTechnicalLimits.MaximumCapturedItems) => new(new("operation"), new("tenant"), new("cell"), new("service"), new("signal"), new("metric"), TelemetrySignalKind.Metric, new(1), new(new string('a', 64)), new(limit), labels);
    private static TelemetryLabel Label(int i) => new(new($"key-{i}"), new($"value-{i}"));
    private static bool Throws<T>(Action a) where T : Exception { try { a(); return false; } catch (T) { return true; } }
    private static bool ThrowsExact(Action a, Type t) { try { a(); return false; } catch (Exception e) { return e.GetType() == t; } }
    private static T Capture<T>(Action a) where T : Exception { try { a(); } catch (T e) { return e; } throw new InvalidOperationException(); }
    private enum Phase { None, GetEnumerator, MoveNext, Current, Dispose }
    private sealed class Hostile<T> : IEnumerable<T>
    {
        private readonly int _count; private readonly Func<T> _factory; private readonly int _extra; private readonly Phase _failure; private readonly Func<Exception>? _fatal;
        public Hostile(int count, Func<T> factory, int extra = -1, Phase failure = Phase.None, Func<Exception>? fatal = null) { _count = count; _factory = factory; _extra = extra; _failure = failure; _fatal = fatal; }
        public int CurrentCalls { get; private set; } public IEnumerator<T> GetEnumerator() { if (_failure == Phase.GetEnumerator) Throw(); return new It(this); } IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private void Throw() { if (_fatal is not null) throw _fatal(); throw new InvalidOperationException("sentinel-secret"); }
        private sealed class It(Hostile<T> o) : IEnumerator<T> { private int i = -1; public T Current { get { o.CurrentCalls++; if (o._failure == Phase.Current || i == o._extra) o.Throw(); return o._factory(); } } object? IEnumerator.Current => Current; public bool MoveNext() { if (o._failure == Phase.MoveNext) o.Throw(); return ++i < o._count; } public void Reset() => throw new NotSupportedException(); public void Dispose() { if (o._failure == Phase.Dispose) o.Throw(); } }
    }
    private sealed class Endless<T>(Func<T> factory) : IEnumerable<T>, IEnumerator<T> { public int CurrentCalls { get; private set; } public T Current { get { CurrentCalls++; return factory(); } } object? IEnumerator.Current => Current; public IEnumerator<T> GetEnumerator() => this; IEnumerator IEnumerable.GetEnumerator() => this; public bool MoveNext() => true; public void Reset() { } public void Dispose() { } }
    private sealed class Mutating<T>(List<T> source) : IEnumerable<T> { public IEnumerator<T> GetEnumerator() => new It(source); IEnumerator IEnumerable.GetEnumerator() => GetEnumerator(); private sealed class It(List<T> s) : IEnumerator<T> { private int i = -1; public T Current => s[i]; object? IEnumerator.Current => Current; public bool MoveNext() => ++i < s.Count; public void Reset() => throw new NotSupportedException(); public void Dispose() => s.Clear(); } }
}

