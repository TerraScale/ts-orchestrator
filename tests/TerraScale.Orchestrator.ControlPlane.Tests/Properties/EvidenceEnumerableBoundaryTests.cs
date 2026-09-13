using System.Collections;
using TerraScale.Orchestrator.ControlPlane.Evidence;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class EvidenceEnumerableBoundaryTests
{
    private const int Maximum = 64;

    [Test]
    public async Task Evidence_snapshot_accepts_exact_max_and_bounds_before_extra_current()
    {
        var exact = Enumerable.Range(0, Maximum).Select(Binary).Cast<EvidenceTestBinary?>().ToArray();
        var subject = EvidenceTestData.Subject(binaries: exact, maximum: Maximum);
        await Assert.That(subject.TestBinaries.Count).IsEqualTo(Maximum);

        var oversized = new EvidenceBoundaryEnumerable<EvidenceTestBinary?>(Maximum + 1, index => Binary(index));
        var rejected = EvidenceTestData.Subject(binaries: oversized, maximum: Maximum);
        await Assert.That(rejected.IsWellFormed).IsFalse();
        await Assert.That(oversized.ExtraCurrentRead).IsFalse();
    }

    [Test]
    public async Task Evidence_snapshot_stops_literal_endless_input_at_the_bound()
    {
        var reads = 0;
        IEnumerable<EvidenceTestBinary?> Endless()
        {
            while (true) { yield return Binary(reads); reads++; }
        }
        var subject = EvidenceTestData.Subject(binaries: Endless(), maximum: Maximum);
        await Assert.That(subject.IsWellFormed).IsFalse();
        await Assert.That(reads).IsEqualTo(Maximum);
    }

    [Test]
    public async Task Evidence_snapshot_fail_closes_every_ordinary_iterator_phase_and_is_secret_safe()
    {
        foreach (var phase in Enum.GetValues<EvidenceIteratorPhase>().Where(phase => phase != EvidenceIteratorPhase.None))
        {
            var source = new EvidenceBoundaryEnumerable<EvidenceTestBinary?>(1, Binary, phase, new InvalidOperationException("secret-iterator-detail"));
            var subject = EvidenceTestData.Subject(binaries: source, maximum: Maximum);
            await Assert.That(subject.IsWellFormed).IsFalse();
            await Assert.That(subject.ToString()).DoesNotContain("secret-iterator-detail");
        }
    }

    [Test]
    public async Task Evidence_snapshot_is_defensive_when_dispose_mutates_the_source()
    {
        var mutable = new List<EvidenceTestBinary?> { Binary(1) };
        var source = new EvidenceBoundaryEnumerable<EvidenceTestBinary?>(1, index => mutable[index], onDispose: mutable.Clear);
        var subject = EvidenceTestData.Subject(binaries: source, maximum: Maximum);
        await Assert.That(subject.TestBinaries.Count).IsEqualTo(1);
        await Assert.That(subject.TestBinaries[0].Identity).IsEqualTo(EvidenceTestData.Binary("binary-1"));
    }

    [Test]
    public async Task Evidence_snapshot_propagates_explicit_fatal_runtime_categories()
    {
        foreach (var fatal in new Exception[] { new OutOfMemoryException("fatal"), new StackOverflowException("fatal"), new AccessViolationException("fatal") })
        {
            var source = new EvidenceBoundaryEnumerable<EvidenceTestBinary?>(1, Binary, EvidenceIteratorPhase.Current, fatal);
            var observed = Capture(() => EvidenceTestData.Subject(binaries: source, maximum: Maximum));
            await Assert.That(observed!.GetType()).IsEqualTo(fatal.GetType());
        }
    }

    private static EvidenceTestBinary Binary(int index) => new(EvidenceTestData.Binary($"binary-{index}"), EvidenceTestData.D((byte)(1 + index % 250)));
    private static Exception? Capture(Action action) { try { action(); return null; } catch (Exception exception) { return exception; } }
}

internal enum EvidenceIteratorPhase { None, GetEnumerator, MoveNext, Current, Dispose }

internal sealed class EvidenceBoundaryEnumerable<T> : IEnumerable<T>
{
    private readonly int _count; private readonly Func<int, T> _factory; private readonly EvidenceIteratorPhase _phase;
    private readonly Exception? _failure; private readonly Action? _onDispose;
    internal EvidenceBoundaryEnumerable(int count, Func<int, T> factory, EvidenceIteratorPhase phase = EvidenceIteratorPhase.None,
        Exception? failure = null, Action? onDispose = null) { _count = count; _factory = factory; _phase = phase; _failure = failure; _onDispose = onDispose; }
    internal bool ExtraCurrentRead { get; private set; }
    public IEnumerator<T> GetEnumerator()
    {
        if (_phase == EvidenceIteratorPhase.GetEnumerator) throw _failure!;
        return new Enumerator(this);
    }
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    private sealed class Enumerator(EvidenceBoundaryEnumerable<T> owner) : IEnumerator<T>
    {
        private int _index = -1;
        public T Current
        {
            get
            {
                if (_index == 64) owner.ExtraCurrentRead = true;
                if (owner._phase == EvidenceIteratorPhase.Current) throw owner._failure!;
                return owner._factory(_index);
            }
        }
        object? IEnumerator.Current => Current;
        public bool MoveNext() { if (owner._phase == EvidenceIteratorPhase.MoveNext) throw owner._failure!; return ++_index < owner._count; }
        public void Reset() => throw new NotSupportedException();
        public void Dispose() { owner._onDispose?.Invoke(); if (owner._phase == EvidenceIteratorPhase.Dispose) throw owner._failure!; }
    }
}

