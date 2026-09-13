using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Tests;

public sealed class ProtocolInputSafetyTests
{
    [Test]
    public async Task AcceptedVersionCaptureAcceptsExactMaximumWithoutConsultingCollectionCount()
    {
        var versions = Enumerable.Range(1, ProtocolTechnicalInputLimits.MaximumAcceptedProtocolVersionCount)
            .Select(static value => ProtocolTestData.Protocol(value))
            .ToArray();
        var source = new LyingReadOnlyCollection<ProtocolRevision>(versions);

        var context = ProtocolTestData.ValidContext(acceptedProtocols: source);
        var result = CommandEnvelopeValidator.Validate(ProtocolTestData.ValidEnvelope(), context, ProtocolTestData.Now);

        await Assert.That(result.IsValid).IsTrue();
    }

    [Test]
    public async Task AcceptedVersionCaptureRejectsMaximumPlusOneBeforeReadingExtraCurrent()
    {
        var values = Enumerable.Range(1, ProtocolTechnicalInputLimits.MaximumAcceptedProtocolVersionCount)
            .Select(static value => ProtocolTestData.Protocol(value))
            .ToArray();
        var source = new MaximumPlusOneCurrentThrowEnumerable<ProtocolRevision>(values);

        var failure = Capture(() => ProtocolTestData.ValidContext(acceptedProtocols: source));

        await Assert.That(failure).IsTypeOf<ArgumentException>();
        await Assert.That(((ArgumentException)failure!).ParamName).IsEqualTo("acceptedProtocolVersions");
        await Assert.That(failure.InnerException).IsNull();
        await Assert.That(failure.Message).DoesNotContain("iterator-secret");
        await Assert.That(source.ExtraCurrentReads).IsEqualTo(0);
    }

    [Test]
    public async Task AcceptedVersionCaptureBoundsEndlessDuplicatesByObservedItems()
    {
        var failure = Capture(() => ProtocolTestData.ValidContext(acceptedProtocols: Endless(ProtocolTestData.Protocol(1))));

        await Assert.That(failure).IsTypeOf<ArgumentException>();
        await Assert.That(failure!.InnerException).IsNull();
    }

    [Test]
    public async Task AcceptedVersionCaptureTranslatesEveryOrdinaryIteratorPhaseWithoutSecretText()
    {
        foreach (var phase in Enum.GetValues<IteratorPhase>())
        {
            var source = new PhaseFaultEnumerable<ProtocolRevision>(
                [ProtocolTestData.Protocol(1)], phase, static () => new InvalidOperationException("iterator-secret"));
            var failure = Capture(() => ProtocolTestData.ValidContext(acceptedProtocols: source));

            await Assert.That(failure).IsTypeOf<ArgumentException>();
            await Assert.That(failure!.InnerException).IsNull();
            await Assert.That(failure.Message).DoesNotContain("iterator-secret");
        }
    }

    [Test]
    public async Task AcceptedVersionCapturePropagatesFatalFailuresFromEveryIteratorPhase()
    {
        foreach (var phase in Enum.GetValues<IteratorPhase>())
        foreach (var factory in FatalFactories())
        {
            var source = new PhaseFaultEnumerable<ProtocolRevision>([ProtocolTestData.Protocol(1)], phase, factory);
            var expected = factory().GetType();
            var failure = Capture(() => ProtocolTestData.ValidContext(acceptedProtocols: source));

            await Assert.That(failure).IsNotNull();
            await Assert.That(failure!.GetType()).IsEqualTo(expected);
        }
    }

    [Test]
    public async Task AcceptedVersionCapturePrioritizesFatalFailureAcrossEnumerationAndDisposal()
    {
        var source = new DualFaultEnumerable<ProtocolRevision>(
            new OutOfMemoryException("fatal-secret"), new InvalidOperationException("dispose-secret"));
        var fatalDispose = new DualFaultEnumerable<ProtocolRevision>(
            new InvalidOperationException("iterator-secret"), new AccessViolationException("fatal-secret"));

        var failure = Capture(() => ProtocolTestData.ValidContext(acceptedProtocols: source));
        var disposeFailure = Capture(() => ProtocolTestData.ValidContext(acceptedProtocols: fatalDispose));

        await Assert.That(failure).IsTypeOf<OutOfMemoryException>();
        await Assert.That(disposeFailure).IsTypeOf<AccessViolationException>();
    }

    [Test]
    public async Task CommandVerifiersPropagateFatalRuntimeFailures()
    {
        foreach (var factory in FatalFactories())
        {
            var digestFailure = Capture(() => CommandEnvelopeValidator.Validate(
                ProtocolTestData.ValidEnvelope(),
                ProtocolTestData.ValidContext(digestVerifier: new ThrowingDigestVerifier(factory)),
                ProtocolTestData.Now));
            var signatureFailure = Capture(() => CommandEnvelopeValidator.Validate(
                ProtocolTestData.ValidEnvelope(),
                ProtocolTestData.ValidContext(signatureVerifier: new ThrowingSignatureVerifier(factory)),
                ProtocolTestData.Now));
            var expected = factory().GetType();

            await Assert.That(digestFailure).IsNotNull();
            await Assert.That(signatureFailure).IsNotNull();
            await Assert.That(digestFailure!.GetType()).IsEqualTo(expected);
            await Assert.That(signatureFailure!.GetType()).IsEqualTo(expected);
        }
    }

    [Test]
    public async Task PermissionPolicyPropagatesFatalFailuresFromEveryIteratorPhaseForAllowAndDeny()
    {
        SubjectGrammarLimits.TryCreate(64, 8, 16, 3, out var limits);
        SubjectPermissionPattern.TryParse("a.*", limits, out var pattern, out _);
        foreach (var phase in Enum.GetValues<IteratorPhase>())
        foreach (var factory in FatalFactories())
        {
            var expected = factory().GetType();
            var allowFailure = Capture(() => SubjectPermissionPolicy.TryCreate(
                new PhaseFaultEnumerable<SubjectPermissionPattern?>([pattern], phase, factory), [], limits,
                out _, out _));
            var denyFailure = Capture(() => SubjectPermissionPolicy.TryCreate(
                [], new PhaseFaultEnumerable<SubjectPermissionPattern?>([pattern], phase, factory), limits,
                out _, out _));

            await Assert.That(allowFailure).IsNotNull();
            await Assert.That(denyFailure).IsNotNull();
            await Assert.That(allowFailure!.GetType()).IsEqualTo(expected);
            await Assert.That(denyFailure!.GetType()).IsEqualTo(expected);
        }
    }

    private static IEnumerable<ProtocolRevision> Endless(ProtocolRevision value)
    {
        while (true) yield return value;
    }

    private static IReadOnlyList<Func<Exception>> FatalFactories() =>
    [
        static () => new OutOfMemoryException("fatal-secret"),
        static () => new StackOverflowException("fatal-secret"),
        static () => new AccessViolationException("fatal-secret"),
    ];

    private static Exception? Capture(Action action)
    {
        try { action(); return null; }
        catch (Exception exception) { return exception; }
    }

    private enum IteratorPhase { GetEnumerator, MoveNext, Current, Dispose }

    private sealed class LyingReadOnlyCollection<T>(IReadOnlyList<T> values) : IReadOnlyCollection<T>
    {
        public int Count => throw new InvalidOperationException("count-secret");
        public IEnumerator<T> GetEnumerator() => values.GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class MaximumPlusOneCurrentThrowEnumerable<T>(IReadOnlyList<T> values) : IEnumerable<T>
    {
        public int ExtraCurrentReads { get; private set; }
        public IEnumerator<T> GetEnumerator() => new Enumerator(this, values);
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

        private sealed class Enumerator(MaximumPlusOneCurrentThrowEnumerable<T> owner, IReadOnlyList<T> values) : IEnumerator<T>
        {
            private int index = -1;
            public T Current
            {
                get
                {
                    if (index < values.Count) return values[index];
                    owner.ExtraCurrentReads++;
                    throw new InvalidOperationException("iterator-secret-extra-current");
                }
            }
            object? System.Collections.IEnumerator.Current => Current;
            public bool MoveNext() { index++; return index <= values.Count; }
            public void Reset() => throw new NotSupportedException();
            public void Dispose() { }
        }
    }

    private sealed class PhaseFaultEnumerable<T>(IReadOnlyList<T> values, IteratorPhase phase, Func<Exception> factory) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() => phase == IteratorPhase.GetEnumerator
            ? throw factory()
            : new Enumerator(values, phase, factory);
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

        private sealed class Enumerator(IReadOnlyList<T> values, IteratorPhase phase, Func<Exception> factory) : IEnumerator<T>
        {
            private int index = -1;
            public T Current => phase == IteratorPhase.Current ? throw factory() : values[index];
            object? System.Collections.IEnumerator.Current => Current;
            public bool MoveNext()
            {
                if (phase == IteratorPhase.MoveNext) throw factory();
                index++;
                return index < values.Count;
            }
            public void Reset() => throw new NotSupportedException();
            public void Dispose() { if (phase == IteratorPhase.Dispose) throw factory(); }
        }
    }

    private sealed class DualFaultEnumerable<T>(Exception enumerationFailure, Exception disposalFailure) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() => new Enumerator(enumerationFailure, disposalFailure);
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Enumerator(Exception enumerationFailure, Exception disposalFailure) : IEnumerator<T>
        {
            public T Current => default!;
            object? System.Collections.IEnumerator.Current => Current;
            public bool MoveNext() => throw enumerationFailure;
            public void Reset() => throw new NotSupportedException();
            public void Dispose() => throw disposalFailure;
        }
    }

    private sealed class ThrowingDigestVerifier(Func<Exception> factory) : IPayloadDigestVerifier
    {
        public VerificationOutcome Verify(OpaquePayload payload, PayloadDigest expectedDigest) => throw factory();
    }

    private sealed class ThrowingSignatureVerifier(Func<Exception> factory) : ICommandSignatureVerifier
    {
        public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature) => throw factory();
    }
}

