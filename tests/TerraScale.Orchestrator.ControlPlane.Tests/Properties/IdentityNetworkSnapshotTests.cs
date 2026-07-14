using System.Collections;
using TerraScale.Orchestrator.ControlPlane.Networking;
using TerraScale.Orchestrator.ControlPlane.Security;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class IdentityNetworkSnapshotTests
{
    private const int Limit = 4096;

    [Test]
    public async Task Security_capture_accepts_exact_limit_and_rejects_max_plus_one_before_Current()
    {
        var exact = Enrollment(Enumerable.Range(0, Limit).Select(i => new BootstrapEnrollmentEvidence(new($"bootstrap-{i}"),
            new("operation-1"), new("principal-1"), SecurityPrincipalKind.Node, new("gru"), SecurityRole.Agent, new(5), EvidenceStatus.Valid)));
        await Assert.That(exact.BootstrapEvidence.Count).IsEqualTo(Limit);

        var probe = new HostileEnumerable<BootstrapEnrollmentEvidence>(Limit + 1, ValidBootstrap, throwOnCurrentIndex: Limit);
        await Assert.That(Throws<ArgumentException>(() => Enrollment(probe))).IsTrue();
        await Assert.That(probe.CurrentCalls).IsEqualTo(Limit);
    }

    [Test]
    public async Task Network_capture_accepts_exact_limit_and_rejects_max_plus_one_before_Current()
    {
        var scope = NetworkingTestData.RouteScope();
        var exact = new NetworkRouteEvidence(scope, Enumerable.Repeat<NetworkRouteObservation?>(null, Limit),
            [NetworkingTestData.Prefix(10)], [NetworkingTestData.Cell(), NetworkingTestData.Cell("sfo")],
            [new(NetworkingTestData.Cell(), NetworkingTestData.Cell("sfo"))], NetworkTopologyShape.ExplicitReplication,
            NetworkProof.Proven, NetworkProof.Proven, NetworkProof.Proven, NetworkProof.Proven, NetworkProof.Proven,
            NetworkProof.Proven, false, Limit, 1, 1, 2);
        await Assert.That(exact.Routes.Count).IsEqualTo(0);

        var probe = new HostileEnumerable<NetworkRouteObservation?>(Limit + 1, () => null, throwOnCurrentIndex: Limit);
        await Assert.That(Throws<ArgumentException>(() => new NetworkRouteEvidence(scope, probe, [NetworkingTestData.Prefix(10)],
            [NetworkingTestData.Cell(), NetworkingTestData.Cell("sfo")], [new(NetworkingTestData.Cell(), NetworkingTestData.Cell("sfo"))],
            NetworkTopologyShape.ExplicitReplication, NetworkProof.Proven, NetworkProof.Proven, NetworkProof.Proven,
            NetworkProof.Proven, NetworkProof.Proven, NetworkProof.Proven, false, Limit + 1, 1, 1, 2))).IsTrue();
        await Assert.That(probe.CurrentCalls).IsEqualTo(Limit);
    }

    [Test]
    public async Task Iterator_failures_are_generic_secret_safe_and_fatal_exceptions_propagate()
    {
        foreach (var phase in new[] { FailurePhase.GetEnumerator, FailurePhase.MoveNext, FailurePhase.Current, FailurePhase.Dispose })
        {
            var error = Capture<ArgumentException>(() => Enrollment(new HostileEnumerable<BootstrapEnrollmentEvidence>(1, ValidBootstrap, failure: phase)));
            await Assert.That(error.Message).DoesNotContain("sentinel-secret");
            await Assert.That(error.InnerException).IsNull();
        }

        var scope = NetworkingTestData.RouteScope();
        foreach (var phase in new[] { FailurePhase.GetEnumerator, FailurePhase.MoveNext, FailurePhase.Current, FailurePhase.Dispose })
        {
            var error = Capture<ArgumentException>(() => RouteEvidence(scope,
                new HostileEnumerable<NetworkRouteObservation?>(1, () => null, failure: phase)));
            await Assert.That(error.Message).DoesNotContain("sentinel-secret");
            await Assert.That(error.InnerException).IsNull();
        }
        foreach (var phase in new[] { FailurePhase.GetEnumerator, FailurePhase.MoveNext, FailurePhase.Current, FailurePhase.Dispose })
        {
            await Assert.That(Throws<OutOfMemoryException>(() => Enrollment(
                new HostileEnumerable<BootstrapEnrollmentEvidence>(1, ValidBootstrap, failure: phase, fatal: true)))).IsTrue();
            await Assert.That(Throws<OutOfMemoryException>(() => RouteEvidence(scope,
                new HostileEnumerable<NetworkRouteObservation?>(1, () => null, failure: phase, fatal: true)))).IsTrue();
        }
    }

    [Test]
    public async Task Infinite_sources_terminate_at_the_technical_cap_without_reading_the_extra_Current()
    {
        var security = new HostileEnumerable<BootstrapEnrollmentEvidence>(int.MaxValue, ValidBootstrap, throwOnCurrentIndex: Limit);
        await Assert.That(Throws<ArgumentException>(() => Enrollment(security))).IsTrue();
        await Assert.That(security.CurrentCalls).IsEqualTo(Limit);

        var network = new HostileEnumerable<NetworkRouteObservation?>(int.MaxValue, () => null, throwOnCurrentIndex: Limit);
        await Assert.That(Throws<ArgumentException>(() => RouteEvidence(NetworkingTestData.RouteScope(), network))).IsTrue();
        await Assert.That(network.CurrentCalls).IsEqualTo(Limit);
    }

    [Test]
    public async Task Dispose_mutation_cannot_change_security_snapshot()
    {
        var source = new List<BootstrapEnrollmentEvidence> { ValidBootstrap() };
        var request = Enrollment(new DisposeMutationEnumerable<BootstrapEnrollmentEvidence>(source));
        await Assert.That(source.Count).IsEqualTo(0);
        await Assert.That(request.BootstrapEvidence.Count).IsEqualTo(1);
        await Assert.That(request.BootstrapEvidence[0].Id.Value).IsEqualTo("bootstrap-1");

        var routeSource = new List<NetworkRouteObservation?> { new(NetworkingTestData.Route(), NetworkingTestData.Cell(),
            NetworkingTestData.Peer(), null, NetworkTrustPlane.Product, NetworkingTestData.Prefix(10)) };
        var routeEvidence = RouteEvidence(NetworkingTestData.RouteScope(), new DisposeMutationEnumerable<NetworkRouteObservation?>(routeSource));
        await Assert.That(routeSource.Count).IsEqualTo(0);
        await Assert.That(routeEvidence.Routes.Count).IsEqualTo(1);
    }

    private static EnrollmentRequest Enrollment(IEnumerable<BootstrapEnrollmentEvidence> bootstrap)
    {
        var cell = new SecurityCellId("gru"); var generation = new SecurityGeneration(5); var operation = new SecurityOperationId("operation-1");
        var principal = new SecurityPrincipal(new("principal-1"), SecurityPrincipalKind.Node, SecurityRole.Agent, cell, generation);
        var issuer = new IssuerSigningCapability(new("issuer-gru"), IssuerCapabilityKind.RegionalIntermediate, cell, TrustScope.Cell, new(1), new(3));
        return new(operation, principal, new("subject-key-1"), new(2), issuer, new(1), new(3), bootstrap,
            [new(new("attestation-1"), new(new string('a', 64)), principal.Id, principal.Kind, cell, principal.Role, generation, new(2), EvidenceStatus.Valid)]);
    }

    private static BootstrapEnrollmentEvidence ValidBootstrap() => new(new("bootstrap-1"), new("operation-1"), new("principal-1"),
        SecurityPrincipalKind.Node, new("gru"), SecurityRole.Agent, new(5), EvidenceStatus.Valid);

    private static NetworkRouteEvidence RouteEvidence(NetworkRouteScope scope, IEnumerable<NetworkRouteObservation?> routes) => new(scope, routes,
        [NetworkingTestData.Prefix(10)], [NetworkingTestData.Cell(), NetworkingTestData.Cell("sfo")],
        [new(NetworkingTestData.Cell(), NetworkingTestData.Cell("sfo"))], NetworkTopologyShape.ExplicitReplication,
        NetworkProof.Proven, NetworkProof.Proven, NetworkProof.Proven, NetworkProof.Proven, NetworkProof.Proven,
        NetworkProof.Proven, false, Limit, 1, 1, 2);

    private static bool Throws<T>(Action action) where T : Exception { try { action(); return false; } catch (T) { return true; } }
    private static T Capture<T>(Action action) where T : Exception { try { action(); } catch (T error) { return error; } throw new InvalidOperationException(); }

    private enum FailurePhase { None, GetEnumerator, MoveNext, Current, Dispose }

    private sealed class HostileEnumerable<T> : IEnumerable<T>
    {
        private readonly int _count; private readonly Func<T> _factory; private readonly int _throwOnCurrentIndex;
        private readonly FailurePhase _failure; private readonly bool _fatal;
        public HostileEnumerable(int count, Func<T> factory, int throwOnCurrentIndex = -1, FailurePhase failure = FailurePhase.None, bool fatal = false)
        { _count = count; _factory = factory; _throwOnCurrentIndex = throwOnCurrentIndex; _failure = failure; _fatal = fatal; }
        public int CurrentCalls { get; private set; }
        public IEnumerator<T> GetEnumerator()
        {
            if (_failure == FailurePhase.GetEnumerator) Throw();
            return new Iterator(this);
        }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private void Throw() { if (_fatal) throw new OutOfMemoryException("sentinel-secret"); throw new InvalidOperationException("sentinel-secret"); }
        private sealed class Iterator(HostileEnumerable<T> owner) : IEnumerator<T>
        {
            private int _index = -1;
            public T Current { get { owner.CurrentCalls++; if (owner._failure == FailurePhase.Current || _index == owner._throwOnCurrentIndex) owner.Throw(); return owner._factory(); } }
            object? IEnumerator.Current => Current;
            public bool MoveNext() { if (owner._failure == FailurePhase.MoveNext) owner.Throw(); _index++; return _index < owner._count; }
            public void Reset() => throw new NotSupportedException();
            public void Dispose() { if (owner._failure == FailurePhase.Dispose) owner.Throw(); }
        }
    }

    private sealed class DisposeMutationEnumerable<T>(List<T> values) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() => new Iterator(values);
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Iterator(List<T> values) : IEnumerator<T>
        {
            private int _index = -1;
            public T Current => values[_index]; object? IEnumerator.Current => Current;
            public bool MoveNext() => ++_index < values.Count;
            public void Reset() => throw new NotSupportedException();
            public void Dispose() => values.Clear();
        }
    }
}
