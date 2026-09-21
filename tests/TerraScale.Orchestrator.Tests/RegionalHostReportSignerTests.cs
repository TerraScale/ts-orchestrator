using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalHostReportSignerTests
{
    [Test]
    public async Task Only_the_exact_accepted_lease_can_sign_and_renewal_requires_replacing_the_snapshot()
    {
        using var material = new SessionMaterial();
        var request = material.Request(material.Enroll(1));
        var lease = new RegionalHostSessionResponse(2, request.RequestId, request.RequestDigest, RegionalHostSessionDecision.Accepted,
            1, 1, request.IssuedAt + RegionalHostSessionAuthority.LeaseLifetime);
        foreach (var invalid in new[]
                 {
                     lease with { SchemaVersion = 1 }, lease with { Decision = RegionalHostSessionDecision.Revoked },
                     lease with { RequestId = new string('a', 32) }, lease with { RequestDigest = new string('a', 64) },
                     lease with { Generation = 2 }, lease with { Epoch = 0 }, lease with { ExpiresAt = null },
                     lease with { ExpiresAt = lease.ExpiresAt!.Value.AddSeconds(1) }
                 })
            await Assert.That(() => new RegionalHostReportSigner(request, invalid, material.Authentication, material.Clock)).Throws<ArgumentException>();
        using var unrelated = new SessionMaterial();
        await Assert.That(() => new RegionalHostReportSigner(request, lease, unrelated.Authentication, material.Clock)).Throws<ArgumentException>();
        var original = new RegionalHostReportSigner(request, lease, material.Authentication, material.Clock);
        var report = new HostAdmissionObservation(1, "gru", request.Enrollment.NodeId, "production", "terrabase-server",
            "sha256:" + new string('a', 64), true, material.Clock.GetUtcNow());
        await Assert.That(original.Sign(report).Proof.Epoch).IsEqualTo(1UL);
        await Assert.That(() => original.Sign(report with { Cell = "fra" })).Throws<InvalidOperationException>();
        await Assert.That(() => original.Sign(report with { Instance = "another-node" })).Throws<InvalidOperationException>();
        material.Clock.Advance(TimeSpan.FromSeconds(20));
        var renewal = material.Request(request.Enrollment, request.SessionId, lease.Epoch);
        var renewedLease = new RegionalHostSessionResponse(2, renewal.RequestId, renewal.RequestDigest,
            RegionalHostSessionDecision.Accepted, 1, 1, renewal.IssuedAt + RegionalHostSessionAuthority.LeaseLifetime);
        await Assert.That(() => new RegionalHostReportSigner(renewal, renewedLease with { Epoch = 2 }, material.Authentication, material.Clock))
            .Throws<ArgumentException>();
        var renewed = new RegionalHostReportSigner(renewal, renewedLease, material.Authentication, material.Clock);
        material.Clock.Advance(TimeSpan.FromSeconds(10));
        await Assert.That(() => original.Sign(report with { ObservedAt = material.Clock.GetUtcNow() })).Throws<InvalidOperationException>();
        await Assert.That(renewed.Sign(report with { ObservedAt = material.Clock.GetUtcNow() }).Proof.Epoch).IsEqualTo(lease.Epoch);
        material.Clock.Advance(TimeSpan.FromSeconds(20));
        await Assert.That(() => renewed.Sign(report with { ObservedAt = material.Clock.GetUtcNow() })).Throws<InvalidOperationException>();
    }
}
