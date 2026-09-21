using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class HostReportReadinessTests
{
    [Test]
    public async Task Admission_pairs_one_artifact_and_session_and_both_authorizations_must_remain_current()
    {
        var now = DateTimeOffset.UtcNow;
        var session = new HostReportSession("enrollment", 1, "session", 1);
        var runtime = new AuthorizedHostReport(null,
            new(2, "gru", "auth-1", "ts-auth", "sha256:" + new string('a', 64), "converged", "auth.service", now),
            session, now.AddSeconds(20));
        var admission = new AuthorizedHostReport(
            new(1, "gru", "auth-1", "production", "ts-auth", runtime.Runtime!.Digest, true, now),
            null, session, now.AddSeconds(10));
        var reader = new AdmissionReader { Report = admission };
        await Assert.That(await HostReportReadiness.ConfirmAdmissionAsync(reader, runtime, TimeProvider.System, CancellationToken.None))
            .IsEqualTo(admission.ExpiresAt);
        foreach (var candidate in new AuthorizedHostReport?[]
                 {
                     null, admission with { Admission = admission.Admission! with { Ready = false } },
                     admission with { Admission = admission.Admission! with { Cell = "fra" } },
                     admission with { Admission = admission.Admission! with { Instance = "auth-2" } },
                     admission with { Admission = admission.Admission! with { ArtifactKey = "terrabase-server" } },
                     admission with { Admission = admission.Admission! with { Digest = "sha256:" + new string('b', 64) } },
                     admission with { Admission = admission.Admission! with { ObservedAt = now.AddHours(1) } },
                     admission with { Admission = admission.Admission! with { ObservedAt = now.AddHours(-1) } },
                     admission with { Session = session with { EnrollmentDigest = "another" } },
                     admission with { Session = session with { Generation = 2 } },
                     admission with { Session = session with { SessionId = "another" } },
                     admission with { Session = session with { Epoch = 2 } },
                     admission with { ExpiresAt = now }
                 })
        {
            reader.Report = candidate;
            await Assert.That(await HostReportReadiness.ConfirmAdmissionAsync(reader, runtime, TimeProvider.System, CancellationToken.None)).IsNull();
        }
        reader.Report = admission;
        await Assert.That(await HostReportReadiness.ConfirmAdmissionAsync(reader, runtime with { ExpiresAt = now },
            TimeProvider.System, CancellationToken.None)).IsNull();
    }

    private sealed class AdmissionReader : IAuthorizedHostReportReader
    {
        internal AuthorizedHostReport? Report { get; set; }
        public Task<AuthorizedHostReport?> ReadAsync(string key, CancellationToken cancellationToken) =>
            key == "host.admission.auth-1.ts-auth" ? Task.FromResult(Report) : throw new InvalidOperationException("Unexpected report key.");
    }
}
