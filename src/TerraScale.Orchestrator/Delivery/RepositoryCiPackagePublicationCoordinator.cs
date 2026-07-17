using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiPackagePublicationDisposition
{
    Unspecified,
    Published,
    Duplicate,
    NotApplicable,
    InvalidEvidence,
    StaleAuthority,
    IdentityConflict,
}

internal sealed record RepositoryCiPublishedPackage(
    string Repository,
    JobId Job,
    string Package,
    string Version,
    string FileName,
    string Sha256,
    long Bytes,
    ForgejoGenericPackagePublicationDisposition Disposition);

internal sealed record RepositoryCiPackagePublicationReceipt(
    RepositoryCiPackagePublicationDisposition Disposition,
    string EvidenceDigest,
    IReadOnlyList<RepositoryCiPublishedPackage> Packages);

internal interface IRepositoryCiPackagePublicationCoordinator
{
    Task<RepositoryCiPackagePublicationReceipt> PublishAsync(
        RepositoryCiQualifiedCandidate qualified,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default);
}

/// <summary>Publishes exact package and native archives from one qualified candidate.</summary>
internal sealed class RepositoryCiPackagePublicationCoordinator(
    CiRunnerDurableEvidenceVerifier evidence,
    IDeliveryObjectStore objects,
    IForgejoGenericPackagePublisher publisher) : IRepositoryCiPackagePublicationCoordinator
{
    private readonly CiRunnerDurableEvidenceVerifier evidence = evidence ??
        throw new ArgumentNullException(nameof(evidence));
    private readonly IDeliveryObjectStore objects = objects ?? throw new ArgumentNullException(nameof(objects));
    private readonly IForgejoGenericPackagePublisher publisher = publisher ??
        throw new ArgumentNullException(nameof(publisher));

    public async Task<RepositoryCiPackagePublicationReceipt> PublishAsync(
        RepositoryCiQualifiedCandidate qualified,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(qualified);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        Validate(qualified);
        if (!authorityStillValid()) return Result(RepositoryCiPackagePublicationDisposition.StaleAuthority);

        var candidate = qualified.Candidate;
        var jobs = candidate.Artifacts
            .Where(static artifact => ForgejoPackageStrategy(artifact.Promotion))
            .GroupBy(static artifact => artifact.Job)
            .OrderBy(static group => group.Key.Value, StringComparer.Ordinal)
            .ToArray();
        if (jobs.Length == 0) return Result(RepositoryCiPackagePublicationDisposition.NotApplicable);

        var prepared = new List<PreparedPackage>(jobs.Length);
        foreach (var job in jobs)
        {
            var artifacts = job.ToArray();
            if (artifacts.Select(static value => value.Repository).Distinct(StringComparer.Ordinal).Count() != 1)
                return Result(RepositoryCiPackagePublicationDisposition.InvalidEvidence);
            var archive = await evidence.ReadCandidateArchiveAsync(candidate, job.Key, cancellationToken);
            if (archive is null) return Result(RepositoryCiPackagePublicationDisposition.InvalidEvidence);
            var repository = artifacts[0].Repository;
            prepared.Add(new(
                repository,
                job.Key,
                PackageName(repository),
                candidate.Digest,
                $"{job.Key.Value}.tar.gz",
                archive));
        }

        var published = new List<RepositoryCiPublishedPackage>(prepared.Count);
        var recorded = false;
        foreach (var package in prepared)
        {
            if (!authorityStillValid()) return Result(
                RepositoryCiPackagePublicationDisposition.StaleAuthority,
                published);
            var receipt = await publisher.PublishAsync(
                package.Repository,
                package.Package,
                package.Version,
                package.FileName,
                package.Archive.Sha256,
                package.Archive.Bytes,
                (destination, token) => objects.CopyToAsync(package.Archive.ObjectName, destination, token),
                authorityStillValid,
                cancellationToken);
            if (receipt.Disposition == ForgejoGenericPackagePublicationDisposition.StaleAuthority)
                return Result(RepositoryCiPackagePublicationDisposition.StaleAuthority, published);
            if (receipt.Disposition == ForgejoGenericPackagePublicationDisposition.IdentityConflict)
                return Result(RepositoryCiPackagePublicationDisposition.IdentityConflict, published);
            if (receipt.Disposition is not (ForgejoGenericPackagePublicationDisposition.Recorded or
                    ForgejoGenericPackagePublicationDisposition.Duplicate))
                throw new InvalidDataException("The Forgejo package publisher returned an invalid disposition.");
            recorded |= receipt.Disposition == ForgejoGenericPackagePublicationDisposition.Recorded;
            published.Add(new(
                package.Repository,
                package.Job,
                package.Package,
                package.Version,
                package.FileName,
                package.Archive.Sha256,
                package.Archive.Bytes,
                receipt.Disposition));
        }

        if (!authorityStillValid()) return Result(
            RepositoryCiPackagePublicationDisposition.StaleAuthority,
            published);
        var packages = published.AsReadOnly();
        return new(
            recorded
                ? RepositoryCiPackagePublicationDisposition.Published
                : RepositoryCiPackagePublicationDisposition.Duplicate,
            EvidenceDigest(qualified, packages),
            packages);
    }

    private static void Validate(RepositoryCiQualifiedCandidate qualified)
    {
        var candidate = qualified.Candidate ??
            throw new InvalidDataException("Package publication requires an immutable candidate.");
        _ = RepositoryCiCandidateAssembler.Restore(
            candidate.Digest,
            candidate.Pipeline.Value,
            candidate.PipelineDigest,
            candidate.ImpactDigest,
            candidate.CandidateRetentionDays,
            candidate.Sources,
            candidate.Jobs,
            candidate.Artifacts);
        _ = RepositoryCiCandidateResolver.Restore(qualified.Digest, candidate, qualified.Sources);
    }

    private static string PackageName(string repository)
    {
        var name = repository[(repository.IndexOf('/') + 1)..].ToLowerInvariant();
        if (name.Length <= 240) return $"ci-{name}";
        var digest = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(name)));
        return $"ci-{name[..207]}-{digest[..32]}";
    }

    private static bool ForgejoPackageStrategy(RepositoryCiPromotionStrategy strategy) => strategy is
        RepositoryCiPromotionStrategy.Package or
        RepositoryCiPromotionStrategy.NativeRolling or
        RepositoryCiPromotionStrategy.NativeBlueGreen or
        RepositoryCiPromotionStrategy.NativeOrdered;

    private static string EvidenceDigest(
        RepositoryCiQualifiedCandidate qualified,
        IReadOnlyList<RepositoryCiPublishedPackage> packages)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteString("qualified", qualified.Digest);
            writer.WriteString("candidate", qualified.Candidate.Digest);
            writer.WriteStartArray("packages");
            foreach (var package in packages)
            {
                writer.WriteStartObject();
                writer.WriteString("repository", package.Repository);
                writer.WriteString("job", package.Job.Value);
                writer.WriteString("package", package.Package);
                writer.WriteString("version", package.Version);
                writer.WriteString("file", package.FileName);
                writer.WriteString("sha256", package.Sha256);
                writer.WriteNumber("bytes", package.Bytes);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return Convert.ToHexStringLower(SHA256.HashData(bytes.WrittenSpan));
    }

    private static RepositoryCiPackagePublicationReceipt Result(
        RepositoryCiPackagePublicationDisposition disposition,
        IEnumerable<RepositoryCiPublishedPackage>? packages = null) => new(
        disposition,
        string.Empty,
        Array.AsReadOnly((packages ?? []).ToArray()));

    private sealed record PreparedPackage(
        string Repository,
        JobId Job,
        string Package,
        string Version,
        string FileName,
        CiRunnerVerifiedArtifactArchive Archive);
}
