using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiOciImagePublicationDisposition
{
    Unspecified,
    Published,
    Duplicate,
    NotApplicable,
    InvalidEvidence,
    StaleAuthority,
    IdentityConflict,
}

internal sealed record RepositoryCiPublishedOciImage(
    string ArtifactRepository,
    JobId Job,
    string RegistryRepository,
    string Tag,
    string ArchiveSha256,
    long ArchiveBytes,
    string PublishedDigest,
    RepositoryCiOciRegistryPublicationDisposition Disposition);

internal sealed record RepositoryCiOciImagePublicationReceipt(
    RepositoryCiOciImagePublicationDisposition Disposition,
    string EvidenceDigest,
    IReadOnlyList<RepositoryCiPublishedOciImage> Images);

internal interface IRepositoryCiOciImagePublicationCoordinator
{
    Task<RepositoryCiOciImagePublicationReceipt> PublishAsync(
        RepositoryCiQualifiedCandidate qualified,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Selects only the explicit OCI-image promotion strategy and reopens the exact durable archive
/// evidence before delegating to the registry adapter.
/// </summary>
internal sealed class RepositoryCiOciImagePublicationCoordinator(
    CiRunnerDurableEvidenceVerifier evidence,
    IDeliveryObjectStore objects,
    IRepositoryCiOciRegistryPublisher publisher) : IRepositoryCiOciImagePublicationCoordinator
{
    private readonly CiRunnerDurableEvidenceVerifier evidence = evidence ??
        throw new ArgumentNullException(nameof(evidence));
    private readonly IDeliveryObjectStore objects = objects ?? throw new ArgumentNullException(nameof(objects));
    private readonly IRepositoryCiOciRegistryPublisher publisher = publisher ??
        throw new ArgumentNullException(nameof(publisher));

    public async Task<RepositoryCiOciImagePublicationReceipt> PublishAsync(
        RepositoryCiQualifiedCandidate qualified,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(qualified);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        try
        {
            ValidateQualified(qualified);
        }
        catch (InvalidDataException)
        {
            return Result(RepositoryCiOciImagePublicationDisposition.InvalidEvidence);
        }
        if (!authorityStillValid()) return Result(RepositoryCiOciImagePublicationDisposition.StaleAuthority);

        IGrouping<JobId, RepositoryCiArtifactResult>[] selected;
        try
        {
            selected = Select(qualified.Candidate);
        }
        catch (InvalidDataException)
        {
            return Result(RepositoryCiOciImagePublicationDisposition.InvalidEvidence);
        }
        if (selected.Length == 0) return Result(RepositoryCiOciImagePublicationDisposition.NotApplicable);

        var prepared = new List<PreparedImage>(selected.Length);
        foreach (var group in selected)
        {
            if (!authorityStillValid())
                return Result(RepositoryCiOciImagePublicationDisposition.StaleAuthority);
            CiRunnerVerifiedArtifactArchive? archive;
            try
            {
                archive = await evidence.ReadCandidateArchiveAsync(
                    qualified.Candidate,
                    group.Key,
                    cancellationToken);
            }
            catch (InvalidDataException)
            {
                return Result(RepositoryCiOciImagePublicationDisposition.InvalidEvidence);
            }
            catch (IOException)
            {
                return Result(RepositoryCiOciImagePublicationDisposition.InvalidEvidence);
            }
            if (archive is null || !Digest(archive.Sha256) || archive.Bytes < 1)
                return Result(RepositoryCiOciImagePublicationDisposition.InvalidEvidence);
            var artifact = group.Single();
            prepared.Add(new(
                artifact.Repository,
                group.Key,
                qualified.Candidate.Digest,
                archive));
        }

        var published = new List<RepositoryCiPublishedOciImage>(prepared.Count);
        var recorded = false;
        foreach (var image in prepared)
        {
            if (!authorityStillValid())
                return Result(RepositoryCiOciImagePublicationDisposition.StaleAuthority, published);
            var receipt = await publisher.PublishAsync(
                image.Repository,
                image.Tag,
                image.Archive.Sha256,
                image.Archive.Bytes,
                (destination, token) => objects.CopyToAsync(image.Archive.ObjectName, destination, token),
                authorityStillValid,
                cancellationToken);
            if (receipt is null) throw new InvalidDataException("The OCI publisher returned no receipt.");
            if (receipt.Disposition == RepositoryCiOciRegistryPublicationDisposition.StaleAuthority)
                return Result(RepositoryCiOciImagePublicationDisposition.StaleAuthority, published);
            if (receipt.Disposition == RepositoryCiOciRegistryPublicationDisposition.IdentityConflict)
                return Result(RepositoryCiOciImagePublicationDisposition.IdentityConflict, published);
            if (receipt.Disposition is not (RepositoryCiOciRegistryPublicationDisposition.Published or
                    RepositoryCiOciRegistryPublicationDisposition.Duplicate) ||
                !ReferenceDigest(receipt.PublishedDigest) ||
                receipt.RegistryRepository.Length == 0 || receipt.Tag != image.Tag)
                throw new InvalidDataException("The OCI publisher returned an invalid disposition or identity.");
            recorded |= receipt.Disposition == RepositoryCiOciRegistryPublicationDisposition.Published;
            published.Add(new(
                image.Repository,
                image.Job,
                receipt.RegistryRepository,
                receipt.Tag,
                image.Archive.Sha256,
                image.Archive.Bytes,
                receipt.PublishedDigest,
                receipt.Disposition));
        }
        if (!authorityStillValid())
            return Result(RepositoryCiOciImagePublicationDisposition.StaleAuthority, published);
        var images = published.AsReadOnly();
        return new(
            recorded
                ? RepositoryCiOciImagePublicationDisposition.Published
                : RepositoryCiOciImagePublicationDisposition.Duplicate,
            EvidenceDigest(qualified, images),
            images);
    }

    private static void ValidateQualified(RepositoryCiQualifiedCandidate qualified)
    {
        if (!RepositoryCiJobExecutionDocument.IsDigest(qualified.Digest) ||
            qualified.Id != $"qualified-{qualified.Digest}")
            throw new InvalidDataException("OCI publication requires a qualified candidate digest.");
        _ = RepositoryCiCandidateAssembler.Restore(
            qualified.Candidate.Digest,
            qualified.Candidate.Pipeline.Value,
            qualified.Candidate.PipelineDigest,
            qualified.Candidate.ImpactDigest,
            qualified.Candidate.CandidateRetentionDays,
            qualified.Candidate.Sources,
            qualified.Candidate.Jobs,
            qualified.Candidate.Artifacts);
        _ = RepositoryCiCandidateResolver.Restore(qualified.Digest, qualified.Candidate, qualified.Sources);
    }

    private static IGrouping<JobId, RepositoryCiArtifactResult>[] Select(RepositoryCiCandidate candidate)
    {
        var allByJob = candidate.Artifacts
            .GroupBy(static artifact => artifact.Job)
            .ToArray();
        foreach (var group in allByJob.Where(static group => group.Any(
                     static artifact => artifact.Promotion == RepositoryCiPromotionStrategy.OciImage)))
        {
            var oci = group.Where(static artifact =>
                    artifact.Promotion == RepositoryCiPromotionStrategy.OciImage)
                .ToArray();
            if (group.Count() != 1 || oci.Length != 1 || oci[0].Architecture != RepositoryCiArchitecture.Any ||
                oci[0].Entrypoints.Count != 0 || !ForgejoWebhookVerifier.IsRepository(oci[0].Repository))
                throw new InvalidDataException("The OCI candidate must contain exactly one non-executable Any artifact per job.");
        }
        var selected = allByJob
            .Where(static group => group.Any(static artifact =>
                artifact.Promotion == RepositoryCiPromotionStrategy.OciImage))
            .OrderBy(static group => group.Key.Value, StringComparer.Ordinal)
            .ToArray();
        if (selected.Length > 1)
            throw new InvalidDataException("The OCI candidate must contain exactly one image artifact.");
        return selected;
    }

    private static string EvidenceDigest(
        RepositoryCiQualifiedCandidate qualified,
        IReadOnlyList<RepositoryCiPublishedOciImage> images)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteString("qualified", qualified.Digest);
            writer.WriteString("candidate", qualified.Candidate.Digest);
            writer.WriteStartArray("images");
            foreach (var image in images)
            {
                writer.WriteStartObject();
                writer.WriteString("repository", image.ArtifactRepository);
                writer.WriteString("job", image.Job.Value);
                writer.WriteString("registryRepository", image.RegistryRepository);
                writer.WriteString("tag", image.Tag);
                writer.WriteString("archiveSha256", image.ArchiveSha256);
                writer.WriteNumber("archiveBytes", image.ArchiveBytes);
                writer.WriteString("publishedDigest", image.PublishedDigest);
                writer.WriteString("disposition", image.Disposition.ToString());
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return Convert.ToHexStringLower(SHA256.HashData(bytes.WrittenSpan));
    }

    private static RepositoryCiOciImagePublicationReceipt Result(
        RepositoryCiOciImagePublicationDisposition disposition,
        IReadOnlyList<RepositoryCiPublishedOciImage>? images = null) => new(
        disposition,
        string.Empty,
        images ?? Array.Empty<RepositoryCiPublishedOciImage>());

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool ReferenceDigest(string? value) => value is { Length: 71 } &&
        value.StartsWith("sha256:", StringComparison.Ordinal) && Digest(value[7..]);

    private sealed record PreparedImage(
        string Repository,
        JobId Job,
        string Tag,
        CiRunnerVerifiedArtifactArchive Archive);
}
