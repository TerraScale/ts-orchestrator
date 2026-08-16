using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>
/// Composes immutable Forgejo archive publication with an injected regional actuator. Publication
/// rollback deliberately retains content-addressed archives; no mutable release channel exists here.
/// </summary>
internal sealed class RepositoryCiForgejoPromotionActuator(
    IRepositoryCiPackagePublicationCoordinator packages,
    IRepositoryCiPromotionActuator regions,
    IRepositoryCiOciImagePublicationCoordinator? oci = null) : IRepositoryCiPromotionActuator
{
    private readonly IRepositoryCiPackagePublicationCoordinator packages = packages ??
        throw new ArgumentNullException(nameof(packages));
    private readonly IRepositoryCiPromotionActuator regions = regions ??
        throw new ArgumentNullException(nameof(regions));
    private readonly IRepositoryCiOciImagePublicationCoordinator? oci = oci;

    public async Task<RepositoryCiPromotionOperationReceipt> ExecuteAsync(
        RepositoryCiPromotionOperation operation,
        RepositoryCiPromotionAuthorization authorization,
        RepositoryCiPromotionLease lease,
        string operationId,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (authorization.Qualified.Digest != lease.QualifiedDigest ||
            authorization.Digest != lease.AuthorizationDigest ||
            authorization.Qualified.Candidate.Digest != lease.CandidateDigest ||
            operationId is not { Length: >= 1 and <= 512 })
            throw new InvalidDataException("The Forgejo promotion operation differs from its durable lease.");
        if (!authorityStillValid()) return new(false, OutcomeDigest(authorization, operationId, "stale-authority"));

        if (operation == RepositoryCiPromotionOperation.Publish)
        {
            var packageReceipt = await packages.PublishAsync(
                authorization.Qualified,
                authorityStillValid,
                cancellationToken);
            if (packageReceipt is null)
                throw new InvalidDataException("The package publisher returned no receipt.");
            var packageSucceeded = packageReceipt.Disposition is RepositoryCiPackagePublicationDisposition.Published or
                RepositoryCiPackagePublicationDisposition.Duplicate or
                RepositoryCiPackagePublicationDisposition.NotApplicable;
            if ((packageReceipt.Disposition is RepositoryCiPackagePublicationDisposition.Published or
                    RepositoryCiPackagePublicationDisposition.Duplicate) &&
                !RepositoryCiJobExecutionDocument.IsDigest(packageReceipt.EvidenceDigest))
                packageSucceeded = false;
            if (!packageSucceeded)
                return new(
                    false,
                    CompositeEvidenceDigest(authorization, operationId, packageReceipt, null));
            if (oci is null)
            {
                var succeeded = packageReceipt.Disposition is RepositoryCiPackagePublicationDisposition.Published or
                RepositoryCiPackagePublicationDisposition.Duplicate;
                return new(
                    succeeded,
                    succeeded && RepositoryCiJobExecutionDocument.IsDigest(packageReceipt.EvidenceDigest)
                        ? packageReceipt.EvidenceDigest
                        : OutcomeDigest(authorization, operationId, packageReceipt.Disposition.ToString()));
            }

            var ociReceipt = await oci.PublishAsync(
                authorization.Qualified,
                authorityStillValid,
                cancellationToken);
            if (ociReceipt is null)
                throw new InvalidDataException("The OCI publisher returned no receipt.");
            var ociSucceeded = ociReceipt.Disposition is RepositoryCiOciImagePublicationDisposition.Published or
                RepositoryCiOciImagePublicationDisposition.Duplicate or
                RepositoryCiOciImagePublicationDisposition.NotApplicable;
            if ((ociReceipt.Disposition is RepositoryCiOciImagePublicationDisposition.Published or
                    RepositoryCiOciImagePublicationDisposition.Duplicate) &&
                !RepositoryCiJobExecutionDocument.IsDigest(ociReceipt.EvidenceDigest))
                ociSucceeded = false;
            var anyPublicationApplied = packageReceipt.Disposition != RepositoryCiPackagePublicationDisposition.NotApplicable ||
                ociReceipt.Disposition != RepositoryCiOciImagePublicationDisposition.NotApplicable;
            return new(
                ociSucceeded && anyPublicationApplied,
                CompositeEvidenceDigest(authorization, operationId, packageReceipt, ociReceipt));
        }

        if (operation == RepositoryCiPromotionOperation.RollbackPublication)
            return new(true, OutcomeDigest(authorization, operationId, "immutable-archives-retained"));
        if (operation == RepositoryCiPromotionOperation.Unspecified)
            throw new ArgumentOutOfRangeException(nameof(operation));
        return await regions.ExecuteAsync(
            operation,
            authorization,
            lease,
            operationId,
            authorityStillValid,
            cancellationToken);
    }

    private static string OutcomeDigest(
        RepositoryCiPromotionAuthorization authorization,
        string operationId,
        string outcome) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
        $"{authorization.Digest}\n{authorization.Qualified.Digest}\n{operationId}\n{outcome}")));

    private static string CompositeEvidenceDigest(
        RepositoryCiPromotionAuthorization authorization,
        string operationId,
        RepositoryCiPackagePublicationReceipt packages,
        RepositoryCiOciImagePublicationReceipt? oci)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteString("authorization", authorization.Digest);
            writer.WriteString("qualified", authorization.Qualified.Digest);
            writer.WriteString("operation", operationId);
            writer.WriteString("packageDisposition", packages.Disposition.ToString());
            writer.WriteString("packageEvidence", packages.EvidenceDigest);
            writer.WriteStartArray("packages");
            foreach (var package in packages.Packages.OrderBy(static value => value.Repository, StringComparer.Ordinal)
                         .ThenBy(static value => value.Job.Value, StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("repository", package.Repository);
                writer.WriteString("job", package.Job.Value);
                writer.WriteString("sha256", package.Sha256);
                writer.WriteNumber("bytes", package.Bytes);
                writer.WriteString("disposition", package.Disposition.ToString());
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            if (oci is null)
            {
                writer.WriteNull("oci");
            }
            else
            {
                writer.WriteStartObject("oci");
                writer.WriteString("disposition", oci.Disposition.ToString());
                writer.WriteString("evidence", oci.EvidenceDigest);
                writer.WriteStartArray("images");
                foreach (var image in oci.Images.OrderBy(static value => value.ArtifactRepository, StringComparer.Ordinal)
                             .ThenBy(static value => value.Job.Value, StringComparer.Ordinal))
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
            writer.WriteEndObject();
        }
        return Convert.ToHexStringLower(SHA256.HashData(bytes.WrittenSpan));
    }
}
