using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>
/// Composes immutable Forgejo archive publication with an injected regional actuator. Publication
/// rollback deliberately retains content-addressed archives; no mutable release channel exists here.
/// </summary>
internal sealed class RepositoryCiForgejoPromotionActuator(
    IRepositoryCiPackagePublicationCoordinator packages,
    IRepositoryCiPromotionActuator regions) : IRepositoryCiPromotionActuator
{
    private readonly IRepositoryCiPackagePublicationCoordinator packages = packages ??
        throw new ArgumentNullException(nameof(packages));
    private readonly IRepositoryCiPromotionActuator regions = regions ??
        throw new ArgumentNullException(nameof(regions));

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
            var receipt = await packages.PublishAsync(
                authorization.Qualified,
                authorityStillValid,
                cancellationToken);
            var succeeded = receipt.Disposition is RepositoryCiPackagePublicationDisposition.Published or
                RepositoryCiPackagePublicationDisposition.Duplicate;
            return new(
                succeeded,
                succeeded && RepositoryCiJobExecutionDocument.IsDigest(receipt.EvidenceDigest)
                    ? receipt.EvidenceDigest
                    : OutcomeDigest(authorization, operationId, receipt.Disposition.ToString()));
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
}
