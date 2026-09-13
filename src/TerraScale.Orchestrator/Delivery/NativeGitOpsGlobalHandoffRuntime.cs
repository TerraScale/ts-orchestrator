using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>Publishes an accepted protected-main source while one exact global lease remains valid.</summary>
internal sealed class NativeGitOpsGlobalHandoffRuntime
{
    internal static readonly TimeSpan Validity = TimeSpan.FromDays(30);
    private readonly Func<string, string, string, long, DateTimeOffset, DateTimeOffset,
        INativeGitOpsCellSpecSigner, Func<bool>, CancellationToken,
        Task<NativeGitOpsGlobalHandoffCoordinationReceipt>> coordinate;
    private readonly INativeGitOpsCellSpecSigner signer;
    private readonly Func<RegionalAuthoritySnapshot> authority;
    private readonly TimeProvider timeProvider;

    internal NativeGitOpsGlobalHandoffRuntime(
        NativeGitOpsGlobalHandoffCoordinator coordinator,
        INativeGitOpsCellSpecSigner signer,
        Func<RegionalAuthoritySnapshot> authority,
        TimeProvider? timeProvider = null)
        : this(
            (repository, branch, commit, epoch, issuedAt, expiresAt, valueSigner, stillValid, token) =>
                coordinator.CoordinateAsync(
                    repository,
                    branch,
                    epoch,
                    issuedAt,
                    expiresAt,
                    valueSigner,
                    stillValid,
                    token,
                    commit),
            signer,
            authority,
            timeProvider)
    {
    }

    internal NativeGitOpsGlobalHandoffRuntime(
        Func<string, string, string, long, DateTimeOffset, DateTimeOffset,
            INativeGitOpsCellSpecSigner, Func<bool>, CancellationToken,
            Task<NativeGitOpsGlobalHandoffCoordinationReceipt>> coordinate,
        INativeGitOpsCellSpecSigner signer,
        Func<RegionalAuthoritySnapshot> authority,
        TimeProvider? timeProvider = null)
    {
        this.coordinate = coordinate ?? throw new ArgumentNullException(nameof(coordinate));
        this.signer = signer ?? throw new ArgumentNullException(nameof(signer));
        this.authority = authority ?? throw new ArgumentNullException(nameof(authority));
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    internal Task<NativeGitOpsGlobalHandoffCoordinationReceipt> CoordinateAsync(
        ForgejoBranchObservation observation,
        long expectedAuthorityEpoch,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(observation);
        var revision = observation.Revision;
        if (observation.Branch != "main" || !observation.Protected || !revision.SignatureVerified ||
            !ForgejoWebhookVerifier.IsRepository(revision.Repository))
            throw new ArgumentException(
                "Native GitOps runtime handoff requires a signed protected-main observation.",
                nameof(observation));
        var lease = authority();
        if (expectedAuthorityEpoch <= 0 || lease.Epoch != expectedAuthorityEpoch ||
            !lease.Ready || !lease.IsLeader || lease.KvRevision <= 0)
            return Task.FromResult(new NativeGitOpsGlobalHandoffCoordinationReceipt(
                NativeGitOpsGlobalHandoffCoordinationDisposition.AuthorityLost,
                NativeGitOpsSignedHandoffJournalDisposition.Unspecified,
                null,
                0));

        bool StillValid() => RepositoryCiController.SameAuthority(lease, authority());
        var issuedAt = timeProvider.GetUtcNow();
        return coordinate(
            revision.Repository,
            observation.Branch,
            revision.Commit,
            lease.Epoch,
            issuedAt,
            issuedAt.Add(Validity),
            signer,
            StillValid,
            cancellationToken);
    }
}

