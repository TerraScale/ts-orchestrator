using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

public enum ForgejoCiTriggerDisposition
{
    Unspecified,
    Ignored,
    Held,
    Dispatch,
}

public enum ForgejoCiTriggerReason
{
    Unspecified,
    FeatureValidation,
    DevelopValidation,
    TrustedArtifactBuild,
    MetadataOnly,
    UnsupportedReference,
    PolicyDenied,
    ProtectedReferenceDeleted,
}

public sealed class ForgejoCiTriggerPlan
{
    private const int MaximumAttempts = 3;

    internal ForgejoCiTriggerPlan(
        ForgejoWebhookEnvelope envelope,
        ForgejoCiTriggerDisposition disposition,
        ForgejoCiTriggerReason reason,
        JobKind jobKind = JobKind.Unspecified,
        TrustZone trustZone = TrustZone.Unspecified,
        IEnumerable<RunnerCapability>? capabilities = null,
        bool mayPublishArtifacts = false)
    {
        Envelope = envelope;
        Disposition = disposition;
        Reason = reason;
        JobKind = jobKind;
        TrustZone = trustZone;
        Capabilities = new ReadOnlyCollection<RunnerCapability>((capabilities ?? []).ToArray());
        MayPublishArtifacts = mayPublishArtifacts;
    }

    public ForgejoWebhookEnvelope Envelope { get; }
    public ForgejoCiTriggerDisposition Disposition { get; }
    public ForgejoCiTriggerReason Reason { get; }
    public JobKind JobKind { get; }
    public TrustZone TrustZone { get; }
    public IReadOnlyList<RunnerCapability> Capabilities { get; }
    public bool MayPublishArtifacts { get; }

    public JobRequest CreateJobRequest(
        ForgejoResolvedRevision resolved,
        long generation,
        long minimumRunnerSequence,
        long maximumRunnerSequence)
    {
        ArgumentNullException.ThrowIfNull(resolved);
        if (Disposition != ForgejoCiTriggerDisposition.Dispatch)
            throw new InvalidOperationException("A non-dispatch Forgejo trigger cannot create CI work.");
        if (resolved.Repository != Envelope.Repository ||
            !StringComparer.OrdinalIgnoreCase.Equals(resolved.Commit, Envelope.Revision))
            throw new ArgumentException("The resolved source does not match the signed Forgejo revision.", nameof(resolved));
        if (!IsObjectId(resolved.Tree) || resolved.Tree.All(static value => value == '0'))
            throw new ArgumentException("The resolved Git tree identity is invalid.", nameof(resolved));
        if (JobKind == JobKind.TrustedBuild && !resolved.SignatureVerified)
            throw new InvalidOperationException("A trusted artifact build requires a verified source commit signature.");
        if (generation <= 0 || minimumRunnerSequence <= 0 || maximumRunnerSequence < minimumRunnerSequence)
            throw new ArgumentOutOfRangeException(nameof(generation), "Generation and runner evidence bounds must be positive and ordered.");

        var identity = Hash($"{Envelope.DedupeKey}\n{JobKind}");
        return new(
            new PipelineId($"forgejo-{identity[..24]}"),
            new JobId($"ci-{identity[..32]}"),
            JobKind,
            new TreeId(resolved.Tree.ToLowerInvariant()),
            generation,
            1,
            MaximumAttempts,
            new IdempotencyId($"forgejo-{identity}"),
            [TrustZone],
            Capabilities,
            minimumRunnerSequence,
            maximumRunnerSequence,
            retryAuthorized: false);
    }

    private static bool IsObjectId(string value) =>
        value.Length is 40 or 64 && value.All(static character => character is
            >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

/// <summary>Maps verified Forgejo events into a closed CI trust and capability policy.</summary>
public static class ForgejoCiTriggerPlanner
{
    public static ForgejoCiTriggerPlan Plan(ForgejoWebhookEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        return envelope.Kind switch
        {
            ForgejoWebhookKind.Push => PlanPush(envelope),
            ForgejoWebhookKind.PullRequest => PlanPullRequest(envelope),
            _ => Held(envelope, ForgejoCiTriggerReason.PolicyDenied),
        };
    }

    private static ForgejoCiTriggerPlan PlanPush(ForgejoWebhookEnvelope envelope)
    {
        if (envelope.IsDeletion)
            return envelope.SourceRef is "refs/heads/develop" or "refs/heads/main"
                ? Held(envelope, ForgejoCiTriggerReason.ProtectedReferenceDeleted)
                : Ignored(envelope, ForgejoCiTriggerReason.UnsupportedReference);
        return envelope.SourceRef switch
        {
            "refs/heads/develop" => Dispatch(
                envelope,
                ForgejoCiTriggerReason.DevelopValidation,
                JobKind.ProductValidation,
                TrustZone.UntrustedProduct,
                [RunnerCapability.Compile, RunnerCapability.Test]),
            // Protected-main delivery is native GitOps/direct delivery. It is journaled as a
            // policy-held event and never becomes an acknowledge-without-work promotion job.
            "refs/heads/main" => Held(envelope, ForgejoCiTriggerReason.PolicyDenied),
            _ => Ignored(envelope, ForgejoCiTriggerReason.UnsupportedReference),
        };
    }

    private static ForgejoCiTriggerPlan PlanPullRequest(ForgejoWebhookEnvelope envelope)
    {
        if (envelope.Action is not ("opened" or "reopened" or "synchronized"))
            return Ignored(envelope, ForgejoCiTriggerReason.MetadataOnly);
        if (envelope.TargetRef == "develop")
            return Dispatch(
                envelope,
                ForgejoCiTriggerReason.FeatureValidation,
                JobKind.ProductValidation,
                TrustZone.UntrustedProduct,
                [RunnerCapability.Compile, RunnerCapability.Test]);
        if (envelope.TargetRef == "main")
            return !envelope.IsFork && envelope.SourceRef == "develop"
                ? Dispatch(
                    envelope,
                    ForgejoCiTriggerReason.TrustedArtifactBuild,
                    JobKind.TrustedBuild,
                    TrustZone.TrustedBuild,
                    [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign],
                    mayPublishArtifacts: true)
                : Held(envelope, ForgejoCiTriggerReason.PolicyDenied);
        return Ignored(envelope, ForgejoCiTriggerReason.UnsupportedReference);
    }

    private static ForgejoCiTriggerPlan Dispatch(
        ForgejoWebhookEnvelope envelope,
        ForgejoCiTriggerReason reason,
        JobKind kind,
        TrustZone zone,
        IEnumerable<RunnerCapability> capabilities,
        bool mayPublishArtifacts = false) => new(
            envelope,
            ForgejoCiTriggerDisposition.Dispatch,
            reason,
            kind,
            zone,
            capabilities,
            mayPublishArtifacts);

    private static ForgejoCiTriggerPlan Held(ForgejoWebhookEnvelope envelope, ForgejoCiTriggerReason reason) =>
        new(envelope, ForgejoCiTriggerDisposition.Held, reason);

    private static ForgejoCiTriggerPlan Ignored(ForgejoWebhookEnvelope envelope, ForgejoCiTriggerReason reason) =>
        new(envelope, ForgejoCiTriggerDisposition.Ignored, reason);
}
