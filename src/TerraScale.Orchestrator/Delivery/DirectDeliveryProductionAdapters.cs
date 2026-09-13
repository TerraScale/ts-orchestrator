using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>
/// The composition-supplied allow-list of admitted direct-delivery targets. Production delivery
/// authorization for a target is exactly membership in this set: it is parsed once from
/// configuration at startup and callers can never select or widen it per request.
/// </summary>
public sealed class DirectDeliveryAdmittedTargets
{
    private readonly Dictionary<(string Service, string Environment), HashSet<string>> admitted =
        new();

    /// <summary>Parses configuration entries of the form 'service:environment:region[,region...]'. Public so the runtime composition root can pass it; the parsed set is immutable admission state.</summary>
    public static DirectDeliveryAdmittedTargets Parse(IEnumerable<string>? entries)
    {
        var targets = new DirectDeliveryAdmittedTargets();
        foreach (var entry in entries ?? [])
        {
            if (entry is null)
                throw new ArgumentException("An admitted delivery target entry is null.", nameof(entries));
            var parts = entry.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length != 3)
                throw new ArgumentException(
                    $"The admitted delivery target '{entry}' must be 'service:environment:region[,region...]'.",
                    nameof(entries));
            var (service, environment) = (parts[0], parts[1]);
            if (!IsBoundedIdentity(service) || !IsBoundedIdentity(environment) ||
                environment is not ("local" or "development" or "production"))
                throw new ArgumentException(
                    $"The admitted delivery target '{entry}' has an invalid service or environment.",
                    nameof(entries));
            var regions = parts[2].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (regions.Length == 0 || regions.Length > DirectDeliveryCoordinator.MaximumRegionCount ||
                regions.Any(region => !IsBoundedIdentity(region)) ||
                regions.Distinct(StringComparer.Ordinal).Count() != regions.Length)
                throw new ArgumentException(
                    $"The admitted delivery target '{entry}' has an invalid region set.",
                    nameof(entries));
            if (!targets.admitted.TryGetValue((service, environment), out var admittedRegions))
                targets.admitted[(service, environment)] = admittedRegions = new(StringComparer.Ordinal);
            foreach (var region in regions)
                if (!admittedRegions.Add(region))
                    throw new ArgumentException(
                        $"The admitted delivery target '{entry}' repeats a region.", nameof(entries));
        }
        return targets;

        static bool IsBoundedIdentity(string value) =>
            value is { Length: > 0 and <= DirectDeliveryCoordinator.MaximumTextLength } &&
            !value.Any(char.IsControl);
    }

    /// <summary>True when no target is admitted at all; production composition must refuse this.</summary>
    public bool IsEmpty => admitted.Count == 0;

    /// <summary>True when the requested target is admitted with a region set that contains every requested region.</summary>
    public bool Admits(DeliveryTarget target) =>
        target.Service is { } service && target.Environment is { } environment &&
        admitted.TryGetValue((service, environment), out var regions) &&
        target.Regions is { Count: > 0 } requested &&
        requested.Count <= DirectDeliveryCoordinator.MaximumRegionCount &&
        requested.All(regions.Contains);
}

/// <summary>The durable identity binding one published artifact to its exact source tree.</summary>
internal sealed record DirectDeliveryArtifactEvidence(
    string Repository,
    string Commit,
    string TreeDigest,
    string ArtifactDigest,
    string ManifestDigest,
    string Kind);

/// <summary>A durable evidence record together with the signing identity that attested it.</summary>
internal sealed record DirectDeliverySignedArtifactEvidence(
    DirectDeliveryArtifactEvidence Evidence,
    string SigningIdentity,
    OpaqueSignature Signature);

internal enum DirectDeliveryArtifactEvidenceDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    IdentityConflict,
}

/// <summary>
/// Durable, signed source-to-artifact evidence for production direct delivery. Each record binds
/// one exact artifact digest (and its manifest digest and kind) to the repository, commit, and
/// tree digest it was built from, is signed by the recording CI signing identity, and is written
/// once under compare-and-set: a different claim for the same artifact digest can never replace
/// it. Production provenance verifies requests against this durable evidence instead of trusting
/// request-supplied digest shapes.
/// </summary>
internal sealed class DirectDeliveryArtifactEvidenceJournal(IForgejoDeliveryLedger ledger)
{
    private const string KeyPrefix = "direct.evidence.";
    private const int MaximumRecordBytes = 8 * 1024;

    private readonly IForgejoDeliveryLedger ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));

    /// <summary>Records signed evidence for one artifact digest; the first record wins durably.</summary>
    public async Task<DirectDeliveryArtifactEvidenceDisposition> RecordAsync(
        DirectDeliveryArtifactEvidence evidence,
        IRepositoryCiArtifactAttestationSigner signer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signer);
        if (!Valid(evidence))
            throw new ArgumentException("The artifact evidence identity is invalid.", nameof(evidence));
        var signed = new DirectDeliverySignedArtifactEvidence(
            evidence,
            signer.Identity,
            signer.Sign(SignedMaterial(evidence)));
        if (signed.Signature is not { IsValid: true } ||
            signed.Signature.Length > RepositoryCiArtifactAttestation.MaximumSignatureBytes)
            throw new InvalidOperationException("The artifact evidence signer returned an invalid signature.");
        var key = Key(evidence.ArtifactDigest);
        var value = Serialize(signed);
        var existing = await ledger.GetAsync(key, cancellationToken).ConfigureAwait(false);
        if (existing is null)
        {
            try
            {
                await ledger.CreateAsync(key, value, cancellationToken).ConfigureAwait(false);
                return DirectDeliveryArtifactEvidenceDisposition.Recorded;
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
                existing = await ledger.GetAsync(key, cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidDataException("The artifact evidence record disappeared after admission.");
            }
        }
        var winner = Read(existing.Value);
        return winner.Evidence == evidence
            ? DirectDeliveryArtifactEvidenceDisposition.Duplicate
            : DirectDeliveryArtifactEvidenceDisposition.IdentityConflict;
    }

    /// <summary>Reads the durable evidence for one artifact digest; null when none is recorded.</summary>
    public async Task<DirectDeliverySignedArtifactEvidence?> ReadAsync(
        string artifactDigest,
        CancellationToken cancellationToken)
    {
        if (!IsDigest(artifactDigest)) throw new ArgumentException("The artifact digest is invalid.");
        var entry = await ledger.GetAsync(Key(artifactDigest), cancellationToken).ConfigureAwait(false);
        if (entry is null) return null;
        var signed = Read(entry.Value);
        // Key↔content binding (mirrors NatsDirectDeliveryJournal.ReadAsync): a record copied to
        // another digest's key — a transplant of a legitimately signed claim — is corruption,
        // never evidence for the digest it was filed under.
        if (!string.Equals(signed.Evidence.ArtifactDigest, artifactDigest, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "The artifact evidence record does not match the digest key it was read under.");
        return signed;
    }

    /// <summary>Verifies the record's signature against the admitted CI signing trust root.</summary>
    public static bool Verifies(
        DirectDeliverySignedArtifactEvidence signed,
        IRepositoryCiArtifactSignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        return signed is not null && Valid(signed.Evidence) &&
            signed.SigningIdentity is { Length: > 0 and <= 512 } &&
            !signed.SigningIdentity.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character)) &&
            signed.Signature is { IsValid: true } &&
            signed.Signature.Length <= RepositoryCiArtifactAttestation.MaximumSignatureBytes &&
            verifier.Verify(signed.SigningIdentity, SignedMaterial(signed.Evidence), signed.Signature) ==
                VerificationOutcome.Valid;
    }

    private static ReadOnlyMemory<byte> SignedMaterial(DirectDeliveryArtifactEvidence evidence) => Material(writer =>
    {
        writer.WriteString("domain", "terrascale.delivery/artifact-evidence/v1");
        writer.WriteString("repository", evidence.Repository);
        writer.WriteString("commit", evidence.Commit);
        writer.WriteString("treeDigest", evidence.TreeDigest);
        writer.WriteString("artifactDigest", evidence.ArtifactDigest);
        writer.WriteString("manifestDigest", evidence.ManifestDigest);
        writer.WriteString("kind", evidence.Kind);
    });

    private static ReadOnlyMemory<byte> Material(Action<Utf8JsonWriter> write)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            write(writer);
            writer.WriteEndObject();
        }
        return bytes.WrittenMemory.ToArray();
    }

    private static string Serialize(DirectDeliverySignedArtifactEvidence signed)
    {
        var value = JsonSerializer.Serialize(
            new EvidenceDocument(
                1,
                signed.Evidence.Repository,
                signed.Evidence.Commit,
                signed.Evidence.TreeDigest,
                signed.Evidence.ArtifactDigest,
                signed.Evidence.ManifestDigest,
                signed.Evidence.Kind,
                signed.SigningIdentity,
                Convert.ToBase64String(signed.Signature.Bytes)),
            JsonOptions);
        if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes)
            throw new InvalidDataException("The artifact evidence record exceeded its bound.");
        return value;
    }

    private static DirectDeliverySignedArtifactEvidence Read(string value)
    {
        if (value is null || Encoding.UTF8.GetByteCount(value) is < 2 or > MaximumRecordBytes)
            throw new InvalidDataException("An artifact evidence record is empty or oversized.");
        EvidenceDocument document;
        try
        {
            document = JsonSerializer.Deserialize<EvidenceDocument>(value, JsonOptions) ??
                throw new JsonException();
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("An artifact evidence record is invalid.", exception);
        }
        var evidence = new DirectDeliveryArtifactEvidence(
            document.Repository,
            document.Commit,
            document.TreeDigest,
            document.ArtifactDigest,
            document.ManifestDigest,
            document.Kind);
        var signed = new DirectDeliverySignedArtifactEvidence(
            evidence,
            document.SigningIdentity,
            OpaqueSignature.TryCopyFrom(Convert.FromBase64String(document.Signature), out var signature) &&
                signature is not null
                ? signature
                : throw new InvalidDataException("An artifact evidence signature is invalid."));
        if (!Valid(evidence) ||
            !string.Equals(JsonSerializer.Serialize(document, JsonOptions), value, StringComparison.Ordinal))
            throw new InvalidDataException("An artifact evidence record is not canonical.");
        return signed;
    }

    private sealed record EvidenceDocument(
        [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
        [property: JsonPropertyName("repository")] string Repository,
        [property: JsonPropertyName("commit")] string Commit,
        [property: JsonPropertyName("treeDigest")] string TreeDigest,
        [property: JsonPropertyName("artifactDigest")] string ArtifactDigest,
        [property: JsonPropertyName("manifestDigest")] string ManifestDigest,
        [property: JsonPropertyName("kind")] string Kind,
        [property: JsonPropertyName("signingIdentity")] string SigningIdentity,
        [property: JsonPropertyName("signature")] string Signature);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private static bool Valid(DirectDeliveryArtifactEvidence evidence) =>
        evidence.Repository is { Length: > 0 and <= DirectDeliveryCoordinator.MaximumTextLength } &&
        !evidence.Repository.Any(char.IsControl) &&
        IsCommit(evidence.Commit) && IsDigest(evidence.TreeDigest) && IsDigest(evidence.ArtifactDigest) &&
        IsDigest(evidence.ManifestDigest) &&
        evidence.Kind is "service" or "package" or "site";

    private static string Key(string artifactDigest) =>
        $"{KeyPrefix}{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(artifactDigest.ToLowerInvariant())))}";

    private static bool IsCommit(string? value) => value is { Length: 40 } && value.All(IsHex);

    private static bool IsDigest(string? value) => value is { Length: 71 } &&
        value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) && value[7..].All(IsHex);

    private static bool IsHex(char value) => value is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
}

/// <summary>
/// Production provenance boundary: a request verifies only when durable, signed evidence binds
/// its exact artifact digest (with manifest digest and kind) to the request's exact source
/// repository, commit, and tree digest. Missing or mismatching evidence is a denial; an
/// unreachable evidence ledger is an infrastructure failure that surfaces as transient.
/// </summary>
internal sealed class DirectDeliveryProductionProvenance(
    DirectDeliveryArtifactEvidenceJournal evidence,
    IRepositoryCiArtifactSignatureVerifier verifier) : IDeliveryProvenanceVerifier
{
    private readonly DirectDeliveryArtifactEvidenceJournal evidence = evidence ??
        throw new ArgumentNullException(nameof(evidence));
    private readonly IRepositoryCiArtifactSignatureVerifier verifier = verifier ??
        throw new ArgumentNullException(nameof(verifier));

    public async ValueTask<DeliveryProvenanceResult> VerifyAsync(
        DeliveryRequest request,
        DeliveryArtifact artifact,
        CancellationToken cancellationToken)
    {
        // An artifact-supplied request without source identity cannot be bound to durable
        // evidence, so production refuses it instead of verifying digest shapes alone.
        if (request.Source is not { } source)
            return Denied(request);
        var signed = await evidence.ReadAsync(
            artifact.Digest ?? string.Empty, cancellationToken).ConfigureAwait(false);
        if (signed is null || !DirectDeliveryArtifactEvidenceJournal.Verifies(signed, verifier))
            return Denied(request);
        var bound = signed.Evidence;
        var verified =
            // The record must be evidence for the EXACT digest being deployed: without this
            // binding, a record legitimately signed for digest X and copied to digest Y's key
            // would admit an unattested artifact (transplant attack).
            string.Equals(bound.ArtifactDigest, artifact.Digest, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(bound.Repository, source.Repository, StringComparison.Ordinal) &&
            string.Equals(bound.Commit, source.Commit, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(bound.TreeDigest, source.TreeDigest, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(bound.ManifestDigest, artifact.ManifestDigest, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(bound.Kind, artifact.Kind, StringComparison.Ordinal);
        return verified
            ? new(true, false, request.ConfigurationRevision, request.MigrationRevision)
            : Denied(request);
    }

    private static DeliveryProvenanceResult Denied(DeliveryRequest request) =>
        new(false, false, request.ConfigurationRevision, request.MigrationRevision);
}

/// <summary>
/// Production target admission: a target resolves only when composition's configured allow-list
/// admits its exact service, environment, and every requested region. The returned target keeps
/// the request/admitted binding defense of the development resolver, so a mutated request can
/// never alias another target's ledger keys.
/// </summary>
internal sealed class DirectDeliveryProductionTargetResolver(
    DirectDeliveryAdmittedTargets admittedTargets,
    IDeliveryTarget target) : IDeliveryTargetResolver
{
    private readonly DirectDeliveryAdmittedTargets admittedTargets = admittedTargets ??
        throw new ArgumentNullException(nameof(admittedTargets));
    private readonly IDeliveryTarget target = target ?? throw new ArgumentNullException(nameof(target));

    public ValueTask<IDeliveryTarget?> ResolveAsync(DeliveryTarget target, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IDeliveryTarget?>(admittedTargets.Admits(target)
            ? new BoundDeliveryTarget(this.target, target)
            : null);
    }
}

/// <summary>
/// The per-request binding that keeps an admitted target pinned to the exact target identity it
/// admitted. Any request whose target differs from the admitted identity is refused at the
/// adapter boundary instead of mutating another target's durable state.
/// </summary>
internal sealed class BoundDeliveryTarget(IDeliveryTarget inner, DeliveryTarget admitted) : IDeliveryTarget
{
    private readonly IDeliveryTarget inner = inner ?? throw new ArgumentNullException(nameof(inner));
    private readonly DeliveryTarget admitted = admitted ?? throw new ArgumentNullException(nameof(admitted));

    private bool Matches(DeliveryRequest request) => request.Target is { } target &&
        string.Equals(target.Service, admitted.Service, StringComparison.Ordinal) &&
        string.Equals(target.Environment, admitted.Environment, StringComparison.Ordinal) &&
        target.Regions is { } regions && regions.SequenceEqual(admitted.Regions ?? []);

    public ValueTask<string?> ObserveCurrentDigestAsync(DeliveryRequest request, string region, CancellationToken cancellationToken) =>
        Matches(request) ? inner.ObserveCurrentDigestAsync(request, region, cancellationToken) : ValueTask.FromResult<string?>(null);

    public ValueTask<DeliveryArtifact?> ObserveCurrentArtifactAsync(DeliveryRequest request, string region, CancellationToken cancellationToken) =>
        Matches(request) ? inner.ObserveCurrentArtifactAsync(request, region, cancellationToken) : ValueTask.FromResult<DeliveryArtifact?>(null);

    public ValueTask<DeliveryMutationResult> ApplyAsync(DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken) =>
        Matches(request) ? inner.ApplyAsync(request, artifact, region, cancellationToken)
            : ValueTask.FromResult(new DeliveryMutationResult(false, false, null, DirectDeliveryErrorCode.UnknownTarget));

    public ValueTask<DeliveryMutationResult> ApplyFencedAsync(DeliveryRequest request, DeliveryArtifact artifact, string region, string? expectedPreviousArtifactDigest, CancellationToken cancellationToken) =>
        Matches(request) ? inner.ApplyFencedAsync(request, artifact, region, expectedPreviousArtifactDigest, cancellationToken)
            : ValueTask.FromResult(new DeliveryMutationResult(false, false, null, DirectDeliveryErrorCode.UnknownTarget));

    public ValueTask<DeliveryHealthResult> CheckHealthAsync(DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken) =>
        Matches(request) ? inner.CheckHealthAsync(request, artifact, region, cancellationToken)
            : ValueTask.FromResult(new DeliveryHealthResult(false));

    public ValueTask<DeliveryConvergenceResult> CheckConvergenceAsync(DeliveryRequest request, DeliveryArtifact artifact, IReadOnlyList<string> regions, CancellationToken cancellationToken) =>
        Matches(request) ? inner.CheckConvergenceAsync(request, artifact, regions, cancellationToken)
            : ValueTask.FromResult(new DeliveryConvergenceResult(false));

    public ValueTask<DeliveryRollbackResult> RollbackAsync(DeliveryRequest request, string region, string targetArtifactDigest, string? targetManifestDigest, CancellationToken cancellationToken) =>
        Matches(request) && targetManifestDigest is not null
            ? inner.RollbackAsync(request, region, targetArtifactDigest, targetManifestDigest, cancellationToken)
            : ValueTask.FromResult(new DeliveryRollbackResult(false, targetArtifactDigest));
}

/// <summary>
/// The composition boundary for direct-delivery adapters. The admitted target allow-list comes
/// from configuration at startup; composition fails closed when the durable evidence verifier or
/// the admitted-target allow-list is absent, exactly like the signed-command-identity rule at
/// the mutation endpoint.
/// </summary>
internal static class DirectDeliveryRuntimeAdapterSet
{
    /// <summary>
    /// Builds the adapter set for one runtime: leader-probe authorization beside the signed
    /// command-envelope seam, provenance over durable signed evidence, target admission from the
    /// configured allow-list, and no artifact builder — a delivery must carry the exact
    /// published artifact.
    /// </summary>
    public static (IDeliveryAuthorizer Authorizer, IDeliveryProvenanceVerifier Provenance,
        IDeliveryTargetResolver TargetResolver, IDeliveryJournal Journal,
        IDeliveryArtifactBuilder? ArtifactBuilder) Create(
        IForgejoDeliveryLedger ledger,
        Func<bool> isLeader,
        Func<DeliveryRequest, bool> authorityIsCurrent,
        DirectDeliveryAdmittedTargets? admittedTargets = null,
        IRepositoryCiArtifactSignatureVerifier? evidenceVerifier = null)
    {
        ArgumentNullException.ThrowIfNull(ledger);
        ArgumentNullException.ThrowIfNull(isLeader);
        ArgumentNullException.ThrowIfNull(authorityIsCurrent);
        // Authorization is the signed command-envelope admission at the mutation endpoint plus
        // this leader/authority-lease probe: production never trusts a bare leadership claim
        // without the signed seam, and the endpoint refuses to register without a verifier.
        var authorizer = new DirectDeliveryLeaderProbeAuthorizer(isLeader);
        var journal = new NatsDirectDeliveryJournal(ledger);
        // An empty configured allow-list would start and deny every request: fail closed at
        // composition, exactly like an absent one, instead of running inert.
        if (admittedTargets is null || admittedTargets.IsEmpty)
            throw new InvalidOperationException(
                "Direct delivery requires a non-empty admitted target allow-list from configuration.");
        if (evidenceVerifier is null)
            throw new InvalidOperationException(
                "Direct delivery requires the durable artifact-evidence signature verifier.");
        return (authorizer,
            new DirectDeliveryProductionProvenance(
                new DirectDeliveryArtifactEvidenceJournal(ledger), evidenceVerifier),
            new DirectDeliveryProductionTargetResolver(admittedTargets, new NatsDirectDeliveryTarget(ledger)),
            journal,
            null);
    }
}

