using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Delivery.DeployHandoffV2;

/// <summary>
/// Immutable startup policy keyed by operation and artifact. No expected value is read from the
/// handoff, and duplicate keys fail startup instead of selecting an arbitrary policy.
/// </summary>
public sealed class CandidateEvidenceHandoffV2AdmissionPolicyCatalog
{
    private const int MaximumCatalogBytes = 4 * 1024 * 1024;
    private const int MaximumPolicies = 512;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        MaxDepth = CandidateEvidenceHandoffV2Contract.MaximumDepth,
    };
    private readonly IReadOnlyDictionary<(string OperationId, string ArtifactDigest), CandidateEvidenceHandoffV2AdmissionPolicy> policies;

    private CandidateEvidenceHandoffV2AdmissionPolicyCatalog(
        IReadOnlyDictionary<(string OperationId, string ArtifactDigest), CandidateEvidenceHandoffV2AdmissionPolicy> policies) =>
        this.policies = policies;

    internal static CandidateEvidenceHandoffV2AdmissionPolicyCatalog Empty { get; } =
        new(new Dictionary<(string, string), CandidateEvidenceHandoffV2AdmissionPolicy>());

    internal bool IsEmpty => policies.Count == 0;

    internal static CandidateEvidenceHandoffV2AdmissionPolicyCatalog Load(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return Empty;
        var fullPath = Path.GetFullPath(path);
        return Parse(ReadBounded(fullPath));
    }

    internal static CandidateEvidenceHandoffV2AdmissionPolicyCatalog Create(
        IEnumerable<CandidateEvidenceHandoffV2AdmissionPolicy> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        var entries = new Dictionary<(string, string), CandidateEvidenceHandoffV2AdmissionPolicy>();
        foreach (var policy in values)
        {
            if (policy is null || !CandidateEvidenceHandoffV2Verifier.IsAdmissionPolicyValid(policy) ||
                policy.RequiredTests.Count != policy.RequiredTests.Distinct(StringComparer.Ordinal).Count())
                throw new InvalidDataException("A candidate handoff v2 admission policy is invalid.");
            var key = (policy.ExpectedOperationId, policy.ExpectedArtifact.Digest);
            if (!entries.TryAdd(key, Copy(policy)))
                throw new InvalidDataException(
                    "The candidate handoff v2 admission-policy catalog repeats an operation/artifact key.");
            if (entries.Count > MaximumPolicies)
                throw new InvalidDataException("The candidate handoff v2 admission-policy catalog is oversized.");
        }
        return new(entries);
    }

    internal CandidateEvidenceHandoffV2AdmissionPolicy? Resolve(
        CandidateEvidenceHandoffV2RoutingIdentity identity,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (!policies.TryGetValue((identity.OperationId, identity.ArtifactDigest), out var policy))
            return null;
        return Copy(policy) with { Now = now };
    }

    internal static CandidateEvidenceHandoffV2AdmissionPolicyCatalog Parse(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length is < 1 or > MaximumCatalogBytes)
            throw new InvalidDataException(
                "The candidate handoff v2 admission-policy catalog is empty or oversized.");
        try
        {
            using var json = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                MaxDepth = CandidateEvidenceHandoffV2Contract.MaximumDepth,
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false,
            });
            RejectDuplicateProperties(json.RootElement, "$");
            var document = JsonSerializer.Deserialize<CatalogDocument>(bytes.Span, JsonOptions)
                ?? throw new JsonException("The admission-policy catalog was null.");
            if (document.SchemaVersion != 1 || document.Policies is null ||
                document.Policies.Count is < 1 or > MaximumPolicies)
                throw new JsonException("The admission-policy catalog schema or policy count is invalid.");
            return Create(document.Policies.Select(static value => value.ToPolicy()));
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "The candidate handoff v2 admission-policy catalog is malformed, ambiguous, or has an unknown field.",
                exception);
        }
    }

    private static byte[] ReadBounded(string path)
    {
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                FileOptions.SequentialScan);
            var buffer = new byte[MaximumCatalogBytes + 1];
            var length = 0;
            while (length < buffer.Length)
            {
                var read = stream.Read(buffer, length, buffer.Length - length);
                if (read == 0)
                    break;
                length += read;
            }
            if (length is < 1 or > MaximumCatalogBytes)
                throw new InvalidDataException(
                    "The candidate handoff v2 admission-policy catalog is absent, empty, or oversized.");
            return buffer.AsSpan(0, length).ToArray();
        }
        catch (FileNotFoundException exception)
        {
            throw new InvalidDataException(
                "The candidate handoff v2 admission-policy catalog is absent, empty, or oversized.",
                exception);
        }
        catch (DirectoryNotFoundException exception)
        {
            throw new InvalidDataException(
                "The candidate handoff v2 admission-policy catalog is absent, empty, or oversized.",
                exception);
        }
    }

    private static CandidateEvidenceHandoffV2AdmissionPolicy Copy(
        CandidateEvidenceHandoffV2AdmissionPolicy policy) =>
        policy with
        {
            ExpectedDependencyLocks = policy.ExpectedDependencyLocks.ToArray(),
            ExpectedTarget = policy.ExpectedTarget with { Regions = policy.ExpectedTarget.Regions.ToArray() },
            ExpectedApprovalDigests = new Dictionary<string, string>(
                policy.ExpectedApprovalDigests,
                StringComparer.Ordinal),
            RequiredTests = policy.RequiredTests.ToHashSet(StringComparer.Ordinal),
        };

    private static void RejectDuplicateProperties(JsonElement value, string path)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name))
                    throw new JsonException($"The policy catalog repeats property '{Bounded(path + "." + property.Name)}'.");
                RejectDuplicateProperties(property.Value, path + "." + property.Name);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in value.EnumerateArray())
                RejectDuplicateProperties(item, $"{path}[{index++}]");
        }
    }

    private static string Bounded(string value) => value.Length <= 160 ? value : value[..160];

    private sealed record CatalogDocument(
        [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
        [property: JsonPropertyName("policies")] IReadOnlyList<PolicyDocument> Policies);

    private sealed record PolicyDocument(
        [property: JsonPropertyName("operationId")] string OperationId,
        [property: JsonPropertyName("audience")] string Audience,
        [property: JsonPropertyName("signingIdentity")] string SigningIdentity,
        [property: JsonPropertyName("deployCli")] CandidateHandoffV2DeployCli DeployCli,
        [property: JsonPropertyName("dependencyLocks")] IReadOnlyList<CandidateHandoffV2DependencyLock> DependencyLocks,
        [property: JsonPropertyName("artifact")] CandidateHandoffV2Artifact Artifact,
        [property: JsonPropertyName("configurationDigest")] string ConfigurationDigest,
        [property: JsonPropertyName("migrationDigest")] string? MigrationDigest,
        [property: JsonPropertyName("target")] CandidateHandoffV2Target Target,
        [property: JsonPropertyName("lease")] CandidateHandoffV2LeaseExpectation Lease,
        [property: JsonPropertyName("rollback")] CandidateHandoffV2Rollback Rollback,
        [property: JsonPropertyName("supplyChainReceiptDigest")] string SupplyChainReceiptDigest,
        [property: JsonPropertyName("firstPartyLicense")] CandidateHandoffV2FirstPartyLicenseExpectation FirstPartyLicense,
        [property: JsonPropertyName("approvalDigests")] IReadOnlyDictionary<string, string> ApprovalDigests,
        [property: JsonPropertyName("requiredTests")] IReadOnlyList<string> RequiredTests,
        [property: JsonPropertyName("maximumEnvelopeAgeSeconds")] int MaximumEnvelopeAgeSeconds,
        [property: JsonPropertyName("maximumCleanWorktreeProofAgeSeconds")] int MaximumCleanWorktreeProofAgeSeconds,
        [property: JsonPropertyName("maximumTestAgeSeconds")] int MaximumTestAgeSeconds,
        [property: JsonPropertyName("maximumSecurityAgeSeconds")] int MaximumSecurityAgeSeconds,
        [property: JsonPropertyName("maximumFirstPartyLicenseAgeSeconds")] int MaximumFirstPartyLicenseAgeSeconds)
    {
        internal CandidateEvidenceHandoffV2AdmissionPolicy ToPolicy()
        {
            if (RequiredTests is null || RequiredTests.Count != RequiredTests.Distinct(StringComparer.Ordinal).Count())
                throw new JsonException("The admission policy repeats a required test identity.");
            return new(
                DateTimeOffset.UnixEpoch,
                OperationId,
                Audience,
                SigningIdentity,
                DeployCli,
                DependencyLocks,
                Artifact,
                ConfigurationDigest,
                MigrationDigest,
                Target,
                Lease,
                Rollback,
                SupplyChainReceiptDigest,
                FirstPartyLicense,
                ApprovalDigests,
                RequiredTests.ToHashSet(StringComparer.Ordinal),
                TimeSpan.FromSeconds(MaximumEnvelopeAgeSeconds),
                TimeSpan.FromSeconds(MaximumCleanWorktreeProofAgeSeconds),
                TimeSpan.FromSeconds(MaximumTestAgeSeconds),
                TimeSpan.FromSeconds(MaximumSecurityAgeSeconds),
                TimeSpan.FromSeconds(MaximumFirstPartyLicenseAgeSeconds));
        }
    }
}

/// <summary>Admission-only production runtime. It verifies evidence and never invokes delivery mutation.</summary>
internal sealed class CandidateEvidenceHandoffV2AdmissionRuntime(
    CandidateEvidenceHandoffV2Consumer consumer,
    CandidateEvidenceHandoffV2AdmissionPolicyCatalog policies)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };
    private readonly CandidateEvidenceHandoffV2Consumer consumer = consumer ??
        throw new ArgumentNullException(nameof(consumer));
    private readonly CandidateEvidenceHandoffV2AdmissionPolicyCatalog policies = policies ??
        throw new ArgumentNullException(nameof(policies));

    internal static CandidateEvidenceHandoffV2AdmissionRuntime ComposeProduction(
        IForgejoDeliveryLedger ledger,
        IRepositoryCiArtifactSignatureVerifier artifactAndHandoffTrust,
        CandidateEvidenceHandoffV2AdmissionPolicyCatalog policies)
    {
        ArgumentNullException.ThrowIfNull(ledger);
        ArgumentNullException.ThrowIfNull(artifactAndHandoffTrust);
        ArgumentNullException.ThrowIfNull(policies);
        return new(
            new(
                new DirectDeliveryArtifactEvidenceJournal(ledger),
                artifactAndHandoffTrust,
                new RepositoryCandidateEvidenceHandoffV2SignatureVerifier(artifactAndHandoffTrust)),
            policies);
    }

    internal async ValueTask<CandidateEvidenceHandoffV2AdmissionReceipt> AdmitAsync(
        ReadOnlyMemory<byte> document,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        if (!CandidateEvidenceHandoffV2Verifier.TryReadRoutingIdentity(document, out var identity))
            return Rejected(
                "invalid",
                "sha256:" + new string('0', 64),
                "handoff_v2_document_invalid",
                "The candidate handoff does not contain one bounded routing identity.",
                "Regenerate the exact signed version-2 handoff.");
        var policy = policies.Resolve(identity, now);
        if (policy is null)
            return Rejected(
                identity.OperationId,
                identity.ArtifactDigest,
                "handoff_v2_policy_missing",
                "No exact startup admission policy exists for this operation and artifact.",
                "Provision the separately authorized operation/artifact policy before retrying the unchanged handoff.");
        var result = await consumer.VerifyAsync(document, policy, cancellationToken).ConfigureAwait(false);
        if (result.Decision != CandidateEvidenceHandoffV2Decision.Verified || result.Admission is null)
            return Rejected(
                identity.OperationId,
                identity.ArtifactDigest,
                result.Error?.Code ?? "handoff_v2_document_invalid",
                result.Error?.Message ?? "The candidate handoff was rejected.",
                result.Error?.Remediation ?? "Regenerate the exact candidate evidence.");
        var request = result.Admission.Delivery;
        if (request.AuthorityGeneration != 0 || request.WriterEpoch != 0 || request.Attempt != 0)
            return Rejected(
                identity.OperationId,
                identity.ArtifactDigest,
                "handoff_v2_authority_forbidden",
                "Candidate admission unexpectedly carried rollout authority.",
                "Keep candidate admission separate from Orchestrator live-lease authorization.");
        return new(
            CandidateEvidenceHandoffV2Contract.SchemaVersion,
            CandidateEvidenceHandoffV2Contract.AdmissionReceiptMediaType,
            identity.OperationId,
            identity.ArtifactDigest,
            "admitted",
            0,
            0,
            0,
            null);
    }

    internal static string SerializeReceipt(CandidateEvidenceHandoffV2AdmissionReceipt receipt) =>
        JsonSerializer.Serialize(receipt, JsonOptions);

    internal static CandidateEvidenceHandoffV2AdmissionReceipt RefusedBeforeAdmission(
        CandidateEvidenceHandoffV2RoutingIdentity identity,
        CandidateEvidenceHandoffV2Error error) =>
        Rejected(identity.OperationId, identity.ArtifactDigest, error.Code, error.Message, error.Remediation);

    private static CandidateEvidenceHandoffV2AdmissionReceipt Rejected(
        string operationId,
        string artifactDigest,
        string code,
        string message,
        string remediation) =>
        new(
            CandidateEvidenceHandoffV2Contract.SchemaVersion,
            CandidateEvidenceHandoffV2Contract.AdmissionReceiptMediaType,
            operationId,
            artifactDigest,
            "rejected",
            0,
            0,
            0,
            new(code, message, remediation));
}
