using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Security;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

internal static class SecurityCompletenessData
{
    private static readonly SecurityCellId Cell = new("gru");
    private static readonly SecurityGeneration Generation = new(5);
    private static readonly SecurityGeneration PolicyGeneration = new(2);
    private static readonly SecurityGeneration IssuerGeneration = new(1);
    private static readonly SecurityGeneration RevocationGeneration = new(3);

    internal static EnrollmentRequest Enrollment(int variant, ulong seed)
    {
        var operation = Operation("enrollment", seed); var principal = Principal(seed);
        var issuer = variant == 13
            ? new IssuerSigningCapability(new("issuer-global"), IssuerCapabilityKind.GlobalAdministrativeIntermediate, Cell, TrustScope.GlobalAdministration, IssuerGeneration, RevocationGeneration)
            : Issuer(variant == 12 ? new(2) : RevocationGeneration);
        var bootstrap = new BootstrapEnrollmentEvidence(new($"bootstrap-{seed}"), variant == 4 ? new("other-operation") : operation,
            variant == 5 ? new("other-principal") : principal.Id, principal.Kind, Cell, principal.Role,
            variant == 8 ? new(4) : Generation, variant == 10 ? EvidenceStatus.Consumed : EvidenceStatus.Valid);
        var attestation = new SecurityAttestationEvidence(new($"attestation-{seed}"), Digest("attestation", seed), principal.Id,
            variant is 14 or 15 ? new("attacker-subject-key") : new($"subject-key-{seed}"), principal.Kind,
            variant == 6 ? new("sfo") : Cell, variant is 7 or 3 ? SecurityRole.TerraBase : principal.Role, Generation, PolicyGeneration,
            variant is 1 or 15 ? EvidenceStatus.Missing : variant == 9 ? EvidenceStatus.Stale : EvidenceStatus.Valid);
        IEnumerable<BootstrapEnrollmentEvidence> bootstraps = variant switch
        {
            2 => [bootstrap, bootstrap],
            3 => [bootstrap, new(new($"bootstrap-{seed}"), operation, principal.Id, principal.Kind, Cell, SecurityRole.TerraBase, Generation, EvidenceStatus.Valid)],
            _ => [bootstrap],
        };
        return new(operation, principal, new($"subject-key-{seed}"), PolicyGeneration, issuer,
            variant == 11 ? new(2) : IssuerGeneration, RevocationGeneration, bootstraps, [attestation]);
    }

    internal static CertificateLifecycleRequest Certificate(int variant, ulong seed)
    {
        var action = variant < 4 ? (CertificateAction)(variant + 1) : variant == 13 ? CertificateAction.Revoke : CertificateAction.Renew;
        var operation = Operation("certificate", seed); var principalCell = variant == 6 ? new SecurityCellId("sfo") : Cell;
        var principal = variant == 15
            ? new SecurityPrincipal(new($"principal-{seed}"), SecurityPrincipalKind.Operator, SecurityRole.Operator, Cell, Generation)
            : Principal(seed, principalCell);
        var key = new SecurityKeyId($"subject-key-{seed}"); var certificate = new SecurityCertificateId($"certificate-{seed}");
        var requestedScope = variant is 8 or 15 ? TrustScope.GlobalAdministration : TrustScope.Cell;
        var usage = variant == 15 ? CertificateUsage.OperatorClient : CertificateUsage.NodeTransport;
        var issuer = variant is 14 or 15
            ? new IssuerSigningCapability(new("issuer-global"), IssuerCapabilityKind.GlobalAdministrativeIntermediate, Cell, TrustScope.GlobalAdministration, IssuerGeneration, RevocationGeneration)
            : Issuer();
        var policy = new CertificateLifecyclePolicy(PolicyGeneration, new(900), new(300), new(100),
            variant == 11 ? [CertificateUsage.Telemetry] : [usage], requestedScope);
        var currentCertificate = new SecurityGeneration(4);
        var validity = new CertificateValidityEvidence(certificate, variant == 7 ? new("other-operation") : operation, principal.Id, principal.CellId, key,
            usage, requestedScope, issuer.IssuerId, issuer.Generation, currentCertificate,
            variant == 10 ? new(1) : PolicyGeneration, variant == 4 ? new(2) : RevocationGeneration,
            variant == 12 ? ValidityStatus.Expired : action == CertificateAction.Issue ? ValidityStatus.Valid : ValidityStatus.RenewalDue,
            RevocationStatus.Current);
        var compromise = new CertificateCompromiseEvidence(certificate, principal.Id, principal.CellId, currentCertificate,
            RevocationGeneration, variant == 13 ? EvidenceStatus.Missing : EvidenceStatus.Valid);
        var requested = action is CertificateAction.Issue or CertificateAction.Revoke ? currentCertificate : new SecurityGeneration(5);
        return new(action, operation, principal, variant == 5 ? new(6) : Generation, key, usage, requestedScope,
            requested, issuer, variant == 9 ? new(2) : IssuerGeneration, policy, validity, RevocationGeneration, compromise);
    }

    internal static AuthorizationRequest Authorization(int variant, ulong seed)
    {
        var operation = Operation("authorization", seed); var principal = Principal(seed);
        var scope = new SecurityResourceScope(SecurityResourceKind.EncryptedSecret, variant == 9 ? new("sfo") : Cell,
            SecurityEnvironment.Production, SecretPurpose.Database);
        var evidence = new PrincipalAuthorizationEvidence(
            variant == 4 ? Principal(seed + 10000) : variant == 5 ? new(principal.Id, principal.Kind, principal.Role, Cell, new(4)) : principal,
            variant == 6 ? new(2) : RevocationGeneration, variant == 6 ? RevocationStatus.Revoked : RevocationStatus.Current, EvidenceStatus.Valid);
        var conflict = new PrincipalAuthorizationEvidence(new(principal.Id, principal.Kind, SecurityRole.TerraBase, Cell, Generation),
            RevocationGeneration, RevocationStatus.Current, EvidenceStatus.Valid);
        var grant = new AuthorizationGrant(PolicyGeneration, principal.Kind, principal.Role, AuthorizationCapability.ReadEncryptedSecret, scope);
        IEnumerable<PrincipalAuthorizationEvidence> evidenceSet = variant switch { 2 => [evidence, evidence], 3 => [evidence, conflict], _ => [evidence] };
        IEnumerable<AuthorizationGrant> grants = variant == 8 ? [] : [grant];
        return new(operation, principal.Id, Generation, Generation, AuthorizationCapability.ReadEncryptedSecret, scope,
            PolicyGeneration, variant == 7 ? new(3) : PolicyGeneration, RevocationGeneration, evidenceSet, grants,
            variant == 1 ? EvidenceStatus.Missing : EvidenceStatus.Valid);
    }

    internal static AuthorizationRequest ConflictingAuthorization(ulong seed, bool reverse)
    {
        var request = Authorization(0, seed); var exact = request.PrincipalEvidence[0];
        var conflict = new PrincipalAuthorizationEvidence(new(request.PrincipalId, SecurityPrincipalKind.Node, SecurityRole.TerraBase, Cell, Generation),
            RevocationGeneration, RevocationStatus.Current, EvidenceStatus.Valid);
        return new(request.OperationId, request.PrincipalId, request.ExpectedPrincipalGeneration, request.CurrentPrincipalGeneration, request.Capability,
            request.ResourceScope, request.PolicyGeneration, request.CurrentPolicyGeneration, request.CurrentRevocationGeneration,
            reverse ? [conflict, exact] : [exact, conflict], request.Grants, request.EvidenceCompleteness);
    }

    internal static SecretLeaseRequest Lease(int variant, ulong seed)
    {
        var action = variant switch { 1 or 9 or 10 => LeaseAction.Renew, 2 => LeaseAction.Revoke, _ => LeaseAction.Grant };
        var operation = Operation("lease", seed); var principal = Principal(seed);
        var evidence = new PrincipalAuthorizationEvidence(principal, variant == 7 ? new(2) : RevocationGeneration,
            variant == 7 ? RevocationStatus.Revoked : RevocationStatus.Current, EvidenceStatus.Valid);
        var secret = new EncryptedSecretMetadata(new($"secret-{seed}"), new(variant == 4 ? 3UL : 2UL), Cell,
            SecurityEnvironment.Production, SecretPurpose.Database, new($"wrap-{seed}"), Digest("ciphertext", seed),
            variant == 3 ? SecretAvailability.Missing : SecretAvailability.Available);
        var policy = new SecretRetentionPolicy(PolicyGeneration, secret.SecretId, Cell, SecurityEnvironment.Production, SecretPurpose.Database,
            [new(1), new(2)], new(300), variant == 4 ? EvidenceStatus.Stale : EvidenceStatus.Valid);
        var capability = action switch { LeaseAction.Grant => AuthorizationCapability.GrantSecretLease, LeaseAction.Renew => AuthorizationCapability.RenewOwnLease, _ => AuthorizationCapability.RevokeLease };
        var scope = new SecurityResourceScope(SecurityResourceKind.SecretLease, Cell, SecurityEnvironment.Production, SecretPurpose.Database);
        var grant = new AuthorizationGrant(PolicyGeneration, principal.Kind, principal.Role, capability, scope);
        SecretLeaseEvidence? existing = action == LeaseAction.Grant ? null : new(new($"lease-{seed}"),
            variant == 9 ? new("other-principal") : principal.Id, secret.SecretId, secret.Version, Cell, secret.Environment, secret.Purpose,
            secret.WrappingKeyId, secret.CiphertextDigest, new(1), PolicyGeneration, LeaseStatus.Active,
            variant == 10 ? ValidityStatus.Expired : ValidityStatus.RenewalDue);
        var requestedGeneration = action switch { LeaseAction.Grant => new SecurityGeneration(variant == 11 ? 2UL : 1UL), LeaseAction.Renew => new(2), _ => new(1) };
        return new(action, operation, new($"lease-{seed}"), evidence, Generation, variant == 6 ? new(6) : Generation,
            secret, policy, variant == 5 ? new(3) : PolicyGeneration, variant == 8 ? [] : [grant], requestedGeneration,
            new(variant == 5 ? 301UL : 100UL), RevocationGeneration, existing);
    }

    internal static SurvivalSecretRequest Survival(int variant, ulong seed, bool reverse = false)
    {
        var operation = Operation("survival", seed); var first = SurvivalTuple(seed, "database", SecretPurpose.Database);
        var second = SurvivalTuple(seed, "messaging", SecretPurpose.Messaging);
        var references = new List<SurvivalSecretReference> { first.Reference, second.Reference };
        var metadata = new List<EncryptedSecretMetadata> { first.Metadata, second.Metadata };
        var policies = new List<SecretRetentionPolicy> { first.Policy, second.Policy };
        switch (variant)
        {
            case 1: references.Add(first.Reference); break;
            case 2: metadata.Add(first.Metadata); break;
            case 3: policies.Add(first.Policy); break;
            case 4: references[0] = new(first.Reference.SecretId, first.Reference.Version, new("sfo"), first.Reference.Environment, first.Reference.Purpose, first.Reference.CiphertextDigest); break;
            case 5: references[0] = new(first.Reference.SecretId, first.Reference.Version, Cell, first.Reference.Environment, first.Reference.Purpose, Digest("wrong", seed)); break;
            case 6: metadata[0] = new(first.Metadata.SecretId, first.Metadata.Version, Cell, first.Metadata.Environment, first.Metadata.Purpose, first.Metadata.WrappingKeyId, first.Metadata.CiphertextDigest, SecretAvailability.Missing); break;
            case 7: policies[0] = new(new(1), first.Policy.SecretId, Cell, first.Policy.Environment, first.Policy.Purpose, first.Policy.RetainedVersions, first.Policy.MaximumLeaseDuration, first.Policy.ExpiryEvidence); break;
            case 8: policies[0] = new(PolicyGeneration, first.Policy.SecretId, Cell, first.Policy.Environment, first.Policy.Purpose, [new(1)], first.Policy.MaximumLeaseDuration, first.Policy.ExpiryEvidence); break;
            case 9: policies[0] = new(PolicyGeneration, first.Policy.SecretId, Cell, first.Policy.Environment, first.Policy.Purpose, first.Policy.RetainedVersions, first.Policy.MaximumLeaseDuration, EvidenceStatus.Stale); break;
            case 10: metadata.RemoveAt(0); break;
        }
        if (reverse) { references.Reverse(); metadata.Reverse(); policies.Reverse(); }
        var bundleGeneration = new SecurityGeneration(seed + 1);
        var currentAcceptedBundleGeneration = new SecurityGeneration(variant == 11 ? seed + 2 : seed + 1);
        return new(operation, Cell, bundleGeneration, currentAcceptedBundleGeneration, PolicyGeneration, references, metadata, policies);
    }

    internal static string InputFingerprint(string kind, int variant, ulong seed) => kind switch
    {
        "enrollment" => EnrollmentFingerprint(Enrollment(variant, seed)),
        "certificate" => CertificateFingerprint(Certificate(variant, seed)),
        "authorization" => AuthorizationFingerprint(Authorization(variant, seed)),
        "lease" => LeaseFingerprint(Lease(variant, seed)),
        "survival" => SurvivalFingerprint(Survival(variant, seed)),
        _ => throw new InvalidDataException("Unknown security replay family."),
    };

    internal static SecurityDecision Decide(string kind, int variant, ulong seed) => kind switch
    {
        "enrollment" => SecurityDecisionEngine.EvaluateEnrollment(Enrollment(variant, seed)),
        "certificate" => SecurityDecisionEngine.EvaluateCertificate(Certificate(variant, seed)),
        "authorization" => SecurityDecisionEngine.Authorize(Authorization(variant, seed)),
        "lease" => SecurityDecisionEngine.EvaluateLease(Lease(variant, seed)),
        "survival" => SecurityDecisionEngine.EvaluateSurvivalSecrets(Survival(variant, seed)),
        _ => throw new InvalidDataException("Unknown security replay family."),
    };

    internal static string OutputFingerprint(SecurityDecision value) =>
        $"authorized={value.Authorized}|intent={value.Intent.GetType().Name}|subject={SubjectFingerprint(value.Intent)}|trace=" +
        string.Join(';', value.Trace.Select(x => $"{x.Code}:{x.Outcome}:{x.Observed}:{x.Required}"));

    private static string EnrollmentFingerprint(EnrollmentRequest value) =>
        $"op={value.OperationId.Value}|principal={PrincipalFingerprint(value.ExpectedPrincipal)}|key={value.SubjectKeyId.Value}|att-policy={value.AttestationPolicyGeneration.Value}|issuer={IssuerFingerprint(value.Issuer)}|current-issuer={value.CurrentIssuerGeneration.Value}|current-revocation={value.CurrentRevocationGeneration.Value}|bootstrap=" +
        string.Join(';', value.BootstrapEvidence.Select(x => $"{x.Id.Value},{x.OperationId.Value},{x.PrincipalId.Value},{x.Audience},{x.CellId.Value},{x.Role},{x.NodeGeneration.Value},{x.Status}")) + "|attestations=" +
        string.Join(';', value.Attestations.Select(x => $"{x.Id.Value},{x.Measurement.Sha256},{x.PrincipalId.Value},{x.SubjectKeyId.Value},{x.Kind},{x.CellId.Value},{x.Role},{x.Generation.Value},{x.PolicyGeneration.Value},{x.Status}"));

    private static string CertificateFingerprint(CertificateLifecycleRequest value) =>
        $"action={value.Action}|op={value.OperationId.Value}|principal={PrincipalFingerprint(value.Principal)}|current-principal={value.CurrentPrincipalGeneration.Value}|key={value.SubjectKeyId.Value}|usage={value.Usage}|scope={value.RequestedScope}|requested-generation={value.RequestedGeneration.Value}|issuer={IssuerFingerprint(value.Issuer)}|current-issuer={value.CurrentIssuerGeneration.Value}|policy={value.Policy.Generation.Value},{value.Policy.Lifetime.Value},{value.Policy.RenewalWindow.Value},{value.Policy.Overlap.Value},{string.Join(',', value.Policy.Usages)},{value.Policy.Scope}|validity={ValidityFingerprint(value.ValidityEvidence)}|current-revocation={value.CurrentRevocationGeneration.Value}|compromise={value.CompromiseEvidence.CertificateId.Value},{value.CompromiseEvidence.PrincipalId.Value},{value.CompromiseEvidence.CellId.Value},{value.CompromiseEvidence.CertificateGeneration.Value},{value.CompromiseEvidence.RevocationGeneration.Value},{value.CompromiseEvidence.Status}";

    private static string AuthorizationFingerprint(AuthorizationRequest value) =>
        $"op={value.OperationId.Value}|principal={value.PrincipalId.Value}|expected-generation={value.ExpectedPrincipalGeneration.Value}|current-generation={value.CurrentPrincipalGeneration.Value}|capability={value.Capability}|scope={ScopeFingerprint(value.ResourceScope)}|policy={value.PolicyGeneration.Value}|current-policy={value.CurrentPolicyGeneration.Value}|current-revocation={value.CurrentRevocationGeneration.Value}|complete={value.EvidenceCompleteness}|evidence=" +
        string.Join(';', value.PrincipalEvidence.Select(x => $"{PrincipalFingerprint(x.Principal)},{x.RevocationGeneration.Value},{x.Revocation},{x.Status}")) + "|grants=" +
        string.Join(';', value.Grants.Select(GrantFingerprint));

    private static string LeaseFingerprint(SecretLeaseRequest value) =>
        $"action={value.Action}|op={value.OperationId.Value}|lease={value.RequestedLeaseId.Value}|principal-evidence={PrincipalFingerprint(value.PrincipalEvidence.Principal)},{value.PrincipalEvidence.RevocationGeneration.Value},{value.PrincipalEvidence.Revocation},{value.PrincipalEvidence.Status}|expected-generation={value.ExpectedPrincipalGeneration.Value}|current-generation={value.CurrentPrincipalGeneration.Value}|secret={MetadataFingerprint(value.Secret)}|policy={PolicyFingerprint(value.Policy)}|current-policy={value.CurrentPolicyGeneration.Value}|grants={string.Join(';', value.Grants.Select(GrantFingerprint))}|requested-generation={value.RequestedLeaseGeneration.Value}|duration={value.RequestedDuration.Value}|current-revocation={value.CurrentRevocationGeneration.Value}|existing={(value.ExistingLease is null ? "none" : LeaseEvidenceFingerprint(value.ExistingLease))}";

    private static string SurvivalFingerprint(SurvivalSecretRequest value) =>
        $"op={value.OperationId.Value}|cell={value.CellId.Value}|bundle={value.BundleGeneration.Value}|current-bundle={value.CurrentAcceptedBundleGeneration.Value}|current-policy={value.CurrentPolicyGeneration.Value}|references=" +
        string.Join(';', value.References.Select(x => $"{x.SecretId.Value},{x.Version.Value},{x.CellId.Value},{x.Environment},{x.Purpose},{x.CiphertextDigest.Sha256}")) + "|metadata=" +
        string.Join(';', value.AvailableVersions.Select(MetadataFingerprint)) + "|policies=" + string.Join(';', value.Policies.Select(PolicyFingerprint));

    private static string SubjectFingerprint(SecurityIntent value) => value switch
    {
        AttestIdentityIntent x => $"{x.OperationId.Value},{x.AttestationId.Value}",
        IssueIdentityIntent x => $"{x.OperationId.Value},{x.Principal.Id.Value},{x.Issuer.IssuerId.Value}",
        IssueCertificateIntent x => CertificateSubject(x.Request), RenewCertificateIntent x => CertificateSubject(x.Request),
        RotateCertificateIntent x => CertificateSubject(x.Request), RevokeCertificateIntent x => CertificateSubject(x.Request),
        AuthorizeCapabilityIntent x => $"{x.OperationId.Value},{x.PrincipalId.Value},{x.Capability},{ScopeFingerprint(x.ResourceScope)}",
        GrantSecretLeaseIntent x => LeaseSubject(x.Request), RenewSecretLeaseIntent x => LeaseSubject(x.Request), RevokeSecretLeaseIntent x => LeaseSubject(x.Request),
        AcceptSurvivalSecretReferencesIntent x => $"{x.OperationId.Value},{x.Request.CellId.Value},{x.Request.BundleGeneration.Value},{string.Join(',', x.Request.References.Select(r => $"{r.SecretId.Value}:{r.Version.Value}"))}",
        HoldSecurityOperationIntent x => x.OperationId.Value,
        _ => throw new InvalidDataException("Unknown security intent subject."),
    };
    private static string CertificateSubject(CertificateLifecycleRequest x) => $"{x.OperationId.Value},{x.Action},{x.Principal.Id.Value},{x.SubjectKeyId.Value},{x.ValidityEvidence.CertificateId.Value},{x.RequestedGeneration.Value}";
    private static string LeaseSubject(SecretLeaseRequest x) => $"{x.OperationId.Value},{x.Action},{x.RequestedLeaseId.Value},{x.PrincipalEvidence.Principal.Id.Value},{x.Secret.SecretId.Value},{x.Secret.Version.Value},{x.RequestedLeaseGeneration.Value}";
    private static string PrincipalFingerprint(SecurityPrincipal x) => $"{x.Id.Value},{x.Kind},{x.Role},{x.CellId.Value},{x.Generation.Value}";
    private static string IssuerFingerprint(IssuerSigningCapability x) => $"{x.IssuerId.Value},{x.Kind},{x.CellId.Value},{x.Scope},{x.Generation.Value},{x.RevocationGeneration.Value}";
    private static string ScopeFingerprint(SecurityResourceScope x) => $"{x.Kind},{x.CellId.Value},{x.Environment},{x.Purpose}";
    private static string GrantFingerprint(AuthorizationGrant x) => $"{x.PolicyGeneration.Value},{x.PrincipalKind},{x.Role},{x.Capability},{ScopeFingerprint(x.ResourceScope)}";
    private static string MetadataFingerprint(EncryptedSecretMetadata x) => $"{x.SecretId.Value},{x.Version.Value},{x.CellId.Value},{x.Environment},{x.Purpose},{x.WrappingKeyId.Value},{x.CiphertextDigest.Sha256},{x.Availability}";
    private static string PolicyFingerprint(SecretRetentionPolicy x) => $"{x.Generation.Value},{x.SecretId.Value},{x.CellId.Value},{x.Environment},{x.Purpose},{string.Join(',', x.RetainedVersions.Select(v => v.Value))},{x.MaximumLeaseDuration.Value},{x.ExpiryEvidence}";
    private static string ValidityFingerprint(CertificateValidityEvidence x) => $"{x.CertificateId.Value},{x.OperationId.Value},{x.PrincipalId.Value},{x.CellId.Value},{x.SubjectKeyId.Value},{x.Usage},{x.Scope},{x.IssuerId.Value},{x.IssuerGeneration.Value},{x.CertificateGeneration.Value},{x.PolicyGeneration.Value},{x.RevocationGeneration.Value},{x.Validity},{x.Revocation}";
    private static string LeaseEvidenceFingerprint(SecretLeaseEvidence x) => $"{x.LeaseId.Value},{x.PrincipalId.Value},{x.SecretId.Value},{x.Version.Value},{x.CellId.Value},{x.Environment},{x.Purpose},{x.WrappingKeyId.Value},{x.CiphertextDigest.Sha256},{x.Generation.Value},{x.PolicyGeneration.Value},{x.Status},{x.Validity}";

    private static (SurvivalSecretReference Reference, EncryptedSecretMetadata Metadata, SecretRetentionPolicy Policy) SurvivalTuple(ulong seed, string suffix, SecretPurpose purpose)
    {
        var id = new SecuritySecretId($"{suffix}-{seed}"); var version = new SecretVersion(2); var digest = Digest(suffix, seed);
        return (new(id, version, Cell, SecurityEnvironment.Recovery, purpose, digest),
            new(id, version, Cell, SecurityEnvironment.Recovery, purpose, new($"wrap-{suffix}-{seed}"), digest, SecretAvailability.Available),
            new(PolicyGeneration, id, Cell, SecurityEnvironment.Recovery, purpose, [new(1), version], new(300), EvidenceStatus.Valid));
    }

    private static SecurityOperationId Operation(string family, ulong seed) => new($"security-{family}-{seed}");
    private static SecurityPrincipal Principal(ulong seed, SecurityCellId? cell = null) => new(new($"principal-{seed}"), SecurityPrincipalKind.Node, SecurityRole.Agent, cell ?? Cell, Generation);
    private static IssuerSigningCapability Issuer(SecurityGeneration? revocation = null) => new(new("issuer-gru"), IssuerCapabilityKind.RegionalIntermediate, Cell, TrustScope.Cell, IssuerGeneration, revocation ?? RevocationGeneration);
    private static SecurityDigest Digest(string family, ulong seed) => new(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{family}:{seed}"))));
}

internal sealed record SecurityPolicyReplayEntry(string Id, ulong Seed, string Kind, int Variant, string Input, string Output);

internal static class SecurityPolicyReplayCorpus
{
    private const string Resource = "TerraScale.Orchestrator.ControlPlane.Tests.Properties.SecurityPolicyReplayCorpus.v1.json";
    private const string Digest = "6cf537ab07c9cd85f7c8cede406dab5be67f27ccb220efc9058e25b2e8c8b8fd";
    private const int MaximumBytes = 32768;
    private static readonly IReadOnlyDictionary<string, int> MaximumVariants = new Dictionary<string, int>(StringComparer.Ordinal)
    { ["enrollment"] = 15, ["certificate"] = 15, ["authorization"] = 9, ["lease"] = 11, ["survival"] = 11 };

    internal static IReadOnlyList<SecurityPolicyReplayEntry> Load()
    {
        using var stream = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream(Resource) ?? throw new InvalidDataException("Replay corpus missing.");
        return Parse(ReadBounded(stream), true);
    }

    internal static byte[] ReadBounded(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream); using var memory = new MemoryStream(); var buffer = new byte[1024]; var total = 0;
        while (true) { var read = stream.Read(buffer, 0, buffer.Length); if (read == 0) break; total = checked(total + read); if (total > MaximumBytes) throw new InvalidDataException("Replay corpus exceeds byte limit."); memory.Write(buffer, 0, read); }
        return memory.ToArray();
    }

    internal static IReadOnlyList<SecurityPolicyReplayEntry> Parse(byte[] bytes, bool enforceDigest)
    {
        if (bytes.Length > MaximumBytes) throw new InvalidDataException("Replay corpus exceeds byte limit.");
        if (enforceDigest && !StringComparer.Ordinal.Equals(Convert.ToHexStringLower(SHA256.HashData(bytes)), Digest)) throw new InvalidDataException("Replay corpus digest mismatch.");
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 4 });
        var root = document.RootElement; Exact(root, "schema", "entries");
        if (root.GetProperty("schema").ValueKind != JsonValueKind.String || root.GetProperty("schema").GetString() != "terrascale.security-policy-replay.v1" || root.GetProperty("entries").ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Replay schema mismatch.");
        var result = new List<SecurityPolicyReplayEntry>();
        foreach (var item in root.GetProperty("entries").EnumerateArray())
        {
            if (result.Count == 64) throw new InvalidDataException("Too many replay entries."); Exact(item, "id", "seed", "kind", "variant", "input", "output");
            result.Add(new(item.GetProperty("id").GetString()!, item.GetProperty("seed").GetUInt64(), item.GetProperty("kind").GetString()!, item.GetProperty("variant").GetInt32(), item.GetProperty("input").GetString()!, item.GetProperty("output").GetString()!));
        }
        if (result.Count == 0 || result.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count() != result.Count ||
            result.Select(x => (x.Kind, x.Seed, x.Variant)).Distinct().Count() != result.Count ||
            result.Any(x => x.Seed == 0 || !CanonicalId(x.Id) || !MaximumVariants.TryGetValue(x.Kind, out var maximum) || x.Variant < 0 || x.Variant > maximum ||
                string.IsNullOrEmpty(x.Input) || string.IsNullOrEmpty(x.Output) ||
                x.Input != SecurityCompletenessData.InputFingerprint(x.Kind, x.Variant, x.Seed) ||
                x.Output != SecurityCompletenessData.OutputFingerprint(SecurityCompletenessData.Decide(x.Kind, x.Variant, x.Seed))))
            throw new InvalidDataException("Replay corpus identity or vocabulary constraints failed.");
        return result.AsReadOnly();
    }

    private static bool CanonicalId(string value) => value.Length is >= 1 and <= 64 && value[0] != '-' && value[^1] != '-' &&
        !value.Contains("--", StringComparison.Ordinal) && value.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

    private static void Exact(JsonElement element, params string[] expected)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Replay object expected.");
        var actual = element.EnumerateObject().Select(x => x.Name).Order(StringComparer.Ordinal).ToArray();
        if (!actual.SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal)) throw new InvalidDataException("Replay shape mismatch.");
    }
}
