using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Networking;
using TerraScale.Orchestrator.ControlPlane.Security;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class IdentityNetworkPropertyTests
{
    private const int Cases = 1000;

    [Test]
    public async Task Enrollment_and_trust_generation_follow_independent_closed_oracle_for_1000_cases()
    {
        var identities = new HashSet<string>(StringComparer.Ordinal); var executed = 0; for (var seed = 0; seed < Cases; seed++)
        {
            var variant = seed % 6;
            var request = SecurityData.Enrollment(variant, (ulong)seed + 1); identities.Add(request.ExpectedPrincipal.Id.Value);
            var decision = SecurityDecisionEngine.EvaluateEnrollment(request);
            var expected = variant == 0 ? "IssueIdentityIntent" : "HoldSecurityOperationIntent";
            Require(decision.Intent.GetType().Name == expected && decision.Authorized == (variant == 0), seed, "enrollment");
            if (variant > 0) Require(Outcome(decision, new[] { SecurityDecisionCode.AttestationCurrent, SecurityDecisionCode.BootstrapUnused,
                SecurityDecisionCode.GenerationCurrent, SecurityDecisionCode.CellMatches, SecurityDecisionCode.RoleMatches }[variant - 1]) is SecurityDecisionOutcome.Rejected, seed, "enrollment reason");
            Require(Serialize(decision) == Serialize(SecurityDecisionEngine.EvaluateEnrollment(SecurityData.Enrollment(variant, (ulong)seed + 1))), seed, "enrollment replay");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
        await Assert.That(identities.Count).IsEqualTo(1000);
    }

    [Test]
    public async Task Certificate_rotation_and_revocation_follow_independent_action_oracle_for_1000_cases()
    {
        var names = new[] { "IssueCertificateIntent", "RenewCertificateIntent", "RotateCertificateIntent", "RevokeCertificateIntent" };
        var executed = 0; for (var seed = 0; seed < Cases; seed++)
        {
            var variant = seed % 5;
            var decision = SecurityDecisionEngine.EvaluateCertificate(SecurityData.Certificate(variant, (ulong)seed + 1));
            var expected = variant < 4 ? names[variant] : "HoldSecurityOperationIntent";
            Require(decision.Intent.GetType().Name == expected && decision.Authorized == (variant < 4), seed, "certificate");
            if (variant == 4) Require(Outcome(decision, SecurityDecisionCode.RevocationCurrent) == SecurityDecisionOutcome.Rejected, seed, "certificate reason");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Vault_authorization_fencing_and_secret_versions_follow_independent_oracle_for_1000_cases()
    {
        var executed = 0; for (var seed = 0; seed < Cases; seed++)
        {
            var variant = seed % 6;
            var authorization = SecurityDecisionEngine.Authorize(SecurityData.Authorization(variant, (ulong)seed + 1));
            Require(authorization.Authorized == (variant == 0), seed, "authorization");
            if (variant > 0) Require(Outcome(authorization, new[] { SecurityDecisionCode.RevocationCurrent, SecurityDecisionCode.RevocationCurrent,
                SecurityDecisionCode.PrincipalMatches, SecurityDecisionCode.PolicyCurrent, SecurityDecisionCode.ExactGrantPresent }[variant - 1]) is SecurityDecisionOutcome.Rejected, seed, "authorization reason");
            var lease = SecurityDecisionEngine.EvaluateLease(SecurityData.Lease(variant, (ulong)seed + 1));
            Require(lease.Authorized == (variant == 0), seed, "lease");
            if (variant > 0) Require(Outcome(lease, new[] { SecurityDecisionCode.SecretAvailable, SecurityDecisionCode.SecretVersionRetained,
                SecurityDecisionCode.SecretVersionRetained, SecurityDecisionCode.GenerationCurrent, SecurityDecisionCode.ExactGrantPresent }[variant - 1]) is SecurityDecisionOutcome.Rejected or SecurityDecisionOutcome.Held, seed, "lease reason");
            Require(!Serialize(lease).Contains("database-password", StringComparison.Ordinal), seed, "secret nonleakage");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Routes_peers_and_generation_follow_independent_stage_oracle_for_1000_cases()
    {
        var expected = new[] { NetworkAction.ConfigureTunnel, NetworkAction.Observe, NetworkAction.ConfigureRoute, NetworkAction.Verify, NetworkAction.Hold,
            NetworkAction.Hold, NetworkAction.Hold, NetworkAction.Rollback };
        var executed = 0; for (var seed = 0; seed < Cases; seed++)
        {
            var variant = seed % expected.Length;
            var actual = Route(variant, (ulong)seed + 1);
            Require(actual.Action == expected[variant], seed, "route");
            Require(actual.Code == new[] { NetworkCode.NextStep, NetworkCode.TunnelHealthRequired, NetworkCode.NextStep, NetworkCode.Completed,
                NetworkCode.StaleGeneration, NetworkCode.Duplicate, NetworkCode.RouteLeak, NetworkCode.TunnelHealthRequired }[variant], seed, "route code");
            Require(actual == Route(variant, (ulong)seed + 1), seed, "route replay");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Ingress_authorization_and_generation_follow_independent_stage_oracle_for_1000_cases()
    {
        var expected = new[] { NetworkAction.Register, NetworkAction.Promote, NetworkAction.DnsUpdate, NetworkAction.Observe, NetworkAction.Verify,
            NetworkAction.Hold, NetworkAction.Hold, NetworkAction.Hold };
        var executed = 0; for (var seed = 0; seed < Cases; seed++)
        {
            var variant = seed % expected.Length;
            var actual = Ingress(variant, (ulong)seed + 1); Require(actual.Action == expected[variant], seed, "ingress");
            Require(actual.Code == new[] { NetworkCode.NextStep, NetworkCode.NextStep, NetworkCode.NextStep, NetworkCode.DnsConvergencePending,
                NetworkCode.Completed, NetworkCode.DefaultDeny, NetworkCode.StaleGeneration, NetworkCode.ForbiddenExposure }[variant], seed, "ingress code");
            executed++;
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Decisions_are_culture_permutation_and_replay_deterministic_for_1000_cases()
    {
        var cultures = new[] { "en-US", "tr-TR", "ar-SA", "ja-JP" };
        var executed = 0; for (var seed = 0; seed < Cases; seed++)
        {
            var previous = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultures[seed % cultures.Length]);
                var forward = SecurityDecisionEngine.Authorize(SecurityData.ConflictingAuthorization(false));
                var reverse = SecurityDecisionEngine.Authorize(SecurityData.ConflictingAuthorization(true));
                Require(Serialize(forward) == Serialize(reverse), seed, "permutation");
                Require(Route(seed % 4, (ulong)seed + 1) == Route(seed % 4, (ulong)seed + 1), seed, "culture replay");
                executed++;
            }
            finally { CultureInfo.CurrentCulture = previous; }
        }
        await Assert.That(executed).IsEqualTo(1000);
    }

    [Test]
    public async Task Accepted_outputs_are_construction_closed_and_replay_corpus_is_whole_file_pinned()
    {
        await Assert.That(typeof(SecurityDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length).IsEqualTo(0);
        await Assert.That(typeof(NetworkDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length).IsEqualTo(0);
        await Assert.That(typeof(SecurityIntent).Assembly.GetTypes().Where(t => typeof(SecurityIntent).IsAssignableFrom(t))
            .SelectMany(t => t.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).Count()).IsEqualTo(0);
        await Assert.That(typeof(SecurityDecision).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Count(method => method.ReturnType == typeof(SecurityDecision) && !method.IsSpecialName)).IsEqualTo(0);
        await Assert.That(typeof(NetworkDecision).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Count(method => method.ReturnType == typeof(NetworkDecision) && !method.IsSpecialName)).IsEqualTo(0);
        await Assert.That(typeof(NetworkIntentSubject).Assembly.GetTypes().Where(t => typeof(NetworkIntentSubject).IsAssignableFrom(t))
            .SelectMany(t => t.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).Count()).IsEqualTo(0);

        var entries = IdentityNetworkReplayCorpus.Load();
        foreach (var entry in entries)
        {
            var actual = entry.Kind switch
            {
                "enrollment" => SecurityDecisionEngine.EvaluateEnrollment(SecurityData.Enrollment(entry.Variant, entry.Seed)).Intent.GetType().Name,
                "certificate" => SecurityDecisionEngine.EvaluateCertificate(SecurityData.Certificate(entry.Variant + 1, entry.Seed)).Intent.GetType().Name,
                "authorization" => SecurityDecisionEngine.Authorize(SecurityData.Authorization(entry.Variant, entry.Seed)).Intent.GetType().Name,
                "lease" => SecurityDecisionEngine.EvaluateLease(SecurityData.Lease(entry.Variant, entry.Seed)).Intent.GetType().Name,
                "route" => Route(entry.Variant, entry.Seed).Action.ToString(),
                "ingress" => Ingress(entry.Variant, entry.Seed).Action.ToString(),
                "public-http" => NetworkingPolicyCompletenessPropertyTests.ReplayPublicHttp(entry.Seed),
                "route-permutation" => NetworkingPolicyCompletenessPropertyTests.ReplayRoutePermutation(entry.Seed),
                "route-provenance" => NetworkingPolicyCompletenessPropertyTests.ReplayRouteProvenance(entry.Seed),
                "endpoint-plan-provenance" => NetworkingPolicyCompletenessPropertyTests.ReplayEndpointPlanProvenance(entry.Seed),
                _ => throw new InvalidDataException("Unknown replay kind."),
            };
            Require(actual == entry.Expected, checked((int)entry.Seed), entry.Id);
        }
        await Assert.That(entries.Count).IsEqualTo(25);
    }

    [Test]
    public async Task Replay_reader_and_parser_reject_every_bounded_shape_and_vocabulary_violation()
    {
        await Assert.That(IdentityNetworkReplayCorpus.ReadBounded(new MemoryStream(new byte[8192])).Length).IsEqualTo(8192);
        await Assert.That(Fails(() => IdentityNetworkReplayCorpus.ReadBounded(new MemoryStream(new byte[8193])))).IsTrue();
        var invalid = new[]
        {
            "{}", "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[],\"extra\":1}",
            "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[{\"id\":\"x\",\"id\":\"y\",\"seed\":1,\"kind\":\"route\",\"variant\":0,\"expected\":\"ConfigureTunnel\"}]}",
            "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":0,\"kind\":\"route\",\"variant\":0,\"expected\":\"ConfigureTunnel\"}]}",
            "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":-1,\"kind\":\"route\",\"variant\":0,\"expected\":\"ConfigureTunnel\"}]}",
            "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":18446744073709551616,\"kind\":\"route\",\"variant\":0,\"expected\":\"ConfigureTunnel\"}]}",
            "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":\"1\",\"kind\":\"route\",\"variant\":0,\"expected\":\"ConfigureTunnel\"}]}",
            "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"kind\":\"route\",\"variant\":0,\"expected\":\"ConfigureTunnel\"},{\"id\":\"x\",\"seed\":2,\"kind\":\"route\",\"variant\":0,\"expected\":\"ConfigureTunnel\"}]}",
            "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"kind\":\"route\",\"variant\":0,\"expected\":\"ConfigureTunnel\"},{\"id\":\"y\",\"seed\":1,\"kind\":\"route\",\"variant\":0,\"expected\":\"ConfigureTunnel\"}]}",
            "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"kind\":\"unknown\",\"variant\":0,\"expected\":\"ConfigureTunnel\"}]}",
            "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"kind\":\"route\",\"variant\":99,\"expected\":\"ConfigureTunnel\"}]}",
            "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[{\"id\":\"x\",\"seed\":1,\"kind\":\"route\",\"variant\":0,\"expected\":\"Verify\"}]}",
            "{/*comment*/\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[]}",
            "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[],}",
            "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[]} trailing",
            "{\"schema\":\"terrascale.identity-network-replay.v1\",\"entries\":[[[[[1]]]]]}",
        };
        foreach (var json in invalid) await Assert.That(Fails(() => IdentityNetworkReplayCorpus.Parse(Encoding.UTF8.GetBytes(json), false))).IsTrue();
    }

    private static NetworkDecision Route(int variant, ulong seed)
    {
        var scope = NetworkingTestData.RouteScope(NetworkingTestData.Prefix(10, (byte)(seed % 251), bits: 16));
        if (variant == 4) return NetworkRoutePlanner.Plan(scope, NetworkingTestData.O(6), scope.Epoch, NetworkingTestData.RouteEvidence(scope));
        if (variant == 5)
        {
            var duplicate = new NetworkRouteObservation(NetworkingTestData.Route(), NetworkingTestData.Cell(), NetworkingTestData.Peer(), null,
                NetworkTrustPlane.Product, NetworkingTestData.Prefix(10));
            return NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, NetworkingTestData.RouteEvidence(scope, [duplicate, duplicate]));
        }
        if (variant == 6) return NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch,
            NetworkingTestData.RouteEvidence(scope, approved: [NetworkingTestData.Prefix(11)]));
        return NetworkRoutePlanner.Plan(scope, scope.Generation, scope.Epoch, NetworkingTestData.RouteEvidence(scope,
            configured: variant == 0 ? NetworkProof.Unknown : NetworkProof.Proven,
            traffic: variant is 0 or 1 ? NetworkProof.Unknown : variant == 7 ? NetworkProof.Contradicted : NetworkProof.Proven,
            healthy: variant == 0 ? NetworkProof.Unknown : NetworkProof.Proven,
            routeConfigured: variant < 3 ? NetworkProof.Unknown : NetworkProof.Proven));
    }

    private static NetworkDecision Ingress(int variant, ulong seed)
    {
        var generation = NetworkingTestData.O(9 + seed); var scope = variant == 7 ? NetworkingTestData.EndpointScope(kind: NetworkServiceKind.Administration, generation: generation) : NetworkingTestData.EndpointScope(generation: generation);
        var evidence = NetworkingTestData.EndpointEvidence(scope,
            admitted: variant == 5 ? NetworkProof.Unknown : NetworkProof.Proven,
            registered: variant == 0 ? NetworkProof.Unknown : NetworkProof.Proven,
            promoted: variant <= 1 ? NetworkProof.Unknown : NetworkProof.Proven,
            dnsRequested: variant <= 2 ? NetworkProof.Unknown : NetworkProof.Proven,
            dnsObserved: variant <= 3 ? NetworkProof.Unknown : NetworkProof.Proven);
        if (variant == 6) evidence = evidence with { ObservedGeneration = NetworkingTestData.O(generation.Value - 1) };
        return NetworkEndpointPlanner.PlanRegister(scope, evidence);
    }

    private static string Serialize(SecurityDecision decision) => $"{decision.Authorized}|{decision.Intent.GetType().Name}|" +
        string.Join(';', decision.Trace.Select(r => $"{r.Code}:{r.Outcome}:{r.Observed}:{r.Required}"));
    private static SecurityDecisionOutcome Outcome(SecurityDecision decision, SecurityDecisionCode code) => decision.Trace.Single(r => r.Code == code).Outcome;
    private static void Require(bool condition, int seed, string property) { if (!condition) throw new InvalidOperationException($"Property {property} failed at seed {seed}."); }
    private static bool Fails(Action action) { try { action(); return false; } catch (Exception) { return true; } }
}

internal static class SecurityData
{
    private static readonly SecurityCellId Cell = new("gru"); private static readonly SecurityGeneration Generation = new(5);
    private static readonly SecurityGeneration Revocation = new(3); private static readonly SecurityOperationId Operation = new("operation-1");
    private static SecurityDigest Digest() => new(new string('a', 64));
    private static SecurityPrincipal Principal(SecurityRole role = SecurityRole.Agent) => new(new("principal-1"), SecurityPrincipalKind.Node, role, Cell, Generation);
    private static IssuerSigningCapability Issuer() => new(new("issuer-gru"), IssuerCapabilityKind.RegionalIntermediate, Cell, TrustScope.Cell, new(1), Revocation);

    internal static EnrollmentRequest Enrollment(int variant, ulong seed)
    {
        var operation = new SecurityOperationId($"operation-{seed}");
        var principal = new SecurityPrincipal(new($"principal-{seed}"), SecurityPrincipalKind.Node, SecurityRole.Agent, Cell, Generation);
        var bootstrap = new BootstrapEnrollmentEvidence(new($"bootstrap-{seed}"), operation, principal.Id, principal.Kind, Cell, principal.Role,
            variant == 3 ? new(4) : Generation, variant == 2 ? EvidenceStatus.Consumed : EvidenceStatus.Valid);
        var attestation = new SecurityAttestationEvidence(new($"attestation-{seed}"), Digest(), principal.Id, new($"subject-key-{seed}"), principal.Kind,
            variant == 4 ? new("sfo") : Cell, variant == 5 ? SecurityRole.TerraBase : principal.Role, Generation, new(2),
            variant == 1 ? EvidenceStatus.Stale : EvidenceStatus.Valid);
        return new(operation, principal, principal.Generation, new($"subject-key-{seed}"), new(2), Issuer(), new(1), Revocation, [bootstrap], [attestation]);
    }

    internal static CertificateLifecycleRequest Certificate(int variant, ulong seed)
    {
        var operation = new SecurityOperationId($"operation-{seed}"); var principal = new SecurityPrincipal(new($"principal-{seed}"), SecurityPrincipalKind.Node, SecurityRole.Agent, Cell, Generation);
        var key = new SecurityKeyId($"subject-key-{seed}"); var certificate = new SecurityCertificateId($"certificate-{seed}");
        var action = variant < 4 ? (CertificateAction)(variant + 1) : CertificateAction.Renew;
        var requested = action is CertificateAction.Issue or CertificateAction.Revoke ? 4UL : 5UL;
        var policy = new CertificateLifecyclePolicy(new(2), new(900), new(300), new(100), [CertificateUsage.NodeTransport], TrustScope.Cell);
        var validity = new CertificateValidityEvidence(certificate, operation, principal.Id, Cell, key,
            CertificateUsage.NodeTransport, TrustScope.Cell, new("issuer-gru"), new(1), new(4), new(2),
            variant == 4 ? new(2) : Revocation, action == CertificateAction.Issue ? ValidityStatus.Valid : ValidityStatus.RenewalDue, RevocationStatus.Current);
        var compromise = new CertificateCompromiseEvidence(certificate, principal.Id, Cell, new(4), Revocation, EvidenceStatus.Valid);
        return new(action, operation, principal, Generation, key, CertificateUsage.NodeTransport, TrustScope.Cell,
            new(requested), Issuer(), new(1), policy, validity, Revocation, compromise);
    }

    internal static AuthorizationRequest Authorization(int variant, ulong seed)
    {
        var principal = new SecurityPrincipal(new($"principal-{seed}"), SecurityPrincipalKind.Node, SecurityRole.Agent, Cell, Generation);
        var scope = new SecurityResourceScope(SecurityResourceKind.EncryptedSecret, Cell, SecurityEnvironment.Production, SecretPurpose.Database);
        var evidence = new PrincipalAuthorizationEvidence(principal, variant == 2 ? new(2) : Revocation,
            variant == 1 ? RevocationStatus.Revoked : RevocationStatus.Current, variant == 3 ? EvidenceStatus.Stale : EvidenceStatus.Valid);
        var grant = new AuthorizationGrant(new(2), principal.Kind, principal.Role, AuthorizationCapability.ReadEncryptedSecret, scope);
        return new(new($"operation-{seed}"), principal.Id, Generation, Generation, AuthorizationCapability.ReadEncryptedSecret, scope, new(2),
            variant == 4 ? new(3) : new(2), Revocation, [evidence], variant == 5 ? [] : [grant], EvidenceStatus.Valid);
    }

    internal static AuthorizationRequest ConflictingAuthorization(bool reverse)
    {
        var exact = Authorization(0, 1); var conflict = new PrincipalAuthorizationEvidence(Principal(SecurityRole.TerraBase), Revocation, RevocationStatus.Current, EvidenceStatus.Valid);
        return new(exact.OperationId, exact.PrincipalId, exact.ExpectedPrincipalGeneration, exact.CurrentPrincipalGeneration, exact.Capability,
            exact.ResourceScope, exact.PolicyGeneration, exact.CurrentPolicyGeneration, exact.CurrentRevocationGeneration,
            reverse ? [conflict, exact.PrincipalEvidence[0]] : [exact.PrincipalEvidence[0], conflict], exact.Grants, exact.EvidenceCompleteness);
    }

    internal static SecretLeaseRequest Lease(int variant, ulong seed)
    {
        var principal = new SecurityPrincipal(new($"principal-{seed}"), SecurityPrincipalKind.Node, SecurityRole.Agent, Cell, Generation); var principalEvidence = new PrincipalAuthorizationEvidence(principal, Revocation, RevocationStatus.Current, EvidenceStatus.Valid);
        var secretId = new SecuritySecretId($"secret-{seed}"); var secret = new EncryptedSecretMetadata(secretId, new(variant == 2 ? 3UL : 2UL), Cell, SecurityEnvironment.Production,
            SecretPurpose.Database, new("wrapping-key-1"), Digest(), variant == 1 ? SecretAvailability.Missing : SecretAvailability.Available);
        var policy = new SecretRetentionPolicy(new(2), secretId, Cell, SecurityEnvironment.Production, SecretPurpose.Database,
            [new(1), new(2)], new(300), variant == 3 ? EvidenceStatus.Stale : EvidenceStatus.Valid);
        var scope = new SecurityResourceScope(SecurityResourceKind.SecretLease, Cell, SecurityEnvironment.Production, SecretPurpose.Database);
        var grant = new AuthorizationGrant(new(2), principal.Kind, principal.Role, AuthorizationCapability.GrantSecretLease, scope);
        return new(LeaseAction.Grant, new($"operation-{seed}"), new($"lease-{seed}"), principalEvidence, Generation, variant == 4 ? new(6) : Generation,
            secret, policy, new(2), variant == 5 ? [] : [grant], new(1), new(100), Revocation, null);
    }
}

internal sealed record IdentityNetworkReplayEntry(string Id, ulong Seed, string Kind, int Variant, string Expected);

internal static class IdentityNetworkReplayCorpus
{
    private const string Resource = "TerraScale.Orchestrator.ControlPlane.Tests.Properties.IdentityNetworkReplayCorpus.v1.json";
    private const string Digest = "82c63295cd856ab39e6281c790b8aee23fff078f0908c47e9cc88bb0638f6d20";
    private const int MaximumBytes = 8192;

    internal static IReadOnlyList<IdentityNetworkReplayEntry> Load()
    {
        using var stream = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream(Resource) ?? throw new InvalidDataException("Replay corpus missing.");
        return Parse(ReadBounded(stream), true);
    }

    internal static byte[] ReadBounded(Stream stream)
    {
        using var memory = new MemoryStream(); var buffer = new byte[1024]; var total = 0;
        while (true) { var read = stream.Read(buffer, 0, buffer.Length); if (read == 0) break; total = checked(total + read); if (total > MaximumBytes) throw new InvalidDataException("Replay corpus exceeds byte limit."); memory.Write(buffer, 0, read); }
        return memory.ToArray();
    }

    internal static IReadOnlyList<IdentityNetworkReplayEntry> Parse(byte[] bytes, bool enforceDigest)
    {
        if (bytes.Length > MaximumBytes) throw new InvalidDataException("Replay corpus exceeds byte limit.");
        var digest = Convert.ToHexStringLower(SHA256.HashData(bytes));
        if (enforceDigest && !StringComparer.Ordinal.Equals(digest, Digest)) throw new InvalidDataException("Replay corpus digest mismatch.");
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 4 });
        var root = document.RootElement; ExactProperties(root, "schema", "entries");
        if (root.GetProperty("schema").GetString() != "terrascale.identity-network-replay.v1") throw new InvalidDataException("Replay schema mismatch.");
        var result = new List<IdentityNetworkReplayEntry>();
        foreach (var item in root.GetProperty("entries").EnumerateArray())
        {
            if (result.Count == 64) throw new InvalidDataException("Too many replay entries.");
            ExactProperties(item, "id", "seed", "kind", "variant", "expected");
            result.Add(new(item.GetProperty("id").GetString()!, item.GetProperty("seed").GetUInt64(), item.GetProperty("kind").GetString()!,
                item.GetProperty("variant").GetInt32(), item.GetProperty("expected").GetString()!));
        }
        if (result.Count == 0 || result.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count() != result.Count ||
            result.Select(x => x.Seed).Distinct().Count() != result.Count || result.Any(x => x.Seed == 0 || x.Variant < 0 ||
                string.IsNullOrWhiteSpace(x.Id) || string.IsNullOrWhiteSpace(x.Expected) || !VocabularyValid(x)))
            throw new InvalidDataException("Replay corpus identity constraints failed.");
        return result.AsReadOnly();
    }

    private static bool VocabularyValid(IdentityNetworkReplayEntry entry) => (entry.Kind, entry.Variant, entry.Expected) switch
    {
        ("enrollment", 0, "IssueIdentityIntent") or ("enrollment", 1 or 2, "HoldSecurityOperationIntent") => true,
        ("certificate", 0, "RenewCertificateIntent") or ("certificate", 1, "RotateCertificateIntent") or ("certificate", 2, "RevokeCertificateIntent") => true,
        ("authorization", 0, "AuthorizeCapabilityIntent") or ("authorization", 1, "HoldSecurityOperationIntent") => true,
        ("lease", 0, "GrantSecretLeaseIntent") or ("lease", 1, "HoldSecurityOperationIntent") => true,
        ("route", 0, "ConfigureTunnel") or ("route", 1, "Observe") or ("route", 2, "ConfigureRoute") or ("route", 3, "Verify") or ("route", 4, "Hold") => true,
        ("ingress", 0, "Register") or ("ingress", 1, "Promote") or ("ingress", 2, "DnsUpdate") or ("ingress", 3, "Observe") or ("ingress", 4, "Verify") or ("ingress", 5, "Hold") => true,
        ("public-http", 0, "ForbiddenExposure") or ("route-permutation", 0, "WrongEvidenceScope") => true,
        ("route-provenance", 0, "Distinct") or ("endpoint-plan-provenance", 0, "Distinct") => true,
        _ => false,
    };

    private static void ExactProperties(JsonElement element, params string[] expected)
    {
        var actual = element.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal).ToArray();
        if (!actual.SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal)) throw new InvalidDataException("Replay corpus shape mismatch.");
    }
}
