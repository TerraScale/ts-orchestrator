using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class ProtocolNegotiationAuditRegressionTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task AcceptedCompatibilityOutputBindsOneThousandExactVersionWindowsAndCanonicalMatrices()
    {
        await Assert.That(Features()).Count().IsEqualTo(4);
        await Assert.That(Enum.GetValues<CompatibilityPair>()
            .Count(static pair => pair != CompatibilityPair.Unspecified)).IsEqualTo(3);
        var signatures = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < Cases; index++)
        {
            var current = index == Cases - 1 ? long.MaxValue : index + 2L;
            var previous = current - 1;
            var outcomes = CompleteOutcomes().ToArray();
            var offset = index % outcomes.Length;
            var permuted = outcomes.Skip(offset).Concat(outcomes.Take(offset)).Reverse().ToArray();
            var policy = new CompatibilityPolicy(current, previous, permuted);
            var decision = UnderCulture(index % 2 == 0 ? "tr-TR" : "ar-SA", () =>
                MessagingPolicyEngine.DecideCompatibility(
                    index % 2 == 0 ? Features() : Features().Reverse().ToArray(), policy));
            var replay = UnderCulture("ja-JP", () => MessagingPolicyEngine.DecideCompatibility(
                Features(), new CompatibilityPolicy(current, previous, outcomes)));
            permuted[0] = new CompatibilityOutcome(CompatibilityFeature.Unspecified,
                CompatibilityPair.Unspecified, Available: false);

            Require(decision.Errors.Count == 0, index, "accepted errors");
            Require(decision.Intents.Count == 0, index, "accepted intents");
            Require(decision.Trace is [{ Sequence: 1, Code: MessagingTraceCode.CompatibilityAccepted,
                Action: MessagingAction.Configure }], index, "accepted trace");
            var receipt = decision.Compatibility;
            Require(receipt is not null, index, "missing receipt");
            Require(receipt!.CurrentVersion == current && receipt.PreviousVersion == previous,
                index, "version scope");
            Require(receipt.Outcomes.Count == 12, index, "matrix count");
            for (var item = 0; item < receipt.Outcomes.Count; item++)
            {
                var expectedFeature = (CompatibilityFeature)(item / 3 + 1);
                var expectedPair = (CompatibilityPair)(item % 3 + 1);
                var actual = receipt.Outcomes[item];
                Require(actual == new CompatibilityOutcome(expectedFeature, expectedPair, Available: true),
                    index, $"canonical matrix {item}");
            }

            var signature = PublicOutputSignature(decision);
            Require(signature == PublicOutputSignature(replay), index, "culture/permutation replay");
            signatures.Add(signature);
        }

        await Assert.That(signatures.Count).IsEqualTo(Cases);
    }

    [Test]
    public async Task RejectedCompatibilityNeverEmitsAcceptanceAndPreservesExactPrecedence()
    {
        var coverage = new HashSet<MessagingErrorCode>();
        for (var index = 0; index < Cases; index++)
        {
            var outcomes = CompleteOutcomes().ToArray();
            IReadOnlyList<CompatibilityFeature> features = Features();
            CompatibilityPolicy policy;
            MessagingErrorCode expected;
            switch (index % 13)
            {
                case 0: policy = new(1, 1, outcomes); expected = MessagingErrorCode.InvalidCatalog; break;
                case 1: policy = new(0, 1, outcomes); expected = MessagingErrorCode.InvalidCatalog; break;
                case 2: policy = new(-1, 1, outcomes); expected = MessagingErrorCode.InvalidCatalog; break;
                case 3: policy = new(2, 0, outcomes); expected = MessagingErrorCode.InvalidCatalog; break;
                case 4: policy = new(3, 1, outcomes); expected = MessagingErrorCode.InvalidCatalog; break;
                case 5: policy = new(2, 1, outcomes.Select((outcome, item) => item == 0
                    ? outcome with { Feature = (CompatibilityFeature)(1_000 + index) } : outcome)); expected = MessagingErrorCode.InvalidCatalog; break;
                case 6: policy = new(2, 1, outcomes.Select((outcome, item) => item == 0
                    ? outcome with { Pair = (CompatibilityPair)(1_000 + index) } : outcome)); expected = MessagingErrorCode.InvalidCatalog; break;
                case 7: policy = new(2, 1, outcomes.Skip(1)); expected = MessagingErrorCode.IncompleteObservation; break;
                case 8: policy = new(2, 1, outcomes.Append(outcomes[0])); expected = MessagingErrorCode.DuplicateEvidence; break;
                case 9: policy = new(2, 1, outcomes.Select((outcome, item) => item == index % outcomes.Length
                    ? outcome with { Available = false } : outcome)); expected = MessagingErrorCode.CompatibilityUnavailable; break;
                case 10: features = Features().Skip(1).ToArray(); policy = new(2, 1, outcomes); expected = MessagingErrorCode.InvalidCatalog; break;
                case 11: features = [.. Features(), CompatibilityFeature.Commands]; policy = new(2, 1, outcomes); expected = MessagingErrorCode.InvalidCatalog; break;
                default: features = [(CompatibilityFeature)(1_000 + index), .. Features().Skip(1)]; policy = new(2, 1, outcomes); expected = MessagingErrorCode.InvalidCatalog; break;
            }

            var decision = MessagingPolicyEngine.DecideCompatibility(features, policy);
            Require(decision.Compatibility is null, index, "rejected receipt");
            Require(decision.Errors.Count == 1 && decision.Errors[0].Code == expected,
                index, "rejection precedence");
            Require(decision.Intents is [HoldMessagingIntent], index, "held intent");
            coverage.Add(expected);
        }

        await Assert.That(coverage).IsEquivalentTo(new[]
        {
            MessagingErrorCode.InvalidCatalog,
            MessagingErrorCode.IncompleteObservation,
            MessagingErrorCode.DuplicateEvidence,
            MessagingErrorCode.CompatibilityUnavailable,
        });
    }

    [Test]
    public async Task CompatibilityAcceptanceIsConstructionClosedAndEveryNonCompatibilityDecisionIsUnscoped()
    {
        var type = typeof(CompatibilityAcceptance);
        await Assert.That(type.IsSealed).IsTrue();
        await Assert.That(type.IsAssignableTo(typeof(IEquatable<CompatibilityAcceptance>))).IsFalse();
        await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Any(static property => property.SetMethod is { IsPublic: true })).IsFalse();
        await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance |
            BindingFlags.DeclaredOnly).Any(static method => method.Name is "Deconstruct" or "<Clone>$")).IsFalse();
        await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)).IsEmpty();

        var partition = MessagingPolicyEngine.DecidePartition(new PartitionRequest(
            new CellId("cell"), 32, ConnectivityState.GlobalDisconnected, AuthorityScope.Regional,
            7, 7, 9, 9, 11, 11, CallerAuthorizesLocalOperation: true, HoldsCurrentGlobalAuthority: false));
        Require(partition.Errors.Count == 0 && partition.Compatibility is null, 0, "partition scope");

        var replacement = MessagingPolicyEngine.DecideReplacement(new ReplacementRequest(
            Policy: null!, Proposed: null!, Persisted: null, Observation: null, MaximumIdentityLength: 0));
        Require(replacement.Errors.Count == 1 && replacement.Compatibility is null, 0, "replacement scope");
    }

    private static CompatibilityFeature[] Features() =>
        Enum.GetValues<CompatibilityFeature>()
            .Where(static feature => feature != CompatibilityFeature.Unspecified)
            .ToArray();

    private static IEnumerable<CompatibilityOutcome> CompleteOutcomes() =>
        Features().SelectMany(static feature =>
            Enum.GetValues<CompatibilityPair>()
                .Where(static pair => pair != CompatibilityPair.Unspecified)
                .Select(pair => new CompatibilityOutcome(feature, pair, Available: true)));

    private static string PublicOutputSignature(MessagingDecision decision)
    {
        var compatibility = decision.Compatibility is null
            ? "compatibility:null"
            : $"compatibility:{decision.Compatibility.CurrentVersion.ToString(CultureInfo.InvariantCulture)}:"
                + $"{decision.Compatibility.PreviousVersion.ToString(CultureInfo.InvariantCulture)}:"
                + string.Join(',', decision.Compatibility.Outcomes.Select(static outcome =>
                    $"{(int)outcome.Feature}/{(int)outcome.Pair}/{outcome.Available}"));
        return string.Join('|', decision.Intents.Select(intent => $"intent:{intent.Action}"))
            + "#" + string.Join('|', decision.Errors.Select(error =>
                $"error:{error.Code}:{error.Requirement}:{error.Operation?.Value}:{error.Server?.Value}:{error.Peer?.Value}"))
            + "#" + string.Join('|', decision.Trace.Select(trace =>
                $"trace:{trace.Sequence.ToString(CultureInfo.InvariantCulture)}:{trace.Code}:{trace.Action}"))
            + "#" + compatibility;
    }

    private static void Require(bool condition, int index, string claim)
    {
        if (!condition) throw new InvalidOperationException($"{claim} failed at case {index}.");
    }

    private static T UnderCulture<T>(string name, Func<T> action)
    {
        var culture = CultureInfo.CurrentCulture;
        var uiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name);
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name);
            return action();
        }
        finally
        {
            CultureInfo.CurrentCulture = culture;
            CultureInfo.CurrentUICulture = uiCulture;
        }
    }
}
