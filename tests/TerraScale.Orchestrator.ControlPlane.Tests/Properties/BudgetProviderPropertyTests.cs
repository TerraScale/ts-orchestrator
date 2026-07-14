using System.Collections;
using System.Globalization;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Budgets;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class BudgetProviderPropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task Budget_projection_matches_independent_checked_arithmetic_oracle_for_1000_cases()
    {
        for (var seed = 0; seed < Cases; seed++)
        {
            var increase = (seed & 1) == 0;
            var current = seed % 37 == 0 ? long.MaxValue - 2 : 100L + seed;
            var delta = seed % 37 == 0 ? 9L : 1L + seed % 97;
            if (!increase && seed % 11 == 0) delta = current + 1;
            var expected = new BigInteger(current) + (increase ? delta : -delta);
            var decision = EvaluateBudget(current, delta, increase);
            var representable = expected >= 0 && expected <= long.MaxValue;
            if (!representable)
            {
                await Assert.That(decision.Kind).IsEqualTo(BudgetDecisionKind.Held);
                await Assert.That(decision.Reason).IsEqualTo(increase ? BudgetDecisionReason.ArithmeticOverflow : BudgetDecisionReason.ArithmeticUnderflow);
                continue;
            }
            await Assert.That(decision.Kind).IsEqualTo(BudgetDecisionKind.Automatic);
            foreach (var actual in Values(decision.Trace!.ProjectedCell).Concat(Values(decision.Trace.ProjectedGlobal)))
                await Assert.That(actual).IsEqualTo((long)expected);
        }
    }

    [Test]
    public async Task Budget_evidence_status_duplicate_and_permutation_oracle_holds_for_1000_cases()
    {
        for (var seed = 0; seed < Cases; seed++)
        {
            var mode = seed % 4;
            var cell = BudgetTestData.CellUsage();
            var global = BudgetTestData.GlobalUsage();
            IEnumerable<BudgetUsageObservation?> usage = mode switch
            {
                0 => seed % 2 == 0 ? [cell, global] : [global, cell],
                1 => [cell, global, cell],
                2 => [new(BudgetUsageScope.Cell, BudgetTestData.Cell(), BudgetTestData.CostCenter(), BudgetTestData.Evidence("cell-usage"), BudgetEvidenceStatus.Stale, BudgetTestData.Q(1), BudgetTestData.Vector(10)), global],
                _ => [new(BudgetUsageScope.Cell, BudgetTestData.Cell(), BudgetTestData.CostCenter(), BudgetTestData.Evidence("cell-usage"), BudgetEvidenceStatus.Unknown, BudgetTestData.Q(1), BudgetTestData.Vector(10)), global],
            };
            var decision = BudgetTestData.Evaluate(usage: usage);
            var expected = mode switch
            {
                0 => BudgetDecisionReason.WithinAutomaticBand,
                1 => BudgetDecisionReason.DuplicateEvidence,
                2 => BudgetDecisionReason.StaleEvidence,
                _ => BudgetDecisionReason.UnknownEvidence,
            };
            await Assert.That(decision.Reason).IsEqualTo(expected);
            await Assert.That(decision.IsAuthorized).IsEqualTo(mode == 0);
        }
    }

    [Test]
    public async Task Budget_node_capacity_projection_matches_independent_integer_oracle_for_1000_cases()
    {
        var max = BudgetTestData.Vector(long.MaxValue);
        for (var seed = 0; seed < Cases; seed++)
        {
            var current = seed % 53;
            var change = 1 + seed % 17;
            var increase = seed % 3 != 0;
            var expected = (long)current + (increase ? change : -change);
            var decision = BudgetTestData.Evaluate(
                policy: BudgetTestData.Policy(automatic: max, approval: max, ceiling: max, provider: max,
                    nodes: [new NodeClassCapacityPolicy(BudgetTestData.NodeClass(), 0, 100, 0)]),
                proposal: BudgetTestData.Proposal(delta: BudgetVector.Zero,
                    direction: increase ? BudgetChangeDirection.Increase : BudgetChangeDirection.Decrease, nodeCount: change),
                nodes: [BudgetTestData.NodeUsage(current)]);
            if (expected < 0)
                await Assert.That(decision.Reason).IsEqualTo(BudgetDecisionReason.ArithmeticUnderflow);
            else
            {
                await Assert.That(decision.IsAuthorized).IsTrue();
                await Assert.That(decision.Trace!.ProjectedNodeCount).IsEqualTo((int)expected);
            }
        }
    }

    [Test]
    public async Task Provider_generation_ownership_and_fencing_oracle_holds_for_1000_cases()
    {
        for (var seed = 0; seed < Cases; seed++)
        {
            var mode = seed % 5;
            var request = ProviderRequest(
                contextEpoch: mode == 1 ? 4UL : mode == 2 ? 6UL : 5UL,
                authorityEpoch: 5,
                observationGeneration: mode == 3 ? 8UL : 7UL,
                ownershipCell: mode == 4 ? new ProviderCellId("sfo") : Cell);
            var decision = ProviderOwnershipEngine.Authorize(request);
            await Assert.That(decision.Authorized).IsEqualTo(mode == 0);
            await Assert.That(decision.Intents.Count).IsEqualTo(mode == 0 ? 1 : 0);
            if (mode is 1 or 2)
                await Assert.That(Reason(decision, ProviderDecisionCode.EpochCurrentOrDurablyResumable).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
            if (mode == 3)
                await Assert.That(Reason(decision, ProviderDecisionCode.GenerationMatches).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
            if (mode == 4)
                await Assert.That(Reason(decision, ProviderDecisionCode.OwnershipMatches).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
        }
    }

    [Test]
    public async Task Provider_duplicate_reorder_and_culture_are_deterministic_for_1000_cases()
    {
        var cultures = new[] { "en-US", "tr-TR", "ar-SA" };
        for (var seed = 0; seed < Cases; seed++)
        {
            var extra = new ProviderOwnershipRecord(new($"other-{seed}"), Cell, Compartment, Generation);
            var evidence = new[] { Ownership(), extra };
            var forward = Serialize(ProviderOwnershipEngine.Authorize(ProviderRequest(ownership: evidence)));
            var original = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultures[seed % cultures.Length]);
                var reverse = Serialize(ProviderOwnershipEngine.Authorize(ProviderRequest(ownership: evidence.Reverse())));
                await Assert.That(reverse).IsEqualTo(forward);
            }
            finally { CultureInfo.CurrentCulture = original; }
            var duplicate = ProviderOwnershipEngine.Authorize(ProviderRequest(ownership: [Ownership(), Ownership()]));
            await Assert.That(duplicate.Authorized).IsFalse();
            await Assert.That(Reason(duplicate, ProviderDecisionCode.EvidenceUnique).Outcome).IsEqualTo(ProviderDecisionOutcome.Held);
        }
    }

    [Test]
    public async Task Handoff_exactness_generation_and_proof_oracle_holds_for_1000_cases()
    {
        for (var seed = 0; seed < Cases; seed++)
        {
            var items = new[] { new HandoffInventoryItem(new($"node-{seed}"), ProviderResourceKind.Node, new(1)) };
            var inventory = new FreshBootstrapInventory(items, items.Reverse(), items);
            var scope = HandoffScope.ForFreshBootstrap(Cell, Compartment, Generation, new("handoff"), inventory);
            var proofScope = seed % 3 == 1
                ? HandoffScope.ForFreshBootstrap(Cell, Compartment, new(8), new("handoff"), inventory)
                : scope;
            var status = seed % 3 == 2 ? HandoffEvidenceStatus.Missing : HandoffEvidenceStatus.Verified;
            var decision = ProviderOwnershipEngine.EvaluateHandoff(new(inventory, scope, Evidence(proofScope, status)));
            await Assert.That(decision.Ready).IsEqualTo(seed % 3 == 0);
            await Assert.That(decision.Intent is not null).IsEqualTo(seed % 3 == 0);
        }
    }

    [Test]
    public async Task Authorizing_outputs_are_construction_closed()
    {
        await Assert.That(typeof(BudgetDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(BudgetApprovalScope).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(ProviderAuthorizationDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(EnableRegionalSelfManagementIntent).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(ProviderIntent).Assembly.GetTypes().Where(t => typeof(ProviderIntent).IsAssignableFrom(t))
            .SelectMany(t => t.GetConstructors(BindingFlags.Public | BindingFlags.Instance))).IsEmpty();
        await Assert.That(typeof(DurableProviderAuthorization).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Any(method => method.ReturnType == typeof(DurableProviderAuthorization))).IsFalse();
        await Assert.That(typeof(ProviderIntent).Assembly.GetTypes().Where(type => typeof(ProviderIntent).IsAssignableFrom(type))
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Any(method => method.ReturnType == typeof(DurableProviderAuthorization))).IsFalse();
        var planned = ProviderOwnershipEngine.Authorize(ProviderRequest());
        var held = ProviderOwnershipEngine.Authorize(ProviderRequest(contextEpoch: 4));
        var accepted = ProviderOwnershipEngine.Authorize(ProviderRequest(call: new(ProviderCallStatus.Accepted, null)));
        var acceptedObserve = ProviderOwnershipEngine.Authorize(ProviderObserveRequest());
        var acceptedAuthorization = accepted.CaptureDurableAuthorization();
        await Assert.That(Capture(() => planned.CaptureDurableAuthorization())).IsTypeOf<InvalidOperationException>();
        await Assert.That(Capture(() => held.CaptureDurableAuthorization())).IsTypeOf<InvalidOperationException>();
        await Assert.That(acceptedObserve.Authorized).IsTrue();
        await Assert.That(acceptedObserve.Intents.Single()).IsTypeOf<ObserveProviderResourceIntent>();
        await Assert.That(Capture(() => acceptedObserve.CaptureDurableAuthorization())).IsTypeOf<InvalidOperationException>();
        await Assert.That(acceptedAuthorization.Irreversible).IsTrue();
        await Assert.That(acceptedAuthorization.OperationId).IsEqualTo(new ProviderOperationId("operation"));
    }

    [Test]
    public async Task Strict_whole_file_pinned_corpus_replays_input_sensitive_cases()
    {
        var corpus = BudgetProviderReplayCorpus.Load();
        await Assert.That(corpus.Count).IsGreaterThanOrEqualTo(8);
        var outcomes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in corpus)
        {
            var actual = item.Domain switch
            {
                "budget" => EvaluateBudget(item.Current, item.Delta, item.Mode == "increase").Reason.ToString(),
                "provider" => ProviderOwnershipEngine.Authorize(ProviderRequest(
                    contextEpoch: item.Current > 0 ? (ulong)item.Current : 1,
                    authorityEpoch: item.Delta > 0 ? (ulong)item.Delta : 1)).Authorized.ToString(CultureInfo.InvariantCulture),
                _ => throw new InvalidDataException("Unknown replay domain."),
            };
            await Assert.That(actual).IsEqualTo(item.Expected);
            outcomes.Add(actual);
        }
        await Assert.That(outcomes.Count).IsGreaterThan(2);
    }

    [Test]
    public async Task Replay_corpus_parser_rejects_noncanonical_and_ambiguous_json()
    {
        var invalid = new[]
        {
            "[{\"Id\":\"a\",\"Id\":\"b\",\"Domain\":\"provider\",\"Mode\":\"epoch\",\"Current\":5,\"Delta\":5,\"Expected\":\"True\"}]",
            "[{\"Id\":\"a\",\"Domain\":\"provider\",\"Mode\":\"epoch\",\"Current\":5,\"Delta\":5}]",
            "[{\"Id\":\"a\",\"Domain\":\"provider\",\"Mode\":\"epoch\",\"Current\":5,\"Delta\":5,\"Expected\":\"True\",\"Extra\":1}]",
            "[{\"Id\":1,\"Domain\":\"provider\",\"Mode\":\"epoch\",\"Current\":5,\"Delta\":5,\"Expected\":\"True\"}]",
            "[{\"Id\":\"a\",\"Domain\":\"provider\",\"Mode\":\"epoch\",\"Current\":\"5\",\"Delta\":5,\"Expected\":\"True\"}]",
            "[{\"Id\":\"a\",\"Domain\":\"provider\",\"Mode\":\"epoch\",\"Current\":5,\"Delta\":5,\"Expected\":true}]",
            "[{\"Id\":\"a\",\"Domain\":\"provider\",\"Mode\":\"increase\",\"Current\":5,\"Delta\":5,\"Expected\":\"True\"}]",
            "[{\"Id\":\"a\",\"Domain\":\"budget\",\"Mode\":\"increase\",\"Current\":5,\"Delta\":5,\"Expected\":\"True\"}]",
            "[/*comment*/{\"Id\":\"a\",\"Domain\":\"provider\",\"Mode\":\"epoch\",\"Current\":5,\"Delta\":5,\"Expected\":\"True\"}]",
            "[{\"Id\":\"a\",\"Domain\":\"provider\",\"Mode\":\"epoch\",\"Current\":5,\"Delta\":5,\"Expected\":\"True\"},]",
            "[] {}",
            "[[[[[[[[[[{}]]]]]]]]]]",
            "[{\"Id\":\"a\",\"Domain\":\"provider\",\"Mode\":\"epoch\",\"Current\":0,\"Delta\":5,\"Expected\":\"False\"}]",
        };
        foreach (var json in invalid)
            await Assert.That(Capture(() => BudgetProviderReplayCorpus.ParseForTest(Encoding.UTF8.GetBytes(json)))).IsTypeOf<InvalidDataException>();
        var tooManyEntries = "[" + string.Join(',', Enumerable.Range(0, 65).Select(index =>
            $"{{\"Id\":\"id-{index}\",\"Domain\":\"provider\",\"Mode\":\"epoch\",\"Current\":5,\"Delta\":5,\"Expected\":\"True\"}}")) + "]";
        await Assert.That(Capture(() => BudgetProviderReplayCorpus.ParseForTest(Encoding.UTF8.GetBytes(tooManyEntries)))).IsTypeOf<InvalidDataException>();
        await Assert.That(Capture(() => BudgetProviderReplayCorpus.ParseForTest(new byte[16_385]))).IsTypeOf<InvalidDataException>();
    }

    private static BudgetDecision EvaluateBudget(long current, long delta, bool increase)
    {
        var max = BudgetTestData.Vector(long.MaxValue);
        return BudgetTestData.Evaluate(
            policy: BudgetTestData.Policy(automatic: max, approval: max, ceiling: max, provider: max,
                nodes: [new NodeClassCapacityPolicy(BudgetTestData.NodeClass(), 0, 5, 0)]),
            proposal: BudgetTestData.Proposal(delta: BudgetTestData.Vector(delta), direction: increase ? BudgetChangeDirection.Increase : BudgetChangeDirection.Decrease, nodeCount: 0),
            usage: [BudgetTestData.CellUsage(BudgetTestData.Vector(current)), BudgetTestData.GlobalUsage(BudgetTestData.Vector(current))],
            nodes: [BudgetTestData.NodeUsage(count: 1)], prices: [BudgetTestData.Price()]);
    }

    private static long[] Values(BudgetVector vector) =>
    [
        vector.Cpu.Value, vector.Memory.Value, vector.Storage.Value, vector.Iops.Value, vector.Throughput.Value,
        vector.PublicIp.Value, vector.LoadBalancerBackend.Value, vector.HourlySpend.Value, vector.DailySpend.Value,
    ];

    private static ProviderCellId Cell { get; } = new("gru");
    private static ProviderCompartmentId Compartment { get; } = new("compartment");
    private static ProviderResourceId Resource { get; } = new("node-1");
    private static ProviderGeneration Generation { get; } = new(7);
    private static ProviderOwnershipRecord Ownership(ProviderCellId? cell = null) => new(Resource, cell ?? Cell, Compartment, Generation);
    private static ProviderAuthorizationRequest ProviderRequest(ulong contextEpoch = 5, ulong authorityEpoch = 5,
        ulong observationGeneration = 7, ProviderCellId? ownershipCell = null, IEnumerable<ProviderOwnershipRecord>? ownership = null,
        ProviderCallEvidence? call = null)
    {
        var context = new ProviderOperationContext(new("operation"), Cell, Compartment, new(contextEpoch), ProviderResourceKind.Node,
            ProviderAction.TerminateNode, new ExistingProviderResource(Resource), Generation, ProviderObservedState.Running,
            ProviderTerminalState.Terminated, [ProviderApproval.RegionalAuthority], new(DeadlineEvidenceStatus.Valid, new(1)),
            new("idempotency"), [ProviderCompensation.ObserveOnly], new TerminateNodeProviderParameters());
        return new(context, new(Cell, Compartment, new(authorityEpoch)), ownership ?? [Ownership(ownershipCell)], [],
            ProviderObservationCompleteness.Complete, [new(Resource, new(observationGeneration), ProviderObservedState.Running)], [],
            [ProviderApproval.RegionalAuthority], null, call ?? new(ProviderCallStatus.NotCalled, null));
    }
    private static HandoffEvidence Evidence(HandoffScope scope, HandoffEvidenceStatus backup) => new(
        new RetainUnmanageHandoffProof(scope, HandoffEvidenceStatus.Verified), new RegionalJournalHandoffProof(scope, HandoffEvidenceStatus.Verified),
        new ProviderReadyHandoffProof(scope, HandoffEvidenceStatus.Verified), new TrustReadyHandoffProof(scope, HandoffEvidenceStatus.Verified),
        new BackupReadyHandoffProof(scope, backup), new RegionalFenceHandoffProof(scope, HandoffEvidenceStatus.Verified));
    private static ProviderAuthorizationRequest ProviderObserveRequest()
    {
        var context = new ProviderOperationContext(new("observe-operation"), Cell, Compartment, new(5), ProviderResourceKind.Node,
            ProviderAction.Observe, new ExistingProviderResource(Resource), Generation, ProviderObservedState.Running,
            ProviderTerminalState.Running, [ProviderApproval.RegionalAuthority], new(DeadlineEvidenceStatus.Valid, new(1)),
            new("observe-idempotency"), [ProviderCompensation.ObserveOnly], new ObserveProviderParameters());
        return new(context, new(Cell, Compartment, new(5)), [Ownership()], [], ProviderObservationCompleteness.Complete,
            [new(Resource, Generation, ProviderObservedState.Running)], [], [ProviderApproval.RegionalAuthority], null,
            new(ProviderCallStatus.Accepted, null));
    }
    private static ProviderDecisionReason Reason(ProviderAuthorizationDecision decision, ProviderDecisionCode code) => decision.Trace.Single(x => x.Code == code);
    private static string Serialize(ProviderAuthorizationDecision decision) => $"{decision.Authorized}|{string.Join(';', decision.Trace.Select(x => $"{x.Code}:{x.Outcome}:{x.Observed}:{x.Required}"))}|{string.Join(',', decision.Intents.Select(x => x.GetType().Name))}";
    private static Exception? Capture(Action action) { try { action(); return null; } catch (Exception exception) { return exception; } }
}

internal sealed record BudgetProviderReplayItem(string Id, string Domain, string Mode, long Current, long Delta, string Expected);

internal static class BudgetProviderReplayCorpus
{
    private const string ResourceName = "TerraScale.Orchestrator.ControlPlane.Tests.Properties.BudgetProviderReplayCorpus.v1.json";
    private const string Sha256 = "99516fac2dba8d0646560ffd23456b73cd7bcce42dbf47be9a980ee27c937b8c";
    private const int MaximumBytes = 16_384;
    private static readonly HashSet<string> PropertyNames = new(StringComparer.Ordinal)
        { "Id", "Domain", "Mode", "Current", "Delta", "Expected" };
    internal static IReadOnlyList<BudgetProviderReplayItem> Load()
    {
        using var stream = typeof(BudgetProviderReplayCorpus).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidDataException("Replay corpus resource is missing.");
        var bytes = ReadBounded(stream);
        var digest = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if (!string.Equals(digest, Sha256, StringComparison.Ordinal)) throw new InvalidDataException("Replay corpus digest mismatch.");
        return Parse(bytes);
    }

    internal static IReadOnlyList<BudgetProviderReplayItem> ParseForTest(byte[] bytes)
    {
        if (bytes.Length > MaximumBytes) throw new InvalidDataException("Replay corpus exceeds its technical bound.");
        return Parse(bytes);
    }

    private static IReadOnlyList<BudgetProviderReplayItem> Parse(byte[] bytes)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8,
            });
            if (document.RootElement.ValueKind != JsonValueKind.Array) throw Invalid();
            var items = new List<BudgetProviderReplayItem>();
            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var element in document.RootElement.EnumerateArray())
            {
                if (items.Count == 64 || element.ValueKind != JsonValueKind.Object) throw Invalid();
                var properties = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject())
                    if (!PropertyNames.Contains(property.Name) || !properties.TryAdd(property.Name, property.Value)) throw Invalid();
                if (properties.Count != PropertyNames.Count) throw Invalid();
                var id = RequiredString(properties["Id"]);
                var domain = RequiredString(properties["Domain"]);
                var mode = RequiredString(properties["Mode"]);
                var expected = RequiredString(properties["Expected"]);
                var current = RequiredInt64(properties["Current"]);
                var delta = RequiredInt64(properties["Delta"]);
                if (id.Length is < 1 or > 64 || id.Any(character => character is not (>= 'a' and <= 'z') and not (>= '0' and <= '9') and not '-')
                    || !ids.Add(id) || current < 0 || delta <= 0 || !ClosedTuple(domain, mode, expected)) throw Invalid();
                if (domain == "provider" && current == 0) throw Invalid();
                items.Add(new(id, domain, mode, current, delta, expected));
            }
            if (items.Count == 0) throw Invalid();
            return items;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Replay corpus JSON is invalid.", exception);
        }
    }

    private static byte[] ReadBounded(Stream stream)
    {
        using var memory = new MemoryStream();
        var buffer = new byte[4_096];
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0) return memory.ToArray();
            if (memory.Length + read > MaximumBytes) throw new InvalidDataException("Replay corpus exceeds its technical bound.");
            memory.Write(buffer, 0, read);
        }
    }

    private static string RequiredString(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.String) throw Invalid();
        return element.GetString() ?? throw Invalid();
    }

    private static long RequiredInt64(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Number || !element.TryGetInt64(out var value)) throw Invalid();
        return value;
    }

    private static bool ClosedTuple(string domain, string mode, string expected) => (domain, mode, expected) switch
    {
        ("budget", "increase", "WithinAutomaticBand" or "ArithmeticOverflow") => true,
        ("budget", "decrease", "WithinAutomaticBand" or "ArithmeticUnderflow") => true,
        ("provider", "epoch", "True" or "False") => true,
        _ => false,
    };

    private static InvalidDataException Invalid() => new("Replay corpus content is invalid.");
}
