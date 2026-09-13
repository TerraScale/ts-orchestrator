using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class CompletionGapAudit2CounterexampleTests
{
    [Test]
    public async Task All_216_independent_verified_handoff_permutations_emit_one_canonical_inventory_across_cultures()
    {
        var items = Items();
        var permutations = Permutations(items).ToArray();
        var canonical = "backend-c|Backend|9;node-a|Node|7;volume-b|Volume|8";
        var cases = 0;

        foreach (var expected in permutations)
        foreach (var pulumi in permutations)
        foreach (var regional in permutations)
        {
            var culture = (cases % 3) switch { 0 => "tr-TR", 1 => "ar-SA", _ => "ja-JP" };
            var decision = UnderCulture(culture, () => Decide(expected, pulumi, regional));
            await Assert.That(decision.Ready).IsTrue();
            await Assert.That(Project(decision.Intent!.Inventory.Expected)).IsEqualTo(canonical);
            await Assert.That(Project(decision.Intent.Inventory.Pulumi)).IsEqualTo(canonical);
            await Assert.That(Project(decision.Intent.Inventory.Regional)).IsEqualTo(canonical);
            cases++;
        }

        await Assert.That(cases).IsEqualTo(216);
    }

    [Test]
    public async Task Canonical_snapshot_retains_exact_items_is_mutation_safe_and_reconstructs_every_leaf()
    {
        var items = Items();
        var expected = new[] { items[2], items[0], items[1] };
        var pulumi = new[] { items[1], items[2], items[0] };
        var regional = new[] { items[0], items[2], items[1] };
        var decision = Decide(expected, pulumi, regional);
        var inventory = decision.Intent!.Inventory;

        foreach (var retained in new[] { inventory.Expected, inventory.Pulumi, inventory.Regional })
        foreach (var item in retained)
            await Assert.That(ReferenceEquals(item, items.Single(candidate => candidate.ResourceId == item.ResourceId))).IsTrue();

        expected[0] = Replacement("mutated-expected");
        pulumi[0] = Replacement("mutated-pulumi");
        regional[0] = Replacement("mutated-regional");
        var canonical = "backend-c|Backend|9;node-a|Node|7;volume-b|Volume|8";
        await Assert.That(Project(inventory.Expected)).IsEqualTo(canonical);
        await Assert.That(Project(inventory.Pulumi)).IsEqualTo(canonical);
        await Assert.That(Project(inventory.Regional)).IsEqualTo(canonical);

        var reconstructedItems = Items();
        var reconstructed = Decide(reconstructedItems.Reverse(), reconstructedItems, reconstructedItems.Skip(1).Concat(reconstructedItems.Take(1)));
        await Assert.That(Project(reconstructed.Intent!.Inventory.Expected)).IsEqualTo(Project(inventory.Expected));
        await Assert.That(Project(reconstructed.Intent.Inventory.Pulumi)).IsEqualTo(Project(inventory.Pulumi));
        await Assert.That(Project(reconstructed.Intent.Inventory.Regional)).IsEqualTo(Project(inventory.Regional));
        await Assert.That(reconstructed.Intent.Scope).IsEqualTo(decision.Intent.Scope);
        await Assert.That(reconstructed.Trace).IsEquivalentTo(decision.Trace);
    }

    [Test]
    public async Task Canonical_comparator_pins_resource_kind_and_generation_tie_breaks_without_weakening_duplicate_denial()
    {
        var id = new ProviderResourceId("shared-resource");
        var node9 = new HandoffInventoryItem(id, ProviderResourceKind.Node, new(9));
        var volume7 = new HandoffInventoryItem(id, ProviderResourceKind.Volume, new(7));
        var node7 = new HandoffInventoryItem(id, ProviderResourceKind.Node, new(7));
        var inventory = new FreshBootstrapInventory([volume7, node9, node7], [node9, node7, volume7], [node7, volume7, node9]);
        var expected = "shared-resource|Node|7;shared-resource|Node|9;shared-resource|Volume|7";

        await Assert.That(Project(inventory.Expected)).IsEqualTo(expected);
        await Assert.That(Project(inventory.Pulumi)).IsEqualTo(expected);
        await Assert.That(Project(inventory.Regional)).IsEqualTo(expected);

        var scope = Scope(inventory);
        var decision = ProviderOwnershipEngine.EvaluateHandoff(new(inventory, scope, scope.BootstrapGeneration, Evidence(scope)));
        await Assert.That(decision.Ready).IsFalse();
        await Assert.That(decision.Intent).IsNull();
        await Assert.That(decision.Trace.Single(reason => reason.Code == ProviderDecisionCode.HandoffInventoryUnique).Outcome)
            .IsEqualTo(ProviderDecisionOutcome.Held);
    }

    [Test]
    public async Task Public_handoff_decision_intent_inventory_scope_trace_and_projection_surfaces_are_exact()
    {
        await Assert.That(Properties(typeof(HandoffDecision))).IsEquivalentTo(new[]
        {
            "Intent:EnableRegionalSelfManagementIntent", "Ready:Boolean", "Trace:IReadOnlyList<ProviderDecisionReason>",
        });
        await Assert.That(Properties(typeof(EnableRegionalSelfManagementIntent))).IsEquivalentTo(new[]
        {
            "CurrentAcceptedBootstrapGeneration:ProviderGeneration", "Inventory:FreshBootstrapInventory", "Scope:HandoffScope",
        });
        await Assert.That(Properties(typeof(FreshBootstrapInventory))).IsEquivalentTo(new[]
        {
            "Expected:IReadOnlyList<HandoffInventoryItem>", "Pulumi:IReadOnlyList<HandoffInventoryItem>", "Regional:IReadOnlyList<HandoffInventoryItem>",
        });
        await Assert.That(Properties(typeof(HandoffScope))).IsEquivalentTo(new[]
        {
            "BootstrapGeneration:ProviderGeneration", "CellId:ProviderCellId", "CompartmentId:ProviderCompartmentId",
            "InventoryFingerprint:HandoffInventoryFingerprint", "OperationId:ProviderOperationId",
        });
        await Assert.That(Properties(typeof(ProviderDecisionReason))).IsEquivalentTo(new[]
        {
            "Code:ProviderDecisionCode", "Observed:UInt64", "Outcome:ProviderDecisionOutcome", "Required:UInt64",
        });
        await Assert.That(Properties(typeof(HandoffInventoryItem))).IsEquivalentTo(new[]
        {
            "Generation:ProviderGeneration", "Kind:ProviderResourceKind", "ResourceId:ProviderResourceId",
        });

        var protectedTypes = new[] { typeof(HandoffDecision), typeof(EnableRegionalSelfManagementIntent),
            typeof(FreshBootstrapInventory), typeof(HandoffScope), typeof(ProviderDecisionReason), typeof(HandoffInventoryItem) };
        var routes = typeof(HandoffDecision).Assembly.GetExportedTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(method => protectedTypes.Contains(method.ReturnType) || IsProjection(method.ReturnType))
            .Select(Route).Order(StringComparer.Ordinal).ToArray();
        await Assert.That(routes).IsEquivalentTo(new[]
        {
            "EnableRegionalSelfManagementIntent.<Clone>$()->EnableRegionalSelfManagementIntent",
            "EnableRegionalSelfManagementIntent.get_Inventory()->FreshBootstrapInventory",
            "EnableRegionalSelfManagementIntent.get_Scope()->HandoffScope",
            "FreshBootstrapInventory.get_Expected()->IReadOnlyList<HandoffInventoryItem>",
            "FreshBootstrapInventory.get_Pulumi()->IReadOnlyList<HandoffInventoryItem>",
            "FreshBootstrapInventory.get_Regional()->IReadOnlyList<HandoffInventoryItem>",
            "HandoffDecision.<Clone>$()->HandoffDecision",
            "HandoffDecision.get_Intent()->EnableRegionalSelfManagementIntent",
            "HandoffDecision.get_Trace()->IReadOnlyList<ProviderDecisionReason>",
            "HandoffInventoryItem.<Clone>$()->HandoffInventoryItem",
            "HandoffProof.get_Scope()->HandoffScope",
            "HandoffRequest.get_ExpectedScope()->HandoffScope",
            "HandoffRequest.get_Inventory()->FreshBootstrapInventory",
            "HandoffScope.<Clone>$()->HandoffScope",
            "HandoffScope.ForFreshBootstrap(ProviderCellId,ProviderCompartmentId,ProviderGeneration,ProviderOperationId,FreshBootstrapInventory)->HandoffScope",
            "ProviderAuthorizationDecision.get_Trace()->IReadOnlyList<ProviderDecisionReason>",
            "ProviderDecisionReason.<Clone>$()->ProviderDecisionReason",
            "ProviderOwnershipEngine.EvaluateHandoff(HandoffRequest)->HandoffDecision",
        });

        await Assert.That(PublicConstructors(typeof(HandoffDecision))).IsEqualTo(0);
        await Assert.That(PublicConstructors(typeof(EnableRegionalSelfManagementIntent))).IsEqualTo(0);
        await Assert.That(PublicConstructors(typeof(HandoffScope))).IsEqualTo(0);
        await Assert.That(PublicConstructors(typeof(ProviderDecisionReason))).IsEqualTo(0);
        await Assert.That(PublicConstructors(typeof(FreshBootstrapInventory))).IsEqualTo(1);
        await Assert.That(PublicConstructors(typeof(HandoffInventoryItem))).IsEqualTo(1);
        await Assert.That(protectedTypes.SelectMany(type => type.GetProperties())
            .Where(property => property.SetMethod?.IsPublic == true)).IsEmpty();
        await Assert.That(routes.Count(route => route.Contains(".<Clone>$", StringComparison.Ordinal))).IsEqualTo(5);
        await Assert.That(routes.Count(route => route.StartsWith("ProviderOwnershipEngine.", StringComparison.Ordinal))).IsEqualTo(1);
    }

    private static HandoffDecision Decide(
        IEnumerable<HandoffInventoryItem> expected,
        IEnumerable<HandoffInventoryItem> pulumi,
        IEnumerable<HandoffInventoryItem> regional)
    {
        var inventory = new FreshBootstrapInventory(expected, pulumi, regional);
        var scope = Scope(inventory);
        return ProviderOwnershipEngine.EvaluateHandoff(
            new(inventory, scope, scope.BootstrapGeneration, Evidence(scope)));
    }

    private static HandoffScope Scope(FreshBootstrapInventory inventory) => HandoffScope.ForFreshBootstrap(
        new("gru"), new("compartment"), new(7), new("handoff"), inventory);

    private static HandoffEvidence Evidence(HandoffScope scope) => new(
        new RetainUnmanageHandoffProof(scope, HandoffEvidenceStatus.Verified),
        new RegionalJournalHandoffProof(scope, HandoffEvidenceStatus.Verified),
        new ProviderReadyHandoffProof(scope, HandoffEvidenceStatus.Verified),
        new TrustReadyHandoffProof(scope, HandoffEvidenceStatus.Verified),
        new BackupReadyHandoffProof(scope, HandoffEvidenceStatus.Verified),
        new RegionalFenceHandoffProof(scope, HandoffEvidenceStatus.Verified));

    private static HandoffInventoryItem[] Items() =>
    [
        new(new("backend-c"), ProviderResourceKind.Backend, new(9)),
        new(new("node-a"), ProviderResourceKind.Node, new(7)),
        new(new("volume-b"), ProviderResourceKind.Volume, new(8)),
    ];

    private static HandoffInventoryItem Replacement(string id) => new(new(id), ProviderResourceKind.Node, new(1));

    private static IEnumerable<HandoffInventoryItem[]> Permutations(IReadOnlyList<HandoffInventoryItem> values)
    {
        for (var first = 0; first < values.Count; first++)
        for (var second = 0; second < values.Count; second++)
        for (var third = 0; third < values.Count; third++)
            if (first != second && first != third && second != third)
                yield return [values[first], values[second], values[third]];
    }

    private static T UnderCulture<T>(string cultureName, Func<T> action)
    {
        var original = CultureInfo.CurrentCulture;
        var originalUi = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = new(cultureName);
            CultureInfo.CurrentUICulture = new(cultureName);
            return action();
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
            CultureInfo.CurrentUICulture = originalUi;
        }
    }

    private static string Project(IEnumerable<HandoffInventoryItem> items) => string.Join(';',
        items.Select(item => $"{item.ResourceId.Value}|{item.Kind}|{item.Generation.Value}"));
    private static string[] Properties(Type type) => type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
        .Select(property => $"{property.Name}:{TypeName(property.PropertyType)}").Order(StringComparer.Ordinal).ToArray();
    private static int PublicConstructors(Type type) => type.GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length;
    private static bool IsProjection(Type type) => type.IsGenericType && type.GetGenericTypeDefinition() == typeof(IReadOnlyList<>) &&
        type.GetGenericArguments()[0] is var item && (item == typeof(HandoffInventoryItem) || item == typeof(ProviderDecisionReason));
    private static string Route(MethodInfo method) => $"{method.DeclaringType!.Name}.{method.Name}({string.Join(',', method.GetParameters().Select(parameter => TypeName(parameter.ParameterType)))})->{TypeName(method.ReturnType)}";
    private static string TypeName(Type type) => type.IsGenericType
        ? $"{type.Name[..type.Name.IndexOf('`')]}<{string.Join(',', type.GetGenericArguments().Select(TypeName))}>"
        : type.Name;
}

