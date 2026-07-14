using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Observability;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class ObservabilityConstructionClosureReviewTests
{
    [Test]
    public async Task Every_exported_public_method_and_accessor_has_an_exact_non_originating_output_inventory()
    {
        var assembly = typeof(ObservabilityDecision).Assembly;
        var methods = assembly.ExportedTypes
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .ToArray();

        var decisionMethods = methods.Where(method => typeof(ObservabilityDecision).IsAssignableFrom(method.ReturnType)).ToArray();
        var expectedDecisionMethods = new[]
        {
            typeof(ObservabilityDecisionEngine).GetMethod(nameof(ObservabilityDecisionEngine.EvaluateAlertRouting))!,
            typeof(ObservabilityDecisionEngine).GetMethod(nameof(ObservabilityDecisionEngine.EvaluateGrafanaProjection))!,
            typeof(ObservabilityDecisionEngine).GetMethod(nameof(ObservabilityDecisionEngine.EvaluateRegionalHealth))!,
            typeof(ObservabilityDecisionEngine).GetMethod(nameof(ObservabilityDecisionEngine.EvaluateTelemetryAdmission))!,
            Clone(typeof(ObservabilityDecision)),
        };
        await Assert.That(Signatures(decisionMethods).SequenceEqual(Signatures(expectedDecisionMethods))).IsTrue();
        await Assert.That(decisionMethods.Count(method => method.IsStatic)).IsEqualTo(4);
        await Assert.That(IsExactClone(Clone(typeof(ObservabilityDecision)), typeof(ObservabilityDecision))).IsTrue();

        var concreteOutputs = assembly.ExportedTypes
            .Where(type => !type.IsAbstract && (typeof(ObservabilityIntent).IsAssignableFrom(type) || typeof(GrafanaChange).IsAssignableFrom(type)))
            .OrderBy(type => type.FullName, StringComparer.Ordinal)
            .ToArray();
        foreach (var output in concreteOutputs)
        {
            var returning = methods.Where(method => output.IsAssignableFrom(method.ReturnType)).ToArray();
            await Assert.That(returning.Length).IsEqualTo(1);
            await Assert.That(IsExactClone(returning.Single(), output)).IsTrue();
        }

        var anyOutputMethods = methods.Where(method =>
            typeof(ObservabilityIntent).IsAssignableFrom(method.ReturnType) || typeof(GrafanaChange).IsAssignableFrom(method.ReturnType)).ToArray();
        var outputHierarchy = assembly.ExportedTypes.Where(type =>
            typeof(ObservabilityIntent).IsAssignableFrom(type) || typeof(GrafanaChange).IsAssignableFrom(type)).ToArray();
        var expectedOutputMethods = outputHierarchy.Select(Clone).Append(typeof(ObservabilityDecision).GetProperty(nameof(ObservabilityDecision.Intent))!.GetMethod!);
        await Assert.That(Signatures(anyOutputMethods).SequenceEqual(Signatures(expectedOutputMethods))).IsTrue();
        await Assert.That(outputHierarchy.Select(Clone).All(method => IsExactClone(method, method.DeclaringType!))).IsTrue();
        var intentGetter = typeof(ObservabilityDecision).GetProperty(nameof(ObservabilityDecision.Intent))!.GetMethod!;
        await Assert.That(intentGetter.IsSpecialName && !intentGetter.IsStatic && intentGetter.GetParameters().Length == 0 &&
            intentGetter.ReturnType == typeof(ObservabilityIntent) && intentGetter.DeclaringType == typeof(ObservabilityDecision)).IsTrue();
    }

    [Test]
    public async Task Every_concrete_output_is_sealed_constructor_closed_and_getter_only()
    {
        var assembly = typeof(ObservabilityDecision).Assembly;
        var outputs = assembly.ExportedTypes.Where(type => type == typeof(ObservabilityDecision) ||
            !type.IsAbstract && (typeof(ObservabilityIntent).IsAssignableFrom(type) || typeof(GrafanaChange).IsAssignableFrom(type))).ToArray();

        await Assert.That(outputs.All(type => type.IsSealed)).IsTrue();
        await Assert.That(outputs.SelectMany(type => type.GetConstructors(BindingFlags.Public | BindingFlags.Instance))).IsEmpty();
        await Assert.That(outputs.SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(method => method.Name == "Deconstruct")).IsEmpty();

        var properties = outputs.SelectMany(type => type.GetProperties(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance));
        await Assert.That(properties.All(property => property.GetMethod is not null && property.SetMethod is null)).IsTrue();
    }

    private static MethodInfo Clone(Type type) => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
        .Single(method => method.Name == "<Clone>$");

    private static bool IsExactClone(MethodInfo method, Type type) =>
        method.Name == "<Clone>$" && !method.IsStatic && method.DeclaringType == type && method.ReturnType == type && method.GetParameters().Length == 0;

    private static IEnumerable<string> Signatures(IEnumerable<MethodInfo> methods) => methods.Select(Signature).Order(StringComparer.Ordinal);
    private static string Signature(MethodInfo method) =>
        $"{method.DeclaringType!.FullName}|{method.Name}|{method.IsStatic}|{method.ReturnType.FullName}|{string.Join(',', method.GetParameters().Select(parameter => parameter.ParameterType.FullName))}";
}
