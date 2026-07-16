using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Reconciliation;

namespace TerraScale.Orchestrator.Development;

public sealed record DevelopmentReconciliationState(
    int DesiredResources,
    int ObservedResources,
    int ConvergedResources,
    int ReconcileIntents,
    int ObserveIntents,
    int HeldResources,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> OrderedResources);

internal static class DevelopmentReconciliation
{
    public static DevelopmentReconciliationState Evaluate(
        DevelopmentTopology topology,
        long generation,
        IReadOnlyList<DevelopmentResourceObservation> observations)
    {
        ArgumentNullException.ThrowIfNull(topology);
        ArgumentNullException.ThrowIfNull(observations);
        if (generation <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(generation));
        }

        var resources = topology.Cells.SelectMany(cell => cell.Resources)
            .Concat(topology.GlobalResources)
            .ToDictionary(resource => resource.Name, StringComparer.Ordinal);
        var desired = resources.Values
            .OrderBy(resource => resource.Name, StringComparer.Ordinal)
            .Select(resource => Desired(resource, topology, generation))
            .ToArray();
        var observed = observations
            .Where(observation => observation.ProcessId is not null)
            .OrderBy(observation => observation.Name, StringComparer.Ordinal)
            .Select(observation => Observed(observation, resources, topology, generation))
            .ToArray();
        var policy = new ReconciliationPolicy(
            Enum.GetNames<DevelopmentResourceKind>(),
            new Dictionary<ResourceIdentity, long>(),
            maximumResources: 64,
            maximumIdentityLength: 128,
            maximumKindLength: 64,
            maximumDigestLength: 64,
            maximumObservationIdLength: 256,
            maximumDependenciesPerResource: 16,
            minimumFreshnessSequence: generation);
        var plan = ReconciliationEngine.Plan(new(desired, observed, policy));
        return new(
            desired.Length,
            observed.Length,
            plan.Steps.Count(step => step.Output is ConvergedResource),
            plan.Steps.Count(step => step.Output is ReconcileResourceIntent),
            plan.Steps.Count(step => step.Output is ObserveResourceIntent),
            plan.Steps.Count(step => step.Output is HoldResource),
            plan.Errors.Select(error => $"{error.Code}:{error.Resource?.Value}:{error.RelatedResource?.Value}").ToArray(),
            plan.Steps.Select(step => step.Desired.Identity.Value).ToArray());
    }

    private static DesiredResource Desired(
        DevelopmentResourcePlan resource,
        DevelopmentTopology topology,
        long generation)
    {
        var dependencies = Dependencies(resource, topology)
            .Order(StringComparer.Ordinal)
            .Select(name => new ResourceIdentity(name))
            .ToArray();
        return new(
            new(resource.Name),
            resource.Kind.ToString(),
            generation,
            Digest(resource, dependencies.Select(dependency => dependency.Value)),
            dependencies);
    }

    private static ObservedResourceState Observed(
        DevelopmentResourceObservation observation,
        IReadOnlyDictionary<string, DevelopmentResourcePlan> resources,
        DevelopmentTopology topology,
        long generation)
    {
        if (!resources.TryGetValue(observation.Name, out var resource) ||
            resource.Cell != observation.Cell ||
            resource.Kind != observation.Kind ||
            resource.Replica != observation.Replica)
        {
            throw new InvalidOperationException(
                $"Development observation '{observation.Name}' is outside the exact topology.");
        }
        var dependencies = Dependencies(resource, topology).Order(StringComparer.Ordinal);
        var condition = observation.State switch
        {
            DevelopmentResourceState.Ready when observation.Healthy => ObservedCondition.Ready,
            DevelopmentResourceState.Failed or DevelopmentResourceState.Degraded => ObservedCondition.Failed,
            _ => ObservedCondition.Held
        };
        return new(
            new(observation.Name),
            observation.Kind.ToString(),
            generation,
            Digest(resource, dependencies),
            $"devhost-{generation}-{observation.Name}-{observation.ProcessId}",
            generation,
            condition);
    }

    private static IReadOnlyList<string> Dependencies(
        DevelopmentResourcePlan resource,
        DevelopmentTopology topology)
    {
        var cell = topology.Cells.SingleOrDefault(candidate => candidate.Cell == resource.Cell);
        return resource.Kind switch
        {
            DevelopmentResourceKind.ControllerAgent => Names(cell, DevelopmentResourceKind.ControlNats),
            DevelopmentResourceKind.TerraBase => Names(cell, DevelopmentResourceKind.ProductNats),
            DevelopmentResourceKind.Authentication => Names(
                cell,
                DevelopmentResourceKind.ProductNats,
                DevelopmentResourceKind.TerraBase),
            DevelopmentResourceKind.Api => Names(cell, DevelopmentResourceKind.Authentication)
                .Concat(topology.GlobalResources.Select(item => item.Name)).ToArray(),
            DevelopmentResourceKind.Dashboard => Names(cell, DevelopmentResourceKind.Api),
            _ => []
        };
    }

    private static IReadOnlyList<string> Names(
        DevelopmentCellPlan? cell,
        params DevelopmentResourceKind[] kinds) => cell is null
        ? []
        : cell.Resources.Where(resource => kinds.Contains(resource.Kind))
            .Select(resource => resource.Name)
            .ToArray();

    private static string Digest(
        DevelopmentResourcePlan resource,
        IEnumerable<string> dependencies)
    {
        var canonical = string.Join(
            '\u001f',
            resource.Name,
            resource.Cell,
            resource.Kind.ToString(),
            resource.Replica.ToString(System.Globalization.CultureInfo.InvariantCulture),
            resource.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            resource.ClusterPort?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            resource.SecondaryPort?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            string.Join(',', dependencies));
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
