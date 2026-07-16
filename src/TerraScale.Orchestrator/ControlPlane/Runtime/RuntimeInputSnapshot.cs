namespace TerraScale.Orchestrator.ControlPlane.Runtime;

/// <summary>Technical denial-of-service safety limits; these are not lifecycle, health, or rollout policy.</summary>
public static class RuntimeTechnicalLimits
{
    public const int MaximumCapturedItems = 4096;
}

internal static class RuntimeInputSnapshot
{
    internal static T[] Copy<T>(IEnumerable<T> source, int maximum, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(source, parameterName);
        var result = new List<T>(Math.Min(maximum, 16));
        try
        {
            using var iterator = source.GetEnumerator();
            while (iterator.MoveNext())
            {
                if (result.Count == maximum) throw new ArgumentException("Runtime input exceeds the technical item limit.", parameterName);
                result.Add(iterator.Current);
            }
        }
        catch (Exception exception) when (exception is not (OutOfMemoryException or StackOverflowException or AccessViolationException))
        {
            throw new ArgumentException("Runtime input could not be captured safely.", parameterName);
        }
        return result.ToArray();
    }
}
