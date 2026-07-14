namespace TerraScale.Orchestrator.Protocol;

/// <summary>
/// Technical acquisition limits for caller-provided protocol inputs. These are
/// denial-of-service bounds, not protocol-version compatibility policy.
/// </summary>
public static class ProtocolTechnicalInputLimits
{
    /// <summary>
    /// Maximum number of accepted-version items captured from a caller enumerable.
    /// N/N-1 policy normally needs two entries; this higher ceiling leaves ample
    /// compatibility headroom without permitting non-terminating acquisition.
    /// </summary>
    public const int MaximumAcceptedProtocolVersionCount = 4_096;
}
