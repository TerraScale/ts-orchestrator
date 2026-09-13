using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Operations;

public sealed record RegionalControllerStatus(
    int SchemaVersion,
    string Cell,
    string Instance,
    int ControlReplicas,
    bool Ready,
    DateTimeOffset StartedAt,
    DateTimeOffset ObservedAt,
    string Build,
    IReadOnlyList<string> Capabilities,
    string AuthorityState,
    bool IsAuthorityLeader,
    long AuthorityEpoch,
    long AuthorityRevision,
    DateTimeOffset? AuthorityLeaseExpiresAt)
{
    public void Validate(string expectedCell)
    {
        if (SchemaVersion != 2 || Cell != expectedCell ||
            string.IsNullOrWhiteSpace(Instance) || ControlReplicas is not (1 or 3 or 5) ||
            !Ready || StartedAt > ObservedAt || ObservedAt > DateTimeOffset.UtcNow.AddMinutes(1) ||
            string.IsNullOrWhiteSpace(Build) || Capabilities.Count == 0 ||
            Capabilities.Any(string.IsNullOrWhiteSpace) ||
            Capabilities.Distinct(StringComparer.Ordinal).Count() != Capabilities.Count ||
            AuthorityState is not ("leader" or "follower") ||
            AuthorityEpoch <= 0 || AuthorityRevision <= 0 || AuthorityLeaseExpiresAt is null ||
            AuthorityLeaseExpiresAt <= ObservedAt ||
            IsAuthorityLeader != (AuthorityState == "leader"))
        {
            throw new InvalidOperationException("The regional operator status response is invalid.");
        }
    }
}

[JsonSerializable(typeof(RegionalControllerStatus))]
internal sealed partial class RegionalControllerStatusJsonContext : JsonSerializerContext;

