using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Bootstrap;

/// <summary>The exact environment and closed workload-role set authorized for one node.</summary>
public sealed record RegionalNodeEnrollmentScope
{
    public RegionalNodeEnrollmentScope(string environment, IReadOnlyList<AdmittedRole> roles)
    {
        if (environment is not { Length: >= 1 and <= 64 } ||
            environment.Any(static c => c is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-')))
            throw new ArgumentException("Node enrollment requires a bounded lowercase environment.", nameof(environment));
        ArgumentNullException.ThrowIfNull(roles);
        if (roles.Count == 0 || roles.Count > AdmittedRoleCatalog.All.Count || roles.Distinct().Count() != roles.Count)
            throw new ArgumentException("Node enrollment requires a nonempty, unique closed role set.", nameof(roles));
        foreach (var role in roles) _ = AdmittedRoleCatalog.Get(role);
        Environment = environment;
        Roles = Array.AsReadOnly(roles.Order().ToArray());
    }

    public string Environment { get; }
    public IReadOnlyList<AdmittedRole> Roles { get; }

    public bool Matches(RegionalNodeEnrollmentScope other) =>
        Environment == other.Environment && Roles.SequenceEqual(other.Roles);

    internal string Canonical() => BootstrapGrantCanonical.EncodeFields(
        [Environment, .. Roles.Select(static role => role.ToString())]);
}
