using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.Protocol.Subjects;

public enum SubjectPermissionPolicyError
{
    None = 0,
    InvalidLimits,
    NullPattern,
    TooManyPatterns,
    DuplicatePattern,
    PatternInAllowAndDeny,
    EnumerationFailed,
}

public enum SubjectPermissionReason
{
    Uninitialized = 0,
    AllowedByPattern,
    DeniedByPattern,
    DeniedEmptyAllowSet,
    DeniedNoAllowMatch,
    DeniedInvalidSubject,
}

public readonly record struct SubjectPermissionDecision
{
    private SubjectPermissionDecision(SubjectPermissionReason reason) => Reason = reason;

    public SubjectPermissionReason Reason { get; }

    public bool IsAllowed => Reason == SubjectPermissionReason.AllowedByPattern;

    internal static SubjectPermissionDecision From(SubjectPermissionReason reason) => new(reason);
}

public sealed class SubjectPermissionPolicy
{
    private readonly SubjectPermissionPattern[] _allow;
    private readonly SubjectPermissionPattern[] _deny;
    private readonly ReadOnlyCollection<SubjectPermissionPattern> _allowView;
    private readonly ReadOnlyCollection<SubjectPermissionPattern> _denyView;

    private SubjectPermissionPolicy(
        SubjectPermissionPattern[] allow,
        SubjectPermissionPattern[] deny)
    {
        _allow = allow;
        _deny = deny;
        _allowView = Array.AsReadOnly(_allow);
        _denyView = Array.AsReadOnly(_deny);
    }

    public IReadOnlyList<SubjectPermissionPattern> AllowPatterns => _allowView;

    public IReadOnlyList<SubjectPermissionPattern> DenyPatterns => _denyView;

    public static bool TryCreate(
        IEnumerable<SubjectPermissionPattern?>? allow,
        IEnumerable<SubjectPermissionPattern?>? deny,
        SubjectGrammarLimits? limits,
        out SubjectPermissionPolicy? result,
        out SubjectPermissionPolicyError error)
    {
        result = null;
        if (limits is null)
        {
            error = SubjectPermissionPolicyError.InvalidLimits;
            return false;
        }

        if (!TryCollect(allow, limits.MaximumPermissionPatternCount, out var allowPatterns, out error))
        {
            return false;
        }

        var remaining = limits.MaximumPermissionPatternCount - allowPatterns.Length;
        if (!TryCollect(deny, remaining, out var denyPatterns, out error))
        {
            return false;
        }

        var allowSet = allowPatterns.ToHashSet();
        if (denyPatterns.Any(allowSet.Contains))
        {
            error = SubjectPermissionPolicyError.PatternInAllowAndDeny;
            return false;
        }

        Array.Sort(allowPatterns);
        Array.Sort(denyPatterns);
        result = new SubjectPermissionPolicy(allowPatterns, denyPatterns);
        error = SubjectPermissionPolicyError.None;
        return true;
    }

    public SubjectPermissionDecision Authorize(ConcreteSubject? subject)
    {
        if (subject is null)
        {
            return SubjectPermissionDecision.From(SubjectPermissionReason.DeniedInvalidSubject);
        }

        foreach (var pattern in _deny)
        {
            if (pattern.Matches(subject))
            {
                return SubjectPermissionDecision.From(SubjectPermissionReason.DeniedByPattern);
            }
        }

        if (_allow.Length == 0)
        {
            return SubjectPermissionDecision.From(SubjectPermissionReason.DeniedEmptyAllowSet);
        }

        foreach (var pattern in _allow)
        {
            if (pattern.Matches(subject))
            {
                return SubjectPermissionDecision.From(SubjectPermissionReason.AllowedByPattern);
            }
        }

        return SubjectPermissionDecision.From(SubjectPermissionReason.DeniedNoAllowMatch);
    }

    private static bool TryCollect(
        IEnumerable<SubjectPermissionPattern?>? source,
        int maximumCount,
        out SubjectPermissionPattern[] patterns,
        out SubjectPermissionPolicyError error)
    {
        var collected = new List<SubjectPermissionPattern>(Math.Min(maximumCount, 16));
        var unique = new HashSet<SubjectPermissionPattern>();
        if (source is not null)
        {
            IEnumerator<SubjectPermissionPattern?> enumerator;
            try { enumerator = source.GetEnumerator(); }
            catch
            {
                patterns = [];
                error = SubjectPermissionPolicyError.EnumerationFailed;
                return false;
            }

            error = SubjectPermissionPolicyError.None;
            try
            {
                while (enumerator.MoveNext())
                {
                    if (collected.Count >= maximumCount)
                    {
                        error = SubjectPermissionPolicyError.TooManyPatterns;
                        break;
                    }

                    var pattern = enumerator.Current;
                    if (pattern is null)
                    {
                        error = SubjectPermissionPolicyError.NullPattern;
                        break;
                    }

                    if (!unique.Add(pattern))
                    {
                        error = SubjectPermissionPolicyError.DuplicatePattern;
                        break;
                    }

                    collected.Add(pattern);
                }
            }
            catch { error = SubjectPermissionPolicyError.EnumerationFailed; }
            try { enumerator.Dispose(); }
            catch { error = SubjectPermissionPolicyError.EnumerationFailed; }
            if (error != SubjectPermissionPolicyError.None)
            {
                patterns = [];
                return false;
            }
        }

        patterns = [.. collected];
        error = SubjectPermissionPolicyError.None;
        return true;
    }
}
