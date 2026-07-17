using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

public sealed record RepositoryCiQualifiedSource(
    string Repository,
    string CandidateCommit,
    string MainCommit,
    string Tree);

public sealed class RepositoryCiQualifiedCandidate
{
    internal RepositoryCiQualifiedCandidate(
        string id,
        string digest,
        RepositoryCiCandidate candidate,
        IReadOnlyList<RepositoryCiQualifiedSource> sources)
    {
        Id = id;
        Digest = digest;
        Candidate = candidate;
        Sources = sources;
    }

    public string Id { get; }
    public string Digest { get; }
    public RepositoryCiCandidate Candidate { get; }
    public IReadOnlyList<RepositoryCiQualifiedSource> Sources { get; }
}

/// <summary>Resolves a main push to the exact already-tested multi-repository tree set.</summary>
public static class RepositoryCiCandidateResolver
{
    public static RepositoryCiQualifiedCandidate Resolve(
        ForgejoCiTriggerPlan trigger,
        RepositoryCiCandidate candidate,
        IEnumerable<ForgejoBranchObservation> currentMainSources)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(currentMainSources);
        if (trigger.Disposition != ForgejoCiTriggerDisposition.Dispatch ||
            trigger.JobKind != JobKind.Promotion || !trigger.RequiresQualifiedCandidate ||
            trigger.Envelope.Kind != ForgejoWebhookKind.Push || trigger.Envelope.SourceRef != "refs/heads/main")
            throw new InvalidOperationException("Only an admitted main push can resolve a qualified candidate.");
        if (!IsDigest(candidate.Digest) || candidate.Id != $"candidate-{candidate.Digest}" ||
            candidate.Sources is not { Count: > 0 and <= 64 } ||
            candidate.Sources.Any(static source => !source.SignatureVerified ||
                !ForgejoWebhookVerifier.IsRepository(source.Repository) ||
                !IsObjectId(source.Commit) || !IsObjectId(source.Tree)))
            throw new InvalidDataException("The release candidate source set is invalid.");

        var mainArray = currentMainSources.Take(65).ToArray();
        if (mainArray.Length != candidate.Sources.Count || mainArray.Any(static source => source is null))
            throw new InvalidDataException("Current main sources must exactly cover the release candidate.");
        foreach (var observation in mainArray)
        {
            var source = observation.Revision;
            if (observation.Branch != "main" || !observation.Protected || !source.SignatureVerified ||
                !ForgejoWebhookVerifier.IsRepository(source.Repository) || !IsObjectId(source.Commit) ||
                !IsObjectId(source.Tree))
                throw new InvalidDataException("A current main source is unsigned or invalid.");
        }
        Dictionary<string, ForgejoResolvedRevision> mainByRepository;
        try
        {
            mainByRepository = mainArray.ToDictionary(
                static observation => observation.Revision.Repository,
                static observation => observation.Revision,
                StringComparer.Ordinal);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException("Current main sources contain a duplicate repository.", exception);
        }
        if (!candidate.Sources.Select(static source => source.Repository).ToHashSet(StringComparer.Ordinal)
            .SetEquals(mainByRepository.Keys))
            throw new InvalidDataException("Current main sources do not match the candidate release set.");
        if (!mainByRepository.TryGetValue(trigger.Envelope.Repository, out var triggeringMain) ||
            !StringComparer.OrdinalIgnoreCase.Equals(triggeringMain.Commit, trigger.Envelope.Revision))
            throw new InvalidDataException("The main webhook revision is not the resolved triggering repository.");

        var qualified = new List<RepositoryCiQualifiedSource>(candidate.Sources.Count);
        foreach (var source in candidate.Sources.OrderBy(static source => source.Repository, StringComparer.Ordinal))
        {
            var main = mainByRepository[source.Repository];
            if (!StringComparer.OrdinalIgnoreCase.Equals(main.Tree, source.Tree))
                throw new InvalidDataException("A current main tree differs from the exact tested candidate tree.");
            qualified.Add(new(
                source.Repository,
                source.Commit.ToLowerInvariant(),
                main.Commit.ToLowerInvariant(),
                source.Tree.ToLowerInvariant()));
        }

        var digest = Digest(candidate, qualified);
        return new($"qualified-{digest}", digest, candidate, ReadOnly(qualified));
    }

    private static string Digest(
        RepositoryCiCandidate candidate,
        IReadOnlyList<RepositoryCiQualifiedSource> sources)
    {
        var value = new StringBuilder(candidate.Digest).Append('\n');
        foreach (var source in sources)
            value.Append(source.Repository).Append(':')
                .Append(source.CandidateCommit).Append(':')
                .Append(source.MainCommit).Append(':')
                .Append(source.Tree).Append('\n');
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value.ToString())));
    }

    private static bool IsObjectId(string? value) => value is { Length: 40 or 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F') &&
        value.Any(static character => character != '0');

    private static bool IsDigest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static IReadOnlyList<T> ReadOnly<T>(List<T> values) =>
        new ReadOnlyCollection<T>(values.ToArray());
}
