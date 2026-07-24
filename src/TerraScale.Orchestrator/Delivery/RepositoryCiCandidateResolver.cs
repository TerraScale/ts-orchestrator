using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using Cysharp.Text;

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

    internal static RepositoryCiQualifiedCandidate Restore(
        string expectedDigest,
        RepositoryCiCandidate candidate,
        IEnumerable<RepositoryCiQualifiedSource> sources)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(sources);
        if (!IsDigest(expectedDigest) || !IsDigest(candidate.Digest) ||
            candidate.Id != $"candidate-{candidate.Digest}")
            throw new InvalidDataException("Persisted qualification identity is invalid.");
        var sourceArray = sources.Take(65).ToArray();
        if (sourceArray.Length != candidate.Sources.Count || sourceArray.Any(static source => source is null) ||
            !sourceArray.SequenceEqual(sourceArray.OrderBy(static source => source.Repository, StringComparer.Ordinal)) ||
            sourceArray.Select(static source => source.Repository).Distinct(StringComparer.Ordinal).Count() != sourceArray.Length)
            throw new InvalidDataException("Persisted qualified sources are invalid.");
        var candidateByRepository = candidate.Sources.ToDictionary(static source => source.Repository, StringComparer.Ordinal);
        foreach (var source in sourceArray)
        {
            if (!candidateByRepository.TryGetValue(source.Repository, out var candidateSource) ||
                !IsObjectId(source.CandidateCommit) || !IsObjectId(source.MainCommit) || !IsObjectId(source.Tree) ||
                !StringComparer.OrdinalIgnoreCase.Equals(source.CandidateCommit, candidateSource.Commit) ||
                !StringComparer.OrdinalIgnoreCase.Equals(source.Tree, candidateSource.Tree))
                throw new InvalidDataException("Persisted qualification differs from its candidate source set.");
        }
        var digest = Digest(candidate, sourceArray);
        if (digest != expectedDigest)
            throw new InvalidDataException("Persisted qualification content does not match its digest.");
        return new($"qualified-{digest}", digest, candidate, ReadOnly(sourceArray.ToList()));
    }

    private static string Digest(
        RepositoryCiCandidate candidate,
        IReadOnlyList<RepositoryCiQualifiedSource> sources)
    {
        using var value = ZString.CreateStringBuilder();
        value.Append(candidate.Digest);
        value.Append('\n');
        foreach (var source in sources)
        {
            value.Append(source.Repository);
            value.Append(':');
            value.Append(source.CandidateCommit);
            value.Append(':');
            value.Append(source.MainCommit);
            value.Append(':');
            value.Append(source.Tree);
            value.Append('\n');
        }
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
