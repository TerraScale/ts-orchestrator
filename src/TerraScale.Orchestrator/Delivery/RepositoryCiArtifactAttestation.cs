using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal interface IRepositoryCiArtifactAttestationSigner
{
    string Identity { get; }
    OpaqueSignature Sign(ReadOnlyMemory<byte> canonicalMaterial);
}

internal interface IRepositoryCiArtifactSignatureVerifier
{
    VerificationOutcome Verify(
        string signingIdentity,
        ReadOnlyMemory<byte> canonicalMaterial,
        OpaqueSignature signature);
}

internal sealed record RepositoryCiSignedArtifact(
    RepositoryCiArtifactSubject Subject,
    SigningIdentityId SigningIdentity,
    SignatureId SignatureId,
    OpaqueSignature Signature);

internal sealed record RepositoryCiSignedRuntimeObservation(
    RepositoryCiArtifactSubject Subject,
    string RunnerIdentity,
    DigestId ObservedRuntimeDigest,
    SignatureId SignatureId,
    OpaqueSignature Signature);

/// <summary>
/// Domain-separates immutable artifact signatures from architecture-specific execution receipts.
/// Separate verifier instances allow the two proofs to use independent trust roots.
/// </summary>
internal static class RepositoryCiArtifactAttestation
{
    internal const int MaximumSignatureBytes = 16 * 1024;

    internal static RepositoryCiSignedArtifact Sign(
        RepositoryCiArtifactSubject subject,
        IRepositoryCiArtifactAttestationSigner signer)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(signer);
        var signingIdentity = new SigningIdentityId(signer.Identity);
        if (!Valid(subject) || !Identity(signingIdentity.Value))
            throw new ArgumentException("The artifact signing subject is invalid.");
        var signature = signer.Sign(ArtifactMaterial(subject, signingIdentity));
        RequireSignature(signature);
        return new(subject, signingIdentity, SignatureIdentity(signature), signature);
    }

    internal static RepositoryCiSignedRuntimeObservation ObserveRuntime(
        RepositoryCiArtifactSubject subject,
        DigestId observedRuntimeDigest,
        IRepositoryCiArtifactAttestationSigner signer)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(observedRuntimeDigest);
        ArgumentNullException.ThrowIfNull(signer);
        var runnerIdentity = signer.Identity;
        if (!Valid(subject) || subject.Architecture == RepositoryCiArchitecture.Any ||
            !Identity(runnerIdentity) || !Digest(observedRuntimeDigest.Value))
            throw new ArgumentException("The native runtime observation is invalid.");
        var signature = signer.Sign(RuntimeMaterial(subject, runnerIdentity, observedRuntimeDigest));
        RequireSignature(signature);
        return new(subject, runnerIdentity, observedRuntimeDigest, SignatureIdentity(signature), signature);
    }

    internal static RepositoryCiVerifiedArtifactAttestation? Validate(
        RepositoryCiArtifactSubject expected,
        RepositoryCiSignedArtifact? artifact,
        RepositoryCiSignedRuntimeObservation? runtime,
        IRepositoryCiArtifactSignatureVerifier artifactVerifier,
        IRepositoryCiArtifactSignatureVerifier runtimeVerifier)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(artifactVerifier);
        ArgumentNullException.ThrowIfNull(runtimeVerifier);
        if (!Valid(expected) || artifact is null || artifact.Subject != expected ||
            artifact.SigningIdentity is not { } signingIdentity || !Identity(signingIdentity.Value) ||
            !ValidSignature(artifact.SignatureId, artifact.Signature) ||
            artifactVerifier.Verify(
                signingIdentity.Value,
                ArtifactMaterial(expected, signingIdentity),
                artifact.Signature) !=
                VerificationOutcome.Valid)
            return null;

        if (expected.Architecture == RepositoryCiArchitecture.Any)
            return runtime is null
                ? new(signingIdentity, artifact.SignatureId, null)
                : null;
        if (runtime is null || runtime.Subject != expected || !Identity(runtime.RunnerIdentity) ||
            runtime.ObservedRuntimeDigest != expected.Digest ||
            !ValidSignature(runtime.SignatureId, runtime.Signature) ||
            runtimeVerifier.Verify(
                runtime.RunnerIdentity,
                RuntimeMaterial(expected, runtime.RunnerIdentity, runtime.ObservedRuntimeDigest),
                runtime.Signature) != VerificationOutcome.Valid)
            return null;
        return new(signingIdentity, artifact.SignatureId, runtime.ObservedRuntimeDigest);
    }

    internal static string SubjectDigest(RepositoryCiArtifactSubject subject)
    {
        ArgumentNullException.ThrowIfNull(subject);
        if (!Valid(subject)) throw new ArgumentException("The artifact subject is invalid.", nameof(subject));
        return Convert.ToHexStringLower(SHA256.HashData(Material(writer =>
        {
            writer.WriteString("domain", "terrascale.ci/artifact-subject/v1");
            WriteSubject(writer, subject);
        }).Span));
    }

    internal static bool StructurallyValid(RepositoryCiSignedArtifact? artifact) => artifact is not null &&
        Valid(artifact.Subject) && Identity(artifact.SigningIdentity?.Value) &&
        ValidSignature(artifact.SignatureId, artifact.Signature);

    internal static bool StructurallyValid(RepositoryCiSignedRuntimeObservation? runtime) => runtime is not null &&
        Valid(runtime.Subject) && runtime.Subject.Architecture != RepositoryCiArchitecture.Any &&
        Identity(runtime.RunnerIdentity) && Digest(runtime.ObservedRuntimeDigest?.Value) &&
        ValidSignature(runtime.SignatureId, runtime.Signature);

    internal static string EntrypointsDigest(
        RepositoryCiArchitecture architecture,
        IReadOnlyList<string>? entrypoints)
    {
        if (!TryEntrypointsDigest(architecture, entrypoints, out var digest))
            throw new ArgumentException("The artifact entrypoint set is invalid.", nameof(entrypoints));
        return digest;
    }

    internal static bool TryEntrypointsDigest(
        RepositoryCiArchitecture architecture,
        IReadOnlyList<string>? entrypoints,
        out string digest)
    {
        digest = string.Empty;
        if (entrypoints is null || !Enum.IsDefined(architecture) ||
            architecture == RepositoryCiArchitecture.Unspecified ||
            architecture == RepositoryCiArchitecture.Any && entrypoints.Count != 0 ||
            architecture != RepositoryCiArchitecture.Any && entrypoints.Count is not (>= 1 and <= 8) ||
            entrypoints.Any(static value => !Entrypoint(value)) ||
            entrypoints.Distinct(StringComparer.Ordinal).Count() != entrypoints.Count ||
            !entrypoints.SequenceEqual(entrypoints.Order(StringComparer.Ordinal), StringComparer.Ordinal))
            return false;
        digest = Convert.ToHexStringLower(SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(string.Join('\n', entrypoints))));
        return true;
    }

    private static ReadOnlyMemory<byte> ArtifactMaterial(
        RepositoryCiArtifactSubject subject,
        SigningIdentityId signingIdentity) => Material(writer =>
    {
        writer.WriteString("domain", "terrascale.ci/artifact-signature/v1");
        WriteSubject(writer, subject);
        writer.WriteString("signingIdentity", signingIdentity.Value);
    });

    private static ReadOnlyMemory<byte> RuntimeMaterial(
        RepositoryCiArtifactSubject subject,
        string runnerIdentity,
        DigestId observedRuntimeDigest) => Material(writer =>
    {
        writer.WriteString("domain", "terrascale.ci/native-runtime-observation/v1");
        WriteSubject(writer, subject);
        writer.WriteString("runnerIdentity", runnerIdentity);
        writer.WriteString("observedRuntimeDigest", observedRuntimeDigest.Value);
    });

    private static ReadOnlyMemory<byte> Material(Action<Utf8JsonWriter> write)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            write(writer);
            writer.WriteEndObject();
        }
        return bytes.WrittenMemory.ToArray();
    }

    private static void WriteSubject(Utf8JsonWriter writer, RepositoryCiArtifactSubject subject)
    {
        writer.WriteString("pipelineDigest", subject.PipelineDigest);
        writer.WriteString("job", subject.Job.Value);
        writer.WriteString("artifact", subject.Artifact.Value);
        writer.WriteString("architecture", subject.Architecture.ToString());
        writer.WriteString("digest", subject.Digest.Value);
        writer.WriteString("entrypointsDigest", subject.EntrypointsDigest);
    }

    private static void RequireSignature(OpaqueSignature? signature)
    {
        if (signature is not { IsValid: true } || signature.Length > MaximumSignatureBytes)
            throw new InvalidDataException("The artifact attestation signer returned an invalid signature.");
    }

    private static bool ValidSignature(SignatureId? identity, OpaqueSignature? signature) =>
        identity is not null && signature is { IsValid: true } &&
        signature.Length <= MaximumSignatureBytes && identity == SignatureIdentity(signature);

    private static SignatureId SignatureIdentity(OpaqueSignature signature) => new(
        $"ci-signature-{Convert.ToHexStringLower(SHA256.HashData(signature.Bytes))}");

    private static bool Valid(RepositoryCiArtifactSubject subject) =>
        Digest(subject.PipelineDigest) && Identity(subject.Job?.Value) && Artifact(subject.Artifact?.Value) &&
        Enum.IsDefined(subject.Architecture) &&
        subject.Architecture != RepositoryCiArchitecture.Unspecified && Digest(subject.Digest?.Value) &&
        Digest(subject.EntrypointsDigest);

    private static bool Artifact(string? value) => value is { Length: >= 1 and <= 256 } &&
        value[0] != '/' && !value.Contains("//", StringComparison.Ordinal) &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or
            >= '0' and <= '9' or '.' or '_' or '-' or '/') &&
        value.Split('/').All(static segment => segment is not ("" or "." or ".."));

    private static bool Entrypoint(string? value) => value is { Length: >= 1 and <= 1024 } &&
        value[0] != '/' && !value.EndsWith('/') && !value.Contains("//", StringComparison.Ordinal) &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or
            >= '0' and <= '9' or '.' or '_' or '-' or '/') &&
        value.Split('/').All(static segment => segment is not ("" or "." or ".."));

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool Identity(string? value) => value is { Length: >= 1 and <= 512 } &&
        !value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character));
}

/// <summary>Loads both signed proofs for one exact subject and verifies them before projection.</summary>
internal sealed class RepositoryCiSignedArtifactAttestationVerifier(
    Func<RepositoryCiArtifactSubject, CancellationToken, Task<RepositoryCiSignedArtifact?>> readArtifact,
    Func<RepositoryCiArtifactSubject, CancellationToken, Task<RepositoryCiSignedRuntimeObservation?>> readRuntime,
    IRepositoryCiArtifactSignatureVerifier artifactVerifier,
    IRepositoryCiArtifactSignatureVerifier runtimeVerifier) : IRepositoryCiArtifactAttestationVerifier
{
    private readonly Func<RepositoryCiArtifactSubject, CancellationToken,
        Task<RepositoryCiSignedArtifact?>> readArtifact = readArtifact ??
            throw new ArgumentNullException(nameof(readArtifact));
    private readonly Func<RepositoryCiArtifactSubject, CancellationToken,
        Task<RepositoryCiSignedRuntimeObservation?>> readRuntime = readRuntime ??
            throw new ArgumentNullException(nameof(readRuntime));
    private readonly IRepositoryCiArtifactSignatureVerifier artifactVerifier = artifactVerifier ??
        throw new ArgumentNullException(nameof(artifactVerifier));
    private readonly IRepositoryCiArtifactSignatureVerifier runtimeVerifier = runtimeVerifier ??
        throw new ArgumentNullException(nameof(runtimeVerifier));

    public async Task<RepositoryCiVerifiedArtifactAttestation?> VerifyAsync(
        RepositoryCiArtifactSubject subject,
        CancellationToken cancellationToken)
    {
        var artifact = await readArtifact(subject, cancellationToken);
        var runtime = subject.Architecture == RepositoryCiArchitecture.Any
            ? null
            : await readRuntime(subject, cancellationToken);
        return RepositoryCiArtifactAttestation.Validate(
            subject,
            artifact,
            runtime,
            artifactVerifier,
            runtimeVerifier);
    }
}

internal sealed class RepositoryCiArtifactProofAuthorityLostException : Exception { }

/// <summary>
/// Mints the controller-owned artifact signature only after the candidate reader has derived an
/// exact subject from read-verified runner evidence. Native-runtime proof remains independent.
/// </summary>
internal sealed class RepositoryCiIssuingArtifactAttestationVerifier(
    RepositoryCiArtifactAttestationJournal journal,
    IRepositoryCiArtifactAttestationSigner signer,
    IRepositoryCiArtifactAttestationVerifier verifier,
    long authorityEpoch,
    long sequence,
    Func<bool> authorityStillValid) : IRepositoryCiArtifactAttestationVerifier
{
    private readonly RepositoryCiArtifactAttestationJournal journal = journal ??
        throw new ArgumentNullException(nameof(journal));
    private readonly IRepositoryCiArtifactAttestationSigner signer = signer ??
        throw new ArgumentNullException(nameof(signer));
    private readonly IRepositoryCiArtifactAttestationVerifier verifier = verifier ??
        throw new ArgumentNullException(nameof(verifier));
    private readonly Func<bool> authorityStillValid = authorityStillValid ??
        throw new ArgumentNullException(nameof(authorityStillValid));

    public async Task<RepositoryCiVerifiedArtifactAttestation?> VerifyAsync(
        RepositoryCiArtifactSubject subject,
        CancellationToken cancellationToken)
    {
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        if (!authorityStillValid()) throw new RepositoryCiArtifactProofAuthorityLostException();

        if (await journal.ReadArtifactAsync(subject, cancellationToken) is null)
        {
            var disposition = await journal.RecordArtifactAsync(
                RepositoryCiArtifactAttestation.Sign(subject, signer),
                authorityEpoch,
                sequence,
                authorityStillValid,
                cancellationToken);
            if (disposition == RepositoryCiArtifactAttestationJournalDisposition.StaleAuthority)
                throw new RepositoryCiArtifactProofAuthorityLostException();
            if (disposition == RepositoryCiArtifactAttestationJournalDisposition.IdentityConflict)
                throw new InvalidDataException("The artifact subject already has a different signed proof.");
            if (disposition is not (RepositoryCiArtifactAttestationJournalDisposition.Recorded or
                    RepositoryCiArtifactAttestationJournalDisposition.Duplicate))
                throw new InvalidDataException("The artifact proof journal returned an unspecified disposition.");
        }
        if (!authorityStillValid()) throw new RepositoryCiArtifactProofAuthorityLostException();
        return await verifier.VerifyAsync(subject, cancellationToken);
    }
}
