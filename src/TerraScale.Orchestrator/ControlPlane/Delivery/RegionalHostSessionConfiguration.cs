using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.Core;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>Controller-owned public enrollment trust, loaded before any regional connection or mutation.</summary>
public sealed class RegionalHostSessionConfiguration
{
    private const int MaximumBytes = 32 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 8
    };

    private RegionalHostSessionConfiguration(RegionalHostEnrollmentPolicy policy) => Policy = policy;

    internal RegionalHostEnrollmentPolicy Policy { get; }
    public string Cell => Policy.Cell;

    public static RegionalHostSessionConfiguration? Load(string? path, string cell)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var resolved = NatsFileResolver.Resolve(path, "TS_ORCH_HOST_SESSION_POLICY_FILE", MaximumBytes, ownerPrivate: false);
        using var stream = File.OpenRead(resolved);
        var bytes = new byte[MaximumBytes + 1];
        var length = stream.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
        if (length is < 1 or > MaximumBytes)
            throw new InvalidDataException("The host session policy exceeds its bounds.");
        var document = JsonSerializer.Deserialize<PolicyDocument>(bytes.AsSpan(0, length), JsonOptions)
            ?? throw new InvalidDataException("The host session policy is empty.");
        if (document.SchemaVersion != 1 || document.Cell != cell ||
            document.MaximumGrantLifetimeSeconds is < 1 or > 86400 ||
            document.Roles is not { Length: > 0 and <= 32 } || document.Roles.Any(string.IsNullOrWhiteSpace) ||
            document.BootstrapTrust is null || document.BootstrapTrust.Keys is not { Length: > 0 and <= 8 } ||
            document.BootstrapTrust.Keys.Any(static key => key is null))
            throw new InvalidDataException("The host session policy requires its exact cell, scope, lifetime and trust bundle.");
        var account = document.NatsAccountPublicKey;
        if (account is not { Length: 56 } || account[0] != 'A' ||
            account.Any(static c => c is not (>= 'A' and <= 'Z' or >= '2' and <= '7')))
            throw new InvalidDataException("The host session policy requires a NATS account public key.");
        var decoded = NKeys.Decode(account);
        if (decoded.Length != 33 || decoded[0] != 0)
            throw new InvalidDataException("The host session policy requires a NATS account public key.");
        var trust = document.BootstrapTrust;
        var bundle = new RotatedBootstrapTrustBundle(trust.BundleVersion,
            trust.Keys.Select(static key =>
            {
                using var publicKey = ReadPublicKey(key.SubjectPublicKeyInfo);
                return new BootstrapTrustBundleKey(key.KeyId, key.KeyVersion, key.Purpose,
                    publicKey.ExportSubjectPublicKeyInfo(), key.AcceptedUntil);
            }).ToArray(),
            trust.CurrentGrantSigningKeyId, trust.CurrentGrantSigningKeyVersion);
        using var signer = ReadPublicKey(document.EnrollmentSignerPublicKey);
        return new(new RegionalHostEnrollmentPolicy(cell, account, document.ClusterName,
            new RegionalNodeEnrollmentScope(document.Environment, document.Roles.Select(HostRuntimeCli.ParseRole).ToArray()),
            document.EnrollmentSignerKeyId, document.EnrollmentSignerKeyVersion, signer, bundle,
            new BootstrapSystemProjectUlds(new(document.SystemOrganizationUlid), new(document.SystemProjectUlid), new(document.SystemDatabaseUlid)),
            document.BootstrapOperation, TimeSpan.FromSeconds(document.MaximumGrantLifetimeSeconds)));
    }

    private static ECDsa ReadPublicKey(string encoded)
    {
        var bytes = Convert.FromBase64String(encoded);
        var key = ECDsa.Create();
        try
        {
            key.ImportSubjectPublicKeyInfo(bytes, out var consumed);
            if (consumed != bytes.Length)
                throw new InvalidDataException("A host session policy key contains trailing data.");
            BootstrapTrustBundleKey.RequireP256(key);
            return key;
        }
        catch { key.Dispose(); throw; }
    }

    internal void ValidateStartup(OrchestratorOptions options, bool hasHostRoles)
    {
        if (options.Cell != Cell || options.Replicas != 3 ||
            options.Command is not (OrchestratorCommand.Run or OrchestratorCommand.Check) ||
            hasHostRoles || options.NatsTls is null ||
            (options.NatsNKeyFile is null && options.NatsCredentialsFile is null))
            throw new InvalidOperationException("Host session authority requires its authenticated R3 regional controller and cannot share the local host admission path.");
    }

    private sealed record PolicyDocument(int SchemaVersion, string Cell, string NatsAccountPublicKey,
        string ClusterName, string Environment, string[] Roles, string EnrollmentSignerKeyId,
        ulong EnrollmentSignerKeyVersion, string EnrollmentSignerPublicKey, string SystemOrganizationUlid,
        string SystemProjectUlid, string SystemDatabaseUlid, string BootstrapOperation,
        int MaximumGrantLifetimeSeconds, TrustDocument BootstrapTrust);

    private sealed record TrustDocument(ulong BundleVersion, string CurrentGrantSigningKeyId,
        ulong CurrentGrantSigningKeyVersion, TrustKeyDocument[] Keys);

    private sealed record TrustKeyDocument(string KeyId, ulong KeyVersion, BootstrapTrustKeyPurpose Purpose,
        string SubjectPublicKeyInfo, DateTimeOffset? AcceptedUntil);
}
