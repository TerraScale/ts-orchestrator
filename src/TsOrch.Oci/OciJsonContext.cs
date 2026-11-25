using System.Text.Json;
using System.Text.Json.Serialization;

namespace TsOrch.Oci;

internal sealed record class ImdsInstanceDocument(
    string Id,
    string CompartmentId,
    string CanonicalRegionName,
    string FaultDomain,
    string Shape,
    ImdsRegionInfo RegionInfo,
    IReadOnlyDictionary<string, JsonElement>? Metadata = null);

internal sealed record class ImdsRegionInfo(string RealmDomainComponent);

internal sealed record class ImdsVnicDocument(string PrivateIp);

internal sealed record class FederationRequestDocument(
    string Certificate,
    string PublicKey,
    IReadOnlyList<string> IntermediateCertificates,
    string Purpose,
    string FingerprintAlgorithm);

internal sealed record class FederationResponseDocument(string Token);

internal sealed record class SecurityTokenClaims(long Exp);

internal sealed record class SecretBundleDocument(
    string SecretId,
    long VersionNumber,
    SecretBundleContentDocument? SecretBundleContent = null);

internal sealed record class SecretBundleContentDocument(string ContentType, string Content);

internal sealed record class OciDockerTokenDocument(
    string Token,
    [property: JsonPropertyName("expires_in")] int? ExpiresIn = null);

internal sealed record class OciDockerTokenClaims(string? Sub = null);

internal sealed record class OciDockerTokenSubject(string? UserId = null, string? TenantId = null);

internal sealed record class DockerRegistryAuthDocument(string Username, string Password);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true)]
[JsonSerializable(typeof(ImdsInstanceDocument))]
[JsonSerializable(typeof(IReadOnlyList<ImdsVnicDocument>))]
[JsonSerializable(typeof(FederationRequestDocument))]
[JsonSerializable(typeof(FederationResponseDocument))]
[JsonSerializable(typeof(SecurityTokenClaims))]
[JsonSerializable(typeof(SecretBundleDocument))]
[JsonSerializable(typeof(OciDockerTokenDocument))]
[JsonSerializable(typeof(OciDockerTokenClaims))]
[JsonSerializable(typeof(OciDockerTokenSubject))]
[JsonSerializable(typeof(DockerRegistryAuthDocument))]
internal sealed partial class OciJsonContext : JsonSerializerContext;
