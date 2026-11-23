using System.Text.Json.Serialization;

namespace TsOrch.Oci;

internal sealed record class ImdsInstanceDocument(
    string Id,
    string CompartmentId,
    string CanonicalRegionName,
    string FaultDomain,
    string Shape,
    ImdsRegionInfo RegionInfo,
    IReadOnlyDictionary<string, string>? Metadata = null);

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
internal sealed partial class OciJsonContext : JsonSerializerContext;
