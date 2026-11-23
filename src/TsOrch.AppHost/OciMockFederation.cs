using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace TsOrch.AppHost;

internal sealed class OciMockFederation(OciMockIdentity identity, TimeProvider timeProvider)
{
    private const string GetHeaders = "date (request-target) host";
    private const string PostHeaders = "date (request-target) host content-length content-type x-content-sha256";

    private readonly byte[] _tokenKey = RandomNumberGenerator.GetBytes(32);

    public string? Issue(HttpRequest request, MockFederationRequest document, ReadOnlySpan<byte> body)
    {
        if (document.Purpose != "DEFAULT" || document.FingerprintAlgorithm != "SHA256"
            || document.IntermediateCertificates is not [var intermediate])
        {
            return null;
        }

        using var leaf = X509Certificate2.CreateFromPem(identity.LeafCertificatePem);
        using var issuer = X509Certificate2.CreateFromPem(identity.IntermediateCertificatePem);
        if (document.Certificate != Convert.ToBase64String(leaf.RawData) || intermediate != Convert.ToBase64String(issuer.RawData)
            || leaf.GetRSAPublicKey() is not { } leafKey)
        {
            return null;
        }

        using (leafKey)
        {
            var fingerprint = string.Join(':', leaf.GetCertHash(HashAlgorithmName.SHA256).Select(static octet => octet.ToString("X2", CultureInfo.InvariantCulture)));
            var keyId = $"{OciMockIdentity.TenancyId}/fed-x509-sha256/{fingerprint}";
            if (!Verify(request, keyId, leafKey, PostHeaders, body))
            {
                return null;
            }
        }

        using var sessionKey = RSA.Create();
        if (!ImportKey(sessionKey, document.PublicKey))
        {
            return null;
        }

        var claims = new MockFederationClaims(timeProvider.GetUtcNow().AddHours(1).ToUnixTimeSeconds(), document.PublicKey);
        var payload = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(claims, AppHostJsonContext.Default.MockFederationClaims));
        var unsigned = $"eyJhbGciOiJIUzI1NiJ9.{payload}";
        return $"{unsigned}.{Base64Url.EncodeToString(HMACSHA256.HashData(_tokenKey, Encoding.ASCII.GetBytes(unsigned)))}";
    }

    public bool VerifyVault(HttpRequest request)
    {
        const string prefix = "Signature version=\"1\",keyId=\"ST$";
        var header = request.Headers.Authorization.ToString();
        if (!header.StartsWith(prefix, StringComparison.Ordinal)
            || header.IndexOf('"', prefix.Length) is var end && end < 0)
        {
            return false;
        }

        var token = header[prefix.Length..end];
        if (token.Split('.') is not [var jwtHeader, var payload, var signature]
            || !Base64Url.IsValid(signature) || !Base64Url.IsValid(payload))
        {
            return false;
        }

        var expected = HMACSHA256.HashData(_tokenKey, Encoding.ASCII.GetBytes($"{jwtHeader}.{payload}"));
        if (!CryptographicOperations.FixedTimeEquals(expected, Base64Url.DecodeFromChars(signature))
            || JsonSerializer.Deserialize(Base64Url.DecodeFromChars(payload), AppHostJsonContext.Default.MockFederationClaims) is not { } claims
            || claims.Exp <= timeProvider.GetUtcNow().ToUnixTimeSeconds())
        {
            return false;
        }

        using var key = RSA.Create();
        return ImportKey(key, claims.PublicKey) && Verify(request, $"ST${token}", key, GetHeaders, []);
    }

    private static bool Verify(HttpRequest request, string keyId, RSA key, string headers, ReadOnlySpan<byte> body)
    {
        var prefix = $"Signature version=\"1\",keyId=\"{keyId}\",algorithm=\"rsa-sha256\",headers=\"{headers}\",signature=\"";
        var authorization = request.Headers.Authorization.ToString();
        if (!authorization.StartsWith(prefix, StringComparison.Ordinal) || !authorization.EndsWith('"')
            || authorization.Length <= prefix.Length + 1
            || !Base64.IsValid(authorization.AsSpan(prefix.Length, authorization.Length - prefix.Length - 1))
            || request.HttpContext.Features.Get<IHttpRequestFeature>()?.RawTarget is not { Length: > 0 } target
            || request.Headers.Date.ToString() is not { Length: > 0 } date)
        {
            return false;
        }

        var canonical = $"date: {date}\n(request-target): {request.Method.ToLowerInvariant()} {target}\nhost: {request.Host}";
        if (headers == PostHeaders)
        {
            var digest = Convert.ToBase64String(SHA256.HashData(body));
            if (request.Headers["x-content-sha256"].ToString() != digest
                || request.ContentLength != body.Length || request.ContentType is not { } contentType)
            {
                return false;
            }

            canonical += string.Create(CultureInfo.InvariantCulture, $"\ncontent-length: {body.Length}\ncontent-type: {contentType}\nx-content-sha256: {digest}");
        }

        return key.VerifyData(Encoding.ASCII.GetBytes(canonical), Convert.FromBase64String(authorization[prefix.Length..^1]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static bool ImportKey(RSA key, string input)
    {
        if (!Base64.IsValid(input))
        {
            return false;
        }

        try
        {
            var encoded = Convert.FromBase64String(input);
            key.ImportSubjectPublicKeyInfo(encoded, out var consumed);
            return consumed == encoded.Length && key.KeySize >= 2048;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
