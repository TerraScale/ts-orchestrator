using System.Buffers.Text;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using TsOrch.Protocol;

namespace TsOrch.Oci;

public sealed class OciInstancePrincipal(
    HttpClient httpClient,
    OciEnvironment environment,
    OciImdsClient imds,
    OciRequestSigner signer,
    TimeProvider timeProvider) : IDisposable
{
    private const string OrganizationalUnitOid = "2.5.4.11";
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromMinutes(5);
    private static readonly AuthenticationHeaderValue MockAuthorization = new("Bearer", OciEnvironment.MockBearerToken);

    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private OciSession? _session;

    public async Task<OrchResult<Done>> AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return environment switch
        {
            OciMock => AuthorizeMock(request),
            OciCloud => await SignAsync(request, cancellationToken),
        };
    }

    public async Task<OrchResult<OciSigningKey>> GetSigningKeyAsync(CancellationToken cancellationToken)
    {
        if (CurrentSession() is { } current)
        {
            return current.Key;
        }

        await _refreshGate.WaitAsync(cancellationToken);
        try
        {
            if (CurrentSession() is { } refreshedConcurrently)
            {
                return refreshedConcurrently.Key;
            }

            var sessionResult = await FederateAsync(cancellationToken);
            if (!sessionResult.TryGetValue(out var session, out var error))
            {
                return error;
            }

            Volatile.Write(ref _session, session);
            return session.Key;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    public void Dispose()
    {
        _refreshGate.Dispose();
        Volatile.Read(ref _session)?.Key.PrivateKey.Dispose();
    }

    private static Done AuthorizeMock(HttpRequestMessage request)
    {
        request.Headers.Authorization = MockAuthorization;
        return new Done();
    }

    private async Task<OrchResult<Done>> SignAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var keyResult = await GetSigningKeyAsync(cancellationToken);
        if (!keyResult.TryGetValue(out var key, out var error))
        {
            return error;
        }

        await signer.SignAsync(request, key, cancellationToken);
        return new Done();
    }

    private OciSession? CurrentSession() =>
        Volatile.Read(ref _session) is { } session && session.ExpiresAt - RefreshMargin > timeProvider.GetUtcNow()
            ? session
            : null;

    private async Task<OrchResult<OciSession>> FederateAsync(CancellationToken cancellationToken)
    {
        var identityResult = await imds.GetIdentityAsync(cancellationToken);
        if (!identityResult.TryGetValue(out var identity, out var identityError))
        {
            return identityError;
        }

        var materialResult = await imds.GetFederationMaterialAsync(cancellationToken);
        if (!materialResult.TryGetValue(out var material, out var materialError))
        {
            return materialError;
        }

        using var leaf = X509Certificate2.CreateFromPem(material.LeafCertificatePem);
        using var intermediate = X509Certificate2.CreateFromPem(material.IntermediateCertificatePem);
        if (TenancyId(leaf) is not { } tenancyId)
        {
            return new Internal("OCI instance identity certificate carries no opc-tenant or opc-identity subject.");
        }

        using var leafKey = RSA.Create();
        leafKey.ImportFromPem(material.LeafPrivateKeyPem);

        var sessionKey = RSA.Create(2048);
        try
        {
            var document = new FederationRequestDocument(
                Convert.ToBase64String(leaf.RawData),
                Convert.ToBase64String(sessionKey.ExportSubjectPublicKeyInfo()),
                [Convert.ToBase64String(intermediate.RawData)],
                "DEFAULT",
                "SHA256");
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                new Uri($"https://auth.{identity.Region}.{identity.RealmDomain}/v1/x509"));
            request.Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(document, OciJsonContext.Default.FederationRequestDocument));
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            await signer.SignAsync(
                request,
                new OciSigningKey($"{tenancyId}/fed-x509-sha256/{Fingerprint(leaf)}", leafKey),
                cancellationToken);

            var responseResult = await OciHttp.SendJsonAsync(httpClient, request, OciJsonContext.Default.FederationResponseDocument, cancellationToken);
            if (!responseResult.TryGetValue(out var response, out var responseError))
            {
                return responseError;
            }

            if (ExpiresAt(response.Token) is not { } expiresAt)
            {
                return new Internal("OCI federation returned a security token without a readable exp claim.");
            }

            var session = new OciSession(new OciSigningKey("ST$" + response.Token, sessionKey), expiresAt);
            sessionKey = null;
            return session;
        }
        finally
        {
            sessionKey?.Dispose();
        }
    }

    private static string? TenancyId(X509Certificate2 certificate)
    {
        foreach (var name in certificate.SubjectName.EnumerateRelativeDistinguishedNames())
        {
            if (name.GetSingleElementType().Value != OrganizationalUnitOid || name.GetSingleElementValue() is not { } value)
            {
                continue;
            }

            if (value.StartsWith("opc-tenant:", StringComparison.Ordinal))
            {
                return value["opc-tenant:".Length..];
            }

            if (value.StartsWith("opc-identity:", StringComparison.Ordinal))
            {
                return value["opc-identity:".Length..];
            }
        }

        return null;
    }

    private static string Fingerprint(X509Certificate2 certificate) =>
        string.Join(':', certificate.GetCertHash(HashAlgorithmName.SHA256).Select(static octet => octet.ToString("X2", CultureInfo.InvariantCulture)));

    private static DateTimeOffset? ExpiresAt(string token)
    {
        var segments = token.Split('.');
        if (segments.Length != 3 || !Base64Url.IsValid(segments[1]))
        {
            return null;
        }

        try
        {
            var claims = JsonSerializer.Deserialize(Base64Url.DecodeFromChars(segments[1]), OciJsonContext.Default.SecurityTokenClaims);
            return claims is null ? null : DateTimeOffset.FromUnixTimeSeconds(claims.Exp);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private sealed record class OciSession(OciSigningKey Key, DateTimeOffset ExpiresAt);
}
