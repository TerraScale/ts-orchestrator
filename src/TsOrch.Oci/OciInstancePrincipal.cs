using System.Buffers.Text;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace TsOrch.Oci;

public readonly record struct OciRequestSigned;

public sealed record class InvalidFederationCredentials(string Message);

public sealed record class FederationRejected(HttpStatusCode Status, string Message);

public sealed record class FederationUnavailable(string Message);

public sealed record class FederationTokenInvalid(string Message);

public readonly union OciAuthorization(
    OciRequestSigned, ImdsRequestRejected, ImdsUnavailable, ImdsDocumentInvalid,
    InvalidFederationCredentials, FederationRejected, FederationUnavailable, FederationTokenInvalid);

public sealed class OciInstancePrincipal(
    HttpClient httpClient,
    OciEnvironment environment,
    OciImdsClient imds,
    OciRequestSigner signer,
    TimeProvider timeProvider) : IDisposable
{
    private const string OrganizationalUnitOid = "2.5.4.11";
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromMinutes(5);

    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private OciSession? _session;

    public async Task<OciAuthorization> AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        await _refreshGate.WaitAsync(cancellationToken);
        try
        {
            if (_session is { } cached && cached.ExpiresAt - RefreshMargin > timeProvider.GetUtcNow())
            {
                return await SignWithAsync(request, cached, cancellationToken);
            }

            var federated = await FederateAsync(cancellationToken);
            return federated switch
            {
                OciSession session => await RememberAndSignAsync(request, session, cancellationToken),
                ImdsRequestRejected rejected => rejected,
                ImdsUnavailable unavailable => unavailable,
                ImdsDocumentInvalid invalid => invalid,
                InvalidFederationCredentials invalid => invalid,
                FederationRejected rejected => rejected,
                FederationUnavailable unavailable => unavailable,
                FederationTokenInvalid invalid => invalid,
            };
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    public void Dispose()
    {
        _session?.Key.PrivateKey.Dispose();
        _refreshGate.Dispose();
    }

    private async Task<OciRequestSigned> SignWithAsync(HttpRequestMessage request, OciSession session, CancellationToken cancellationToken)
    {
        await signer.SignAsync(request, session.Key, cancellationToken);
        return new OciRequestSigned();
    }

    private async Task<OciRequestSigned> RememberAndSignAsync(HttpRequestMessage request, OciSession session, CancellationToken cancellationToken)
    {
        _session?.Key.PrivateKey.Dispose();
        _session = session;
        return await SignWithAsync(request, session, cancellationToken);
    }

    private async Task<FederationSession> FederateAsync(CancellationToken cancellationToken)
    {
        var identity = await imds.GetIdentityAsync(cancellationToken);
        return identity switch
        {
            OciInstanceIdentity instance => await FetchMaterialAsync(instance, cancellationToken),
            ImdsRequestRejected rejected => rejected,
            ImdsUnavailable unavailable => unavailable,
            ImdsDocumentInvalid invalid => invalid,
        };
    }

    private async Task<FederationSession> FetchMaterialAsync(OciInstanceIdentity identity, CancellationToken cancellationToken)
    {
        var read = await imds.GetFederationMaterialAsync(cancellationToken);
        return read switch
        {
            OciFederationMaterial material => await FederateAsync(identity, material, cancellationToken),
            ImdsRequestRejected rejected => rejected,
            ImdsUnavailable unavailable => unavailable,
        };
    }

    private async Task<FederationSession> FederateAsync(OciInstanceIdentity identity, OciFederationMaterial material, CancellationToken cancellationToken)
    {
        var decoded = DecodeMaterial(material);
        return decoded switch
        {
            FederationCredentials credentials => await RequestSessionAsync(identity, credentials, cancellationToken),
            InvalidFederationCredentials invalid => invalid,
        };
    }

    private static FederationMaterial DecodeMaterial(OciFederationMaterial material)
    {
        try
        {
            using var leaf = X509Certificate2.CreateFromPem(material.LeafCertificatePem, material.LeafPrivateKeyPem);
            using var intermediate = X509Certificate2.CreateFromPem(material.IntermediateCertificatePem);
            if (TenancyId(leaf) is not { Length: > 0 } tenancyId || leaf.GetRSAPrivateKey() is not { } key)
            {
                return new InvalidFederationCredentials("OCI instance identity requires an RSA key and an opc-tenant or opc-identity subject.");
            }

            return new FederationCredentials(
                new OciSigningKey($"{tenancyId}/fed-x509-sha256/{Fingerprint(leaf)}", key),
                Convert.ToBase64String(leaf.RawData), Convert.ToBase64String(intermediate.RawData));
        }
        catch (CryptographicException exception)
        {
            return new InvalidFederationCredentials($"OCI instance identity PEM is invalid: {exception.Message}");
        }
        catch (ArgumentException exception)
        {
            return new InvalidFederationCredentials($"OCI instance identity PEM is invalid: {exception.Message}");
        }
    }

    private async Task<FederationSession> RequestSessionAsync(OciInstanceIdentity identity, FederationCredentials credentials, CancellationToken cancellationToken)
    {
        using var leafKey = credentials.Key.PrivateKey;
        var sessionKey = RSA.Create(2048);
        var transferred = false;
        try
        {
            var document = new FederationRequestDocument(credentials.Certificate,
                Convert.ToBase64String(sessionKey.ExportSubjectPublicKeyInfo()), [credentials.Intermediate], "DEFAULT", "SHA256");
            var endpoint = environment switch
            {
                OciMock mock => new Uri(mock.BaseUrl, "v1/x509"),
                OciCloud => new Uri($"https://auth.{identity.Region}.{identity.RealmDomain}/v1/x509"),
            };
            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
            request.Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(document, OciJsonContext.Default.FederationRequestDocument));
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            await signer.SignAsync(request, credentials.Key, cancellationToken);

            var response = await OciHttp.SendAsync(httpClient, request, cancellationToken);
            var exchange = response switch
            {
                OciPayload payload => ReadSession(payload.Body, sessionKey),
                OciHttpRejected rejected => (FederationExchange)new FederationRejected(rejected.Status, rejected.Message),
                OciConnectionLost lost => (FederationExchange)new FederationUnavailable(lost.Message),
                OciResponseTimedOut => (FederationExchange)new FederationUnavailable("OCI federation response timed out."),
            };
            return exchange switch
            {
                OciSession session => TransferSession(session, ref transferred),
                FederationRejected rejected => rejected,
                FederationUnavailable unavailable => unavailable,
                FederationTokenInvalid invalid => invalid,
            };
        }
        finally
        {
            if (!transferred)
            {
                sessionKey.Dispose();
            }
        }
    }

    private static OciSession TransferSession(OciSession session, ref bool transferred)
    {
        transferred = true;
        return session;
    }

    private FederationExchange ReadSession(string payload, RSA sessionKey)
    {
        var document = OciHttp.Decode(payload, OciJsonContext.Default.FederationResponseDocument, out var error);
        if (document is null)
        {
            return new FederationTokenInvalid(error ?? "OCI federation response is missing.");
        }

        return ExpiresAt(document.Token) is { } expiry && expiry > timeProvider.GetUtcNow()
            ? new OciSession(new OciSigningKey("ST$" + document.Token, sessionKey), expiry)
            : new FederationTokenInvalid("OCI federation returned a security token without a valid future exp claim.");
    }

    private static string? TenancyId(X509Certificate2 certificate)
    {
        foreach (var name in certificate.SubjectName.EnumerateRelativeDistinguishedNames())
        {
            if (name.HasMultipleElements || name.GetSingleElementType().Value != OrganizationalUnitOid || name.GetSingleElementValue() is not { } value)
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
            return claims is { Exp: >= -62_135_596_800 and <= 253_402_300_799 } ? DateTimeOffset.FromUnixTimeSeconds(claims.Exp) : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private sealed record class OciSession(OciSigningKey Key, DateTimeOffset ExpiresAt);

    private sealed record class FederationCredentials(OciSigningKey Key, string Certificate, string Intermediate);

    private readonly union FederationMaterial(FederationCredentials, InvalidFederationCredentials);

    private readonly union FederationExchange(OciSession, FederationRejected, FederationUnavailable, FederationTokenInvalid);

    private readonly union FederationSession(OciSession, ImdsRequestRejected, ImdsUnavailable, ImdsDocumentInvalid,
        InvalidFederationCredentials, FederationRejected, FederationUnavailable, FederationTokenInvalid);
}
