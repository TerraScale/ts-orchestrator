using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace TsOrch.Oci;

public sealed class OciRequestSigner(TimeProvider timeProvider)
{
    private const string ContentSha256Header = "x-content-sha256";
    private const string BodylessHeaders = "date (request-target) host";
    private const string BodyHeaders = "date (request-target) host content-length content-type x-content-sha256";

    public async Task SignAsync(HttpRequestMessage request, OciSigningKey key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(key);
        var uri = request.RequestUri is { IsAbsoluteUri: true } absolute
            ? absolute
            : throw new ArgumentException("OCI requests need an absolute request URI.", nameof(request));

        var date = timeProvider.GetUtcNow();
        request.Headers.Date = date;
        request.Headers.Host = uri.Authority;

        var signingString = new StringBuilder()
            .Append("date: ").Append(date.ToString("r", CultureInfo.InvariantCulture)).Append('\n')
            .Append("(request-target): ").Append(RequestTargetMethod(request.Method)).Append(' ').Append(uri.PathAndQuery).Append('\n')
            .Append("host: ").Append(uri.Authority);

        var signedHeaders = BodylessHeaders;
        if (CarriesBody(request.Method))
        {
            var content = request.Content ??= new ByteArrayContent([]);
            content.Headers.ContentType ??= new MediaTypeHeaderValue("application/json");
            var body = await content.ReadAsByteArrayAsync(cancellationToken);
            var contentSha256 = Convert.ToBase64String(SHA256.HashData(body));
            content.Headers.ContentLength = body.Length;
            request.Headers.Remove(ContentSha256Header);
            request.Headers.TryAddWithoutValidation(ContentSha256Header, contentSha256);
            signingString
                .Append("\ncontent-length: ").Append(body.Length.ToString(CultureInfo.InvariantCulture))
                .Append("\ncontent-type: ").Append(content.Headers.ContentType)
                .Append("\nx-content-sha256: ").Append(contentSha256);
            signedHeaders = BodyHeaders;
        }

        var signature = key.PrivateKey.SignData(
            Encoding.ASCII.GetBytes(signingString.ToString()),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Signature",
            $"version=\"1\",keyId=\"{key.KeyId}\",algorithm=\"rsa-sha256\",headers=\"{signedHeaders}\",signature=\"{Convert.ToBase64String(signature)}\"");
    }

    private static bool CarriesBody(HttpMethod method) =>
        method == HttpMethod.Post || method == HttpMethod.Put || method == HttpMethod.Patch;

    private static string RequestTargetMethod(HttpMethod method) => method.Method switch
    {
        "GET" => "get",
        "HEAD" => "head",
        "POST" => "post",
        "PUT" => "put",
        "PATCH" => "patch",
        "DELETE" => "delete",
        "OPTIONS" => "options",
        var other => throw new ArgumentException($"Unsupported OCI request method '{other}'.", nameof(method)),
    };
}
