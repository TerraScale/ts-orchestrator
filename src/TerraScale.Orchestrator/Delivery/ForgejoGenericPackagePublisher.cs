using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace TerraScale.Orchestrator.Delivery;

internal enum ForgejoGenericPackagePublicationDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    StaleAuthority,
    IdentityConflict,
}

internal sealed record ForgejoGenericPackagePublicationReceipt(
    ForgejoGenericPackagePublicationDisposition Disposition);

internal interface IForgejoGenericPackagePublisher
{
    Task<ForgejoGenericPackagePublicationReceipt> PublishAsync(
        string repository,
        string package,
        string version,
        string fileName,
        string sha256,
        long bytes,
        Func<Stream, CancellationToken, Task> copyContent,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default);
}

/// <summary>Publishes one immutable generic package file and verifies its exact readback.</summary>
internal sealed class ForgejoGenericPackagePublisher : IForgejoGenericPackagePublisher, IAsyncDisposable
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromMinutes(5);
    private const long MaximumPackageBytes = 2L * 1024 * 1024 * 1024 + 64L * 1024 * 1024;
    private readonly ForgejoSourceConfiguration configuration;
    private readonly HttpClient client;

    internal ForgejoGenericPackagePublisher(
        ForgejoSourceConfiguration configuration,
        HttpClient client)
    {
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.client = client ?? throw new ArgumentNullException(nameof(client));
    }

    internal static ForgejoGenericPackagePublisher Create(ForgejoSourceConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return new(configuration, new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
        })
        {
            Timeout = Timeout.InfiniteTimeSpan,
        });
    }

    public ValueTask DisposeAsync()
    {
        client.Dispose();
        return ValueTask.CompletedTask;
    }

    public async Task<ForgejoGenericPackagePublicationReceipt> PublishAsync(
        string repository,
        string package,
        string version,
        string fileName,
        string sha256,
        long bytes,
        Func<Stream, CancellationToken, Task> copyContent,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        Validate(repository, package, version, fileName, sha256, bytes);
        ArgumentNullException.ThrowIfNull(copyContent);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (!authorityStillValid()) return Stale();

        var owner = repository[..repository.IndexOf('/')];
        var uri = PackageUri(owner, package, version, fileName);
        var existing = await ReadAsync(uri, sha256, bytes, cancellationToken);
        if (existing is ExistingPackage.Exact)
            return authorityStillValid() ? Duplicate() : Stale();
        if (existing is ExistingPackage.Conflict) return Conflict();
        if (!authorityStillValid()) return Stale();
        using (var verifiedSource = new HashingWriteStream(bytes))
        {
            await copyContent(verifiedSource, cancellationToken);
            var verified = verifiedSource.Complete();
            if (verified.Bytes != bytes || verified.Sha256 != sha256)
                throw new InvalidDataException("The package source differs from its declared identity.");
        }
        if (!authorityStillValid()) return Stale();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(RequestTimeout);
        using var request = Request(HttpMethod.Put, uri);
        request.Content = new CopyContent(bytes, copyContent, authorityStillValid);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        }
        catch (Exception exception) when (CausedByAuthorityLoss(exception))
        {
            return Stale();
        }
        var status = response.StatusCode;
        using (response)
        {
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                throw new UnauthorizedAccessException("Forgejo package credentials were denied.");
            if (response.StatusCode is not (HttpStatusCode.Created or HttpStatusCode.Conflict))
                throw new HttpRequestException("Forgejo package publication failed.", null, response.StatusCode);
        }

        var readback = await ReadAsync(uri, sha256, bytes, cancellationToken);
        if (readback is ExistingPackage.Conflict or ExistingPackage.Absent) return Conflict();
        if (!authorityStillValid()) return Stale();
        return status == HttpStatusCode.Created ? Recorded() : Duplicate();
    }

    private async Task<ExistingPackage> ReadAsync(
        Uri uri,
        string sha256,
        long bytes,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(RequestTimeout);
        using var request = Request(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true };
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if (response.StatusCode == HttpStatusCode.NotFound) return ExistingPackage.Absent;
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new UnauthorizedAccessException("Forgejo package credentials were denied.");
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException("Forgejo package readback failed.", null, response.StatusCode);
        if (response.Content.Headers.ContentEncoding.Count != 0 ||
            !string.Equals(response.Content.Headers.ContentType?.MediaType,
                "application/octet-stream", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Forgejo returned an encoded or untyped package file.");
        if (response.Content.Headers.ContentLength is { } length && length != bytes)
            return ExistingPackage.Conflict;

        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
        var observed = await HashAsync(stream, bytes, timeout.Token);
        return observed.Bytes == bytes && observed.Sha256 == sha256
            ? ExistingPackage.Exact
            : ExistingPackage.Conflict;
    }

    private HttpRequestMessage Request(HttpMethod method, Uri uri)
    {
        var request = new HttpRequestMessage(method, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("token", configuration.ReadToken());
        return request;
    }

    private Uri PackageUri(string owner, string package, string version, string fileName) => new(
        configuration.Server,
        $"api/packages/{Uri.EscapeDataString(owner)}/generic/{Uri.EscapeDataString(package)}/" +
        $"{Uri.EscapeDataString(version)}/{Uri.EscapeDataString(fileName)}");

    private static async Task<(string Sha256, long Bytes)> HashAsync(
        Stream stream,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        long bytes = 0;
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer, cancellationToken);
                if (read == 0) break;
                if (read > maximumBytes - bytes) return (string.Empty, bytes + read);
                hash.AppendData(buffer, 0, read);
                bytes += read;
            }
            return (Convert.ToHexStringLower(hash.GetHashAndReset()), bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static void Validate(
        string repository,
        string package,
        string version,
        string fileName,
        string sha256,
        long bytes)
    {
        if (!ForgejoWebhookVerifier.IsRepository(repository))
            throw new ArgumentException("The package repository identity is invalid.", nameof(repository));
        if (!Component(package, 256))
            throw new ArgumentException("The package name is invalid.", nameof(package));
        if (!Component(version, 128))
            throw new ArgumentException("The package version is invalid.", nameof(version));
        if (!Component(fileName, 256))
            throw new ArgumentException("The package file name is invalid.", nameof(fileName));
        if (!RepositoryCiJobExecutionDocument.IsDigest(sha256))
            throw new ArgumentException("The package digest is invalid.", nameof(sha256));
        if (bytes is < 1 or > MaximumPackageBytes)
            throw new ArgumentOutOfRangeException(nameof(bytes));
    }

    private static bool Component(string? value, int maximumLength) =>
        value is { Length: > 0 } && value is not ("." or "..") && value.Length <= maximumLength &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or
            >= '0' and <= '9' or '.' or '_' or '-');

    private static bool CausedByAuthorityLoss(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
            if (current is AuthorityLostException) return true;
        return false;
    }

    private static ForgejoGenericPackagePublicationReceipt Recorded() =>
        new(ForgejoGenericPackagePublicationDisposition.Recorded);

    private static ForgejoGenericPackagePublicationReceipt Duplicate() =>
        new(ForgejoGenericPackagePublicationDisposition.Duplicate);

    private static ForgejoGenericPackagePublicationReceipt Stale() =>
        new(ForgejoGenericPackagePublicationDisposition.StaleAuthority);

    private static ForgejoGenericPackagePublicationReceipt Conflict() =>
        new(ForgejoGenericPackagePublicationDisposition.IdentityConflict);

    private enum ExistingPackage
    {
        Absent,
        Exact,
        Conflict,
    }

    private sealed class AuthorityLostException : IOException;

    private sealed class CopyContent(
        long length,
        Func<Stream, CancellationToken, Task> copy,
        Func<bool> authorityStillValid) : HttpContent
    {
        protected override bool TryComputeLength(out long computedLength)
        {
            computedLength = length;
            return true;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override async Task SerializeToStreamAsync(
            Stream stream,
            TransportContext? context,
            CancellationToken cancellationToken)
        {
            await using var guarded = new AuthorityWriteStream(stream, length, authorityStillValid);
            await copy(guarded, cancellationToken);
            if (guarded.Bytes != length)
                throw new InvalidDataException("The package source did not match its declared length.");
        }
    }

    private sealed class HashingWriteStream(long maximumBytes) : Stream
    {
        private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private bool completed;

        internal long Bytes { get; private set; }

        internal (string Sha256, long Bytes) Complete()
        {
            if (completed) throw new InvalidOperationException("The package source digest was already completed.");
            completed = true;
            return (Convert.ToHexStringLower(hash.GetHashAndReset()), Bytes);
        }

        public override void Write(byte[] buffer, int offset, int count) =>
            Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Capture(buffer);
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Capture(buffer.Span);
            return ValueTask.CompletedTask;
        }

        private void Capture(ReadOnlySpan<byte> value)
        {
            if (value.Length > maximumBytes - Bytes)
                throw new InvalidDataException("The package source exceeded its declared length.");
            hash.AppendData(value);
            Bytes += value.Length;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) hash.Dispose();
            base.Dispose(disposing);
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => Bytes;
        public override long Position { get => Bytes; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private sealed class AuthorityWriteStream(
        Stream destination,
        long length,
        Func<bool> authorityStillValid) : Stream
    {
        internal long Bytes { get; private set; }

        public override void Write(byte[] buffer, int offset, int count) =>
            Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Check();
            CheckLength(buffer.Length);
            destination.Write(buffer);
            Bytes = checked(Bytes + buffer.Length);
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            Check();
            CheckLength(buffer.Length);
            await destination.WriteAsync(buffer, cancellationToken);
            Bytes = checked(Bytes + buffer.Length);
        }

        private void Check()
        {
            if (!authorityStillValid()) throw new AuthorityLostException();
        }

        private void CheckLength(int count)
        {
            if (count > length - Bytes)
                throw new InvalidDataException("The package source exceeded its declared length.");
        }

        protected override void Dispose(bool disposing) { }
        public override ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => Bytes;
        public override long Position { get => Bytes; set => throw new NotSupportedException(); }
        public override void Flush() => destination.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) =>
            destination.FlushAsync(cancellationToken);
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
