using System.Net;
using System.Security.Cryptography;
using NATS.Client.Core;

namespace TerraScale.Orchestrator.Delivery;

public sealed class ForgejoWebhookConfiguration
{
    private ForgejoWebhookConfiguration(Uri listenPrefix, string repository, string secretFile)
    {
        ListenPrefix = listenPrefix;
        Repository = repository;
        SecretFile = secretFile;
    }

    public Uri ListenPrefix { get; }
    public string Repository { get; }
    public string SecretFile { get; }

    public static ForgejoWebhookConfiguration? Resolve(
        string? listenPrefix,
        string? repository,
        string? secretFile)
    {
        var supplied = new[] { listenPrefix, repository, secretFile }
            .Count(static value => !string.IsNullOrWhiteSpace(value));
        if (supplied == 0) return null;
        if (supplied != 3)
            throw new ArgumentException(
                "Forgejo webhook configuration requires listen prefix, repository, and secret file together.");
        if (!Uri.TryCreate(listenPrefix, UriKind.Absolute, out var prefix) ||
            prefix.Scheme is not ("http" or "https") ||
            !string.IsNullOrEmpty(prefix.UserInfo) || !string.IsNullOrEmpty(prefix.Query) ||
            !string.IsNullOrEmpty(prefix.Fragment) || !prefix.AbsolutePath.EndsWith('/') ||
            prefix.Host is "*" or "+" || prefix.Port <= 0)
            throw new ArgumentException("The Forgejo webhook listen prefix is invalid.");
        if (prefix.Scheme == "http" && !IsLoopback(prefix.Host))
            throw new ArgumentException("Plaintext Forgejo webhook ingress must listen only on loopback.");
        if (!ForgejoWebhookVerifier.IsRepository(repository))
            throw new ArgumentException("The Forgejo webhook repository must be an owner/name identity.");

        return new(prefix, repository!, ResolveSecretFile(secretFile!));
    }

    private static bool IsLoopback(string host) =>
        host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
        IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address);

    internal byte[] ReadSecret()
    {
        var path = ResolveSecretFile(SecretFile);
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length is < ForgejoWebhookVerifier.MinimumSecretBytes or > 4096)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new InvalidOperationException("The Forgejo webhook secret file is not bounded and strong.");
        }
        return bytes;
    }

    private static string ResolveSecretFile(string value)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Forgejo webhook secrets require Linux file permissions.");
        var path = Path.GetFullPath(value);
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is < ForgejoWebhookVerifier.MinimumSecretBytes or > 4096)
            throw new ArgumentException("The Forgejo webhook secret file must be bounded, strong, and existing.");
        var mode = File.GetUnixFileMode(path);
        if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                     UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
            throw new ArgumentException("The Forgejo webhook secret file must be private to the current user.");
        return path;
    }
}

internal sealed class ForgejoWebhookServer : IAsyncDisposable
{
    private const int MaximumConcurrentRequests = 8;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);
    private readonly ForgejoWebhookConfiguration configuration;
    private readonly ForgejoWebhookJournal journal;
    private readonly HttpListener listener = new();
    private readonly CancellationTokenSource stopping = new();
    private readonly byte[] secret;

    private ForgejoWebhookServer(
        ForgejoWebhookConfiguration configuration,
        ForgejoWebhookJournal journal)
    {
        this.configuration = configuration;
        this.journal = journal;
        secret = configuration.ReadSecret();
        listener.Prefixes.Add(configuration.ListenPrefix.AbsoluteUri);
        try
        {
            listener.Start();
            Completion = RunAsync(stopping.Token);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(secret);
            listener.Close();
            stopping.Dispose();
            throw;
        }
    }

    internal Task Completion { get; }

    internal static ForgejoWebhookServer Start(
        ForgejoWebhookConfiguration configuration,
        ForgejoWebhookJournal journal) => new(configuration, journal);

    public async ValueTask DisposeAsync()
    {
        await stopping.CancelAsync();
        listener.Stop();
        try
        {
            await Completion;
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested)
        {
        }
        finally
        {
            listener.Close();
            CryptographicOperations.ZeroMemory(secret);
            stopping.Dispose();
        }
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        var requests = new List<Task>(MaximumConcurrentRequests);
        try
        {
            while (true)
            {
                for (var index = requests.Count - 1; index >= 0; index--)
                {
                    if (!requests[index].IsCompleted) continue;
                    var completed = requests[index];
                    requests.RemoveAt(index);
                    await completed;
                }
                if (requests.Count == MaximumConcurrentRequests)
                {
                    var completed = await Task.WhenAny(requests);
                    await completed;
                    requests.Remove(completed);
                    continue;
                }

                var context = await listener.GetContextAsync().WaitAsync(cancellationToken);
                requests.Add(HandleAsync(context, cancellationToken));
            }
        }
        catch (HttpListenerException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            await Task.WhenAll(requests);
        }
    }

    private async Task HandleAsync(HttpListenerContext context, CancellationToken stoppingToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        timeout.CancelAfter(RequestTimeout);
        var status = HttpStatusCode.ServiceUnavailable;
        try
        {
            status = await EvaluateAsync(context.Request, timeout.Token);
        }
        catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
        {
            status = HttpStatusCode.RequestTimeout;
        }
        catch (Exception exception) when (exception is IOException or NatsException or TimeoutException)
        {
            status = HttpStatusCode.ServiceUnavailable;
        }
        finally
        {
            try
            {
                context.Response.StatusCode = (int)status;
                context.Response.ContentLength64 = 0;
                context.Response.Close();
            }
            catch (Exception exception) when (exception is HttpListenerException or InvalidOperationException or ObjectDisposedException)
            {
            }
        }
    }

    private async Task<HttpStatusCode> EvaluateAsync(
        HttpListenerRequest request,
        CancellationToken cancellationToken)
    {
        if (request.HttpMethod != "POST") return HttpStatusCode.MethodNotAllowed;
        if (request.Url?.AbsolutePath != configuration.ListenPrefix.AbsolutePath)
            return HttpStatusCode.NotFound;
        if (request.ContentLength64 > ForgejoWebhookVerifier.MaximumPayloadBytes)
            return HttpStatusCode.RequestEntityTooLarge;

        var payload = await ReadPayloadAsync(request.InputStream, request.ContentLength64, cancellationToken);
        if (payload is null) return HttpStatusCode.RequestEntityTooLarge;
        var verification = ForgejoWebhookVerifier.Verify(
            payload,
            secret,
            configuration.Repository,
            request.ContentType,
            request.Headers["X-Forgejo-Signature"],
            request.Headers["X-Forgejo-Delivery"],
            request.Headers["X-Forgejo-Event"]);
        if (!verification.Accepted)
            return verification.Error == ForgejoWebhookError.UnsupportedContentType
                ? HttpStatusCode.UnsupportedMediaType
                : verification.Error == ForgejoWebhookError.PayloadTooLarge
                    ? HttpStatusCode.RequestEntityTooLarge
                    : HttpStatusCode.Unauthorized;

        var receipt = await journal.AcceptAsync(verification.Envelope!, cancellationToken);
        return receipt.Disposition switch
        {
            ForgejoWebhookJournalDisposition.Accepted or ForgejoWebhookJournalDisposition.Duplicate =>
                HttpStatusCode.Accepted,
            ForgejoWebhookJournalDisposition.DeliveryCollision or ForgejoWebhookJournalDisposition.PayloadReplay =>
                HttpStatusCode.Conflict,
            _ => HttpStatusCode.ServiceUnavailable,
        };
    }

    private static async Task<byte[]?> ReadPayloadAsync(
        Stream input,
        long contentLength,
        CancellationToken cancellationToken)
    {
        var capacity = contentLength is > 0 and <= ForgejoWebhookVerifier.MaximumPayloadBytes
            ? checked((int)contentLength)
            : 0;
        await using var output = new MemoryStream(capacity);
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken);
            if (read == 0) return output.ToArray();
            if (output.Length + read > ForgejoWebhookVerifier.MaximumPayloadBytes) return null;
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }
}
