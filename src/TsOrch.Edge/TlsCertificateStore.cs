using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TsOrch.Edge;

public sealed partial class TlsCertificateStore(
    EdgeServerOptions options,
    TimeProvider timeProvider,
    ILogger<TlsCertificateStore> logger) : BackgroundService
{
    public const string CertificateFileName = "cert.pem";
    public const string KeyFileName = "key.pem";

    private static readonly TimeSpan FallbackLifetime = TimeSpan.FromDays(7);

    private EdgeCertificate? _current;
    private (FileStamp Certificate, FileStamp Key) _stamp;

    public bool HasValidConfiguredCertificate =>
        Volatile.Read(ref _current) is { Configured: true, Leaf: var leaf }
        && timeProvider.GetUtcNow().UtcDateTime >= leaf.NotBefore.ToUniversalTime()
        && timeProvider.GetUtcNow().UtcDateTime <= leaf.NotAfter.ToUniversalTime();

    public X509Certificate2 Certificate => Loaded().Leaf;

    public SslServerAuthenticationOptions CreateServerOptions() =>
        new() { ServerCertificateContext = Loaded().Context };

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        Reload();
        if (Volatile.Read(ref _current) is null)
        {
            Interlocked.CompareExchange(ref _current, CreateFallback(), null);
            LogFallbackCertificate(logger, options.TlsDirectory);
        }

        await base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var monitor = new FileChangeMonitor(options.TlsDirectory, timeProvider);
        Reload();
        await foreach (var _ in monitor.ReadAllAsync(stoppingToken))
        {
            Reload();
        }
    }

    private EdgeCertificate Loaded() =>
        Volatile.Read(ref _current) ?? throw new InvalidOperationException("TLS certificate store is used before it started.");

    private void Reload()
    {
        var certificatePath = Path.Combine(options.TlsDirectory, CertificateFileName);
        var keyPath = Path.Combine(options.TlsDirectory, KeyFileName);
        var stamp = (FileStamp.Read(certificatePath), FileStamp.Read(keyPath));
        if (!stamp.Item1.Exists || !stamp.Item2.Exists || stamp == _stamp)
        {
            return;
        }

        try
        {
            var certificatePem = File.ReadAllText(certificatePath);
            var leaf = X509Certificate2.CreateFromPem(certificatePem, File.ReadAllText(keyPath));
            var chain = new X509Certificate2Collection();
            chain.ImportFromPem(certificatePem);
            var intermediates = new X509Certificate2Collection(
                chain.Where(certificate => !string.Equals(certificate.Thumbprint, leaf.Thumbprint, StringComparison.Ordinal)).ToArray());
            var now = timeProvider.GetUtcNow().UtcDateTime;
            if (now < leaf.NotBefore.ToUniversalTime() || now > leaf.NotAfter.ToUniversalTime())
            {
                LogCertificateOutsideValidity(logger, leaf.Subject);
                leaf.Dispose();
                return;
            }

            var certificate = new EdgeCertificate(leaf, SslStreamCertificateContext.Create(leaf, intermediates, offline: true), Configured: true);
            Interlocked.Exchange(ref _current, certificate);
            _stamp = stamp;
            LogCertificateLoaded(logger, leaf.Subject, leaf.NotAfter);
        }
        catch (Exception exception) when (exception is CryptographicException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            LogCertificateRejected(logger, options.TlsDirectory, exception);
        }
    }

    private EdgeCertificate CreateFallback()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
        var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
        subjectAlternativeNames.AddDnsName("localhost");
        subjectAlternativeNames.AddIpAddress(IPAddress.Loopback);
        subjectAlternativeNames.AddIpAddress(IPAddress.IPv6Loopback);
        request.CertificateExtensions.Add(subjectAlternativeNames.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var now = timeProvider.GetUtcNow();
        var leaf = request.CreateSelfSigned(now.AddMinutes(-5), now.Add(FallbackLifetime));
        return new EdgeCertificate(leaf, SslStreamCertificateContext.Create(leaf, null, offline: true), Configured: false);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Loaded TLS certificate {Subject} valid until {NotAfter}")]
    private static partial void LogCertificateLoaded(ILogger logger, string subject, DateTime notAfter);

    [LoggerMessage(Level = LogLevel.Error, Message = "Rejected TLS certificate in {Directory}; keeping the previous certificate")]
    private static partial void LogCertificateRejected(ILogger logger, string directory, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "No TLS certificate in {Directory}; serving a temporary self-signed loopback certificate until sync_tls arrives")]
    private static partial void LogFallbackCertificate(ILogger logger, string directory);

    [LoggerMessage(Level = LogLevel.Error, Message = "Rejected TLS certificate {Subject} outside its validity period")]
    private static partial void LogCertificateOutsideValidity(ILogger logger, string subject);

    private sealed record class EdgeCertificate(X509Certificate2 Leaf, SslStreamCertificateContext Context, bool Configured);
}
