using System.IO.Pipelines;
using System.Text;

namespace TerraScale.Orchestrator.Tests;

public sealed class NatsFixtureDiagnosticsTests
{
    [Test]
    public async Task Live_drain_reports_failure_categories_before_process_exit_without_raw_credentials()
    {
        var pipe = new Pipe();
        using var reader = new StreamReader(pipe.Reader.AsStream());
        var diagnostics = new NatsFixtureDiagnostics();
        var drain = diagnostics.DrainAsync(reader);
        var secret = "synthetic-private-credential";
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try
        {
            await pipe.Writer.WriteAsync(Encoding.UTF8.GetBytes(
                $"[ERR] TLS handshake error: x509: bad certificate {secret}\n" +
                $"[ERR] Authentication Error: {secret}\n" +
                "Listening for client connections\n"), deadline.Token);
            while (!diagnostics.Snapshot().Contains("listen-ready=1", StringComparison.Ordinal))
                await Task.Delay(TimeSpan.FromMilliseconds(10), deadline.Token);
            await Assert.That(drain.IsCompleted).IsFalse();
            await Assert.That(diagnostics.Snapshot()).IsEqualTo(
                "tls-handshake-error=1,certificate-error=1,authentication-error=1,listen-ready=1,process-error=2");
        }
        finally
        {
            await pipe.Writer.CompleteAsync();
            await drain.WaitAsync(TimeSpan.FromSeconds(3));
        }
    }

    [Test]
    public async Task Oversized_and_unterminated_lines_remain_bounded_and_cannot_expose_payloads()
    {
        var text = new string('x', 100_000) + " TLS handshake error\n" +
                   "-----BEGIN PRIVATE KEY-----\nsynthetic-secret-body\n-----END PRIVATE KEY-----\n" +
                   "Server is ready";
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(text));
        using var reader = new StreamReader(stream);
        var diagnostics = new NatsFixtureDiagnostics();
        await diagnostics.DrainAsync(reader);
        await Assert.That(diagnostics.Snapshot()).IsEqualTo("server-ready=1,oversized-lines=1");
    }

    [Test]
    public async Task Concurrent_output_and_error_streams_preserve_both_event_counts()
    {
        using var outputStream = new MemoryStream(Encoding.UTF8.GetBytes(
            string.Concat(Enumerable.Repeat("Route connection created\n", 100))));
        using var errorStream = new MemoryStream(Encoding.UTF8.GetBytes(
            string.Concat(Enumerable.Repeat("[ERR] address already in use\n", 100))));
        using var output = new StreamReader(outputStream);
        using var error = new StreamReader(errorStream);
        var diagnostics = new NatsFixtureDiagnostics();
        await Task.WhenAll(
            Task.Run(() => diagnostics.DrainAsync(output)),
            Task.Run(() => diagnostics.DrainAsync(error)));
        await Assert.That(diagnostics.Snapshot()).IsEqualTo(
            "address-in-use=100,route-established=100,process-error=100");
    }
}
