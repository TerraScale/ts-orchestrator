using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace TerraScale.Orchestrator.Tooling;

internal static partial class NatsSmokeCommand
{
    private const string ExpectedBinarySha256 = "588b858328bc507ddff3b6078cda7db762f28e6da8c3fa368099a204f0f37a37";
    private const string ExpectedVersion = "2.14.3";

    public static async Task<int> RunAsync(string[] arguments)
    {
        var binary = Environment.GetEnvironmentVariable("TS_NATS_SERVER") ?? FindOnPath("nats-server")
            ?? throw new ToolValidationException(["nats-server is absent"]);
        if (ToolingSupport.Sha256(binary) != ExpectedBinarySha256)
        {
            throw new ToolValidationException(["local nats-server does not match the checked smoke candidate"]);
        }

        var version = ToolingSupport.RunProcess(binary, ["-v"], timeoutMilliseconds: 5_000);
        if (version.ExitCode != 0 || version.StandardOutput.Trim().Replace("nats-server: v", string.Empty, StringComparison.Ordinal) != ExpectedVersion)
        {
            throw new ToolValidationException(["local nats-server does not match the checked smoke candidate"]);
        }

        var clientPort = FreePort();
        var monitorPort = FreePort();
        while (monitorPort == clientPort) monitorPort = FreePort();
        var temporary = Path.Combine(Path.GetTempPath(), $"terrascale-nats-l0c-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporary);
        var checks = new Dictionary<string, bool>(StringComparer.Ordinal)
        {
            ["corePubSub"] = false,
            ["coreRequestReply"] = false,
            ["jetStreamCreatePublishGet"] = false,
            ["monitoringLoopback"] = false,
            ["processCleanup"] = false,
            ["temporaryStoreCleanup"] = false,
        };
        Process? process = null;
        try
        {
            process = Process.Start(new ProcessStartInfo
            {
                FileName = binary,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                ArgumentList = { "-js", "-a", "127.0.0.1", "-p", clientPort.ToString(System.Globalization.CultureInfo.InvariantCulture), "-m", monitorPort.ToString(System.Globalization.CultureInfo.InvariantCulture), "-sd", Path.Combine(temporary, "store") }
            }) ?? throw new InvalidOperationException("nats-server did not start");

            NatsProtocol? protocol = null;
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (DateTime.UtcNow < deadline)
            {
                if (process.HasExited) throw new InvalidOperationException("nats-server exited before readiness");
                try { protocol = new NatsProtocol(clientPort); break; }
                catch (SocketException) { await Task.Delay(50); }
            }
            if (protocol is null) throw new TimeoutException("nats-server readiness deadline exceeded");
            using (protocol)
            {
                protocol.Send("SUB l0c.core 10\r\nPUB l0c.core 5\r\nhello\r\n");
                var core = protocol.NextMessage();
                checks["corePubSub"] = core.Subject == "l0c.core" && Encoding.UTF8.GetString(core.Payload) == "hello";

                protocol.Send("SUB l0c.service 11\r\nSUB _INBOX.L0C.REPLY 12\r\nPUB l0c.service _INBOX.L0C.REPLY 4\r\nping\r\n");
                var request = protocol.NextMessage();
                if (request.Subject == "l0c.service" && request.Reply == "_INBOX.L0C.REPLY" && Encoding.UTF8.GetString(request.Payload) == "ping")
                {
                    protocol.Send("PUB _INBOX.L0C.REPLY 4\r\npong\r\n");
                    var reply = protocol.NextMessage();
                    checks["coreRequestReply"] = reply.Subject == "_INBOX.L0C.REPLY" && Encoding.UTF8.GetString(reply.Payload) == "pong";
                }

                var config = Encoding.UTF8.GetBytes("{\"name\":\"L0C_SMOKE\",\"subjects\":[\"l0c.events\"],\"storage\":\"file\"}");
                var created = JsonNode.Parse(protocol.Request("$JS.API.STREAM.CREATE.L0C_SMOKE", config, 20)) as JsonObject;
                if (created?.ContainsKey("error") == true) throw new InvalidOperationException("stream create failed");
                var ack = JsonNode.Parse(protocol.Request("l0c.events", "event"u8.ToArray(), 21));
                var fetched = JsonNode.Parse(protocol.Request("$JS.API.STREAM.MSG.GET.L0C_SMOKE", "{\"seq\":1}"u8.ToArray(), 22));
                checks["jetStreamCreatePublishGet"] = ack?["seq"]?.GetValue<long>() == 1 && fetched?["message"]?["seq"]?.GetValue<long>() == 1;
            }

            using var monitor = new TcpClient();
            monitor.Connect(IPAddress.Loopback, monitorPort);
            var monitorStream = monitor.GetStream();
            monitorStream.Write("GET /healthz?js-enabled-only=true HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"u8);
            var buffer = new byte[4096];
            var read = monitorStream.Read(buffer);
            checks["monitoringLoopback"] = Encoding.ASCII.GetString(buffer, 0, read).Contains("200 OK", StringComparison.Ordinal);
        }
        finally
        {
            if (process is not null && !process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5_000);
            }
            checks["processCleanup"] = process is null || process.HasExited;
            try { Directory.Delete(temporary, recursive: true); } catch (DirectoryNotFoundException) { }
            checks["temporaryStoreCleanup"] = !Directory.Exists(temporary);
            process?.Dispose();
        }

        if (checks.Values.Any(value => !value)) throw new ToolValidationException([$"local smoke checks failed: {string.Join(',', checks.Where(pair => !pair.Value).Select(pair => pair.Key))}"]);
        var report = new JsonObject
        {
            ["schemaVersion"] = 1,
            ["classification"] = "bounded-local-x64-l0c-smoke-not-production-qualification",
            ["harnessPath"] = "testlab/nats/run_local_l0c_smoke.cs",
            ["harnessSha256"] = ToolingSupport.Sha256(Path.Combine(ToolingSupport.Root, "testlab/nats/run_local_l0c_smoke.cs")),
            ["hostArchitecture"] = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture switch
            {
                System.Runtime.InteropServices.Architecture.X64 => "x86_64",
                System.Runtime.InteropServices.Architecture.Arm64 => "aarch64",
                var architecture => architecture.ToString().ToLowerInvariant(),
            },
            ["server"] = new JsonObject { ["version"] = ExpectedVersion, ["binarySha256"] = ExpectedBinarySha256 },
            ["network"] = "loopback-only-dynamic-ports",
            ["credentials"] = "none",
            ["checks"] = new JsonObject(checks.Select(pair => KeyValuePair.Create<string, JsonNode?>(pair.Key, pair.Value))),
            ["notTested"] = new JsonArray("ARM64", "JWT/NKeys/accounts/permissions", "TLS/mTLS/routes/gateways", "R3/peer-loss/snapshot-restore", "KV CAS/watch", "Object Store", "durable-consumer-redelivery/backoff", "N/N-1 mixed versions"),
        };
        Console.Write(ToolingSupport.Serialize(report));
        return 0;
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static string? FindOnPath(string name) =>
        (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator)
            .Select(directory => Path.Combine(directory, name)).FirstOrDefault(File.Exists);

    private sealed class NatsProtocol : IDisposable
    {
        private readonly TcpClient client = new();
        private readonly NetworkStream stream;
        public NatsProtocol(int port)
        {
            client.ReceiveTimeout = 3_000;
            client.SendTimeout = 3_000;
            client.Connect(IPAddress.Loopback, port);
            stream = client.GetStream();
            if (!ReadLine().StartsWith("INFO ", StringComparison.Ordinal)) throw new InvalidDataException("expected NATS INFO");
            Send("CONNECT {\"verbose\":false,\"pedantic\":true}\r\nPING\r\n");
            while (ReadLine() is var line && line != "PONG") if (line.StartsWith("-ERR", StringComparison.Ordinal)) throw new InvalidDataException(line);
        }
        public void Send(string value) => stream.Write(Encoding.ASCII.GetBytes(value));
        public Message NextMessage()
        {
            while (true)
            {
                var line = ReadLine();
                if (line.StartsWith("-ERR", StringComparison.Ordinal)) throw new InvalidDataException(line);
                if (!line.StartsWith("MSG ", StringComparison.Ordinal)) continue;
                var fields = line.Split(' ');
                var size = int.Parse(fields[^1], System.Globalization.CultureInfo.InvariantCulture);
                var payload = new byte[size]; stream.ReadExactly(payload);
                if (ReadLine() != string.Empty) throw new InvalidDataException("message payload missing CRLF");
                return new(fields[1], fields.Length == 5 ? fields[3] : null, payload);
            }
        }
        public byte[] Request(string subject, byte[] payload, int sid)
        {
            var inbox = $"_INBOX.L0C.{sid}";
            Send($"SUB {inbox} {sid}\r\nPUB {subject} {inbox} {payload.Length}\r\n");
            stream.Write(payload); Send("\r\n");
            return NextMessage().Payload;
        }
        private string ReadLine()
        {
            using var bytes = new MemoryStream();
            while (true)
            {
                var value = stream.ReadByte();
                if (value < 0) throw new EndOfStreamException();
                if (value == '\r') { if (stream.ReadByte() != '\n') throw new InvalidDataException("invalid NATS line"); return Encoding.ASCII.GetString(bytes.ToArray()); }
                bytes.WriteByte((byte)value);
            }
        }
        public void Dispose() { stream.Dispose(); client.Dispose(); }
        internal sealed record Message(string Subject, string? Reply, byte[] Payload);
    }
}
