using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using Cysharp.Text;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

internal static class CiDispatchFingerprint
{
    internal static string Create(DispatchJobIntent intent) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(intent))));

    internal static string Canonical(DispatchJobIntent intent)
    {
        var request = intent.Request;
        var runner = intent.SelectedRunnerEvidence;
        using var builder = new ZStringWriter();
        builder.Write("ci-dispatch-v2;");
        Add(builder, request.Pipeline.Value); Add(builder, request.Job.Value); Add(builder, request.Kind);
        Add(builder, request.Tree.Value); Add(builder, request.Generation); Add(builder, request.Attempt);
        Add(builder, request.MaximumAttempts); Add(builder, request.Idempotency.Value);
        Add(builder, request.AllowedZones); Add(builder, request.RequiredCapabilities);
        Add(builder, request.MinimumRunnerSequence); Add(builder, request.MaximumRunnerSequence);
        Add(builder, request.RetryAuthorized); Add(builder, runner.Runner.Value); Add(builder, runner.Zone);
        Add(builder, runner.Sequence); Add(builder, runner.Available); Add(builder, runner.Capabilities);
        Add(builder, intent.MaximumIdentityLength);
        return builder.ToString();
    }

    private static void Add(ZStringWriter builder, string value)
    {
        builder.Write('S');
        builder.Write(value.Length.ToString(CultureInfo.InvariantCulture));
        builder.Write(':');
        builder.Write(value);
        builder.Write(';');
    }
    private static void Add(ZStringWriter builder, long value)
    {
        builder.Write('L');
        builder.Write(value.ToString(CultureInfo.InvariantCulture));
        builder.Write(';');
    }
    private static void Add(ZStringWriter builder, int value)
    {
        builder.Write('I');
        builder.Write(value.ToString(CultureInfo.InvariantCulture));
        builder.Write(';');
    }
    private static void Add(ZStringWriter builder, bool value) => builder.Write(value ? "B1;" : "B0;");
    private static void Add<T>(ZStringWriter builder, T value) where T : struct, Enum =>
        Add(builder, Convert.ToInt64(value, CultureInfo.InvariantCulture));
    private static void Add<T>(ZStringWriter builder, IReadOnlyList<T> values) where T : struct, Enum
    {
        builder.Write('A');
        builder.Write(values.Count.ToString(CultureInfo.InvariantCulture));
        builder.Write('[');
        foreach (var value in values) Add(builder, value);
        builder.Write("];");
    }
}
