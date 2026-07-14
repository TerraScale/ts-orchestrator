using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

internal static class CiDispatchFingerprint
{
    internal static string Create(DispatchJobIntent intent) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(intent))));

    internal static string Canonical(DispatchJobIntent intent)
    {
        var request = intent.Request;
        var runner = intent.SelectedRunnerEvidence;
        var builder = new StringBuilder("ci-dispatch-v2;");
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

    private static void Add(StringBuilder builder, string value) =>
        builder.Append('S').Append(value.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(value).Append(';');
    private static void Add(StringBuilder builder, long value) =>
        builder.Append('L').Append(value.ToString(CultureInfo.InvariantCulture)).Append(';');
    private static void Add(StringBuilder builder, int value) =>
        builder.Append('I').Append(value.ToString(CultureInfo.InvariantCulture)).Append(';');
    private static void Add(StringBuilder builder, bool value) => builder.Append(value ? "B1;" : "B0;");
    private static void Add<T>(StringBuilder builder, T value) where T : struct, Enum =>
        Add(builder, Convert.ToInt64(value, CultureInfo.InvariantCulture));
    private static void Add<T>(StringBuilder builder, IReadOnlyList<T> values) where T : struct, Enum
    {
        builder.Append('A').Append(values.Count.ToString(CultureInfo.InvariantCulture)).Append('[');
        foreach (var value in values) Add(builder, value);
        builder.Append("];");
    }
}
