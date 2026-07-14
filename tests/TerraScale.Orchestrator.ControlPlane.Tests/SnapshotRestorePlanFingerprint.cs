using System.Globalization;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Snapshots;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

internal static class SnapshotRestorePlanFingerprint
{
    internal static string Create(SnapshotRestorePlan plan)
    {
        var material = plan.AcceptedSnapshot.SignedMaterial;
        var builder = new StringBuilder("snapshot-restore-plan/v1|");
        Append(builder, material.Authority.Value!);
        Append(builder, material.Stream.Value!);
        Append(builder, material.SnapshotId.Value!);
        Append(builder, material.Schema.Value!);
        Append(builder, material.SigningKey.Value!);
        Append(builder, material.Epoch.Value);
        Append(builder, material.StreamSequence.Value);
        Append(builder, material.Generation.Value);
        Append(builder, material.StateDigest.Bytes);
        Append(builder, plan.AcceptedSnapshot.Signature.Bytes);
        Append(builder, plan.ReplayStartSequence.Value);
        return builder.ToString();
    }

    private static void Append(StringBuilder builder, string value) =>
        builder.Append(value.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(value).Append('|');

    private static void Append(StringBuilder builder, ulong value) =>
        builder.Append(value.ToString(CultureInfo.InvariantCulture)).Append('|');

    private static void Append(StringBuilder builder, ReadOnlySpan<byte> value) =>
        builder.Append(value.Length.ToString(CultureInfo.InvariantCulture)).Append(':')
            .Append(Convert.ToHexString(value)).Append('|');
}
