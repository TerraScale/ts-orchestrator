using System.Globalization;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Snapshots;
using Cysharp.Text;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

internal static class SnapshotRestorePlanFingerprint
{
    internal static string Create(SnapshotRestorePlan plan)
    {
        var material = plan.AcceptedSnapshot.SignedMaterial;
        using var builder = new ZStringWriter();
        builder.Write("snapshot-restore-plan/v1|");
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

    private static void Append(ZStringWriter builder, string value)
    {
        builder.Write(value.Length.ToString(CultureInfo.InvariantCulture));
        builder.Write(':');
        builder.Write(value);
        builder.Write('|');
    }

    private static void Append(ZStringWriter builder, ulong value)
    {
        builder.Write(value.ToString(CultureInfo.InvariantCulture));
        builder.Write('|');
    }

    private static void Append(ZStringWriter builder, ReadOnlySpan<byte> value)
    {
        builder.Write(value.Length.ToString(CultureInfo.InvariantCulture));
        builder.Write(':');
        builder.Write(Convert.ToHexString(value));
        builder.Write('|');
    }
}

