using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

internal static class DeliveryStageFingerprint
{
    internal static string Create(StageReleaseIntent intent) => Create(intent.ReleaseSpec, intent.Availability);

    internal static string Create(ReleaseSpec release, CellArtifactAvailability availability)
    {
        var canonical = new StringBuilder();
        Add(canonical, release.Release.Value);
        Add(canonical, release.Operation.Value);
        Add(canonical, release.Generation.ToString(CultureInfo.InvariantCulture));
        Add(canonical, release.Artifact.Value);
        Add(canonical, release.Digest.Value);
        Add(canonical, release.SigningIdentity.Value);
        Add(canonical, release.Signature.Value);
        Add(canonical, ((int)release.Architecture).ToString(CultureInfo.InvariantCulture));
        Add(canonical, release.RollbackArtifact.Value);
        Add(canonical, release.RollbackDigest.Value);
        Add(canonical, release.RollbackSigningIdentity.Value);
        Add(canonical, release.RollbackSignature.Value);
        Add(canonical, ((int)release.RollbackArchitecture).ToString(CultureInfo.InvariantCulture));
        Add(canonical, ((int)release.Strategy).ToString(CultureInfo.InvariantCulture));
        Add(canonical, ((int)release.RollbackPolicy).ToString(CultureInfo.InvariantCulture));
        Add(canonical, release.OrderedCells.Count.ToString(CultureInfo.InvariantCulture));
        foreach (var cell in release.OrderedCells)
            Add(canonical, cell.Value);

        Add(canonical, availability.Release.Value);
        Add(canonical, availability.Operation.Value);
        Add(canonical, availability.Generation.ToString(CultureInfo.InvariantCulture));
        Add(canonical, availability.Cell.Value);
        Add(canonical, availability.ForwardArtifact.Value);
        Add(canonical, availability.ForwardDigest.Value);
        Add(canonical, availability.ForwardSigningIdentity.Value);
        Add(canonical, availability.ForwardSignature.Value);
        Add(canonical, ((int)availability.ForwardArchitecture).ToString(CultureInfo.InvariantCulture));
        Add(canonical, availability.RollbackArtifact.Value);
        Add(canonical, availability.RollbackDigest.Value);
        Add(canonical, availability.RollbackSigningIdentity.Value);
        Add(canonical, availability.RollbackSignature.Value);
        Add(canonical, ((int)availability.RollbackArchitecture).ToString(CultureInfo.InvariantCulture));
        Add(canonical, availability.ForwardAvailable ? "1" : "0");
        Add(canonical, availability.RollbackAvailable ? "1" : "0");

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString())));
    }

    private static void Add(StringBuilder target, string value) => target.Append(value.Length.ToString(CultureInfo.InvariantCulture))
        .Append(':').Append(value).Append(';');
}
