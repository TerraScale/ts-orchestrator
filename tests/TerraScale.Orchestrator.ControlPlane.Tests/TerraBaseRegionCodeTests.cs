using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class TerraBaseRegionCodeTests
{
    [Test]
    public async Task Region_code_accepts_only_registered_exact_uppercase_values()
    {
        foreach (var value in new[] { "GRU", "SFO", "FRA" })
        {
            await Assert.That(TerraBaseRegionCode.TryCreate(value, out var region)).IsTrue();
            await Assert.That(region).IsNotNull();
            await Assert.That(region!.Value).IsEqualTo(value);
        }

        foreach (var value in new string?[]
                 {
                     null, "", "gru", "Gru", " GRU", "GRU ", "GR", "GRUU", "IAD", "US1", "G-U", "G.U",
                     "GRÜ", "GLOBAL", "G\0U",
                 })
        {
            await Assert.That(TerraBaseRegionCode.TryCreate(value, out var refused)).IsFalse();
            await Assert.That(refused).IsNull();
        }
    }
}
