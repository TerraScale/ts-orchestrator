using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Bootstrap;

namespace TerraScale.Orchestrator.Tests;

public sealed class OciRegionIntentTests
{
    private const string GruOnly = """
        {"schemaVersion":1,"generation":7,"bootstrapRegion":"GRU",
         "regions":[{"cell":"GRU","ociRegion":"sa-saopaulo-1"}]}
        """;

    [Test]
    public async Task Supported_regions_authorize_only_their_canonical_compute_endpoint()
    {
        var intent = Parse("""
            {"schemaVersion":1,"generation":8,"bootstrapRegion":"GRU","regions":[
              {"cell":"GRU","ociRegion":"sa-saopaulo-1"},
              {"cell":"SFO","ociRegion":"us-sanjose-1"},
              {"cell":"FRA","ociRegion":"eu-frankfurt-1"}]}
            """);
        intent.RequireEndpoint("gru", new("https://iaas.sa-saopaulo-1.oraclecloud.com/"));
        intent.RequireEndpoint("sfo", new("https://iaas.us-sanjose-1.oraclecloud.com/"));
        intent.RequireEndpoint("fra", new("https://iaas.eu-frankfurt-1.oraclecloud.com/"));
        await Assert.That(intent.Generation).IsEqualTo(8);
        await Assert.That(() => Parse(GruOnly).RequireCell("sfo")).Throws<InvalidDataException>();
    }

    [Test]
    [Arguments("https://iaas.us-sanjose-1.oraclecloud.com/")]
    [Arguments("https://iaas.sa-saopaulo-1.oraclecloud.com.evil.invalid/")]
    [Arguments("http://iaas.sa-saopaulo-1.oraclecloud.com/")]
    [Arguments("https://iaas.sa-saopaulo-1.oraclecloud.com:8443/")]
    [Arguments("https://user@iaas.sa-saopaulo-1.oraclecloud.com/")]
    [Arguments("https://iaas.sa-saopaulo-1.oraclecloud.com/path")]
    [Arguments("https://iaas.sa-saopaulo-1.oraclecloud.com/?query")]
    [Arguments("https://iaas.sa-saopaulo-1.oraclecloud.com/#fragment")]
    [Arguments("/relative")]
    public async Task Rejects_endpoints_outside_the_cell(string endpoint)
    {
        await Assert.That(() => Parse(GruOnly).RequireEndpoint("GRU", new(endpoint, UriKind.RelativeOrAbsolute)))
            .Throws<InvalidDataException>();
    }

    [Test]
    [Arguments("\"schemaVersion\":1", "\"schemaVersion\":2")]
    [Arguments("\"generation\":7", "\"generation\":0")]
    [Arguments("\"bootstrapRegion\":\"GRU\"", "\"bootstrapRegion\":\"SFO\"")]
    [Arguments("\"cell\":\"GRU\"", "\"cell\":\"gru\"")]
    [Arguments("\"sa-saopaulo-1\"", "\"us-ashburn-1\"")]
    [Arguments("[{\"cell\":\"GRU\",\"ociRegion\":\"sa-saopaulo-1\"}]", "[]")]
    [Arguments("[{\"cell\":\"GRU\",\"ociRegion\":\"sa-saopaulo-1\"}]", "[null]")]
    public async Task Rejects_invalid_region_intent(string from, string to)
    {
        await Assert.That(() => Parse(GruOnly.Replace(from, to, StringComparison.Ordinal)))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task Rejects_ambiguous_unknown_and_duplicate_properties_or_cells()
    {
        await Assert.That(() => Parse(GruOnly.Replace("\"generation\":7", "\"generation\":7,\"generation\":8")))
            .Throws<JsonException>();
        await Assert.That(() => Parse(GruOnly.Replace("\"generation\":7", "\"Generation\":7")))
            .Throws<JsonException>();
        await Assert.That(() => Parse(GruOnly.Replace("\"generation\":7", "\"generation\":7,\"ready\":true")))
            .Throws<JsonException>();
        await Assert.That(() => Parse(GruOnly.Replace(
            "\"regions\":[", "\"regions\":[{\"cell\":\"GRU\",\"ociRegion\":\"sa-saopaulo-1\"},")))
            .Throws<InvalidDataException>();
        await Assert.That(() => Parse(new string(' ', 16 * 1024 + 1))).Throws<InvalidDataException>();
    }

    [Test]
    public async Task Load_requires_a_bounded_private_regular_file()
    {
        if (!OperatingSystem.IsLinux()) return;
        var directory = Directory.CreateTempSubdirectory("ts-orch-region-intent-");
        var path = Path.Combine(directory.FullName, "intent.json");
        try
        {
            await Assert.That(() => OciRegionIntent.Load(null)).Throws<ArgumentException>();
            await Assert.That(() => OciRegionIntent.Load(path)).Throws<ArgumentException>();
            await File.WriteAllTextAsync(path, GruOnly);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            await Assert.That(OciRegionIntent.Load(path).Generation).IsEqualTo(7);
            var link = Path.Combine(directory.FullName, "link.json");
            File.CreateSymbolicLink(link, path);
            await Assert.That(() => OciRegionIntent.Load(link)).Throws<ArgumentException>();
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.GroupRead);
            await Assert.That(() => OciRegionIntent.Load(path)).Throws<ArgumentException>();
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            await File.WriteAllTextAsync(path, new string(' ', 16 * 1024 + 1));
            await Assert.That(() => OciRegionIntent.Load(path)).Throws<ArgumentException>();
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static OciRegionIntent Parse(string value) => OciRegionIntent.Parse(Encoding.UTF8.GetBytes(value));
}
