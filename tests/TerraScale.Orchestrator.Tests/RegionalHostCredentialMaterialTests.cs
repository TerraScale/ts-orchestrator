using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalHostCredentialMaterialTests
{
    [Test]
    public async Task An_earlier_trust_anchor_expiry_limits_the_entire_material_generation()
    {
        using var fixture = new HostCredentialMaterialFixture(certificateKind: "short-ca");
        var clock = new LeaseTestClock(DateTimeOffset.UtcNow);
        var material = fixture.Load(clock);
        using var ca = X509CertificateLoader.LoadCertificateFromFile(fixture.Tls.CaFile);
        using var certificate = X509CertificateLoader.LoadCertificateFromFile(fixture.Tls.CertificateFile);
        await Assert.That(ca.NotAfter).IsLessThan(certificate.NotAfter);
        await Assert.That((await material.ObserveAsync(CancellationToken.None))?.ExpiresAt)
            .IsEqualTo(new DateTimeOffset(ca.NotAfter.ToUniversalTime()));
        clock.Advance(TimeSpan.FromMinutes(31));
        await Assert.That(await material.ObserveAsync(CancellationToken.None)).IsNull();
    }

    [Test]
    public async Task Symlink_ancestors_cannot_substitute_a_credential_directory()
    {
        using var fixture = new HostCredentialMaterialFixture();
        var material = fixture.Load();
        var original = fixture.Directory.FullName;
        var moved = original + "-moved";
        Directory.Move(original, moved);
        try
        {
            Directory.CreateSymbolicLink(original, moved);
            await Assert.That(await material.ObserveAsync(CancellationToken.None)).IsNull();
        }
        finally
        {
            if (Directory.Exists(original)) Directory.Delete(original);
            Directory.Move(moved, original);
        }
    }

    [Test]
    public async Task JWT_expiry_limits_material_even_when_the_certificate_lives_longer()
    {
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeSeconds());
        using var fixture = new HostCredentialMaterialFixture(jwtExpires: expiresAt.ToUnixTimeSeconds());
        var clock = new LeaseTestClock(DateTimeOffset.UtcNow);
        var material = fixture.Load(clock);
        await Assert.That((await material.ObserveAsync(CancellationToken.None))?.ExpiresAt).IsEqualTo(expiresAt);
        clock.Advance(TimeSpan.FromMinutes(1));
        await Assert.That(await material.ObserveAsync(CancellationToken.None)).IsNull();
    }

    [Test]
    [Arguments("expired")]
    [Arguments("future")]
    public async Task JWT_validity_is_required_even_with_matching_signed_files(string invalid)
    {
        var now = DateTimeOffset.UtcNow;
        using var fixture = new HostCredentialMaterialFixture(jwtExpires: invalid == "expired" ? now.AddMinutes(-1).ToUnixTimeSeconds() : null,
            jwtNotBefore: invalid == "future" ? now.AddMinutes(1).ToUnixTimeSeconds() : null);
        await Assert.That(() => fixture.Load()).Throws<InvalidDataException>();
    }

    [Test]
    public async Task Production_configuration_requires_signed_material()
    {
        await Assert.That(() => RegionalHostAdmissionConfiguration.Load(_ => null, "gru")).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Material_remains_valid_after_bootstrap_expiry_without_authorizing_a_new_bootstrap(bool jwt)
    {
        using var fixture = new HostCredentialMaterialFixture(jwt);
        var clock = new LeaseTestClock(DateTimeOffset.UtcNow);
        var material = fixture.Load(clock);
        var first = await material.ObserveAsync(CancellationToken.None);
        using var certificate = X509CertificateLoader.LoadCertificateFromFile(fixture.Tls.CertificateFile);
        await Assert.That(first?.ExpiresAt).IsEqualTo(new DateTimeOffset(certificate.NotAfter.ToUniversalTime()));
        clock.Advance(TimeSpan.FromMinutes(6));
        await Assert.That(await material.ObserveAsync(CancellationToken.None)).IsEqualTo(first);
        await Assert.That(fixture.Session.Policy().AllowsFreshEnrollment(material.Enrollment, clock.GetUtcNow(), clock.GetUtcNow().AddSeconds(30))).IsFalse();
        await Assert.That(fixture.Session.Policy().AllowsContinuingEnrollment(material.Enrollment, clock.GetUtcNow(), clock.GetUtcNow().AddSeconds(30))).IsTrue();
        clock.Advance(TimeSpan.FromHours(1));
        await Assert.That(await material.ObserveAsync(CancellationToken.None)).IsNull();
    }

    [Test]
    [Arguments("ca")]
    [Arguments("server")]
    [Arguments("no-eku")]
    [Arguments("wrong-usage")]
    [Arguments("expired")]
    [Arguments("future")]
    public async Task Invalid_certificate_validity_or_usage_is_rejected_even_with_a_signed_manifest(string kind)
    {
        using var fixture = new HostCredentialMaterialFixture(certificateKind: kind);
        await Assert.That(() => fixture.Load()).Throws<InvalidDataException>();
    }

    [Test]
    [Arguments("node")]
    [Arguments("region")]
    [Arguments("account")]
    [Arguments("cluster")]
    [Arguments("environment")]
    [Arguments("role")]
    [Arguments("signer")]
    [Arguments("project")]
    public async Task Enrollment_requires_exact_identity_scope_and_trust(string mismatch)
    {
        using var fixture = new HostCredentialMaterialFixture();
        var original = fixture.Configuration;
        var changed = mismatch switch
        {
            "node" => original with { NodeId = "wrong-node" },
            "region" => original with { Region = "FRA" },
            "account" => original with { NatsAccountPublicKey = "A-other" },
            "cluster" => original with { ClusterName = "wrong-cluster" },
            "environment" => original with { Scope = new("staging", original.Scope.Roles) },
            "role" => original with { Scope = new("production", [AdmittedRole.Authentication]) },
            "signer" => original with { EnrollmentSignerKeyVersion = 2 },
            "project" => original with { ExpectedSystemProject = new(original.ExpectedSystemProject.OrganizationUlid,
                original.ExpectedSystemProject.ProjectUlid, new("00000000000000000000000009")) },
            _ => throw new ArgumentOutOfRangeException(nameof(mismatch))
        };
        await Assert.That(() => RegionalHostCredentialMaterial.Load(changed, fixture.Authentication, fixture.Tls)).Throws<InvalidDataException>();
    }

    [Test]
    [Arguments("manifest")]
    [Arguments("enrollment")]
    [Arguments("trust")]
    [Arguments("signer")]
    [Arguments("nats")]
    [Arguments("ca")]
    [Arguments("certificate")]
    [Arguments("key")]
    public async Task Mutating_any_pinned_file_revokes_material_evidence(string item)
    {
        using var fixture = new HostCredentialMaterialFixture();
        var material = fixture.Load();
        var path = item switch
        {
            "manifest" => fixture.Configuration.BundleFile,
            "enrollment" => fixture.Configuration.EnrollmentFile,
            "trust" => fixture.Configuration.BootstrapTrustBundleFile,
            "signer" => fixture.Configuration.EnrollmentSignerPublicKeyFile,
            "nats" => fixture.Authentication.CredentialsFile!,
            "ca" => fixture.Tls.CaFile,
            "certificate" => fixture.Tls.CertificateFile,
            "key" => fixture.Tls.KeyFile,
            _ => throw new ArgumentOutOfRangeException(nameof(item))
        };
        File.AppendAllText(path, "\n");
        await Assert.That(await material.ObserveAsync(CancellationToken.None)).IsNull();
    }

    [Test]
    [Arguments("duplicate")]
    [Arguments("missing")]
    [Arguments("extra")]
    [Arguments("relative")]
    [Arguments("alias")]
    [Arguments("hash")]
    public async Task A_signed_manifest_must_unambiguously_name_the_exact_transport_files(string invalid)
    {
        using var fixture = new HostCredentialMaterialFixture();
        var manifest = JsonNode.Parse(File.ReadAllText(fixture.Configuration.BundleFile))!.AsObject();
        var files = manifest["files"]!.AsArray();
        switch (invalid)
        {
            case "duplicate": files[1] = files[0]!.DeepClone(); break;
            case "missing": files.RemoveAt(0); break;
            case "extra": files.Add(files[0]!.DeepClone()); break;
            case "relative": files[0]!["path"] = "host.creds"; break;
            case "alias": files[0]!["path"] = fixture.Directory.FullName + "/./host.creds"; break;
            case "hash": files[0]!["sha256"] = new string('0', 64); break;
        }
        fixture.Bind(manifest.ToJsonString());
        await Assert.That(() => fixture.Load()).Throws<InvalidDataException>();
    }

    [Test]
    [Arguments("wrong-key")]
    [Arguments("wrong-ca")]
    [Arguments("wrong-fingerprint")]
    public async Task Signed_files_still_require_key_chain_and_grant_certificate_binding(string invalid)
    {
        using var fixture = new HostCredentialMaterialFixture();
        using var other = new HostCredentialMaterialFixture();
        if (invalid == "wrong-key") File.Copy(other.Tls.KeyFile, fixture.Tls.KeyFile, overwrite: true);
        if (invalid == "wrong-ca") File.Copy(other.Tls.CaFile, fixture.Tls.CaFile, overwrite: true);
        fixture.Bind(fingerprint: invalid == "wrong-fingerprint" ? new BootstrapCertificateFingerprint(new string('0', 64)) : null);
        if (invalid == "wrong-key") await Assert.That(() => fixture.Load()).Throws<ArgumentException>();
        else await Assert.That(() => fixture.Load()).Throws<InvalidDataException>();
    }

    [Test]
    [Arguments("missing")]
    [Arguments("public")]
    [Arguments("symlink")]
    [Arguments("oversized")]
    public async Task Delivered_files_must_remain_bounded_private_and_present(string invalid)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Host credentials require Linux permissions.");
        using var fixture = new HostCredentialMaterialFixture();
        var material = fixture.Load();
        var path = fixture.Tls.KeyFile;
        switch (invalid)
        {
            case "missing": File.Delete(path); break;
            case "public": File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.OtherRead); break;
            case "symlink":
                File.Move(path, path + ".moved");
                File.CreateSymbolicLink(path, path + ".moved");
                break;
            case "oversized": File.WriteAllBytes(path, new byte[256 * 1024 + 1]); break;
        }
        await Assert.That(await material.ObserveAsync(CancellationToken.None)).IsNull();
    }
}
