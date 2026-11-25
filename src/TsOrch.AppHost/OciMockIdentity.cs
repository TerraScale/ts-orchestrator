using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;

namespace TsOrch.AppHost;

internal sealed record class OciMockIdentity(
    ImdsInstanceDocument Instance,
    IReadOnlyList<ImdsVnicDocument> Vnics,
    string LeafCertificatePem,
    string LeafPrivateKeyPem,
    string IntermediateCertificatePem)
{
    public const string TenancyId = "ocid1.tenancy.oc1..localdev";
    public const string CompartmentId = "ocid1.compartment.oc1..localdev";
    public const string InstanceId = "ocid1.instance.oc1.sa-saopaulo-1.localdev";
    public const string OciRegion = "sa-saopaulo-1";

    public static OciMockIdentity Create(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        var now = timeProvider.GetUtcNow();

        using var intermediateKey = RSA.Create(2048);
        var intermediateRequest = new CertificateRequest(
            "CN=TsOrch Local OCI Intermediate, O=TerraScale Local",
            intermediateKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        intermediateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(intermediateRequest.PublicKey, false));
        using var intermediate = intermediateRequest.CreateSelfSigned(now.AddHours(-1), now.AddDays(30));

        using var leafKey = RSA.Create(2048);
        var subject = new X500DistinguishedNameBuilder();
        subject.AddCommonName(InstanceId);
        subject.AddOrganizationalUnitName("opc-certtype:instance");
        subject.AddOrganizationalUnitName($"opc-compartment:{CompartmentId}");
        subject.AddOrganizationalUnitName($"opc-instance:{InstanceId}");
        subject.AddOrganizationalUnitName($"opc-tenant:{TenancyId}");
        var leafRequest = new CertificateRequest(subject.Build(), leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], false));
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        using var leaf = leafRequest.Create(intermediate, now.AddHours(-1), now.AddDays(7), serial);

        var instance = new ImdsInstanceDocument(
            InstanceId,
            "ts-orch-local",
            CompartmentId,
            "Uocm:SA-SAOPAULO-1-AD-1",
            "FAULT-DOMAIN-1",
            "gru",
            OciRegion,
            "VM.Standard.A1.Flex",
            "Running",
            new ImdsRegionInfoDocument("OC1", "oraclecloud.com", "GRU", OciRegion),
            new JsonObject
            {
                ["ts_region"] = "gru",
                ["ts_pool"] = "worker",
                ["compute_management"] = new JsonObject { ["instance_configuration"] = new JsonObject { ["state"] = "SUCCEEDED" } },
            });
        IReadOnlyList<ImdsVnicDocument> vnics =
        [
            new ImdsVnicDocument("ocid1.vnic.oc1.sa-saopaulo-1.localdev", "127.0.0.1", "02:00:17:00:00:01", "127.0.0.1", "127.0.0.0/8"),
        ];

        return new OciMockIdentity(
            instance,
            vnics,
            leaf.ExportCertificatePem(),
            leafKey.ExportRSAPrivateKeyPem(),
            intermediate.ExportCertificatePem());
    }
}
