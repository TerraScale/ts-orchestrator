using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TerraScale.Orchestrator.Bootstrap;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Bootstrap;

/// <summary>
/// Test-owned mint for the short-lived self-signed ECDSA P-256 workload certificate the grant
/// binds. Production workload identity issuance stays with the Orchestrator provider adapter;
/// this local, testable shape moved out of the production assembly with the GOAL P0 purity cut
/// (REQ-ORCH-021).
/// </summary>
internal static class TestWorkloadCertificateFactory
{
    public static BootstrapWorkloadCertificate Issue(
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        string commonName = "terrascale-bootstrap-workload")
    {
        if (notAfter <= notBefore) throw new ArgumentOutOfRangeException(nameof(notAfter), "A workload certificate must have a positive lifetime.");
        ArgumentException.ThrowIfNullOrEmpty(commonName);
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        try
        {
            var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);
            var certificate = request.CreateSelfSigned(notBefore.UtcDateTime, notAfter.UtcDateTime);
            return new BootstrapWorkloadCertificate(certificate, key);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }
}
