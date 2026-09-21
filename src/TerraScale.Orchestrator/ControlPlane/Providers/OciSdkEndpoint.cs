using Oci.Common;

namespace TerraScale.Orchestrator.ControlPlane.Providers;

/// <summary>Keep a reviewed explicit endpoint authoritative over the credential's home region.</summary>
internal static class OciSdkEndpoint
{
    internal static T Pin<T>(T client) where T : RegionalClientBase
    {
        // SetRegion installs a realm/dual-stack template during SDK construction.
        // An explicit endpoint alone does not clear it: request construction can
        // expand that stale template and bypass the supplied regional endpoint.
        client.SetRealmSpecificEndpointTemplate(null);
        return client;
    }
}
