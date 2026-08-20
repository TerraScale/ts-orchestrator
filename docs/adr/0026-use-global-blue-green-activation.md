# Use a global blue-green activation barrier

TerraScale prepares the exact release candidate beside the active version in every region. Traffic switches globally only after every region passes health checks and the synthetic customer journey. If any region fails before activation, no region switches. A qualifying failure after activation returns all regions to the previous qualified digest.
