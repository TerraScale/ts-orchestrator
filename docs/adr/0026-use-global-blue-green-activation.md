# Use a global blue-green activation barrier

Status: Superseded by workspace D-67. Delivery now uses one GRU canary followed
by a one-host-at-a-time rolling deployment that preserves RF=2.

TerraScale prepares the exact release candidate beside the active version in every region. Traffic switches globally only after every region passes health checks and the synthetic customer journey. If any region fails before activation, no region switches. A qualifying failure after activation returns all regions to the previous qualified digest.
