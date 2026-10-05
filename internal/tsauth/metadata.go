package tsauth

// Reload only this table, in one nft transaction. The systemd unit seeds the
// empty table before this file runs on first boot. Filter after destination
// NAT, including established sockets; other tables cannot bypass its drop.
// The host agent runs as root; native workloads lack host capabilities and
// cannot assume host UID 0 or alter this rule.
// The controller account needs instance metadata for its OCI client.
// OCI's NTP shares the address; only timesyncd keeps UDP/123 access.
const metadataRules = `destroy table inet terrascale_metadata
table inet terrascale_metadata {
    chain output {
        type filter hook output priority 0; policy accept;
        ip daddr 169.254.169.254 meta skuid "systemd-timesync" udp dport 123 accept
        ip daddr 169.254.169.254 meta skuid != { 0, "terrascale-orchestrator" } counter drop
    }
}
`
