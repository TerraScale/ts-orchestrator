package tsauth

// Replace only our tables atomically. Local filtering follows DNAT, including
// established sockets and IPv4-mapped sockets, which the kernel sends as IPv4.
// Namespace traffic has no trusted host UID: block routed and bridged paths,
// including bridges without br_netfilter. Only host root may obtain identity;
// workloads use host resolved/timesync rather than direct link-local access.
const metadataRules = `destroy table inet terrascale_metadata
destroy table bridge terrascale_metadata
table inet terrascale_metadata {
    chain prerouting {
        type filter hook prerouting priority -300; policy accept;
        ip daddr 169.254.169.254 counter drop
    }
    chain output {
        type filter hook output priority 0; policy accept;
        ip daddr 169.254.169.254 udp dport 123 accept
        ip daddr 169.254.169.254 meta skuid "systemd-resolve" meta l4proto { tcp, udp } th dport 53 accept
        ip daddr 169.254.169.254 meta skuid 0 accept
        ip daddr 169.254.169.254 counter drop
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
        ip daddr 169.254.169.254 counter drop
    }
}
table bridge terrascale_metadata {
    chain forward {
        type filter hook forward priority 0; policy accept;
        ip daddr 169.254.169.254 counter drop
    }
}
`

const metadataUnit = `[Unit]
Description=Reserve OCI instance metadata for host root
DefaultDependencies=no
After=local-fs.target systemd-sysusers.service nftables.service
Wants=network-pre.target
Before=network-pre.target shutdown.target
Before=containerd.service ts-orch.service terrascale-orchestrator-managed-host-start.service terrascale-orchestrator-controller-install.service terrascale-orchestrator-bootstrap.service terrascale-orchestrator-managed-runtime.service terrascale-orchestrator-controller.service terrascale-orchestrator-host-setup.service terrascale-orchestrator-host.service
Conflicts=shutdown.target

[Service]
Type=oneshot
ExecStartPre=/bin/sh -c '/usr/sbin/nft list table inet terrascale_metadata >/dev/null 2>&1 || /usr/sbin/nft add table inet terrascale_metadata'
ExecStartPre=/bin/sh -c '/usr/sbin/nft list table bridge terrascale_metadata >/dev/null 2>&1 || /usr/sbin/nft add table bridge terrascale_metadata'
ExecStart=/usr/sbin/nft -f /etc/terrascale-orchestrator/ts-auth-metadata.nft
RemainAfterExit=no

[Install]
RequiredBy=network-pre.target containerd.service ts-orch.service terrascale-orchestrator-managed-host-start.service terrascale-orchestrator-controller-install.service terrascale-orchestrator-bootstrap.service terrascale-orchestrator-managed-runtime.service terrascale-orchestrator-controller.service terrascale-orchestrator-host-setup.service terrascale-orchestrator-host.service
`
