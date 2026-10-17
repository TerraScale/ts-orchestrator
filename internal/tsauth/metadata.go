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
        ip daddr 169.254.169.254 meta skuid "systemd-timesync" udp dport 123 accept
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
