package selfupdate

const NetBirdAgentUnit = "terrascale-netbird-agent.service"

// NetBirdAgentService is deploy/systemd's copy byte for byte. The worker
// applies signed host commands under root without broadening host privileges.
const NetBirdAgentService = `[Unit]
Description=Apply authenticated TerraScale NetBird client changes
Wants=network-online.target
After=network-online.target terrascale-orchestrator-host-setup.service
PartOf=terrascale-orchestrator-host.service
ConditionPathExists=/etc/terrascale-orchestrator/host.json
StartLimitIntervalSec=0

[Service]
Type=simple
ExecCondition=/bin/sh -c 'b=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator; [ -x "$$b" ] || b=/usr/local/bin/terrascale-orchestrator; exec "$$b" netbird agent run --help'
ExecStart=/bin/sh -c 'b=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator; [ -x "$$b" ] || b=/usr/local/bin/terrascale-orchestrator; exec "$$b" netbird agent run --config /etc/terrascale-orchestrator/host.json'
Restart=on-failure
RestartSec=5s
UMask=0077
StateDirectory=terrascale-netbird-agent terrascale-orchestrator/netbird-managed
StateDirectoryMode=0700
# This root worker verifies signed host commands before changing the binary
# or systemd units; the workload host remains under ProtectSystem=strict.
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`

const NetBirdAgentHostDropin = "[Unit]\nWants=terrascale-netbird-agent.service\nAfter=terrascale-netbird-agent.service\n\n[Service]\nInaccessiblePaths=-/var/lib/terrascale-netbird-agent -/var/lib/terrascale-orchestrator/netbird-managed\n"

const NetBirdEnrollDropin = `[Service]
ExecStart=
ExecStart=/bin/sh -c 'b=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator; [ -x "$$b" ] || b=/usr/local/bin/terrascale-orchestrator; exec "$$b" netbird-enroll --config /etc/terrascale-orchestrator/netbird.json'
# A missing client is installed from the verified image fallback.
ReadWritePaths=/usr/local/bin /var/lib/terrascale-orchestrator
`
