package selfupdate

import (
	"errors"
	"os"
	"path/filepath"
)

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

// InstallNetBirdAgent adds the privileged worker only to managed hosts.
func InstallNetBirdAgent(systemdDir string) (bool, error) {
	if _, err := os.Stat(filepath.Join(systemdDir, HostSetupUnit)); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	managedRuntime, err := ManagedRuntimeInstalled(systemdDir, os.Geteuid())
	if err != nil {
		return false, err
	}
	changed := false
	for relative, contents := range map[string]string{
		NetBirdAgentUnit: NetBirdAgentService,
		"terrascale-orchestrator-host.service.d/65-netbird-agent.conf": NetBirdAgentHostDropin,
		"terrascale-netbird-enroll.service.d/zz-selfupdate.conf":       NetBirdEnrollDropin,
	} {
		if managedRuntime && relative == HostUnit+".d/65-netbird-agent.conf" {
			continue
		}
		path := filepath.Join(systemdDir, relative)
		if current, err := os.ReadFile(path); err == nil && string(current) == contents {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return changed, err
		}
		if err := writeFileAtomic(path, []byte(contents), 0o644); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}
