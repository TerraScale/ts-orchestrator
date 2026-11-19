package netbird

import "github.com/TerraScale/ts-orchestrator/internal/hostos"

const ServerServiceName = "netbird-server"

func ClientBinary() string {
	if hostos.NixOS() {
		return "/run/current-system/sw/bin/netbird"
	}
	return "/usr/local/bin/netbird"
}
