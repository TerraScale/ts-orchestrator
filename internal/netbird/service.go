package netbird

import "github.com/TerraScale/ts-orchestrator/internal/hostos"

const ServerServiceName = "netbird-server"

const (
	ubuntuClient = "/usr/local/bin/netbird"
	nixosClient  = "/run/current-system/sw/bin/netbird"
)

func ClientBinary() string {
	if hostos.NixOS() {
		return nixosClient
	}
	return ubuntuClient
}

func RemoteClientBinary() string {
	return "$(if test -e " + hostos.Marker + "; then echo " + nixosClient + "; else echo " + ubuntuClient + "; fi)"
}
