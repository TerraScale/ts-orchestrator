package hostos

import "os"

const Marker = "/etc/NIXOS"

func NixOS() bool {
	_, err := os.Stat(Marker)
	return err == nil
}

func UnitDirectory() string {
	if NixOS() {
		return "/run/systemd/system"
	}
	return "/etc/systemd/system"
}
