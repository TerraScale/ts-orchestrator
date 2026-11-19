package hostos

import "os"

func NixOS() bool {
	_, err := os.Stat("/etc/NIXOS")
	return err == nil
}

func UnitDirectory() string {
	if NixOS() {
		return "/run/systemd/system"
	}
	return "/etc/systemd/system"
}
