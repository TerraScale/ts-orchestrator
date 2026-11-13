package main

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	defer unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	for _, path := range []string{"/proc", "/sys", "/run", "/tmp", "/work"} {
		must(os.MkdirAll(path, 0o755))
	}
	must(unix.Mount("proc", "/proc", "proc", 0, ""))
	must(unix.Mount("sysfs", "/sys", "sysfs", 0, ""))
	must(unix.Mount("tmpfs", "/run", "tmpfs", 0, "mode=0755"))
	must(unix.Mount("ramfs", "/tmp", "ramfs", 0, "mode=1777"))
	must(os.MkdirAll("/firmware/class/dmi/id", 0o755))
	must(os.WriteFile("/firmware/class/dmi/id/chassis_asset_tag", []byte("OracleCloud.com\n"), 0o644))
	must(unix.Mount("/firmware", "/sys", "", unix.MS_BIND, ""))
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	must(err)
	for _, address := range []struct {
		name string
		ip   [4]byte
	}{{"lo", [4]byte{127, 0, 0, 1}}, {"lo:1", [4]byte{169, 254, 169, 254}}} {
		request, err := unix.NewIfreq(address.name)
		must(err)
		must(request.SetInet4Addr(address.ip[:]))
		must(unix.IoctlIfreq(socket, unix.SIOCSIFADDR, request))
	}
	request, err := unix.NewIfreq("lo")
	must(err)
	request.SetUint16(unix.IFF_UP | unix.IFF_LOOPBACK)
	must(unix.IoctlIfreq(socket, unix.SIOCSIFFLAGS, request))
	must(unix.Close(socket))
	for _, args := range [][]string{{"/alert-lane"}, {"/host-lane", "/ts-orch", "/work"}} {
		command := exec.Command(args[0], args[1:]...)
		command.Env = []string{"PATH=/bin", "HOME=/root"}
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			fmt.Println("credential-vm e2e: FAIL:", err)
			return
		}
	}
	fmt.Println("credential-vm e2e: PASS")
}
