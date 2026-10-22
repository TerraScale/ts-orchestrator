//go:build linux

package hostvolume

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The fixture uses an image-backed loop device and private mount namespaces;
// it never mounts or formats an existing host volume.
func TestRetainedMountKernelIntegration(t *testing.T) {
	if os.Getenv("TS_VOLUME_OBSERVER_FIXTURE") != "mount" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command("sudo", "-n", "env", "TS_VOLUME_OBSERVER_FIXTURE=mount", "nice", "-n", "19", "unshare", "--mount", executable, "-test.run=^TestRetainedMountKernelIntegration$", "-test.v")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("real block/mount fixture: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("/run", "ts-data-volume-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(directory, "disk")
	file, err := os.OpenFile(disk, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(32 << 20); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	device := strings.TrimSpace(fixtureCommand(t, "losetup", "--find", "--show", "--nooverlap", disk))
	t.Cleanup(func() { fixtureCommand(t, "losetup", "--detach", device) })
	const uuid = "0d370616-bf07-48e3-90a4-75e58c799c01"
	fixtureCommand(t, "mkfs.ext4", "-q", "-F", "-U", uuid, device)
	// udev may link the fresh filesystem in the shared /dev first; a tmpfs in this
	// private mount namespace keeps the fixture's link race-free and off the host.
	byUUID := "/dev/disk/by-uuid"
	if err := os.MkdirAll(byUUID, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", byUUID, "tmpfs", 0, "mode=0755"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(byUUID, unix.MNT_DETACH); err != nil {
			t.Error(err)
		}
	})
	uuidPath := filepath.Join(byUUID, uuid)
	if err := os.Symlink(device, uuidPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(uuidPath); err != nil {
			t.Error(err)
		}
	})
	volume := filepath.Join(directory, "volume")
	if err := os.Mkdir(volume, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(device, volume, "ext4", MountFlags, "errors=remount-ro"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(volume, 0); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(volume, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(volume, 0, 65534); err != nil {
		t.Fatal(err)
	}
	for _, child := range []string{"data", "replication"} {
		path := filepath.Join(volume, child)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	pins := MountPins{DevicePath: device, MountPath: volume, FileSystemUUID: uuid, FileSystemType: "ext4", UID: 65534, GID: 65534}
	witness, err := ObserveMount(pins)
	if err != nil {
		t.Fatal(err)
	}
	defer witness.Close()
	if err := witness.Recheck(); err != nil {
		t.Fatal(err)
	}
	rootfs := filepath.Join(directory, "rootfs")
	for _, path := range []string{rootfs, filepath.Join(rootfs, "retained"), filepath.Join(rootfs, "alias")} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command("unshare", "--mount", executable, "-test.run=^TestContainerMountFixture$")
	child.Env = append(os.Environ(), "TS_VOLUME_OBSERVER_FIXTURE=container", "TS_VOLUME_OBSERVER_ROOT="+rootfs, "TS_VOLUME_OBSERVER_SOURCE="+volume)
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	child.Stderr = &logs
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		child.Process.Kill()
		child.Wait()
		if logs.Len() > 0 {
			t.Log(logs.String())
		}
	})
	reader := bufio.NewReader(output)
	ready, err := reader.ReadString('\n')
	if err != nil || ready != "ready\n" {
		t.Fatalf("container mount fixture: %q, %v, %s", ready, err, logs.String())
	}
	if err := witness.VerifyContainerMount(child.Process.Pid, "/retained"); err != nil {
		t.Fatalf("actual cross-namespace retained bind: %v", err)
	}
	if err := witness.VerifyContainerMount(child.Process.Pid, "/retained/data"); err == nil {
		t.Fatal("partial filesystem root accepted as retained bind")
	}
	if _, err := fmt.Fprintln(input, "shadow"); err != nil {
		t.Fatal(err)
	}
	if ack, err := reader.ReadString('\n'); err != nil || ack != "shadowed\n" {
		t.Fatalf("shadow mount fixture: %q, %v", ack, err)
	}
	if err := witness.VerifyContainerMount(child.Process.Pid, "/retained"); err == nil {
		t.Fatal("second mount in container namespace accepted")
	}
	if err := unix.Mount("", volume, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOATIME, ""); err != nil {
		t.Fatal(err)
	}
	if err := witness.Recheck(); err == nil {
		t.Fatal("lost noexec protection accepted")
	}
	if err := HardenRemount(volume); err != nil {
		t.Fatal(err)
	}
	if err := witness.Recheck(); err != nil {
		t.Fatal(err)
	}
	witness.Close()
	if err := witness.Recheck(); err == nil {
		t.Fatal("closed retained witness accepted")
	}
}

func TestContainerMountFixture(t *testing.T) {
	if os.Getenv("TS_VOLUME_OBSERVER_FIXTURE") != "container" {
		return
	}
	root, source := os.Getenv("TS_VOLUME_OBSERVER_ROOT"), os.Getenv("TS_VOLUME_OBSERVER_SOURCE")
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(source, filepath.Join(root, "retained"), "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	if err := HardenRemount(filepath.Join(root, "retained")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chroot(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("/"); err != nil {
		t.Fatal(err)
	}
	fmt.Println("ready")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if scanner.Text() != "shadow" {
			t.Fatal("unknown fixture command")
		}
		if err := unix.Mount("/retained", "/alias", "", unix.MS_BIND, ""); err != nil {
			t.Fatal(err)
		}
		fmt.Println("shadowed")
	}
}

func fixtureCommand(t *testing.T, command string, args ...string) string {
	t.Helper()
	output, err := exec.Command(command, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s fixture command: %v: %s", command, err, output)
	}
	return string(output)
}

func TestRetainedMountRefusesUntrustedDevices(t *testing.T) {
	var zero MountWitness
	zero.Close()
	if err := zero.Recheck(); err == nil {
		t.Fatal("uninitialized retained witness accepted")
	}
	for _, device := range []string{"/dev/null", "/tmp/loop0", "/dev/oracleoci/../../sda", "/dev/../dev/sda"} {
		if fd, _, err := openBlockDevice(device); err == nil {
			unix.Close(fd)
			t.Fatalf("untrusted block device accepted: %s", device)
		}
	}
}
