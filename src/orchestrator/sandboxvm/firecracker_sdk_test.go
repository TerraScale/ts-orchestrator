//go:build sandboxvm

package sandboxvm

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	"golang.org/x/sys/unix"
)

func TestSDKConfigCarriesNetworkSeedAndBoundedDiagnostics(t *testing.T) {
	t.Parallel()
	root, err := os.MkdirTemp("", "sandboxvm-sdk-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	uid, gid := 1000, 1000
	config := Config{
		ID: "gru-member-1", VCPU: 1, MemoryMiB: 512,
		KernelImage: filepath.Join(root, "vmlinux"), RootDrive: filepath.Join(root, "rootfs.ext4"), DataDrive: filepath.Join(root, "data.ext4"), DataDriveReadOnly: true, SeedDrive: filepath.Join(root, "seed.img"),
		StateRoot: root, JailerUID: &uid, JailerGID: &gid, FirecrackerBinary: filepath.Join(root, "firecracker"), JailerBinary: filepath.Join(root, "jailer"),
		NetworkNamespace: "/var/run/netns/ts-n-gru", TapName: "ts-t-gru-01", GuestMAC: "06:00:0a:4d:00:0a",
	}
	sdk, err := buildSDKConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if sdk.KernelArgs != "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw" {
		t.Fatalf("kernel args = %q", sdk.KernelArgs)
	}
	if sdk.NetNS != config.NetworkNamespace || len(sdk.NetworkInterfaces) != 1 {
		t.Fatalf("network not carried into SDK config: %#v", sdk.NetworkInterfaces)
	}
	static := sdk.NetworkInterfaces[0].StaticConfiguration
	if static == nil || static.HostDevName != config.TapName || static.MacAddress != config.GuestMAC {
		t.Fatalf("static network = %#v", static)
	}
	if len(sdk.Drives) != 3 || sdk.Drives[2].DriveID == nil || *sdk.Drives[2].DriveID != "seed" || sdk.Drives[2].IsReadOnly == nil || !*sdk.Drives[2].IsReadOnly {
		t.Fatalf("seed drive is not read-only: %#v", sdk.Drives)
	}
	if sdk.Drives[1].DriveID == nil || *sdk.Drives[1].DriveID != "data" || sdk.Drives[1].IsReadOnly == nil || !*sdk.Drives[1].IsReadOnly {
		t.Fatalf("data drive did not carry read-only plan: %#v", sdk.Drives[1])
	}
	if sdk.JailerCfg == nil || sdk.JailerCfg.ExecFile != config.FirecrackerBinary || sdk.JailerCfg.JailerBinary != config.JailerBinary || sdk.JailerCfg.CgroupVersion != "2" || sdk.JailerCfg.Daemonize {
		t.Fatalf("jailer config = %#v", sdk.JailerCfg)
	}
	if sdk.JailerCfg.ChrootBaseDir != root || sdk.SocketPath != jailerSocketPath {
		t.Fatalf("chroot/socket = %q / %q", sdk.JailerCfg.ChrootBaseDir, sdk.SocketPath)
	}
	if !sdk.Seccomp.Enabled {
		t.Fatal("Firecracker built-in seccomp was disabled")
	}
	stateDir := filepath.Join(root, "firecracker", config.ID)
	if sdk.LogPath != "" || sdk.MetricsPath != "" || sdk.LogFifo != filepath.Join(stateDir, "firecracker-log.fifo") || sdk.MetricsFifo != filepath.Join(stateDir, "firecracker-metrics.fifo") || sdk.FifoLogWriter == nil {
		t.Fatal("jailed bounded diagnostic FIFOs were not configured")
	}
	if _, ok := sdk.JailerCfg.ChrootStrategy.(*jailerChrootStrategy); !ok {
		t.Fatalf("chroot strategy = %T", sdk.JailerCfg.ChrootStrategy)
	}
	detached := config
	detached.DataDrive = ""
	detached.DataDriveReadOnly = false
	detachedSDK, err := buildSDKConfig(detached)
	if err != nil {
		t.Fatal(err)
	}
	if len(detachedSDK.Drives) != 2 || firecracker.StringValue(detachedSDK.Drives[0].DriveID) != "rootfs" || firecracker.StringValue(detachedSDK.Drives[1].DriveID) != "seed" {
		t.Fatalf("detached drive config = %#v", detachedSDK.Drives)
	}
	constructed, err := NewSDKMachineFactory()(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	machine, ok := constructed.(*sdkMachine)
	if !ok {
		t.Fatalf("machine type = %T", constructed)
	}
	defer machine.Close()
	if machine.machine.Cfg.SocketPath != filepath.Join(stateDir, "root", "api.sock") {
		t.Fatalf("SDK host socket = %q", machine.machine.Cfg.SocketPath)
	}
	if machine.machine.Cfg.JailerCfg == nil || machine.machine.Cfg.JailerCfg.UID == nil || machine.machine.Cfg.JailerCfg.GID == nil || *machine.machine.Cfg.JailerCfg.UID == 0 || *machine.machine.Cfg.JailerCfg.GID == 0 || machine.machine.Cfg.JailerCfg.Daemonize {
		t.Fatalf("SDK jailer target = %#v", machine.machine.Cfg.JailerCfg)
	}
	cgroupRoot, err := discoverCgroup2Mount()
	if err != nil {
		t.Fatal(err)
	}
	if !machine.machine.Handlers.FcInit.Has(firecracker.LinkFilesToRootFSHandlerName) || !machine.machine.Handlers.FcInit.Has(attachCgroupHandlerName) || machine.cgroup == nil || machine.cgroup.path != filepath.Join(cgroupRoot, cgroupParentName, config.ID) {
		t.Fatalf("SDK owned cgroup = %#v", machine.cgroup)
	}
}

func TestJailerStrategyHardLinksRegularDrives(t *testing.T) {
	root := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 || gid == 0 {
		uid, gid = 1000, 1000
	}
	write := func(name string, mode os.FileMode) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(name), mode); err != nil {
			t.Fatal(err)
		}
		if (os.Getuid() != uid || os.Getgid() != gid) && mode == 0600 {
			if err := os.Chown(path, uid, gid); err != nil {
				t.Fatal(err)
			}
		}
		return path
	}
	kernel := write("vmlinux", 0644)
	rootDrive := write("rootfs.ext4", 0600)
	dataDrive := write("data.ext4", 0600)
	logFIFO := filepath.Join(root, "firecracker-log.fifo")
	metricsFIFO := filepath.Join(root, "firecracker-metrics.fifo")
	for _, path := range []string{logFIFO, metricsFIFO} {
		if err := syscall.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
	}
	jailRoot := filepath.Join(root, "firecracker", "vm-1", "root")
	if err := os.MkdirAll(jailRoot, 0700); err != nil {
		t.Fatal(err)
	}
	writable := false
	machine := &firecracker.Machine{Cfg: firecracker.Config{
		KernelImagePath: kernel,
		Drives: []models.Drive{
			{DriveID: firecracker.String("rootfs"), PathOnHost: firecracker.String(rootDrive), IsRootDevice: firecracker.Bool(true), IsReadOnly: &writable},
			{DriveID: firecracker.String("data"), PathOnHost: firecracker.String(dataDrive), IsRootDevice: firecracker.Bool(false), IsReadOnly: &writable},
		},
		LogFifo: logFIFO, MetricsFifo: metricsFIFO,
		JailerCfg: &firecracker.JailerConfig{ID: "vm-1", UID: &uid, GID: &gid, ExecFile: filepath.Join(root, "firecracker"), ChrootBaseDir: root},
	}}
	strategy := jailerChrootStrategy{kernelImage: kernel, blockOps: realBlockNodeOperations()}
	if err := strategy.stageJailFiles(context.Background(), machine); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		source string
		name   string
	}{
		{source: kernel, name: "vmlinux"},
		{source: rootDrive, name: "rootfs.ext4"},
		{source: dataDrive, name: "data.ext4"},
	} {
		sourceInfo, sourceErr := os.Stat(tc.source)
		jailInfo, jailErr := os.Stat(filepath.Join(jailRoot, tc.name))
		if sourceErr != nil || jailErr != nil || !os.SameFile(sourceInfo, jailInfo) {
			t.Fatalf("staged %s identity: source=%v jail=%v", tc.name, sourceErr, jailErr)
		}
	}
	if machine.Cfg.KernelImagePath != "vmlinux" || firecracker.StringValue(machine.Cfg.Drives[0].PathOnHost) != "rootfs.ext4" || firecracker.StringValue(machine.Cfg.Drives[1].PathOnHost) != "data.ext4" {
		t.Fatalf("jailed config paths = kernel %q drives %#v", machine.Cfg.KernelImagePath, machine.Cfg.Drives)
	}
}

func TestCreateJailBlockDeviceUsesExactDeviceIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), faultDataDriveJailName)
	source := blockDeviceIdentity{Path: "/dev/dm-7", Device: 1, Inode: 2, Rdev: 0x1234}
	var gotMode uint32
	var gotDevice int
	var gotUID, gotGID int
	removed := false
	ops := blockNodeOperations{
		mknod: func(gotPath string, mode uint32, device int) error {
			if gotPath != path {
				t.Fatalf("mknod path = %q", gotPath)
			}
			gotMode, gotDevice = mode, device
			return nil
		},
		chown: func(_ string, uid, gid int) error { gotUID, gotGID = uid, gid; return nil },
		chmod: func(_ string, mode os.FileMode) error {
			if mode != 0600 {
				t.Fatalf("chmod mode = %04o", mode)
			}
			return nil
		},
		inspect: func(gotPath string, uid, gid int) (blockDeviceIdentity, error) {
			return blockDeviceIdentity{Path: gotPath, Device: 3, Inode: 4, Rdev: source.Rdev}, nil
		},
		remove: func(string) error { removed = true; return nil },
	}
	if err := createJailBlockDevice(path, 1000, 1001, source, ops); err != nil {
		t.Fatal(err)
	}
	if gotMode != uint32(unix.S_IFBLK|0600) || gotDevice != int(source.Rdev) || gotUID != 1000 || gotGID != 1001 || removed {
		t.Fatalf("block staging = mode %#o device %#x owner %d:%d removed=%v", gotMode, gotDevice, gotUID, gotGID, removed)
	}
	ops.inspect = func(string, int, int) (blockDeviceIdentity, error) {
		return blockDeviceIdentity{Rdev: source.Rdev + 1}, nil
	}
	if err := createJailBlockDevice(path, 1000, 1001, source, ops); err == nil {
		t.Fatal("mismatched jailed block device was accepted")
	}
	if !removed {
		t.Fatal("failed block staging did not remove its node")
	}
}

func TestOwnedCgroupUsesBoundedResourcesAndNUMANode(t *testing.T) {
	numa := 2
	cfg := Config{ID: "gru-member-1", VCPU: 2, MemoryMiB: 512, FirecrackerBinary: "/opt/terrascale/firecracker", JailerNumaNode: &numa}
	cgroup := newOwnedCgroup("/sys/fs/cgroup", cfg)
	if cgroup.path != "/sys/fs/cgroup/terrascale-sandboxvm/gru-member-1" || cgroup.jailerPath != "/sys/fs/cgroup/firecracker/gru-member-1" {
		t.Fatalf("cgroup paths = %q / %q", cgroup.path, cgroup.jailerPath)
	}
	if cgroup.cpuMax != "200000 100000" || cgroup.memoryMax != "671088640" || cgroup.pidsMax != "64" || cgroup.numaNode != numa {
		t.Fatalf("cgroup limits = cpu %q, memory %q, pids %q, NUMA %d", cgroup.cpuMax, cgroup.memoryMax, cgroup.pidsMax, cgroup.numaNode)
	}
	if !cpuSetContains("0-3,8-9", "1-2,8") || cpuSetContains("0-3", "3-4") || cpuSetContains("0-3", "bad") {
		t.Fatal("cpuset containment validation failed")
	}
}

func TestBoundedDiagnosticWriterNeverExceedsLimit(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "firecracker.log")
	writer := &boundedDiagnosticWriter{path: path, limit: 8}
	input := bytes.Repeat([]byte("x"), 32)
	if n, err := writer.Write(input); err != nil || n != len(input) {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 8 || writer.observation().Bytes != 8 || !writer.observation().Truncated {
		t.Fatalf("bounded output = %d bytes, observation=%+v", len(data), writer.observation())
	}
}

func TestBoundedDiagnosticWriterRetainsBoundAcrossRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "firecracker.log")
	first, err := newBoundedDiagnosticWriter(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := newBoundedDiagnosticWriter(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write([]byte("-second")); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first-se" || second.observation().Bytes != 8 || !second.observation().Truncated {
		t.Fatalf("bounded restart output = %q, observation=%+v", data, second.observation())
	}
}

func TestBoundedDiagnosticWriterRejectsUnsafeExistingPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "diagnostic")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := newBoundedDiagnosticWriter(link, 8); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("symlink error = %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := newBoundedDiagnosticWriter(link, 8); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("mode error = %v", err)
	}
}
