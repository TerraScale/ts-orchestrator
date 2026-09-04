//go:build sandboxvm

package sandboxvm

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		KernelImage: filepath.Join(root, "vmlinux"), RootDrive: filepath.Join(root, "rootfs.ext4"), DataDrive: filepath.Join(root, "data.ext4"), SeedDrive: filepath.Join(root, "seed.img"),
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
