//go:build sandboxvm

package sandboxvm

import (
	"path/filepath"
	"testing"
)

func TestSDKConfigCarriesNetworkSeedAndBoundedDiagnostics(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	config := Config{
		ID: "gru-member-1", VCPU: 1, MemoryMiB: 512,
		KernelImage: filepath.Join(root, "vmlinux"), RootDrive: filepath.Join(root, "rootfs.ext4"), DataDrive: filepath.Join(root, "data.ext4"), SeedDrive: filepath.Join(root, "seed.img"),
		SocketPath: filepath.Join(root, "firecracker.sock"), NetworkNamespace: "/var/run/netns/ts-n-gru", TapName: "ts-t-gru-01", GuestMAC: "06:00:0a:4d:00:0a",
		LogPath: filepath.Join(root, "firecracker.log"), MetricsPath: filepath.Join(root, "firecracker.metrics"),
	}
	sdk := buildSDKConfig(config)
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
	if sdk.LogPath != config.LogPath || sdk.MetricsPath != config.MetricsPath {
		t.Fatal("bounded diagnostic paths were dropped")
	}
}
