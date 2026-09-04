package vmimage

import (
	"bytes"
	"strings"
	"testing"
)

func TestNoCloudSeedIsDeterministicAndComplete(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	kernel, rootfs := []byte("kernel"), []byte("rootfs")
	image := testManifest(writeTestFile(t, dir, "kernel", kernel), writeTestFile(t, dir, "rootfs", rootfs), kernel, rootfs)
	guestSeed, err := BuildGuestChannelSeed(GuestSeedSpec{
		Image: image, Hostname: "gru-member-1", InstanceID: "gru-member-1", Region: "gru", DataDiskPath: "/dev/vdb",
		Artifacts: []GuestArtifact{
			guestArtifact("terrabase", "3.0.0", "/artifacts/terrabase", []byte("terrabase")),
			guestArtifact("ts-node", "3.0.0", "/artifacts/ts-node", []byte("ts-node")),
			guestArtifact("orchestrator", "3.0.0", "/artifacts/orchestrator", []byte("orchestrator")),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	spec := NoCloudSeedSpec{
		InstanceID: "gru-member-1", Hostname: "gru-member-1", Region: "gru",
		Address: "10.77.0.10", PrefixBits: 24, Gateway: "10.77.0.1",
		Nameservers:      []string{"9.9.9.9", "1.1.1.1", "9.9.9.9"},
		SSHAuthorizedKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBB8hhavGePnkrgQT92jQZ3sm2CEuJtBQp8uYpOUwV4v vmqual",
		DataDevice:       "/dev/vdb", DataMount: "/var/lib/terrascale", GuestSeed: guestSeed,
	}
	first, err := BuildNoCloudSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildNoCloudSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.MetaData, second.MetaData) || !bytes.Equal(first.NetworkConfig, second.NetworkConfig) || !bytes.Equal(first.UserData, second.UserData) {
		t.Fatal("NoCloud output changed for identical input")
	}
	for _, expected := range []string{"instance-id: 'gru-member-1'", "terrascale-region: 'gru'"} {
		if !strings.Contains(string(first.MetaData), expected) {
			t.Fatalf("metadata does not contain %q", expected)
		}
	}
	for _, expected := range []string{"10.77.0.10/24", "via: 10.77.0.1", "addresses: [1.1.1.1, 9.9.9.9]"} {
		if !strings.Contains(string(first.NetworkConfig), expected) {
			t.Fatalf("network config does not contain %q", expected)
		}
	}
	for _, expected := range []string{"#cloud-config", "ssh_pwauth: false", "lock_passwd: true", "guest-seed.json", "terrascale-data", "/var/lib/terrascale"} {
		if !strings.Contains(string(first.UserData), expected) {
			t.Fatalf("user data does not contain %q", expected)
		}
	}
	if strings.Contains(string(first.UserData), "PRIVATE KEY") {
		t.Fatal("NoCloud seed contains private key material")
	}
}

func TestNoCloudSeedRejectsUnsafeOrInconsistentInput(t *testing.T) {
	t.Parallel()
	base := NoCloudSeedSpec{
		InstanceID: "gru-member-1", Hostname: "gru-member-1", Region: "gru",
		Address: "10.77.0.10", PrefixBits: 24, Gateway: "10.77.0.1",
		SSHAuthorizedKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBB8hhavGePnkrgQT92jQZ3sm2CEuJtBQp8uYpOUwV4v vmqual",
		GuestSeed:        []byte("not-json"),
	}
	if _, err := BuildNoCloudSeed(base); err == nil || !strings.Contains(err.Error(), "guest seed") {
		t.Fatalf("invalid guest seed accepted: %v", err)
	}
	base.GuestSeed = []byte(`{}`)
	base.Gateway = "10.78.0.1"
	if _, err := BuildNoCloudSeed(base); err == nil || !strings.Contains(err.Error(), "share") {
		t.Fatalf("off-subnet gateway accepted: %v", err)
	}
	base.Gateway = "10.77.0.1"
	base.SSHAuthorizedKey = "ssh-rsa AAAA legacy"
	if _, err := BuildNoCloudSeed(base); err == nil || !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("unadmitted SSH key accepted: %v", err)
	}
}

func TestMACForIPv4(t *testing.T) {
	t.Parallel()
	mac, err := MACForIPv4("10.77.2.14")
	if err != nil {
		t.Fatal(err)
	}
	if mac != "06:00:0a:4d:02:0e" {
		t.Fatalf("MAC = %q", mac)
	}
	if _, err := MACForIPv4("not-an-address"); err == nil {
		t.Fatal("invalid address was accepted")
	}
}
