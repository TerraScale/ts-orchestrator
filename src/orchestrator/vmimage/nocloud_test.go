package vmimage

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"strings"
	"testing"
)

func TestNoCloudSeedIsDeterministicAndComplete(t *testing.T) {
	t.Parallel()
	spec := validNoCloudSpec(t)
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
	for _, expected := range []string{"#cloud-config", "ssh_pwauth: false", "lock_passwd: true", `restrict,command="/usr/local/libexec/terrascale-vmqual-control"`, GuestSeedPath, "terrascale-data", "/var/lib/terrascale", "f0VMRgIBAQA"} {
		if !strings.Contains(string(first.UserData), expected) {
			t.Fatalf("user data does not contain %q", expected)
		}
	}
	if strings.Contains(string(first.UserData), "is-system-running") {
		t.Fatal("cloud-final contains a self-waiting systemd readiness command")
	}
	if strings.Contains(string(first.UserData), "PRIVATE KEY") {
		t.Fatal("NoCloud seed contains private key material")
	}
}

func TestNoCloudSeedRejectsInvalidGuestControl(t *testing.T) {
	t.Parallel()
	spec := validNoCloudSpec(t)
	tests := []struct {
		name    string
		control []byte
		want    string
	}{
		{name: "missing", want: "size"},
		{name: "malformed", control: []byte("not-elf"), want: "not ELF"},
		{name: "header only", control: elfHeader64(elf.EM_AARCH64), want: "entry segment"},
		{name: "wrong architecture", control: runnableELF64(elf.EM_X86_64), want: "architecture"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := spec
			candidate.GuestControl = test.control
			if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid guest control accepted: %v", err)
			}
		})
	}
}

func TestNoCloudSeedRejectsUnsafeOrInconsistentInput(t *testing.T) {
	t.Parallel()
	base := validNoCloudSpec(t)
	candidate := base
	candidate.GuestSeed = []byte("not-json")
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "guest seed") {
		t.Fatalf("invalid guest seed accepted: %v", err)
	}
	candidate = base
	candidate.Gateway = "10.78.0.1"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "share") {
		t.Fatalf("off-subnet gateway accepted: %v", err)
	}
	candidate = base
	candidate.SSHAuthorizedKey = "ssh-rsa AAAA legacy"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("unadmitted SSH key accepted: %v", err)
	}
	candidate = base
	candidate.SSHAuthorizedKey = "ssh-ed25519 AAAA"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("malformed SSH key accepted: %v", err)
	}
	candidate = base
	candidate.DataDevice = "/dev/vda"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "/dev/vdb") {
		t.Fatalf("root drive accepted as data disk: %v", err)
	}
	candidate = base
	candidate.DataMount = "/srv/data"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "/var/lib/terrascale") {
		t.Fatalf("unexpected data mount accepted: %v", err)
	}
	candidate = base
	candidate.Hostname = "gru-member-2"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched seed identity accepted: %v", err)
	}
	for _, address := range []string{"127.0.0.2", "10.77.0.0", "10.77.0.255"} {
		candidate = base
		candidate.Address = address
		if _, err := BuildNoCloudSeed(candidate); err == nil {
			t.Fatalf("unusable guest address %q accepted", address)
		}
	}
	for _, gateway := range []string{"127.0.0.1", "10.77.0.0", "10.77.0.255"} {
		candidate = base
		candidate.Gateway = gateway
		if _, err := BuildNoCloudSeed(candidate); err == nil {
			t.Fatalf("unusable gateway %q accepted", gateway)
		}
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

func validNoCloudSpec(t *testing.T) NoCloudSeedSpec {
	t.Helper()
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
	return NoCloudSeedSpec{
		InstanceID: "gru-member-1", Hostname: "gru-member-1", Region: "gru",
		Address: "10.77.0.10", PrefixBits: 24, Gateway: "10.77.0.1",
		Nameservers:      []string{"9.9.9.9", "1.1.1.1", "9.9.9.9"},
		SSHAuthorizedKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBB8hhavGePnkrgQT92jQZ3sm2CEuJtBQp8uYpOUwV4v vmqual",
		DataDevice:       "/dev/vdb", DataMount: "/var/lib/terrascale", GuestSeed: guestSeed,
		GuestControl: runnableELF64(elf.EM_AARCH64),
	}
}

func elfHeader64(machine elf.Machine) []byte {
	data := make([]byte, 64)
	copy(data, []byte{0x7f, 'E', 'L', 'F'})
	data[4] = byte(elf.ELFCLASS64)
	data[5] = byte(elf.ELFDATA2LSB)
	data[6] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(data[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(data[18:20], uint16(machine))
	binary.LittleEndian.PutUint32(data[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint16(data[52:54], 64)
	binary.LittleEndian.PutUint16(data[54:56], 56)
	binary.LittleEndian.PutUint16(data[58:60], 64)
	return data
}

func runnableELF64(machine elf.Machine) []byte {
	data := append(elfHeader64(machine), make([]byte, 60)...)
	const (
		programOffset  = 64
		segmentOffset  = 120
		virtualAddress = 0x400078
	)
	binary.LittleEndian.PutUint64(data[24:32], virtualAddress)
	binary.LittleEndian.PutUint64(data[32:40], programOffset)
	binary.LittleEndian.PutUint16(data[56:58], 1)
	binary.LittleEndian.PutUint32(data[programOffset:programOffset+4], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(data[programOffset+4:programOffset+8], uint32(elf.PF_R|elf.PF_X))
	binary.LittleEndian.PutUint64(data[programOffset+8:programOffset+16], segmentOffset)
	binary.LittleEndian.PutUint64(data[programOffset+16:programOffset+24], virtualAddress)
	binary.LittleEndian.PutUint64(data[programOffset+24:programOffset+32], virtualAddress)
	binary.LittleEndian.PutUint64(data[programOffset+32:programOffset+40], 4)
	binary.LittleEndian.PutUint64(data[programOffset+40:programOffset+48], 4)
	binary.LittleEndian.PutUint64(data[programOffset+48:programOffset+56], 1)
	if machine == elf.EM_AARCH64 {
		binary.LittleEndian.PutUint32(data[segmentOffset:], 0xd65f03c0)
	} else {
		data[segmentOffset] = 0xc3
	}
	return data
}
