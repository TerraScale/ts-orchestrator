//go:build linux

package host

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/oci"

	"golang.org/x/sys/unix"
)

func TestManagedRuntimePinsRequireExactPreprovisionedIdentity(t *testing.T) {
	registration, desired, _ := managedContractFixture()
	// The host mutation lease and TerraBase certificate have independent epochs.
	desired.AuthorityEpoch = 9
	if err := validateDesired(desired, registration.Cell, registration); err != nil {
		t.Fatalf("independent controller and TerraBase epochs rejected: %v", err)
	}
	root := "/srv/tb"
	paths, err := runtimePaths(root, *desired.ManagedMember)
	if err != nil {
		t.Fatal(err)
	}
	pins := ManagedRuntimePins{
		DevicePath: "/dev/sdb", MountPath: paths.mount,
		FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4",
		TrustedKeySHA256: strings.Repeat("1", 64), ServerCertificateSHA256: strings.Repeat("2", 64),
		ServerPrivateKeySHA256: strings.Repeat("3", 64), ClientCARootsSHA256: strings.Repeat("4", 64),
		ClientManagedMaterialManifestSHA256: strings.Repeat("5", 64),
		LiveS3ConfigSHA256:                  strings.Repeat("7", 64),
		LiveS3TargetSHA256:                  strings.Repeat("8", 64),
		LiveS3Credential:                    oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3},
		ReplicationListenAddress:            "10.0.0.11:7000",
		ReplicationPeerMemberID:             "01HW000000E008000000000002",
		ReplicationPeerAddress:              "10.0.0.12:7001", ReplicationServerCASHA256: strings.Repeat("6", 64),
	}
	desired.ManagedMember.Runtime = &pins
	desired.ManagedMember.AttachmentETag = "etag-current"
	if err := validateDesired(desired, registration.Cell, registration); err != nil {
		t.Fatal(err)
	}
	sqlDesired := desired
	sqlPins := pins
	sqlPins.SQLSchemaBundleSHA256 = strings.Repeat("9", 64)
	sqlLaunch := *desired.ManagedMember
	sqlLaunch.Runtime = &sqlPins
	sqlDesired.ManagedMember = &sqlLaunch
	if err := validateDesired(sqlDesired, registration.Cell, registration); err != nil {
		t.Fatalf("valid signed SQL bundle pin was rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*ManagedRuntimePins)
	}{
		{"relative mount", func(p *ManagedRuntimePins) { p.MountPath = "volume" }},
		{"symlink-like device path", func(p *ManagedRuntimePins) { p.DevicePath = "/dev/../tmp/sdb" }},
		{"missing trust key digest", func(p *ManagedRuntimePins) { p.TrustedKeySHA256 = "" }},
		{"missing signed client manifest", func(p *ManagedRuntimePins) { p.ClientManagedMaterialManifestSHA256 = "" }},
		{"missing live S3 config", func(p *ManagedRuntimePins) { p.LiveS3ConfigSHA256 = "" }},
		{"invalid SQL bundle digest", func(p *ManagedRuntimePins) { p.SQLSchemaBundleSHA256 = "bad" }},
		{"missing exact Vault version", func(p *ManagedRuntimePins) { p.LiveS3Credential.VersionNumber = 0 }},
		{"invalid filesystem UUID", func(p *ManagedRuntimePins) { p.FileSystemUUID = "unknown" }},
		{"unapproved filesystem type", func(p *ManagedRuntimePins) { p.FileSystemType = "fuse" }},
		{"DNS listener", func(p *ManagedRuntimePins) { p.ReplicationListenAddress = "example.com:7000" }},
		{"loopback listener", func(p *ManagedRuntimePins) { p.ReplicationListenAddress = "127.0.0.1:7000" }},
		{"public listener", func(p *ManagedRuntimePins) { p.ReplicationListenAddress = "198.51.100.11:7000" }},
		{"wildcard listener", func(p *ManagedRuntimePins) { p.ReplicationListenAddress = "0.0.0.0:7000" }},
		{"IPv6 listener", func(p *ManagedRuntimePins) { p.ReplicationListenAddress = "[fd00::11]:7000" }},
		{"public peer", func(p *ManagedRuntimePins) { p.ReplicationPeerAddress = "198.51.100.12:7001" }},
		{"partial peer", func(p *ManagedRuntimePins) { p.ReplicationPeerAddress = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := desired
			runtime := pins
			test.change(&runtime)
			launch := *copy.ManagedMember
			launch.Runtime = &runtime
			copy.ManagedMember = &launch
			if err := validateDesired(copy, registration.Cell, registration); err == nil {
				t.Fatal("invalid signed runtime pins were accepted")
			}
		})
	}
	otherAttempt := *desired.ManagedMember
	otherAttempt.Member.HostAttempt++
	otherPaths, err := runtimePaths(root, otherAttempt)
	if err != nil || otherPaths.memberDir == paths.memberDir {
		t.Fatalf("host attempt did not isolate runtime directory: %v", err)
	}
}

func TestExclusiveMountRequiresVisibleMountAtTargetOnly(t *testing.T) {
	device := unix.Mkdev(8, 1)
	path := filepath.Join(t.TempDir(), "mountinfo")
	target := "/var/lib/terrascale/member/volume"
	entry := func(id int, where, fs string) string {
		return fmt.Sprintf("%d 1 8:1 / %s rw,relatime - %s /dev/sdb rw\n", id, where, fs)
	}
	write := func(data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(entry(23, target, "ext4"))
	if id, err := exclusiveMountEntry(path, target, device, "ext4", 23); err != nil || id != 23 {
		t.Fatalf("exact mount = %d, %v", id, err)
	}
	// A ProtectSystem service namespace sees one propagated copy per slave
	// mount of the runtime root; only the visible one is pinned.
	write(entry(23, target, "ext4") + entry(31, target, "ext4"))
	if id, err := exclusiveMountEntry(path, target, device, "ext4", 31); err != nil || id != 31 {
		t.Fatalf("shadowed propagated mount = %d, %v", id, err)
	}
	for _, test := range []struct {
		name    string
		content string
		visible uint64
	}{
		{"second mount elsewhere", entry(23, target, "ext4") + entry(24, "/other", "ext4"), 23},
		{"wrong target", entry(23, "/other", "ext4"), 23},
		{"wrong filesystem", entry(23, target, "xfs"), 23},
		{"no mount", "", 23},
		{"visible mount is another device", entry(23, target, "ext4"), 40},
	} {
		t.Run(test.name, func(t *testing.T) {
			write(test.content)
			if _, err := exclusiveMountEntry(path, target, device, "ext4", test.visible); err == nil {
				t.Fatal("unsafe mount accepted")
			}
		})
	}
}

func TestMountedRootCannotBeReplacedByTenant(t *testing.T) {
	identity := WorkloadIdentity{UID: 65534, GID: 65534}
	device := unix.Mkdev(8, 1)
	stat := syscall.Stat_t{Dev: device, Uid: 0, Gid: identity.GID}
	if !validManagedMountRoot(&stat, os.ModeDir|0750, identity, device) {
		t.Fatal("safe host-owned volume root rejected")
	}
	for _, test := range []struct {
		name string
		mode os.FileMode
		uid  uint32
		gid  uint32
		dev  uint64
	}{
		{"tenant owns root", os.ModeDir | 0750, identity.UID, identity.GID, device},
		{"tenant can rename children", os.ModeDir | 0770, 0, identity.GID, device},
		{"world can rename children", os.ModeDir | 0757, 0, identity.GID, device},
		{"different block device", os.ModeDir | 0750, 0, identity.GID, unix.Mkdev(8, 2)},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := syscall.Stat_t{Dev: test.dev, Uid: test.uid, Gid: test.gid}
			if validManagedMountRoot(&candidate, test.mode, identity, device) {
				t.Fatal("tenant-writable or retargeted mounted root accepted")
			}
		})
	}
}

func TestOracleOCIAliasTargetAllowsOnlyOneRelativeDeviceHop(t *testing.T) {
	alias := "/dev/oracleoci/oraclevdb"
	resolved, err := oracleOCIAliasTarget(alias, "../sdb")
	if err != nil || resolved != "/dev/sdb" {
		t.Fatalf("canonical OCI alias = %q, %v", resolved, err)
	}
	for _, target := range []string{"/dev/sdb", "../../tmp/sdb", "../disk/by-id/volume", "sdb", "../sdb other"} {
		if _, err := oracleOCIAliasTarget(alias, target); err == nil {
			t.Fatalf("unsafe OCI alias target %q accepted", target)
		}
	}
}

func TestManagedDeviceAncestorsRejectWritableDirectAndAliasParents(t *testing.T) {
	for _, test := range []struct {
		path string
		want int
	}{
		{"/dev/sdb", 1},
		{"/dev/oracleoci/oraclevdb", 2},
	} {
		ancestors, err := managedDeviceAncestors(test.path)
		if err != nil || len(ancestors) != test.want || ancestors[0] != "/dev" {
			t.Fatalf("device %q ancestors = %v, %v", test.path, ancestors, err)
		}
	}
	if _, err := managedDeviceAncestors("/dev/disk/by-id/volume"); err == nil {
		t.Fatal("nested device path bypassed ancestor checks")
	}
	root := syscall.Stat_t{Uid: 0}
	if !validManagedDeviceAncestor(os.ModeDir|0755, &root) {
		t.Fatal("root-owned nonwritable /dev rejected")
	}
	for _, mode := range []os.FileMode{os.ModeDir | 0775, os.ModeDir | 0757, os.ModeSymlink | 0777} {
		if validManagedDeviceAncestor(mode, &root) {
			t.Fatalf("writable or linked /dev parent mode %v accepted", mode)
		}
	}
	foreign := syscall.Stat_t{Uid: 1000}
	if validManagedDeviceAncestor(os.ModeDir|0755, &foreign) {
		t.Fatal("nonroot device parent accepted")
	}
}

func TestOpenDeviceWitnessSurvivesPathReplacementUntilClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	old, err := statOpenWitness(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if held, err := statOpenWitness(int(file.Fd())); err != nil || !sameDeviceObject(held, old) {
		t.Fatalf("held descriptor changed with path replacement: %+v, %v", held, err)
	}
	replacement, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	current, err := statOpenWitness(int(replacement.Fd()))
	if err != nil || sameDeviceObject(current, old) {
		t.Fatalf("replacement path reused held object: %+v, %v", current, err)
	}
	_ = replacement.Close()
	_ = file.Close()
	if _, err := statOpenWitness(-1); err == nil {
		t.Fatal("closed witness accepted")
	}
}

func TestManagedReportRejectsStaleOrRetargetedEvidence(t *testing.T) {
	_, desired, _ := managedContractFixture()
	desired.ManagedMember.AttachmentETag = "etag-current"
	desired.ManagedMember.Runtime = &ManagedRuntimePins{
		DevicePath: "/dev/sdb", MountPath: "/srv/managed/volume",
		FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4",
	}
	report := Report{State: "running", Managed: &ManagedRuntimeReport{
		Member: desired.ManagedMember.Member, Authority: desired.ManagedMember.Authority,
		OCI: desired.ManagedMember.OCI, VolumeID: desired.ManagedMember.VolumeID,
		AttachmentID: desired.ManagedMember.AttachmentID, AttachmentETag: desired.ManagedMember.AttachmentETag,
		FileSystemUUID: desired.ManagedMember.Runtime.FileSystemUUID,
		FileSystemType: "ext4", MountDevice: "/dev/sdb", MountPath: "/srv/managed/volume", MountID: 23,
		ProcessPID: 1234, ProcessStart: "123456", ProcessCgroup: "/terrascale-host/terrabase",
		ProcessBootID: "000000000000c41e716df070e27a2bf2", StorageRecovered: true, ListenerReady: true,
	}}
	if err := validateManagedReportForDesired(report, desired); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*Report)
	}{
		{"old volume", func(r *Report) { r.Managed.VolumeID = "ocid1.volume.old" }},
		{"old attachment ETag", func(r *Report) { r.Managed.AttachmentETag = "etag-old" }},
		{"changed mount", func(r *Report) { r.Managed.MountID = 0 }},
		{"changed filesystem", func(r *Report) { r.Managed.FileSystemUUID = "different" }},
		{"changed incarnation", func(r *Report) { r.Managed.Member.Scope.Incarnation = strings.Repeat("f", 32) }},
		{"wrong TerraBase epoch", func(r *Report) { r.Managed.Authority.Epoch++ }},
		{"missing process boot", func(r *Report) { r.Managed.ProcessBootID = "" }},
		{"local listener down", func(r *Report) { r.Managed.ListenerReady = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := report
			observation := *report.Managed
			copy.Managed = &observation
			test.change(&copy)
			if err := validateManagedReportForDesired(copy, desired); err == nil {
				t.Fatal("stale or retargeted report accepted")
			}
		})
	}
	restarted := report
	newProcess := *report.Managed
	newProcess.ProcessPID++
	newProcess.ProcessStart = "123999"
	newProcess.ProcessBootID = "000000000000c41e716df070e27a2bf3"
	restarted.Managed = &newProcess
	if err := validateManagedReportForDesired(restarted, desired); err != nil {
		t.Fatalf("fresh restart observation rejected: %v", err)
	}
}
