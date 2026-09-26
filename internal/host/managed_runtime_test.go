//go:build linux

package host

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestManagedRuntimePinsRequireExactPreprovisionedIdentity(t *testing.T) {
	registration, desired, _ := managedContractFixture()
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
		ReplicationListenAddress: "127.0.0.1:7000",
	}
	desired.ManagedMember.Runtime = &pins
	desired.ManagedMember.AttachmentETag = "etag-current"
	if err := validateDesired(desired, registration.Cell, registration); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*ManagedRuntimePins)
	}{
		{"relative mount", func(p *ManagedRuntimePins) { p.MountPath = "volume" }},
		{"symlink-like device path", func(p *ManagedRuntimePins) { p.DevicePath = "/dev/../tmp/sdb" }},
		{"missing trust key digest", func(p *ManagedRuntimePins) { p.TrustedKeySHA256 = "" }},
		{"invalid filesystem UUID", func(p *ManagedRuntimePins) { p.FileSystemUUID = "unknown" }},
		{"unapproved filesystem type", func(p *ManagedRuntimePins) { p.FileSystemType = "fuse" }},
		{"DNS listener", func(p *ManagedRuntimePins) { p.ReplicationListenAddress = "example.com:7000" }},
		{"partial peer", func(p *ManagedRuntimePins) { p.ReplicationPeerMemberID = registration.ManagedMember.Scope.MemberID }},
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

func TestExclusiveMountRejectsDuplicateAndWrongSource(t *testing.T) {
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
	if id, err := findExclusiveMount(path, target, device, "ext4"); err != nil || id != 23 {
		t.Fatalf("exact mount = %d, %v", id, err)
	}
	for _, test := range []struct{ name, content string }{
		{"duplicate mount", entry(23, target, "ext4") + entry(24, "/other", "ext4")},
		{"wrong target", entry(23, "/other", "ext4")},
		{"wrong filesystem", entry(23, target, "xfs")},
		{"no mount", entry(23, target, "ext4")[:0]},
	} {
		t.Run(test.name, func(t *testing.T) {
			write(test.content)
			if _, err := findExclusiveMount(path, target, device, "ext4"); err == nil {
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

func TestManagedReportRejectsStaleOrRetargetedEvidence(t *testing.T) {
	_, desired, _ := managedContractFixture()
	desired.ManagedMember.Runtime = &ManagedRuntimePins{
		DevicePath: "/dev/sdb", MountPath: "/srv/managed/volume",
		FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4",
	}
	report := Report{State: "running", Managed: &ManagedRuntimeReport{
		Member: desired.ManagedMember.Member, Authority: desired.ManagedMember.Authority,
		OCI: desired.ManagedMember.OCI, VolumeID: desired.ManagedMember.VolumeID,
		AttachmentID: desired.ManagedMember.AttachmentID, FileSystemUUID: desired.ManagedMember.Runtime.FileSystemUUID,
		FileSystemType: "ext4", MountDevice: "/dev/sdb", MountPath: "/srv/managed/volume", MountID: 23,
		ProcessPID: 1234, ProcessStart: "123456", ProcessCgroup: "/terrascale-host/terrabase",
		ProcessBootID: strings.Repeat("a", 32), StorageRecovered: true, ListenerReady: true,
	}}
	if err := validateManagedReportForDesired(report, desired); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*Report)
	}{
		{"old volume", func(r *Report) { r.Managed.VolumeID = "ocid1.volume.old" }},
		{"changed mount", func(r *Report) { r.Managed.MountID = 0 }},
		{"changed filesystem", func(r *Report) { r.Managed.FileSystemUUID = "different" }},
		{"changed incarnation", func(r *Report) { r.Managed.Member.Scope.Incarnation = strings.Repeat("f", 32) }},
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
	newProcess.ProcessBootID = strings.Repeat("b", 32)
	restarted.Managed = &newProcess
	if err := validateManagedReportForDesired(restarted, desired); err != nil {
		t.Fatalf("fresh restart observation rejected: %v", err)
	}
}
