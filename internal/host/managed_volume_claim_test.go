//go:build linux

package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func managedClaimFixture(t *testing.T) (string, ManagedMemberLaunch, WorkloadIdentity, int, uint64) {
	t.Helper()
	root := t.TempDir()
	for _, child := range []string{"data", "replication"} {
		if err := os.Mkdir(filepath.Join(root, child), 0700); err != nil {
			t.Fatal(err)
		}
	}
	launch := ManagedMemberLaunch{
		VolumeID: "ocid1.volume.oc1..member-a",
		Member: ManagedMemberBinding{Scope: MemberScope{
			ClusterID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TenantID: "01HW000000E008000000000001",
			DatabaseID: "01HW000000E008000000000002", ShardID: 7,
			MemberID: "01HW000000E008000000000003", Incarnation: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		}, HostAttempt: 1},
		Authority: MemberAuthority{Epoch: 3, ConfigurationID: strings.Repeat("c", 64), CertificateSHA256: strings.Repeat("d", 64)},
		Runtime:   &ManagedRuntimePins{FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4", TrustedKeySHA256: strings.Repeat("e", 64)},
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	return root, launch, WorkloadIdentity{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}, fd, stat.Dev
}

func TestManagedVolumeClaimCrashCutsHoldPartialShard(t *testing.T) {
	root, launch, identity, fd, device := managedClaimFixture(t)
	certificate := []byte("signed authority fixture")
	claim := filepath.Join(root, managedVolumeClaimName)
	apply := func() error {
		return ensureManagedVolumeClaimAt(fd, launch, identity, device, certificate, int64(os.Getuid()))
	}
	if err := apply(); err != nil {
		entries, _ := os.ReadDir(root)
		preformatErr := managedPreformatEmpty(fd, launch, identity, device, true)
		t.Fatalf("fresh preformat claim: %v; preformat=%v entries=%v", err, preformatErr, entries)
	}
	if err := managedReadExactFile(fd, managedVolumeClaimName, managedVolumeClaimBytes(launch), device, int64(os.Getuid())); err != nil {
		t.Fatalf("claim was not durable and exact: %v", err)
	}
	if err := apply(); err != nil {
		t.Fatalf("exact claim and absent shard retry: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "replication", "shard"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil {
		t.Fatal("partial TerraBase shard was accepted")
	}
	if err := os.Mkdir(filepath.Join(root, "replication", "shard", "authority"), 0700); err != nil {
		t.Fatal(err)
	}
	record, err := managedAcceptedAuthorityRecord(launch, certificate)
	if err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(root, "replication", "shard", "authority", "accepted.tbca")
	if err := os.WriteFile(recordPath, record, 0600); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err != nil {
		t.Fatalf("exact accepted authority recovery: %v", err)
	}
	if err := os.Remove(recordPath); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(recordPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil {
		t.Fatal("FIFO accepted authority record was accepted")
	}
	if err := os.Remove(recordPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath, record, 0600); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, "replication", "shard", "authority", "lock")
	if err := unix.Mkfifo(lockPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil {
		t.Fatal("FIFO authority lock was accepted")
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err != nil {
		t.Fatalf("exact recovery with safe lock: %v", err)
	}
	tempPath := filepath.Join(root, "replication", "shard", "authority", ".accepted-partial.tmp")
	if err := os.WriteFile(tempPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil {
		t.Fatal("partial authority directory was accepted")
	}
	if err := os.Remove(tempPath); err != nil {
		t.Fatal(err)
	}
	foreignRootPath := filepath.Join(root, "foreign")
	if err := os.WriteFile(foreignRootPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil {
		t.Fatal("ambiguous recovered volume root was accepted")
	}
	if err := os.Remove(foreignRootPath); err != nil {
		t.Fatal(err)
	}
	foreignParentPath := filepath.Join(root, "replication", "foreign")
	if err := os.WriteFile(foreignParentPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil {
		t.Fatal("ambiguous replication parent was accepted")
	}
	if err := os.Remove(foreignParentPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil {
		t.Fatal("foreign accepted authority was accepted")
	}
	if err := os.Remove(claim); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil {
		t.Fatal("unclaimed existing shard was adopted")
	}
}
