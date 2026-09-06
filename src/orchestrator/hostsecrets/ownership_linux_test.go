//go:build linux

package hostsecrets

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func ownershipFixture(t *testing.T) (int, string, Seed, ownershipRecord) {
	t.Helper()
	fd, root := directoryFixture(t)
	seed := testSeed()
	entry := testEntry()
	entry.Destination = "/etc/terrascale/orchestrator/global/client.key"
	seed.Entries = append(seed.Entries, entry)
	receipt := testEntry()
	receipt.Destination = StorageTransitionReceiptKeyPath
	seed.Entries = append(seed.Entries, receipt)
	p := prepareFixture(t, fd, seed)
	for _, entry := range seed.Entries {
		if err := p.publish(entry, []byte("private-canary")); err != nil {
			t.Fatal(err)
		}
	}
	p.close()
	return fd, root, seed, ownershipRecord{SeedDigest: seedDigest(seed), ManifestDigest: digest([]byte("authenticated-manifest")), User: OrchestratorUser, UID: os.Geteuid(), GID: os.Getgid()}
}
func TestOwnershipHandoffKeepsDirectoriesProtectedAndNodePrivate(t *testing.T) {
	fd, root, seed, record := ownershipFixture(t)
	p := prepareFixture(t, fd, seed)
	if err := p.admitOwnership(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	p.close()
	for path, mode := range map[string]os.FileMode{".": 0711, "orchestrator": 0711, "orchestrator/global": 0711, "ts-node-bootstrap": 0700, "orchestrator/global/client.key": 0600, "ts-node-bootstrap/client.key": 0600, "ts-node-bootstrap/storage-transition-receipt.key": 0600} {
		info, err := os.Stat(filepath.Join(root, path))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("incorrect protected traversal/file mode for %s", path)
		}
	}
	p = prepareFixture(t, fd, seed)
	defer p.close()
	if err := p.admitOwnership(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	changed := record
	changed.ManifestDigest = digest([]byte("different-manifest"))
	if err := p.admitOwnership(context.Background(), changed); err != ErrJournal {
		t.Fatal("handoff accepted unrelated manifest")
	}
	changed = record
	changed.UID++
	if err := p.admitOwnership(context.Background(), changed); err != ErrJournal {
		t.Fatal("handoff accepted changed numeric owner")
	}
}
func TestRecordedOwnershipResumesAfterDirectorySyncFailure(t *testing.T) {
	fd, root, seed, record := ownershipFixture(t)
	body, _ := json.Marshal(record)
	pathFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = publishRecord(pathFD, ownershipName, body)
	unix.Close(pathFD)
	if err != ErrJournal {
		t.Fatal("test did not produce ownership directory-sync failure")
	}
	p := prepareFixture(t, fd, seed)
	defer p.close()
	// ready is the same retry path used by Bootstrap before ts-node config load.
	for _, entry := range seed.Entries {
		ready, err := p.ready(entry)
		if err != nil || !ready {
			t.Fatalf("interrupted handoff did not resume: %v", err)
		}
	}
	info, err := os.Stat(filepath.Join(root, "orchestrator/global"))
	if err != nil || info.Mode().Perm() != 0711 {
		t.Fatal("retry did not finish traversal handoff")
	}
}
func TestMissingHandedOffCredentialIsNotRecreated(t *testing.T) {
	fd, root, seed, record := ownershipFixture(t)
	p := prepareFixture(t, fd, seed)
	if err := p.admitOwnership(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	p.close()
	entry := seed.Entries[1]
	if err := os.Remove(filepath.Join(root, entryName(entry))); err != nil {
		t.Fatal(err)
	}
	p = prepareFixture(t, fd, seed)
	defer p.close()
	if _, err := p.ready(entry); err != ErrOwnership {
		t.Fatal("missing handed-off credential could be fetched again")
	}
	if err := p.publish(entry, []byte("private-canary")); err != ErrOwnership {
		t.Fatal("recreated handed-off credential")
	}
}
func TestIncompleteBootstrapCannotAdmitOwnership(t *testing.T) {
	fd, root, seed, record := ownershipFixture(t)
	if err := os.Remove(filepath.Join(root, entryName(seed.Entries[1]))); err != nil {
		t.Fatal(err)
	}
	p := prepareFixture(t, fd, seed)
	defer p.close()
	if err := p.admitOwnership(context.Background(), record); err != ErrPublish {
		t.Fatal("admitted owner before complete credential verification")
	}
	if _, err := os.Stat(filepath.Join(root, ownershipName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recorded ownership over missing credential")
	}
}

// Run explicitly as root against temporary directories only. No account is
// created and no path under /etc is read or changed.
func TestRootServiceOwnershipHandoff(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for numeric credential ownership test")
	}
	fd, root, seed, record := ownershipFixture(t)
	record.UID, record.GID = 65534, 65534
	p := prepareFixture(t, fd, seed)
	if err := p.admitOwnership(context.Background(), record); err != nil {
		p.close()
		t.Fatal(err)
	}
	p.close()
	leaf := filepath.Join(root, entryName(seed.Entries[1]))
	var stat unix.Stat_t
	if err := unix.Stat(leaf, &stat); err != nil || stat.Uid != 65534 || stat.Gid != 65534 || stat.Mode&07777 != 0600 {
		t.Fatal("credential ownership did not move root to exact service UID/GID")
	}
	for _, relative := range []string{".", "orchestrator", "orchestrator/global"} {
		if err := unix.Stat(filepath.Join(root, relative), &stat); err != nil || stat.Uid != 0 || stat.Mode&07777 != 0711 {
			t.Fatal("handoff changed directory owner or unsafe traversal mode")
		}
	}
	nodeLeaf := filepath.Join(root, entryName(seed.Entries[0]))
	if err := unix.Stat(nodeLeaf, &stat); err != nil || stat.Uid != 0 || stat.Mode&07777 != 0600 {
		t.Fatal("node secret lost root-private ownership")
	}
	p = prepareFixture(t, fd, seed)
	for _, entry := range seed.Entries {
		ready, err := p.ready(entry)
		if err != nil || !ready {
			p.close()
			t.Fatal("restart did not recognize transferred service ownership")
		}
	}
	p.close()
	// The Go test framework's enclosing temporary directory starts0700.
	// Allow traversal of that test-only ancestor for the numeric-UID probe.
	if err := os.Chmod(filepath.Dir(root), 0711); err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(root, "orchestrator/global/ca.pem")
	if err := os.WriteFile(public, []byte("public-test-certificate"), 0644); err != nil {
		t.Fatal(err)
	}
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Fatal("cat required for numeric-UID readability probe")
	}
	readAsService := func(path string) ([]byte, error) {
		command := exec.Command(cat, path)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
		return command.Output()
	}
	body, err := readAsService(leaf)
	if err != nil || string(body) != "private-canary" {
		t.Fatal("numeric service UID cannot read its handed-off credential")
	}
	erase(body)
	body, err = readAsService(public)
	if err != nil || string(body) != "public-test-certificate" {
		t.Fatal("numeric service UID cannot traverse to public trust file")
	}
	if _, err := readAsService(nodeLeaf); err == nil {
		t.Fatal("numeric service UID can read root ts-node secret")
	}
	receiptLeaf := filepath.Join(root, entryName(seed.Entries[2]))
	if err := unix.Stat(receiptLeaf, &stat); err != nil || stat.Uid != 0 || stat.Mode&07777 != 0600 {
		t.Fatal("transition receipt key lost root-private ownership")
	}
	if _, err := readAsService(receiptLeaf); err == nil {
		t.Fatal("service can read transition receipt key")
	}
	if err := os.Chown(leaf, 65534, 65533); err != nil {
		t.Fatal(err)
	}
	p = prepareFixture(t, fd, seed)
	defer p.close()
	if _, err := p.ready(seed.Entries[1]); err != ErrOwnership {
		t.Fatal("retry accepted unjournaled service GID")
	}
}
