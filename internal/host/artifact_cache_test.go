package host

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

func TestArtifactChunksReadBackendWithoutConsumer(t *testing.T) {
	c, conn, store, _, _ := testController(t)
	defer c.closeCache()
	data := bytes.Repeat([]byte("terrascale-binary"), artifactChunkBytes/16*3)
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if _, err := store.PutBytes(t.Context(), "sha256-"+digest, data); err != nil {
		t.Fatal(err)
	}
	var copied []byte
	for offset := int64(0); offset < int64(len(data)); {
		part, total, err := c.readArtifactChunk(t.Context(), digest, offset, artifactChunkBytes)
		if errors.Is(err, errArtifactPreparing) {
			select {
			case <-time.After(10 * time.Millisecond):
				continue
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		if total != int64(len(data)) {
			t.Fatalf("total %d", total)
		}
		copied = append(copied, part...)
		offset += int64(len(part))
	}
	if !bytes.Equal(copied, data) {
		t.Fatal("cached chunks changed artifact bytes")
	}
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := js.Stream(t.Context(), "OBJ_HOST_TEST_ARTIFACTS")
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Consumers != 0 {
		t.Fatalf("artifact read created %d consumers", info.State.Consumers)
	}
}

func TestInstalledArtifactPermissionsAndUnsafeEntries(t *testing.T) {
	identity := testAgentIdentity()
	install := filepath.Join(t.TempDir(), "install")
	role := filepath.Join(install, "terrabase")
	data := []byte("#!/bin/sh\nexit 0\n")
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	root := filepath.Join(role, "sha256-"+digest)
	for _, directory := range []string{install, role, root} {
		if err := ensureInstallDirectory(directory, identity.GID); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(directory)
		if err != nil {
			t.Fatal(err)
		}
		owner := info.Sys().(*syscall.Stat_t)
		if info.Mode().Perm() != 0710 || owner.Uid != uint32(os.Geteuid()) || owner.Gid != identity.GID {
			t.Fatalf("unsafe install directory %s: mode=%#o uid=%d gid=%d", directory, info.Mode().Perm(), owner.Uid, owner.Gid)
		}
	}
	path := filepath.Join(root, "terrabase")
	if err := os.WriteFile(path, data, 0500); err != nil {
		t.Fatal(err)
	}
	valid, err := verifyInstalledArtifact(path, digest, identity.GID)
	if err != nil || !valid {
		t.Fatalf("verified legacy artifact was not repaired: valid=%t err=%v", valid, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	owner := info.Sys().(*syscall.Stat_t)
	if info.Mode().Perm() != 0550 || owner.Uid != uint32(os.Geteuid()) || owner.Gid != identity.GID {
		t.Fatalf("unsafe verified artifact: mode=%#o uid=%d gid=%d", info.Mode().Perm(), owner.Uid, owner.Gid)
	}
	if err := os.Chmod(path, 0570); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyInstalledArtifact(path, digest, identity.GID); err == nil {
		t.Fatal("tenant-writable artifact was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/true", path); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyInstalledArtifact(path, digest, identity.GID); err == nil {
		t.Fatal("artifact symlink was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), path); err != nil {
		t.Fatal(err)
	}
	if err := ensureInstallDirectory(path, identity.GID); err == nil {
		t.Fatal("install directory symlink was accepted")
	}
}

func TestWorkloadPathBoundariesBeforeNativeProbe(t *testing.T) {
	root := testAgentInstallParent(t)
	install := filepath.Join(root, "install")
	state := testAgentStateRoot(t)
	identity := testAgentIdentity()
	if err := ValidateWorkloadPaths(install, state, identity); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{install, install}, {root, install}, {install, filepath.Join(install, "state")}} {
		if err := ValidateWorkloadPaths(pair[0], pair[1], identity); err == nil || !strings.Contains(err.Error(), "overlap") {
			t.Fatalf("overlapping paths accepted: %v", pair)
		}
	}
	if err := ValidateWorkloadPaths(install, state, WorkloadIdentity{}); err == nil {
		t.Fatal("zero workload identity was accepted")
	}
	if err := ValidateWorkloadPaths("/", state, identity); err == nil {
		t.Fatal("filesystem root was accepted as install root")
	}
	if err := os.Symlink(root, install); err != nil {
		t.Fatal(err)
	}
	if err := ValidateWorkloadPaths(install, state, identity); err == nil {
		t.Fatal("symlinked install root was accepted")
	}
	if err := os.Remove(install); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0755); err != nil {
		t.Fatal(err)
	}
	if err := ValidateWorkloadPaths(install, state, identity); err == nil {
		t.Fatal("exposed state root was accepted")
	}
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	other := WorkloadIdentity{UID: identity.UID + 1, GID: identity.GID + 1}
	privateInstall := filepath.Join(t.TempDir(), "install")
	if err := ValidateWorkloadPaths(privateInstall, state, other); err == nil || !strings.Contains(err.Error(), "cannot traverse") {
		t.Fatalf("untraversable install root parent was accepted: %v", err)
	}
	installParent, err := os.MkdirTemp("", "ts-install-boundary-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(installParent); err != nil {
			t.Errorf("remove install boundary parent: %v", err)
		}
	})
	if err := os.Chmod(installParent, 0755); err != nil {
		t.Fatal(err)
	}
	stateParent := filepath.Dir(testAgentStateRoot(t))
	t.Cleanup(func() {
		if err := os.Chmod(stateParent, 0o700); err != nil {
			t.Errorf("restore private state boundary parent: %v", err)
		}
	})
	if err := os.Chmod(stateParent, 0777); err != nil {
		t.Fatal(err)
	}
	writableError := "replace host path"
	if os.Geteuid() == 0 {
		writableError = "group- or world-writable"
	}
	if err := ValidateWorkloadPaths(filepath.Join(installParent, "install"), filepath.Join(stateParent, "state"), other); err == nil ||
		!strings.Contains(err.Error(), writableError) {
		t.Fatalf("tenant-writable state ancestor was accepted: %v", err)
	}
	cell := filepath.Join(state, "gru")
	if err := os.Mkdir(cell, 0755); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateHostState(state, "gru", "node-a"); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("exposed state cell directory was accepted: %v", err)
	}
}
