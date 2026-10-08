package agent

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
	network "git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"golang.org/x/sys/unix"
)

func TestSpoolAnchorsWritesReadsAndRenameAgainstReplacedAncestors(t *testing.T) {
	for _, ancestor := range []string{"host", "host/cell/node/netbird"} {
		t.Run(ancestor, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "host/cell/node/netbird")
			s, err := openSpool(directory, true)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			file, temporary, err := s.temporary()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString("staged artifact"); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			replaced := filepath.Join(root, ancestor)
			outside := t.TempDir()
			suffix, err := filepath.Rel(replaced, directory)
			if err != nil {
				t.Fatal(err)
			}
			outsideSpool := filepath.Join(outside, suffix)
			if err := os.MkdirAll(outsideSpool, 0700); err != nil {
				t.Fatal(err)
			}
			outsideFile := filepath.Join(outsideSpool, "status.json")
			if err := os.WriteFile(outsideFile, []byte("outside sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replaced, replaced+".moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, replaced); err != nil {
				t.Fatal(err)
			}
			if err := s.rename(temporary, "binary"); err != nil {
				t.Fatal(err)
			}
			if err := s.write("status.json", []byte("worker status")); err != nil {
				t.Fatal(err)
			}
			for name, want := range map[string]string{"binary": "staged artifact", "status.json": "worker status"} {
				wire, err := s.read(name, 4096)
				if err != nil || string(wire) != want {
					t.Fatalf("descriptor read %s was redirected: %q %v", name, wire, err)
				}
			}
			if wire, err := os.ReadFile(outsideFile); err != nil || string(wire) != "outside sentinel" {
				t.Fatalf("root write escaped into replaced ancestor: %q %v", wire, err)
			}
			entries, err := os.ReadDir(outsideSpool)
			if err != nil || len(entries) != 1 {
				t.Fatalf("spool temporary or artifact escaped: %v %v", entries, err)
			}
			if err := Write(directory, "result.json", []byte("redirected")); err == nil {
				t.Fatal("new writer followed a symlink component")
			}
			if _, err := read(directory, "status.json", 4096); err == nil {
				t.Fatal("new reader followed a symlink component")
			}
		})
	}
}

func TestSpoolWriteReplacesDestinationSymlinksWithoutFollowingThem(t *testing.T) {
	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "protected")
	if err := os.WriteFile(outside, []byte("outside sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"status.json", "result.json"} {
		if err := os.Symlink(outside, filepath.Join(directory, name)); err != nil {
			t.Fatal(err)
		}
		if err := Write(directory, name, []byte("public diagnostic")); err != nil {
			t.Fatal(err)
		}
		wire, err := read(directory, name, 4096)
		if err != nil || string(wire) != "public diagnostic" {
			t.Fatalf("output symlink was not replaced by a regular file: %q %v", wire, err)
		}
	}
	if wire, err := os.ReadFile(outside); err != nil || string(wire) != "outside sentinel" {
		t.Fatalf("worker followed destination symlink outside spool: %q %v", wire, err)
	}
	for _, name := range []string{"", ".", "..", "../escape", "/"} {
		if err := Write(directory, name, nil); err == nil {
			t.Fatalf("write accepted escaping filename %q", name)
		}
		if _, err := read(directory, name, 4096); err == nil {
			t.Fatalf("read accepted escaping filename %q", name)
		}
	}
}

func TestWorkerResultUsesHeldSpoolAfterRelayReplacesPath(t *testing.T) {
	cfg, command, key := workerFixture(t)
	s, err := openSpool(cfg.Directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	cfg.spool = s
	outside := t.TempDir()
	last := ledger{}
	if err := applyStep(t.Context(), cfg, &last, signCommand(t, cfg, key, command, 3), func(context.Context, network.Command) error {
		if err := os.Rename(cfg.Directory, cfg.Directory+".moved"); err != nil {
			return err
		}
		return os.Symlink(outside, cfg.Directory)
	}); err != nil {
		t.Fatal(err)
	}
	wire, err := s.read("result.json", 4096)
	if err != nil || !strings.Contains(string(wire), command.ID) {
		t.Fatalf("worker lost its anchored result: %q %v", wire, err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("worker wrote to the relay's symlink target: %v %v", entries, err)
	}
}

func relayTestBinary(command *network.Command) ([]byte, string) {
	artifact := make([]byte, 64)
	copy(artifact, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(artifact[16:], 3)
	machine := uint16(183)
	if runtime.GOARCH == "amd64" {
		machine = 62
	}
	binary.LittleEndian.PutUint16(artifact[18:], machine)
	binary.LittleEndian.PutUint32(artifact[20:], 1)
	binary.LittleEndian.PutUint16(artifact[52:], 64)
	sum := sha256.Sum256(artifact)
	digest := hex.EncodeToString(sum[:])
	if runtime.GOARCH == "amd64" {
		command.Target.Pin.Archives.AMD64.BinarySHA256 = digest
	} else {
		command.Target.Pin.Archives.Arm64.BinarySHA256 = digest
	}
	return artifact, digest
}

func TestRelayStagesArtifactOnHeldDirectoryAfterAncestorReplacement(t *testing.T) {
	cfg, command, key := workerFixture(t)
	root := t.TempDir()
	cfg.Directory = filepath.Join(root, "host/node/netbird")
	artifact, digest := relayTestBinary(&command)
	outside := t.TempDir()
	if err := Relay(t.Context(), cfg, signCommand(t, cfg, key, command, 3), func(_ context.Context, _ string, out io.Writer) error {
		ancestor := filepath.Join(root, "host")
		if err := os.Rename(ancestor, ancestor+".moved"); err != nil {
			return err
		}
		if err := os.Symlink(outside, ancestor); err != nil {
			return err
		}
		_, err := out.Write(artifact)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "host.moved/node/netbird")
	if err := client.VerifyBinary(filepath.Join(moved, "binary-"+digest), digest, runtime.GOARCH); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moved, "step.json")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("relay redirected staging outside its held directory: %v %v", entries, err)
	}
}

func TestRelayFileSyncFailureDoesNotPublishBinaryOrStep(t *testing.T) {
	cfg, command, key := workerFixture(t)
	artifact, digest := relayTestBinary(&command)
	err := Relay(t.Context(), cfg, signCommand(t, cfg, key, command, 3), func(_ context.Context, _ string, out io.Writer) error {
		if _, err := out.Write(artifact); err != nil {
			return err
		}
		file, ok := out.(*os.File)
		if !ok {
			t.Fatal("relay artifact writer is not its held temporary file")
		}
		// The valid temporary bytes remain, but fsync fails while Close succeeds.
		fd, err := unix.Open("/dev/null", unix.O_WRONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.Dup2(fd, int(file.Fd()))
	})
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("artifact sync failure was not propagated: %v", err)
	}
	for _, name := range []string{"binary-" + digest, "step.json"} {
		if _, err := os.Stat(filepath.Join(cfg.Directory, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed artifact sync published %s: %v", name, err)
		}
	}
	if entries, err := os.ReadDir(cfg.Directory); err != nil || len(entries) != 0 {
		t.Fatalf("failed artifact sync left its temporary file: %v %v", entries, err)
	}
}

func TestSpoolRenamePropagatesDirectorySyncFailure(t *testing.T) {
	directory := t.TempDir()
	s, err := openSpool(directory, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	file, temporary, err := s.temporary()
	if err != nil {
		t.Fatal(err)
	}
	defer s.remove(temporary)
	if _, err := file.WriteString("verified artifact"); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(directory, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	// O_PATH supports renameat through the same inode, but not fsync.
	if err := unix.Dup2(fd, int(s.directory.Fd())); err != nil {
		t.Fatal(err)
	}
	if err := s.rename(temporary, "binary"); !errors.Is(err, unix.EBADF) {
		t.Fatalf("rename ignored its directory sync failure: %v", err)
	}
	if body, err := os.ReadFile(filepath.Join(directory, "binary")); err != nil || string(body) != "verified artifact" {
		t.Fatalf("test failed before the renamed entry's sync: %q %v", body, err)
	}
	if err := s.sync("binary", client.MaxBinaryBytes); !errors.Is(err, unix.EBADF) {
		t.Fatalf("cached artifact ignored its directory sync failure: %v", err)
	}
}

func TestSpoolSyncRejectsUnsafeCachedArtifacts(t *testing.T) {
	directory := t.TempDir()
	s, err := openSpool(directory, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if err := os.WriteFile(filepath.Join(directory, "binary"), []byte("verified artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.sync("binary", client.MaxBinaryBytes); err != nil {
		t.Fatalf("protected cached artifact failed to sync: %v", err)
	}
	if err := os.Symlink("binary", filepath.Join(directory, "symlink")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(directory, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		limit int64
	}{{"../binary", 4096}, {"binary", -1}, {"binary", 1}, {"symlink", 4096}, {"fifo", 4096}} {
		if err := s.sync(test.name, test.limit); err == nil {
			t.Fatalf("sync accepted unsafe cached artifact %q with limit %d", test.name, test.limit)
		}
	}
	if err := os.Chmod(filepath.Join(directory, "binary"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := s.sync("binary", client.MaxBinaryBytes); err == nil {
		t.Fatal("sync accepted a writable cached artifact")
	}
}

func TestSpoolDiagnosticsReadableAndAuthorityPrivate(t *testing.T) {
	parent := t.TempDir()
	if os.Geteuid() == 0 {
		if err := os.Chown(parent, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	parentInfo, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	owner := parentInfo.Sys().(*syscall.Stat_t)
	directory := filepath.Join(parent, "cell/node/netbird")
	for _, name := range []string{"status.json", "result.json"} {
		if err := Write(directory, name, []byte("public diagnostic")); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0644 {
			t.Fatalf("relay cannot read diagnostic %s: %v", name, err)
		}
	}
	for _, path := range []string{"cell", "cell/node", "cell/node/netbird"} {
		info, err := os.Stat(filepath.Join(parent, path))
		if err != nil {
			t.Fatal(err)
		}
		created := info.Sys().(*syscall.Stat_t)
		if created.Uid != owner.Uid || created.Gid != owner.Gid || info.Mode().Perm() != 0700 {
			t.Fatal("root-first spool directory did not inherit private relay ownership")
		}
	}
	private := t.TempDir()
	if err := saveLedger(private, ledger{ActionID: "45DBCR8Q0GQD0HCEPS6PDDNM5K"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(private, "ledger.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private authority became readable by relay: %v", err)
	}
	if os.Geteuid() == 0 {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		executableFile, err := os.Open(executable)
		if err != nil {
			t.Fatal(err)
		}
		defer executableFile.Close()
		publicDir, err := os.Open(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer publicDir.Close()
		privateDir, err := os.Open(private)
		if err != nil {
			t.Fatal(err)
		}
		defer privateDir.Close()
		// Go's root-owned build directory may be 0700; pass the executable
		// itself so the relay UID does not need to traverse that directory.
		child := exec.Command("/proc/self/fd/5", "-test.run=^TestSpoolRelayReader$")
		child.Env = append(os.Environ(), "TS_TEST_SPOOL_READER=1", "GORACE=atexit_sleep_ms=0")
		child.ExtraFiles = []*os.File{publicDir, privateDir, executableFile}
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: owner.Uid, Gid: owner.Gid}}
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("unprivileged relay cannot use root-created spool: %s %v", output, err)
		}
	}
	if _, err := read(directory, "../ledger.json", 4096); err == nil {
		t.Fatal("descriptor-relative read accepted parent escape")
	}
	if err := Write(directory, "/", nil); err == nil {
		t.Fatal("descriptor-relative write accepted absolute name")
	}
	if _, err := openSpool(filepath.Join(t.TempDir(), "absent"), false); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing spool did not remain absent: %v", err)
	}
}

func TestSpoolRelayReader(t *testing.T) {
	if os.Getenv("TS_TEST_SPOOL_READER") != "1" {
		return
	}
	for _, name := range []string{"status.json", "result.json"} {
		fd, err := unix.Openat(3, name, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		file := os.NewFile(uintptr(fd), name)
		wire, err := io.ReadAll(file)
		file.Close()
		if err != nil || string(wire) != "public diagnostic" {
			t.Fatalf("unreadable worker diagnostic: %q %v", wire, err)
		}
	}
	if fd, err := unix.Openat(4, "ledger.json", unix.O_RDONLY|unix.O_NOFOLLOW, 0); !errors.Is(err, unix.EACCES) {
		if err == nil {
			unix.Close(fd)
		}
		t.Fatalf("relay read private root ledger: %v", err)
	}
	fd, err := unix.Openat(3, "step.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		t.Fatalf("relay cannot create signed steps in root-created directory: %v", err)
	}
	unix.Close(fd)
}
