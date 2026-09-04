package vmguest

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type executorCall struct {
	path string
	args []string
}

type fakeExecutor struct {
	calls  []executorCall
	stdout []byte
	stderr []byte
	err    error
}

type fixedNetworkDialer struct {
	connection net.Conn
	err        error
	network    string
	endpoint   string
}

func (dialer *fixedNetworkDialer) DialContext(_ context.Context, network, endpoint string) (net.Conn, error) {
	dialer.network = network
	dialer.endpoint = endpoint
	return dialer.connection, dialer.err
}

type chunkedConn struct {
	net.Conn
	readLimit  int
	writeLimit int
}

func (connection *chunkedConn) Read(data []byte) (int, error) {
	if connection.readLimit > 0 && len(data) > connection.readLimit {
		data = data[:connection.readLimit]
	}
	return connection.Conn.Read(data)
}

func (connection *chunkedConn) Write(data []byte) (int, error) {
	if connection.writeLimit > 0 && len(data) > connection.writeLimit {
		data = data[:connection.writeLimit]
	}
	return connection.Conn.Write(data)
}

func (executor *fakeExecutor) Run(_ context.Context, path string, args []string, stdout, stderr io.Writer) error {
	executor.calls = append(executor.calls, executorCall{path: path, args: append([]string(nil), args...)})
	_, _ = stdout.Write(executor.stdout)
	_, _ = stderr.Write(executor.stderr)
	return executor.err
}

func TestServeForcedExecutesOnlyTheValidatedArgv(t *testing.T) {
	executor := &fakeExecutor{stdout: []byte("running\n")}
	config := testConfig(t, executor)
	response := serveRequest(t, config, Request{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"is-system-running"}}, "")
	if response.Error != "" || response.Command == nil || response.Command.ExitCode != 0 || string(response.Command.Stdout) != "running\n" {
		t.Fatalf("response = %+v", response)
	}
	if len(executor.calls) != 1 || executor.calls[0].path != "/usr/bin/systemctl" || strings.Join(executor.calls[0].args, " ") != "is-system-running" {
		t.Fatalf("executor calls = %+v", executor.calls)
	}

	response = serveRequest(t, config, Request{SchemaVersion: 1, Operation: OperationProbe}, "uname -a")
	if !strings.Contains(response.Error, "original command") || len(executor.calls) != 1 {
		t.Fatalf("SSH_ORIGINAL_COMMAND was not rejected: %+v", response)
	}
}

func TestServeForcedReturnsBoundedProbeFacts(t *testing.T) {
	executor := &fakeExecutor{stdout: bytes.Repeat([]byte("x"), MaxOutputBytes+128)}
	response := serveRequest(t, testConfig(t, executor), Request{SchemaVersion: 1, Operation: OperationProbe}, "")
	if response.Error != "" || response.Probe == nil || len(executor.calls) != 7 {
		t.Fatalf("probe response=%+v calls=%d", response, len(executor.calls))
	}
	for _, result := range []CommandResult{response.Probe.Systemd, response.Probe.PID1, response.Probe.CgroupV2, response.Probe.DataMount, response.Probe.Network, response.Probe.Time, response.Probe.SeedDigest} {
		if len(result.Stdout) != MaxOutputBytes || !result.StdoutTruncated {
			t.Fatalf("probe output was not bounded: bytes=%d truncated=%v", len(result.Stdout), result.StdoutTruncated)
		}
	}
}

func TestNetworkExchangeHandlesPartialIOAndReturnsExactFrame(t *testing.T) {
	client, peer := net.Pipe()
	dialer := &fixedNetworkDialer{connection: &chunkedConn{Conn: client, readLimit: 1, writeLimit: 2}}
	challenge := []byte("random-controller-challenge")
	reply := []byte("exact-peer-response")
	peerDone := serveNetworkExchangePeer(peer, challenge, uint32(len(reply)), reply, nil)
	config := Config{NetworkExchangeEndpoint: "10.77.0.1:4100", NetworkDialer: dialer, CommandTimeout: time.Second}
	response, err := networkExchange(context.Background(), config, "10.77.0.1:4100", challenge)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, reply) {
		t.Fatalf("network response = %q, want %q", response, reply)
	}
	if dialer.network != "tcp4" || dialer.endpoint != "10.77.0.1:4100" {
		t.Fatalf("dial = %q %q", dialer.network, dialer.endpoint)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

func TestNetworkExchangeRejectsOversizedTruncatedAndTrailingFrames(t *testing.T) {
	tests := []struct {
		name     string
		length   uint32
		response []byte
		trailing []byte
	}{
		{name: "oversized", length: MaxNetworkBytes + 1},
		{name: "empty", length: 0},
		{name: "truncated", length: 8, response: []byte("short")},
		{name: "trailing", length: 2, response: []byte("ok"), trailing: []byte("x")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, peer := net.Pipe()
			challenge := []byte("challenge")
			peerDone := serveNetworkExchangePeer(peer, challenge, test.length, test.response, test.trailing)
			config := Config{NetworkExchangeEndpoint: "192.168.10.1:9876", NetworkDialer: &fixedNetworkDialer{connection: client}, CommandTimeout: time.Second}
			if response, err := networkExchange(context.Background(), config, "192.168.10.1:9876", challenge); err == nil || response != nil {
				t.Fatalf("invalid frame returned response %q, error %v", response, err)
			}
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNetworkExchangeDeadlineClosesStalledConnection(t *testing.T) {
	client, peer := net.Pipe()
	challenge := []byte("challenge")
	requestRead := make(chan error, 1)
	peerClosed := make(chan error, 1)
	go func() {
		defer peer.Close()
		requestRead <- readNetworkChallenge(peer, challenge)
		var data [1]byte
		_, err := peer.Read(data[:])
		peerClosed <- err
	}()
	config := Config{NetworkExchangeEndpoint: "172.16.20.1:1234", NetworkDialer: &fixedNetworkDialer{connection: client}, CommandTimeout: 20 * time.Millisecond}
	response, err := networkExchange(context.Background(), config, "172.16.20.1:1234", challenge)
	if !errors.Is(err, context.DeadlineExceeded) || response != nil {
		t.Fatalf("stalled exchange returned response %q, error %v", response, err)
	}
	if err := <-requestRead; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-peerClosed:
		if err == nil {
			t.Fatal("peer read succeeded after the exchange deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not close the network connection")
	}
}

func TestNetworkExchangeRequiresExactTrustedEndpoint(t *testing.T) {
	dialer := &fixedNetworkDialer{}
	config := Config{NetworkExchangeEndpoint: "10.77.0.1:4100", NetworkDialer: dialer, CommandTimeout: time.Second}
	for _, endpoint := range []string{"10.77.0.2:4100", "10.77.0.1:4101"} {
		response, err := networkExchange(context.Background(), config, endpoint, []byte("challenge"))
		if err == nil || response != nil || dialer.endpoint != "" {
			t.Fatalf("unauthorized endpoint %q returned response %q, error %v, dialed %q", endpoint, response, err, dialer.endpoint)
		}
	}
	config.NetworkExchangeEndpoint = ""
	if _, err := networkExchange(context.Background(), config, "10.77.0.1:4100", []byte("challenge")); err == nil || dialer.endpoint != "" {
		t.Fatalf("network exchange without trusted endpoint returned %v and dialed %q", err, dialer.endpoint)
	}
	invalidConfig := testConfig(t, &fakeExecutor{})
	invalidConfig.NetworkExchangeEndpoint = "1.1.1.1:4100"
	if _, err := invalidConfig.validate(); err == nil {
		t.Fatal("configuration accepted a public network exchange endpoint")
	}
	serveConfig := testConfig(t, &fakeExecutor{})
	serveConfig.NetworkExchangeEndpoint = "10.77.0.1:4100"
	serveConfig.NetworkDialer = dialer
	response := serveRequest(t, serveConfig, Request{SchemaVersion: SchemaVersion, Operation: OperationNetwork, Path: "10.77.0.2:4100", Data: []byte("challenge")}, "")
	if response.Error == "" || len(response.Data) != 0 || dialer.endpoint != "" {
		t.Fatalf("forced-command relay response = %+v, dialed %q", response, dialer.endpoint)
	}
}

func serveNetworkExchangePeer(connection net.Conn, challenge []byte, responseLength uint32, response, trailing []byte) <-chan error {
	done := make(chan error, 1)
	go func() {
		defer connection.Close()
		if err := readNetworkChallenge(connection, challenge); err != nil {
			done <- err
			return
		}
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], responseLength)
		if err := writeNetworkBytes(context.Background(), connection, header[:]); err != nil {
			done <- err
			return
		}
		if err := writeNetworkBytes(context.Background(), connection, response); err != nil {
			done <- err
			return
		}
		if err := writeNetworkBytes(context.Background(), connection, trailing); err != nil {
			done <- err
			return
		}
		done <- nil
	}()
	return done
}

func readNetworkChallenge(connection net.Conn, expected []byte) error {
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length != uint32(len(expected)) {
		return fmt.Errorf("challenge length = %d, want %d", length, len(expected))
	}
	challenge := make([]byte, int(length))
	if _, err := io.ReadFull(connection, challenge); err != nil {
		return err
	}
	if !bytes.Equal(challenge, expected) {
		return fmt.Errorf("challenge = %q, want %q", challenge, expected)
	}
	return nil
}

func TestServeForcedPersistsAndReadsOnlyOwnedFiles(t *testing.T) {
	config := testConfig(t, &fakeExecutor{})
	payload := []byte("survives reboot")
	write := serveRequest(t, config, Request{SchemaVersion: 1, Operation: OperationDataWrite, Path: "proof/value", Data: payload}, "")
	if write.Error != "" {
		t.Fatal(write.Error)
	}
	read := serveRequest(t, config, Request{SchemaVersion: 1, Operation: OperationDataRead, Path: "proof/value"}, "")
	if read.Error != "" || !bytes.Equal(read.Data, payload) {
		t.Fatalf("read response = %+v", read)
	}
	info, err := os.Stat(filepath.Join(config.DataRoot, "proof", "value"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("persistent file mode = %v, %v", info, err)
	}

	artifact := serveRequest(t, config, Request{SchemaVersion: 1, Operation: OperationPut, Path: "terrabase/v1/artifact", Data: []byte("binary"), Mode: 0o644}, "")
	if artifact.Error != "" {
		t.Fatal(artifact.Error)
	}
	info, err = os.Stat(filepath.Join(config.InboxRoot, "terrabase", "v1", "artifact"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("artifact file mode = %v, %v", info, err)
	}
}

func TestStorageRejectsSymlinkEscapeAndOversizeRead(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	if err := os.Symlink(external, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(context.Background(), root, "link/file", []byte("escape"), 0o600); err == nil {
		t.Fatal("write followed a symlink directory")
	}
	if err := os.WriteFile(filepath.Join(root, "large"), bytes.Repeat([]byte("x"), 17), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := boundedRead(context.Background(), root, "large", 16); err == nil {
		t.Fatal("oversized file was read")
	}
	if err := os.Symlink(filepath.Join(root, "large"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := boundedRead(context.Background(), root, "alias", 32); err == nil {
		t.Fatal("read followed a symlink")
	}
	referent := filepath.Join(external, "referent")
	if err := os.WriteFile(referent, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(referent, filepath.Join(root, "write-alias")); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(context.Background(), root, "write-alias", []byte("replacement"), 0o600); err == nil {
		t.Fatal("write replaced a symlink target")
	}
	outside, err := os.ReadFile(referent)
	if err != nil || string(outside) != "outside" {
		t.Fatalf("outside referent changed: %q, %v", outside, err)
	}
	exact, err := boundedRead(context.Background(), root, "large", 17)
	if err != nil || len(exact) != 17 {
		t.Fatalf("exact-limit read failed: bytes=%d err=%v", len(exact), err)
	}
}

func TestStorageRejectsWritableRootAndHandlesConcurrentParents(t *testing.T) {
	base := t.TempDir()
	unsafe := filepath.Join(base, "unsafe")
	if err := os.Mkdir(unsafe, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(context.Background(), unsafe, "file", []byte("value"), 0o600); err == nil {
		t.Fatal("write admitted a group/world-writable root")
	}

	root := filepath.Join(base, "safe")
	var group sync.WaitGroup
	errorsSeen := make(chan error, 12)
	for index := range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			name := filepath.Join("component", "v1", fmt.Sprintf("artifact-%d", index))
			errorsSeen <- atomicWrite(context.Background(), root, name, []byte("value"), 0o600)
		}()
	}
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(filepath.Join(root, "component", "v1"))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("storage directory mode = %v, %v", info, err)
	}
}

func TestStorageQuotaAccountsNewFilesAndReplacementDeltas(t *testing.T) {
	root := filepath.Join(t.TempDir(), "quota")
	quota := storageQuota{maxBytes: 5, maxFiles: 2}
	write := func(path, value string) error {
		return atomicWriteWithinQuota(context.Background(), root, path, []byte(value), 0o600, quota)
	}
	if err := write("a", "aaa"); err != nil {
		t.Fatal(err)
	}
	if err := write("nested/b", "bb"); err != nil {
		t.Fatal(err)
	}
	if err := write("nested/c", "x"); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("file-count overflow returned %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "nested", "c")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected file-count overflow mutated storage: %v", err)
	}
	if err := write("new/c", "x"); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("missing-parent file-count overflow returned %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected quota write created parent directories: %v", err)
	}
	if err := write("a", "aa"); err != nil {
		t.Fatalf("shrinking replacement failed: %v", err)
	}
	if err := write("nested/b", "bbb"); err != nil {
		t.Fatalf("exact byte-boundary replacement failed: %v", err)
	}
	if err := write("nested/b", "bbbb"); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("byte overflow returned %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "nested", "b")); err != nil || string(data) != "bbb" {
		t.Fatalf("rejected replacement changed the target: %q, %v", data, err)
	}
}

func TestStorageRejectsHardLinksAndCleansReservedTemps(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(external, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(external, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := boundedRead(context.Background(), root, "linked", 32); err == nil {
		t.Fatal("read admitted a file with another hard link")
	}
	if err := atomicWrite(context.Background(), root, "linked", []byte("replacement"), 0o600); err == nil {
		t.Fatal("write replaced a file with another hard link")
	}
	if data, err := os.ReadFile(external); err != nil || string(data) != "private" {
		t.Fatalf("hard-linked referent changed: %q, %v", data, err)
	}
	if err := os.Remove(filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}

	unsafeMode := filepath.Join(root, "unsafe-mode")
	if err := os.WriteFile(unsafeMode, []byte("private"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := boundedRead(context.Background(), root, "unsafe-mode", 32); err == nil {
		t.Fatal("read admitted a group/world-readable file")
	}
	if err := atomicWrite(context.Background(), root, "unsafe-mode", []byte("replacement"), 0o600); err == nil {
		t.Fatal("write replaced a file with an unexpected mode")
	}

	directory := filepath.Join(root, "proof")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(directory, ".vmguest-write-0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(stale, []byte("abandoned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(context.Background(), root, "proof/value", []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reserved stale temporary file remains: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(directory, "value")); err != nil || string(data) != "published" {
		t.Fatalf("published file = %q, %v", data, err)
	}
}

func TestStorageDetectsInPlaceSameSizeMutation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "changing")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), MaxPersistentBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	started := make(chan struct{})
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		value := byte('b')
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			if _, err := file.WriteAt([]byte{value}, 0); err != nil {
				done <- err
				return
			}
			if value == 'b' {
				value = 'c'
			} else {
				value = 'b'
			}
			runtime.Gosched()
		}
	}()
	<-started
	detected := false
	for range 20 {
		if _, err := boundedRead(context.Background(), root, "changing", MaxPersistentBytes); err != nil {
			detected = true
			break
		}
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !detected {
		t.Fatal("same-size in-place mutation escaped metadata validation")
	}
}

func TestStorageStartupCleanupWalksEveryOwnedDirectory(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "one", "two", "three")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	temps := []string{
		filepath.Join(root, ".vmguest-write-0123456789abcdef0123456789abcdef"),
		filepath.Join(root, "one", ".vmguest-write-1123456789abcdef0123456789abcdef"),
		filepath.Join(deep, ".vmguest-write-2123456789abcdef0123456789abcdef"),
	}
	for _, path := range temps {
		if err := os.WriteFile(path, []byte("abandoned"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kept := filepath.Join(deep, "artifact")
	if err := os.WriteFile(kept, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupStorageRoot(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	for _, path := range temps {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale temporary file remains at %s: %v", path, err)
		}
	}
	if data, err := os.ReadFile(kept); err != nil || string(data) != "keep" {
		t.Fatalf("ordinary storage file changed: %q, %v", data, err)
	}
}

func TestStorageCleanupScansPastLargeAndUnrelatedDeepState(t *testing.T) {
	root := t.TempDir()
	for index := 0; index <= 4096; index++ {
		path := filepath.Join(root, fmt.Sprintf("entry-%04d", index))
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stale := filepath.Join(root, ".vmguest-write-3123456789abcdef0123456789abcdef")
	if err := os.WriteFile(stale, []byte("abandoned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupStorageRoot(context.Background(), root); err != nil {
		t.Fatalf("large storage cleanup failed: %v", err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup stopped before removing a stale file: %v", err)
	}

	root = t.TempDir()
	tooDeep := filepath.Join(root, "one", "two", "three", "four")
	if err := os.MkdirAll(tooDeep, 0o700); err != nil {
		t.Fatal(err)
	}
	validDepthTemp := filepath.Join(root, "one", "two", "three", ".vmguest-write-4123456789abcdef0123456789abcdef")
	if err := os.WriteFile(validDepthTemp, []byte("abandoned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupStorageRoot(context.Background(), root); err != nil {
		t.Fatalf("unrelated deep directory denied cleanup: %v", err)
	}
	if _, err := os.Lstat(validDepthTemp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("valid-depth stale file remains: %v", err)
	}
	if info, err := os.Stat(tooDeep); err != nil || !info.IsDir() {
		t.Fatalf("unrelated deep directory changed: %v, %v", info, err)
	}
}

func TestStorageRejectsNestedMountTraversal(t *testing.T) {
	root := t.TempDir()
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "value"), []byte("mounted"), 0o600); err != nil {
		t.Fatal(err)
	}
	mountpoint := filepath.Join(root, "nested")
	if err := os.Mkdir(mountpoint, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(source, mountpoint, "", unix.MS_BIND, ""); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skip("bind mounts are not permitted for this test user")
		}
		t.Fatal(err)
	}
	defer unix.Unmount(mountpoint, unix.MNT_DETACH)
	if err := atomicWrite(context.Background(), root, "nested/new", []byte("value"), 0o600); err == nil {
		t.Fatal("write crossed a nested mount")
	}
	if _, err := boundedRead(context.Background(), root, "nested/value", 32); err == nil {
		t.Fatal("read crossed a nested mount")
	}
}

func TestStorageMountIDDistinguishesFilesystems(t *testing.T) {
	root := t.TempDir()
	rootFD, err := unix.Open(root, directoryOpenFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	rootMount, err := descriptorMountID(rootFD)
	if err != nil {
		t.Fatal(err)
	}
	pathMount, err := pathMountID(unix.AT_FDCWD, root, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		t.Fatal(err)
	}
	if rootMount != pathMount {
		t.Fatalf("descriptor mount %d differs from path mount %d", rootMount, pathMount)
	}

	other, err := os.MkdirTemp("/dev/shm", "vmguest-mount-")
	if err != nil {
		t.Skipf("cannot create an owned directory on /dev/shm: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(other) })
	otherFD, err := unix.Open(other, directoryOpenFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(otherFD)
	otherMount, err := descriptorMountID(otherFD)
	if err != nil {
		t.Fatal(err)
	}
	if rootMount == otherMount {
		t.Skip("temporary directory and /dev/shm are on the same mount")
	}
	if err := validateOwnedDirectory(otherFD, rootMount); err == nil {
		t.Fatal("owned directory from another mount was accepted")
	}
}

func TestStorageHonorsCancellationBeforeMutationAndWhileQueued(t *testing.T) {
	root := filepath.Join(t.TempDir(), "storage")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := atomicWrite(ctx, root, "value", []byte("data"), 0o600); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write returned %v", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled write created its storage root: %v", err)
	}

	storageWriteGate <- struct{}{}
	queuedContext, queuedCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer queuedCancel()
	err := atomicWrite(queuedContext, root, "value", []byte("data"), 0o600)
	<-storageWriteGate
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued write ignored its deadline: %v", err)
	}
}

func TestStorageParentDescriptorIsCloseOnExec(t *testing.T) {
	root := t.TempDir()
	rootFD, err := openStorageRoot(context.Background(), root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	parentFD, _, err := openStorageParent(context.Background(), rootFD, "value", false)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parentFD)
	flags, err := unix.FcntlInt(uintptr(parentFD), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("storage parent descriptor can leak across exec")
	}
}

func TestServeForcedCancelsStalledInput(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	config := testConfig(t, &fakeExecutor{})
	go func() {
		done <- ServeForced(ctx, reader, io.Discard, "", config)
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stalled session returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled session did not observe cancellation")
	}
}

type controlledReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (reader *controlledReader) Read(_ []byte) (int, error) {
	reader.once.Do(func() { close(reader.started) })
	<-reader.release
	return 0, io.EOF
}

type controlledWriter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type rejectedDeadlineReader struct{}

func (rejectedDeadlineReader) Read([]byte) (int, error) { panic("unexpected read") }
func (rejectedDeadlineReader) SetReadDeadline(time.Time) error {
	return os.ErrNoDeadline
}

type rejectedDeadlineWriter struct{}

func (rejectedDeadlineWriter) Write([]byte) (int, error) { panic("unexpected write") }
func (rejectedDeadlineWriter) SetWriteDeadline(time.Time) error {
	return os.ErrNoDeadline
}

func (writer *controlledWriter) Write(data []byte) (int, error) {
	writer.once.Do(func() { close(writer.started) })
	<-writer.release
	return len(data), nil
}

func TestServeForcedDoesNotDetachNonClosableIO(t *testing.T) {
	reader := &controlledReader{started: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	config := testConfig(t, &fakeExecutor{})
	go func() { done <- ServeForced(ctx, reader, io.Discard, "", config) }()
	<-reader.started
	cancel()
	select {
	case err := <-done:
		t.Fatalf("ServeForced detached its blocked request reader: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(reader.release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("released request reader returned %v", err)
	}

	writer := &controlledWriter{started: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan error, 1)
	request := `{"schemaVersion":1,"operation":"probe"}`
	config = testConfig(t, &fakeExecutor{})
	go func() {
		done <- ServeForced(ctx, strings.NewReader(request), writer, "rejected", config)
	}()
	<-writer.started
	cancel()
	select {
	case err := <-done:
		t.Fatalf("ServeForced detached its blocked response writer: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(writer.release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("released response writer returned %v", err)
	}
}

func TestServeForcedRejectsUncancellableDeadlineIO(t *testing.T) {
	config := testConfig(t, &fakeExecutor{})
	if err := ServeForced(context.Background(), rejectedDeadlineReader{}, io.Discard, "", config); err == nil || !strings.Contains(err.Error(), "reader does not support cancellation") {
		t.Fatalf("uncancellable request reader returned %v", err)
	}
	if err := ServeForced(context.Background(), strings.NewReader(`{"schemaVersion":1,"operation":"probe"}`), rejectedDeadlineWriter{}, "", config); err == nil || !strings.Contains(err.Error(), "writer does not support cancellation") {
		t.Fatalf("uncancellable response writer returned %v", err)
	}
}

func TestDefaultConfigUsesRuntimeGuestSeedPath(t *testing.T) {
	const expected = "/etc/terrascale/vmqual-guest-seed.json"
	config := DefaultConfig()
	if DefaultSeedPath != expected || config.SeedPath != expected {
		t.Fatalf("default seed path = %q, config seed path = %q", DefaultSeedPath, config.SeedPath)
	}
}

func TestConfigRejectsOverlappingStorageAndSeedPaths(t *testing.T) {
	config := testConfig(t, &fakeExecutor{})
	config.DataRoot = filepath.Join(config.InboxRoot, "data")
	if _, err := config.validate(); err == nil {
		t.Fatal("overlapping storage roots were accepted")
	}
	config = testConfig(t, &fakeExecutor{})
	config.SeedPath = filepath.Join(config.DataRoot, "seed.json")
	if _, err := config.validate(); err == nil {
		t.Fatal("seed inside writable storage was accepted")
	}
	config = testConfig(t, &fakeExecutor{})
	config.DataRoot = filepath.Join(config.SeedPath, "data")
	if _, err := config.validate(); err == nil {
		t.Fatal("writable storage inside the seed path was accepted")
	}

	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "storage"), 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	config = testConfig(t, &fakeExecutor{})
	config.InboxRoot = filepath.Join(real, "storage")
	config.DataRoot = filepath.Join(alias, "storage")
	if _, err := config.validate(); err == nil {
		t.Fatal("storage roots aliased through a symlink were accepted")
	}
}

func TestServeForcedEncodesProtocolErrors(t *testing.T) {
	var output bytes.Buffer
	if err := ServeForced(context.Background(), strings.NewReader(`{"schemaVersion":1,"operation":"execute","path":"/bin/sh"}`), &output, "", testConfig(t, &fakeExecutor{})); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != SchemaVersion || response.Error == "" {
		t.Fatalf("protocol error response = %+v", response)
	}
	if err := ServeForced(context.Background(), strings.NewReader(`{}`), nil, "", Config{}); err == nil {
		t.Fatal("accepted nil response writer")
	}
}

func TestRunCommandRecordsExecutorFailure(t *testing.T) {
	executor := &fakeExecutor{stderr: []byte("failed"), err: errors.New("spawn failed")}
	config := testConfig(t, executor)
	result := runCommand(context.Background(), config, "/usr/bin/systemctl", []string{"is-system-running"})
	if result.ExitCode != -1 || result.Error == "" || string(result.Stderr) != "failed" {
		t.Fatalf("command result = %+v", result)
	}
}

type deadlineExecutor struct{}

func (deadlineExecutor) Run(ctx context.Context, _ string, _ []string, _, _ io.Writer) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestRunCommandReportsDeadlineAsExit124(t *testing.T) {
	config := testConfig(t, deadlineExecutor{})
	config.CommandTimeout = 10 * time.Millisecond
	result := runCommand(context.Background(), config, "/usr/bin/systemctl", []string{"is-system-running"})
	if result.ExitCode != 124 || !strings.Contains(result.Error, context.DeadlineExceeded.Error()) {
		t.Fatalf("deadline result = %+v", result)
	}
}

func serveRequest(t *testing.T, config Config, request Request, original string) Response {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := ServeForced(context.Background(), bytes.NewReader(data), &output, original, config); err != nil {
		t.Fatal(err)
	}
	var response Response
	decoder := json.NewDecoder(&output)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	return response
}

func testConfig(t *testing.T, executor Executor) Config {
	t.Helper()
	root := t.TempDir()
	return Config{
		InboxRoot: filepath.Join(root, "inbox"),
		DataRoot:  filepath.Join(root, "data"),
		SeedPath:  filepath.Join(root, "seed.json"),
		Executor:  executor,
	}
}
