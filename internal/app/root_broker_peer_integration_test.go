//go:build fixturetest

package app

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootociwire"
	"golang.org/x/sys/unix"
)

const rootBrokerPeerFixtureStage = "TS_ROOT_BROKER_PEER_FIXTURE"
const rootBrokerPeerFixtureBinary = "/run/root-broker-peer-fixture"

// This privileged fixture mutates only the subprocess's private tmpfs /run.
func TestRootBrokerPeerServiceUserIntegration(t *testing.T) {
	switch os.Getenv(rootBrokerPeerFixtureStage) {
	case "namespace":
		prepareRootBrokerPeerFixture(t)
		return
	case "server":
		runRootBrokerPeerFixtureServer(t)
		return
	case "ordinary":
		runRootBrokerPeerFixtureOrdinary(t)
		return
	case "":
	default:
		t.Fatal("unknown root broker peer fixture stage")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("requires root and a private mount namespace")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestRootBrokerPeerServiceUserIntegration$", "-test.count=1")
	command.Env = []string{"PATH=/usr/bin:/bin", rootBrokerPeerFixtureStage + "=namespace"}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = time.Second
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("requires permission to create a private mount namespace")
		}
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("private broker peer fixture: %v\n%s", err, output.String())
	}
}

func requireRootBrokerPeerFixtureNamespace(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("namespace fixture requires root:root")
	}
	self, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.Readlink("/proc/" + strconv.Itoa(os.Getppid()) + "/ns/mnt")
	if err != nil || self == parent {
		t.Fatal("refusing fixture mutations without a distinct mount namespace")
	}
}

func prepareRootBrokerPeerFixture(t *testing.T) {
	requireRootBrokerPeerFixtureNamespace(t)
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", "/run", "tmpfs", unix.MS_NODEV|unix.MS_NOSUID, "mode=0755,size=512m"); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	destination, err := os.OpenFile(rootBrokerPeerFixtureBinary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := errors.Join(destination.Chown(0, 0), destination.Chmod(0o755), destination.Close(), source.Close())
	if err := errors.Join(copyErr, closeErr); err != nil {
		t.Fatal(err)
	}
	// Exec retains the isolated mount namespace and its original parent-death signal.
	if err := unix.Exec(rootBrokerPeerFixtureBinary,
		[]string{rootBrokerPeerFixtureBinary, "-test.run=^TestRootBrokerPeerServiceUserIntegration$", "-test.count=1"},
		[]string{"PATH=/usr/bin:/bin", rootBrokerPeerFixtureStage + "=server"}); err != nil {
		t.Fatal(err)
	}
}

func runRootBrokerPeerFixtureServer(t *testing.T) {
	requireRootBrokerPeerFixtureNamespace(t)
	var filesystem unix.Statfs_t
	if unix.Statfs("/run", &filesystem) != nil || filesystem.Type != unix.TMPFS_MAGIC {
		t.Fatal("refusing fixture mutations outside private tmpfs /run")
	}
	var ownRun, parentRun unix.Stat_t
	if unix.Stat("/run", &ownRun) != nil ||
		unix.Stat("/proc/"+strconv.Itoa(os.Getppid())+"/root/run", &parentRun) != nil ||
		ownRun.Dev == parentRun.Dev && ownRun.Ino == parentRun.Ino {
		t.Fatal("refusing fixture mutations in the parent's /run")
	}
	witness, err := rootoci.CaptureProcess(os.Getpid())
	if err != nil {
		t.Fatalf("capture actual root server's freshly copied executable: %v", err)
	}
	defer witness.Close()
	if err := os.Mkdir("/run/terrascale-orchestrator", 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	var sockets []*rootBrokerSocket
	var workers sync.WaitGroup
	errorsFound := make(chan error, 5)
	defer func() {
		cancel()
		for _, socket := range sockets {
			_ = socket.Close()
		}
		workers.Wait()
		close(errorsFound)
		for err := range errorsFound {
			t.Error(err)
		}
	}()
	for _, path := range []string{rootBrokerStartupSocket, rootBrokerObservationSocket, rootBrokerReconnectSocket, rootBrokerClientSocket, rootBrokerSourceSocket} {
		socket, err := listenRootBrokerSocket(path, 65534)
		if err != nil {
			t.Fatal(err)
		}
		sockets = append(sockets, socket)
		workers.Go(func() {
			if err := serveRootBrokerPeerFixture(ctx, socket, path, witness); err != nil && ctx.Err() == nil {
				errorsFound <- err
			}
		})
	}
	command := exec.CommandContext(ctx, rootBrokerPeerFixtureBinary, "-test.run=^TestRootBrokerPeerServiceUserIntegration$", "-test.count=1")
	command.Env = []string{"PATH=/usr/bin:/bin", rootBrokerPeerFixtureStage + "=ordinary"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}},
		Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = time.Second
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("ordinary service-user fixture: %v\n%s", err, output.String())
	}
	if err := witness.Verify(); err != nil {
		t.Fatalf("actual root server changed during service-user observation: %v", err)
	}
}

func serveRootBrokerPeerFixture(ctx context.Context, socket *rootBrokerSocket, path string, witness *rootoci.ProcessWitness) error {
	conn, err := socket.listener.AcceptUnix()
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	input := bufio.NewScanner(conn)
	input.Buffer(make([]byte, 32), 64)
	for input.Scan() {
		if witness.Verify() != nil {
			return errors.New("root server process witness changed")
		}
		var err error
		switch input.Text() {
		case "mode-bad":
			err = os.Chmod(path, 0o666)
		case "mode-good":
			err = os.Chmod(path, 0o660)
		case "directory-bad":
			err = os.Chmod("/run/terrascale-orchestrator", 0o775)
		case "directory-good":
			err = os.Chmod("/run/terrascale-orchestrator", 0o755)
		case "replace":
			if path != rootBrokerObservationSocket {
				return errors.New("replacement fixture requires the observation endpoint")
			}
			if err := os.Rename(path, path+".retired"); err != nil {
				return err
			}
			replacement, listenErr := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if listenErr != nil {
				return listenErr
			}
			replacement.SetUnlinkOnClose(false)
			defer replacement.Close()
			err = errors.Join(os.Chown(path, 0, 65534), os.Chmod(path, 0o660))
		default:
			return fmt.Errorf("unknown fixture action %q", input.Text())
		}
		if err != nil {
			return err
		}
		if _, err := io.WriteString(conn, "ok\n"); err != nil {
			return err
		}
	}
	return input.Err()
}

func runRootBrokerPeerFixtureOrdinary(t *testing.T) {
	if os.Geteuid() != 65534 || os.Getegid() != 65534 {
		t.Fatal("ordinary fixture did not drop to the service UID and GID")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		t.Fatal("ordinary fixture retained supplementary groups")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	connections := make(map[string]*net.UnixConn)
	pins := make(map[string]rootBrokerPeerIdentity)
	socketPins := make(map[string]bool)
	var process string
	for _, path := range []string{rootBrokerStartupSocket, rootBrokerObservationSocket, rootBrokerReconnectSocket, rootBrokerClientSocket, rootBrokerSourceSocket} {
		connection, err := new(net.Dialer).DialContext(ctx, "unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		conn, ok := connection.(*net.UnixConn)
		if !ok {
			t.Fatal("fixed broker socket did not yield a Unix connection")
		}
		deadline, _ := ctx.Deadline()
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		peer, err := rootociwire.PeerCredential(conn)
		if err != nil || peer.PID != os.Getppid() || peer.UID != 0 || peer.GID != 0 {
			t.Fatalf("fixed socket lacks the actual root parent peer: %+v, %v", peer, err)
		}
		witness, err := rootoci.CaptureProcess(peer.PID)
		if err == nil {
			_ = witness.Close()
			t.Fatal("ordinary service user unexpectedly obtained a full root process witness")
		}
		identity, err := rootBrokerPeerBinding(conn, path)
		if err != nil || identity.process == "" || identity.socket == "" {
			t.Fatalf("ordinary root-peer authentication failed for %s: %v", path, err)
		}
		confirmed, err := rootBrokerPeerBinding(conn, path)
		if err != nil || confirmed != identity {
			t.Fatalf("root peer pin drifted without mutation for %s: %v", path, err)
		}
		if process == "" {
			process = identity.process
		}
		if identity.process != process || socketPins[identity.socket] {
			t.Fatal("fixed endpoints did not retain one root process and distinct socket identities")
		}
		socketPins[identity.socket] = true
		connections[path], pins[path] = conn, identity
	}
	conn := connections[rootBrokerObservationSocket]
	reader := &rootBrokerReader{}
	if err := reader.verify(conn); err != nil {
		t.Fatal(err)
	}
	if _, err := rootBrokerPeerBinding(conn, "/run/terrascale-orchestrator/unregistered.sock"); !errors.Is(err, rootoci.ErrUnauthorized) {
		t.Fatal("accepted a socket path outside the fixed endpoints")
	}
	mutate := func(action string) {
		t.Helper()
		if _, err := io.WriteString(conn, action+"\n"); err != nil {
			t.Fatal(err)
		}
		var acknowledgement [3]byte
		if _, err := io.ReadFull(conn, acknowledgement[:]); err != nil || string(acknowledgement[:]) != "ok\n" {
			t.Fatalf("fixture mutation %s failed: %q, %v", action, acknowledgement, err)
		}
	}
	for _, test := range []struct{ bad, good string }{{"mode-bad", "mode-good"}, {"directory-bad", "directory-good"}} {
		mutate(test.bad)
		if _, err := rootBrokerPeerBinding(conn, rootBrokerObservationSocket); !errors.Is(err, rootoci.ErrUnauthorized) {
			t.Fatalf("accepted unsafe %s", test.bad)
		}
		if err := reader.verify(conn); !errors.Is(err, rootoci.ErrUnauthorized) {
			t.Fatalf("native reader accepted unsafe %s", test.bad)
		}
		mutate(test.good)
		identity, err := rootBrokerPeerBinding(conn, rootBrokerObservationSocket)
		if err != nil || identity != pins[rootBrokerObservationSocket] || reader.verify(conn) != nil {
			t.Fatalf("restored socket lost its original pin: %v", err)
		}
	}
	mutate("replace")
	replacement, err := rootBrokerPeerBinding(conn, rootBrokerObservationSocket)
	if err != nil || replacement.process != process || replacement.socket == pins[rootBrokerObservationSocket].socket {
		t.Fatalf("same-process socket replacement was not distinguished: %+v, %v", replacement, err)
	}
	if err := reader.verify(conn); !errors.Is(err, rootoci.ErrUnauthorized) {
		t.Fatal("native reader accepted replacement of its pinned socket")
	}
}
