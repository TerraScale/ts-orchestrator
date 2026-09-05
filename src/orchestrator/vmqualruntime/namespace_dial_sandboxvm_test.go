//go:build sandboxvm && linux

package vmqualruntime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestGuestNamespaceDialRejectsInvalidInput(t *testing.T) {
	for _, test := range []struct{ namespace, target string }{
		{"/proc/self/ns/net", "10.77.0.10:22"},
		{"/run/netns/../netns/guest", "10.77.0.10:22"},
		{"/run/netns/guest", "localhost:22"},
		{"/run/netns/guest", "127.0.0.1:22"},
		{"/run/netns/guest", "10.77.0.10:80"},
		{"/run/netns/guest", "[::1]:22"},
	} {
		if conn, err := dialGuestNamespace(context.Background(), test.namespace, test.target); err == nil {
			conn.Close()
			t.Fatalf("invalid input accepted: %+v", test)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dialGuestNamespace(ctx, "/run/netns/unit-absent", "10.77.0.10:22"); err != context.Canceled {
		t.Fatalf("cancellation = %v", err)
	}
	if _, err := dialGuestNamespace(nil, "/run/netns/unit-absent", "10.77.0.10:22"); err == nil {
		t.Fatal("nil context accepted")
	}
}

// This opt-in test owns one temporary namespace, exercises real SSH-port TCP
// traffic without a root route, and verifies the caller namespace is unchanged.
func TestGuestNamespaceDialRealIsolatedSocket(t *testing.T) {
	if os.Getenv("TS_VM_NAMESPACE_DIAL_TEST") != "1" {
		t.Skip("set TS_VM_NAMESPACE_DIAL_TEST=1 under a runner with CAP_SYS_ADMIN and CAP_NET_ADMIN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	name := fmt.Sprintf("vmq-dial-%d", os.Getpid())
	run := func(args ...string) {
		t.Helper()
		output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v %s", args, err, output)
		}
	}
	run("netns", "add", name)
	defer func() {
		if output, err := exec.Command("ip", "netns", "del", name).CombinedOutput(); err != nil {
			t.Errorf("delete owned namespace: %v %s", err, output)
		}
	}()
	run("-n", name, "link", "set", "lo", "up")
	run("-n", name, "address", "add", "10.77.254.10/32", "dev", "lo")
	before, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	server := exec.CommandContext(ctx, "ip", "netns", "exec", name, "python3", "-u", "-c", `import socket
s=socket.socket();s.bind(('10.77.254.10',22));s.listen(1);print('ready',flush=True)
c,a=s.accept();c.sendall(b'SSH-2.0-vmqual-test\r\n');c.close();s.close()`)
	pipe, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	server.Stderr = os.Stderr
	server.WaitDelay = time.Second
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if server.ProcessState == nil {
			_ = server.Process.Kill()
			_ = server.Wait()
		}
	}()
	if line, err := bufio.NewReader(pipe).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("listener readiness %q %v", line, err)
	}
	hostCtx, hostCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	hostConn, hostErr := (&net.Dialer{}).DialContext(hostCtx, "tcp4", "10.77.254.10:22")
	hostCancel()
	if hostErr == nil {
		hostConn.Close()
		t.Fatal("isolated namespace unexpectedly reachable from host")
	}
	connection, err := dialGuestNamespace(ctx, "/run/netns/"+name, "10.77.254.10:22")
	if err != nil {
		t.Fatal(err)
	}
	connection.SetReadDeadline(time.Now().Add(time.Second))
	data, err := io.ReadAll(connection)
	connection.Close()
	if err != nil || string(data) != "SSH-2.0-vmqual-test\r\n" {
		t.Fatalf("namespace traffic %q %v", data, err)
	}
	after, err := os.Readlink("/proc/self/ns/net")
	if err != nil || before != after {
		t.Fatalf("caller namespace changed: %q -> %q %v", before, after, err)
	}
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}
}
