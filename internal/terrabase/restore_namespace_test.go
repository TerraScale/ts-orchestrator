package terrabase

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRestoreNamespaceCommandIsolatesBeforeExec(t *testing.T) {
	command, err := restoreNamespaceCommand(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { command.ExtraFiles[0].Close() })
	if command.SysProcAttr == nil || command.SysProcAttr.Cloneflags != syscall.CLONE_NEWNET ||
		!slices.Equal(command.Args[1:], []string{"terrabase", "__restore-check"}) {
		t.Fatalf("helper is not isolated before exec: %+v", command)
	}
	if !slices.Equal(command.Env, []string{"HOME=/", "LANG=C", "PATH=/usr/bin:/bin"}) {
		t.Fatalf("helper inherited host credentials or networking configuration: %q", command.Env)
	}
	current, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", os.Getppid()))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(current, parent) {
		if err := runIsolatedRestoreCheck(t.Context(), strings.NewReader("{}"), io.Discard); err == nil ||
			!strings.Contains(err.Error(), "network namespace") {
			t.Fatalf("direct helper invocation bypassed isolation: %v", err)
		}
	}
}

// This process check needs no root or OCI: a user namespace grants permission
// to bring up only the child network namespace's loopback. The member's
// listeners and all readiness/admin/document traffic stay within that child.
func TestRestoreNamespaceHasOnlyLoopbackAndLocalTraffic(t *testing.T) {
	const namespaceStage = "TS_RESTORE_NAMESPACE_TEST_STAGE"
	if os.Getenv(namespaceStage) == "member" {
		interfaces, err := net.Interfaces()
		if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagUp == 0 {
			t.Fatalf("member exec inherited non-loopback networking: %+v, %v", interfaces, err)
		}
		return
	}
	if os.Getenv(namespaceStage) == "helper" {
		if err := enableRestoreLoopback(); err != nil {
			t.Fatal(err)
		}
		// An exec performed after loopback setup retains the isolated namespace.
		member := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
		member.Env = []string{namespaceStage + "=member"}
		if output, err := member.CombinedOutput(); err != nil {
			t.Fatalf("member exec: %v: %s", err, output)
		}
		hostClient := &http.Client{Transport: &http.Transport{}, Timeout: time.Second}
		if response, err := hostClient.Get(os.Getenv("TS_RESTORE_HOST_URL")); err == nil {
			response.Body.Close()
			t.Fatal("private namespace reached the host's loopback listener")
		}
		servers := restoreServers{readyStatus: http.StatusOK, keyStatus: http.StatusCreated, keySecret: "s3cret",
			docStatus: http.StatusOK, docID: "00000000000000000000000005"}
		if etag, err := servers.verify(t, 5*time.Second); err != nil || etag != `"v7"` {
			t.Fatalf("readiness/admin/document traffic in namespace: %q, %v", etag, err)
		}
		return
	}
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer host.Close()
	command, err := restoreNamespaceCommand(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { command.ExtraFiles[0].Close() })
	// Reuse production NEWNET launch; NEWUSER only grants this test's uid the
	// capability to create it without mounting or changing a real volume.
	command.Args = []string{command.Path, "-test.run=^" + t.Name() + "$", "-test.count=1", "-test.v"}
	command.Env = append(command.Env, namespaceStage+"=helper", "TS_RESTORE_HOST_URL="+host.URL)
	command.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER
	command.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
	command.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) {
			t.Skipf("kernel does not allow test user/network namespaces: %v", err)
		}
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("namespaced restore check: %v:\n%s", err, output.String())
	}
	t.Logf("namespaced restore check:\n%s", output.String())
}
