package terrabase

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type isolatedRestoreRequest struct {
	Layout       Layout
	Check        restoreCheckRequest
	Organization string
	Wait         time.Duration
}

// restoreNamespaceCommand creates the namespace before exec: TerraBase can
// never bind a host interface, even during startup. The helper performs every
// HTTP request inside that same namespace; no Go thread switches namespaces.
func restoreNamespaceCommand(ctx context.Context) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	hostNetwork, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, executable, "terrabase", "__restore-check")
	command.ExtraFiles = []*os.File{hostNetwork}
	command.Env = []string{"HOME=/", "LANG=C", "PATH=/usr/bin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 50 * time.Second // Member shutdown is bounded at 45 seconds.
	return command, nil
}

func checkRestoreInNamespace(ctx context.Context, layout Layout, request restoreCheckRequest) (string, error) {
	wire, err := json.Marshal(isolatedRestoreRequest{layout, request, request.organization, request.wait})
	if err != nil {
		return "", err
	}
	command, err := restoreNamespaceCommand(ctx)
	if err != nil {
		return "", err
	}
	defer command.ExtraFiles[0].Close()
	command.Stdin, command.Stderr = bytes.NewReader(wire), os.Stderr
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("isolated restore-check: %w", err)
	}
	var etag string
	if err := json.Unmarshal(output, &etag); err != nil {
		return "", fmt.Errorf("isolated restore-check result: %w", err)
	}
	return etag, nil
}

// runIsolatedRestoreCheck is a private same-binary helper. Direct invocation
// in the caller's namespace fails before starting or reading the database.
func runIsolatedRestoreCheck(ctx context.Context, input io.Reader, output io.Writer) error {
	if err := enableRestoreLoopback(); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(input, restoreBodyLimit+1))
	if err != nil || len(data) > restoreBodyLimit {
		return errors.New("invalid isolated restore-check request")
	}
	var payload isolatedRestoreRequest
	if err := json.Unmarshal(data, &payload); err != nil || payload.Layout == "" {
		return errors.New("invalid isolated restore-check request")
	}
	r := payload.Check
	request, err := resolveRestoreCheck(r.Binary, payload.Organization, r.Document, r.ScratchInstance, r.RestoredVolume, r.ReadyPath, payload.Wait, true)
	if err != nil {
		return err
	}
	if _, err := VerifyRelease(request.Binary, request.Binary+".sha256"); err != nil {
		return err
	}
	etag, err := checkRestoreMember(ctx, payload.Layout, request)
	if err == nil {
		wire, marshalErr := json.Marshal(etag)
		if marshalErr != nil {
			return marshalErr
		}
		_, err = fmt.Fprintf(output, "%s\n", wire)
	}
	return err
}

func enableRestoreLoopback() error {
	// The parent opens its namespace before clone and passes it as FD 3.
	// Reading /proc/<parent>/ns/net is denied inside a test user namespace.
	link, err := os.Readlink("/proc/self/fd/3")
	if err != nil || !strings.HasPrefix(link, "net:[") {
		return errors.New("restore-check helper requires an inherited network namespace descriptor")
	}
	hostNetwork := os.NewFile(3, "host-network-namespace")
	defer hostNetwork.Close()
	current, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return err
	}
	parent, err := hostNetwork.Stat()
	if err != nil {
		return err
	}
	if os.SameFile(current, parent) {
		return errors.New("restore-check helper requires a new network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	if len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagLoopback == 0 {
		return errors.New("restore-check namespace must contain only loopback")
	}
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(socket)
	loopback, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(socket, unix.SIOCGIFFLAGS, loopback); err != nil {
		return err
	}
	loopback.SetUint16(loopback.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(socket, unix.SIOCSIFFLAGS, loopback)
}
