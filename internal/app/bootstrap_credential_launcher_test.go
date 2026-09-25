package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/brokerauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// TestMain gives the test executable the same hidden-command dispatch as the
// production binary. Both callers below use the real /proc/self/exe path.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && (os.Args[1] == "bootstrap-credential-check" || os.Args[1] == "bootstrap-admit-restart") {
		command := os.Args[1]
		if command == "bootstrap-credential-check" {
			block := credentialDelayPath(os.Getppid())
			if _, err := os.Stat(block); err == nil {
				_ = os.WriteFile(block+".entered", []byte(strconv.Itoa(os.Getpid())), 0o600)
				time.Sleep(30 * time.Second)
			}
		} else {
			clock := &fixedControllerClock{bound: brokerauth.ClockBound{SampledAt: time.Now(), MaxError: time.Millisecond}}
			controllerBrokerClockProbe = func() brokerauth.ClockProbe { return clock }
		}
		err := Run(context.Background(), os.Args[1:], io.Discard)
		if command == "bootstrap-admit-restart" {
			_ = os.WriteFile(hiddenAdmissionPath(os.Getppid()), []byte(fmt.Sprint(err)), 0o600)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func credentialDelayPath(parentPID int) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("ts-credential-delay-%d", parentPID))
}

func hiddenAdmissionPath(parentPID int) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("ts-hidden-admission-%d", parentPID))
}

func TestDefaultLiveCredentialLauncherAndDeadline(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("default root-to-service credential launcher requires root")
	}
	if os.Getenv("TS_LIVE_CREDENTIAL_NAMESPACE") != "1" {
		runCredentialNamespace(t)
		return
	}
	request, source, _, err := serviceCredentialChildFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	request, expected := installCredentialFixture(t, request, source)
	check, err := bootstrapstart.NewLiveCredentialChecker(request.Config, request.UID, request.GID,
		request.ResponseKeyFile, request.BrokerTicketKeyFile, func() error {
			return errors.New("root caller must validate controller keys through the service child")
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := check.VerifyLiveCredentials(t.Context(), expected); err != nil {
		t.Fatalf("default /proc/self/exe service child rejected valid credentials: %v", err)
	}

	block := credentialDelayPath(os.Getpid())
	if err := os.WriteFile(block, []byte("block the hidden child"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(block)
		_ = os.Remove(block + ".entered")
	})
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	start := time.Now()
	err = check.VerifyLiveCredentials(ctx, expected)
	elapsed := time.Since(start)
	if !errors.Is(err, bootstrapstart.ErrLiveCredentials) || elapsed < 14*time.Second || elapsed > 22*time.Second {
		t.Fatalf("default service child deadline = %v after %s, want 15-second refusal", err, elapsed)
	}
	childWire, err := os.ReadFile(block + ".entered")
	if err != nil {
		t.Fatalf("timed child never entered the hidden command: %v", err)
	}
	childPID, err := strconv.Atoi(string(childWire))
	if err != nil {
		t.Fatalf("invalid timed child PID %q: %v", childWire, err)
	}
	if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(childPID))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("timed service child PID %d remains after launcher return: %v", childPID, err)
	}
}

func runCredentialNamespace(t *testing.T) {
	t.Helper()
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Fatal(err)
	}
	mount, err := exec.LookPath("mount")
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const script = `set -eu
"$1" --make-rprivate /
"$1" -t tmpfs -o size=16m,mode=0755 tmpfs /var/lib
TS_LIVE_CREDENTIAL_NAMESPACE=1 "$2" -test.v -test.run='^TestDefaultLiveCredentialLauncherAndDeadline$'
`
	command := exec.CommandContext(t.Context(), unshare, "--mount", "--fork", "--", "/bin/sh", "-c", script,
		"ts-live-credential-namespace", mount, self)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("private default credential launcher fixture: %v\n%s", err, output)
	}
}

func installCredentialFixture(t *testing.T, request bootstrapstart.CredentialChildRequest,
	source string,
) (bootstrapstart.CredentialChildRequest, map[string]string) {
	t.Helper()
	if err := os.Mkdir(bootstrapstart.MaterialDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(bootstrapstart.MaterialDirectory, int(request.UID), int(request.GID)); err != nil {
		t.Fatal(err)
	}
	expected := make(map[string]string)
	install := func(path string) string {
		if path == "" {
			return ""
		}
		if filepath.Dir(path) != source {
			t.Fatalf("credential source escaped fixture: %s", path)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(path)
		digest := sha256.Sum256(content)
		want := hex.EncodeToString(digest[:])
		if previous, ok := expected[name]; ok {
			if previous != want {
				t.Fatalf("credential fixture reused filename %s with different bytes", name)
			}
			return filepath.Join(bootstrapstart.MaterialDirectory, name)
		}
		target := filepath.Join(bootstrapstart.MaterialDirectory, name)
		if err := os.WriteFile(target, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(target, int(request.UID), int(request.GID)); err != nil {
			t.Fatal(err)
		}
		expected[name] = want
		return target
	}
	request.Config.CredentialsFile = install(request.Config.CredentialsFile)
	request.Config.TLS.CAFile = install(request.Config.TLS.CAFile)
	request.Config.TLS.CertFile = install(request.Config.TLS.CertFile)
	request.Config.TLS.KeyFile = install(request.Config.TLS.KeyFile)
	request.Config.Embedded.TLS.CAFile = install(request.Config.Embedded.TLS.CAFile)
	request.Config.Embedded.TLS.CertFile = install(request.Config.Embedded.TLS.CertFile)
	request.Config.Embedded.TLS.KeyFile = install(request.Config.Embedded.TLS.KeyFile)
	request.Config.Embedded.RouteTLS.CAFile = install(request.Config.Embedded.RouteTLS.CAFile)
	request.Config.Embedded.RouteTLS.CertFile = install(request.Config.Embedded.RouteTLS.CertFile)
	request.Config.Embedded.RouteTLS.KeyFile = install(request.Config.Embedded.RouteTLS.KeyFile)
	request.Config.Embedded.OperatorJWTFile = install(request.Config.Embedded.OperatorJWTFile)
	request.Config.Embedded.SystemJWTFile = install(request.Config.Embedded.SystemJWTFile)
	request.Config.Embedded.CellJWTFile = install(request.Config.Embedded.CellJWTFile)
	request.Config.Embedded.SystemCredentialsFile = install(request.Config.Embedded.SystemCredentialsFile)
	request.Config.Embedded.TicketPublicKeyFile = install(request.Config.Embedded.TicketPublicKeyFile)
	request.Config.Embedded.RoutePasswordFile = install(request.Config.Embedded.RoutePasswordFile)
	request.ResponseKeyFile = install(request.ResponseKeyFile)
	request.BrokerTicketKeyFile = install(request.BrokerTicketKeyFile)
	return request, expected
}

func TestPublicControllerRunRejectsBeforeNATSThroughSameBinaryAdmission(t *testing.T) {
	if os.Getenv("TS_PUBLIC_RUN_NAMESPACE") == "1" {
		clock := &fixedControllerClock{bound: brokerauth.ClockBound{SampledAt: time.Now(), MaxError: time.Millisecond}}
		controllerBrokerClockProbe = func() brokerauth.ClockProbe { return clock }
		marker := hiddenAdmissionPath(os.Getpid())
		defer os.Remove(marker)
		err := Run(t.Context(), []string{"run", "--config", os.Getenv("TS_PUBLIC_RUN_CONFIG")}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "controller admission child failed") ||
			strings.Contains(err.Error(), "embedded regional NATS") {
			t.Fatalf("public controller run bypassed pre-NATS admission: %v", err)
		}
		proof, err := os.ReadFile(marker)
		if err != nil || !strings.Contains(string(proof), "load fixed baked controller bootstrap inputs") {
			t.Fatalf("same-binary hidden admission was not reached: proof %q, %v", proof, err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("service-account public controller caller requires a private root fixture")
	}
	runPublicControllerNamespace(t)
}

func runPublicControllerNamespace(t *testing.T) {
	t.Helper()
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Fatal(err)
	}
	mount, err := exec.LookPath("mount")
	if err != nil {
		t.Fatal(err)
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Fatal(err)
	}
	mkdir, err := exec.LookPath("mkdir")
	if err != nil {
		t.Fatal(err)
	}
	chmod, err := exec.LookPath("chmod")
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/tmp", "ts-public-controller-run-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "controller.json")
	wire, err := protocol.EncodeJSON(Config{NATS: natscell.Config{Cell: "gru"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, wire, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	const script = `set -eu
"$1" --make-rprivate /
"$1" -t tmpfs -o size=8m,mode=0755 tmpfs /etc
if [ -d /run/nscd ]; then "$1" -t tmpfs -o size=1m,mode=0755 tmpfs /run/nscd; fi
printf 'root:x:0:0:root:/root:/sbin/nologin\nterrascale-orchestrator:x:1000:1000:service:/nonexistent:/sbin/nologin\n' > /etc/passwd
printf 'root:x:0:\nterrascale-orchestrator:x:1000:\n' > /etc/group
printf 'passwd: files\ngroup: files\n' > /etc/nsswitch.conf
"$1" -t tmpfs -o size=8m,mode=0755 tmpfs /var/lib
"$3" -p /etc/terrascale-orchestrator/bootstrap
printf 'invalid fixture\n' > /etc/terrascale-orchestrator/bootstrap/identity.json
"$4" 0444 /etc/terrascale-orchestrator/bootstrap/identity.json
"$2" --nnp --bounding-set=-all --reuid=1000 --regid=1000 --clear-groups -- "$5" -test.v -test.run='^TestPublicControllerRunRejectsBeforeNATSThroughSameBinaryAdmission$'
`
	command := exec.CommandContext(t.Context(), unshare, "--mount", "--fork", "--", "/bin/sh", "-c", script,
		"ts-public-controller-namespace", mount, setpriv, mkdir, chmod, self)
	command.Env = append(os.Environ(), "TS_PUBLIC_RUN_NAMESPACE=1", "TS_PUBLIC_RUN_CONFIG="+configPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("public Run through private same-binary admission: %v\n%s", err, output)
	}
}
