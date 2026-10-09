package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/brokerauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

const (
	bootstrapAdmissionTestUID = 1000
	bootstrapAdmissionTestGID = 1000
	bootstrapAdmissionCaps    = uint64(0xe3)
)

func TestControllerAdmissionSupervisorBoundsAndRoundTripsStrictConfig(t *testing.T) {
	directory := t.TempDir()
	wirePath := filepath.Join(directory, "child-config.json")
	environmentPath := filepath.Join(directory, "child-environment.txt")
	startedPath := filepath.Join(directory, "child-started")
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Fatal(err)
	}
	executable := writeAdmissionShell(t, fmt.Sprintf(`#!/bin/sh
set -eu
[ "$1" = "bootstrap-admit-initial" ] || exit 91
printf started > %s
%s > %s || exit 92
printf '%%s\n%%s\n%%s\n' "$PATH" "$LANG" "${OCI_CONFIG_FILE-unset}" > %s
`, shellQuote(startedPath), shellQuote(cat), shellQuote(wirePath), shellQuote(environmentPath)))

	t.Setenv("OCI_CONFIG_FILE", "must-not-be-inherited")
	want := Config{
		NATS: natscell.Config{Cell: "gru", Instance: "broker-a", Replicas: 3, CredentialsFile: "/var/lib/example/controller.creds"},
		Controller: ControllerConfig{CandidateID: "0000000000RTDFYAHDCP6Y401P", ArtifactStoreMaxBytes: 64 << 20,
			TrustedSigners: []TrustedSignerConfig{{Actor: "operator", PublicKey: "public-key", Roles: []string{"terrabase"}}},
			Workloads:      map[string]WorkloadProfile{"terrabase": {Args: []string{"-region", "gru"}, Env: map[string]string{"LOG_LEVEL": "debug"}}}},
	}
	if err := superviseControllerAdmission(t.Context(), want, "bootstrap-admit-initial", executable); err != nil {
		t.Fatalf("supervise bounded admission child: %v", err)
	}
	wire, err := os.ReadFile(wirePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) == 0 || len(wire) > maxConfigBytes {
		t.Fatalf("child config wire size = %d, want 1..%d", len(wire), maxConfigBytes)
	}
	var got Config
	if err := protocol.DecodeStrict(wire, &got, maxConfigBytes); err != nil {
		t.Fatalf("decode child config strictly: %v", err)
	}
	wantWire, err := protocol.EncodeJSON(want)
	if err != nil {
		t.Fatal(err)
	}
	gotWire, err := protocol.EncodeJSON(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, wantWire) || !bytes.Equal(gotWire, wire) {
		t.Fatalf("child config wire changed during strict round trip:\n got: %s\nwant: %s", gotWire, wantWire)
	}
	environment, err := os.ReadFile(environmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(environment) != "/usr/bin:/bin\nC\nunset\n" {
		t.Fatalf("child received unexpected environment: %q", environment)
	}

	tooLarge := want
	tooLarge.Controller.CandidateID = strings.Repeat("x", maxConfigBytes)
	if err := superviseControllerAdmission(t.Context(), tooLarge, "bootstrap-admit-initial", executable); err == nil {
		t.Fatal("oversized admission config reached child")
	}
	if _, err := os.Stat(startedPath); err != nil {
		t.Fatalf("bounded child did not run for valid config: %v", err)
	}
	if err := os.Remove(startedPath); err != nil {
		t.Fatal(err)
	}
	if err := superviseControllerAdmission(t.Context(), tooLarge, "bootstrap-admit-restart", executable); err == nil {
		t.Fatal("oversized restart config reached child")
	}
	if _, err := os.Stat(startedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversized config started admission child: %v", err)
	}
	if err := superviseControllerAdmission(t.Context(), want, "unknown-admission-command", executable); err == nil {
		t.Fatal("supervisor accepted an unknown admission command")
	}
}

// The admission child digests the signed config file's exact bytes, so a
// binary with new or defaulted members still matches the signed digest.
func TestControllerAdmissionChildReceivesTheLoadedBytes(t *testing.T) {
	directory := t.TempDir()
	wirePath := filepath.Join(directory, "child-config.json")
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Fatal(err)
	}
	executable := writeAdmissionShell(t, fmt.Sprintf("#!/bin/sh\n%s > %s\n", shellQuote(cat), shellQuote(wirePath)))
	signed := []byte(`{ "version": 1000, "nats": {"cell": "gru", "instance": "ctl-1"}, "added_by_newer_binary": true }`)
	configPath := filepath.Join(directory, "controller.json")
	if err := os.WriteFile(configPath, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := superviseControllerAdmission(t.Context(), cfg, "bootstrap-admit-restart", executable); err != nil {
		t.Fatal(err)
	}
	if wire, err := os.ReadFile(wirePath); err != nil || !bytes.Equal(wire, signed) {
		t.Fatalf("child config = %q, %v; want the signed bytes", wire, err)
	}
	if child, err := decodeConfig(signed); err != nil || child.NATS.Instance != "ctl-1" || controllerSHA256(child.wire) != controllerSHA256(signed) {
		t.Fatalf("child decoded %+v, %v", child, err)
	}
}

func TestControllerAdmissionChildRejectsInvalidOrOversizedStdin(t *testing.T) {
	for _, input := range []string{
		`{"nats":{},"unexpected":true}`,
		strings.Repeat(" ", maxConfigBytes+1),
	} {
		if err := runControllerAdmissionChild(t.Context(), "bootstrap-admit-initial", strings.NewReader(input)); err == nil {
			t.Fatal("admission child accepted invalid or oversized stdin")
		}
	}
}

func TestControllerAdmissionTimeoutStopsServiceUIDDescendant(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("service-UID process-group timeout requires the privileged test invocation")
	}
	if !bootstrapAdmissionCapabilitiesMatch(t, bootstrapAdmissionCaps) {
		t.Skip("run this process-group boundary under the bootstrap unit's exact five-capability set")
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Fatal(err)
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("/tmp", "ts-admission-process-group-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		os.RemoveAll(directory)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	servicePIDPath := filepath.Join(directory, "service-child.pid")
	markerPath := filepath.Join(directory, "service-child-survived")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
[ "$1" = "bootstrap-admit-initial" ] || exit 91
exec %s --reuid=%d --regid=%d --clear-groups -- /bin/sh -c 'printf "%%s\n" "$$" > %s; (%s 2; printf survived > %s) & wait'
`, shellQuote(setpriv), bootstrapAdmissionTestUID, bootstrapAdmissionTestGID, shellQuote(servicePIDPath), shellQuote(sleep), shellQuote(markerPath))
	executable := writeAdmissionShell(t, script)
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	err = superviseControllerAdmission(ctx, Config{NATS: natscell.Config{Cell: "gru"}}, "bootstrap-admit-initial", executable)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("short admission deadline returned %v, want deadline exceeded", err)
	}
	pidWire, err := os.ReadFile(servicePIDPath)
	if err != nil {
		t.Fatalf("service-UID descendant did not start before cancellation: %v", err)
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(string(pidWire)))
	if err != nil {
		t.Fatalf("parse service child pid %q: %v", pidWire, err)
	}
	time.Sleep(2200 * time.Millisecond)
	if _, err := os.Stat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("service-UID process group left a delayed marker: %v", err)
	}
	if state, err := processState(childPID); err == nil && state != 'Z' {
		t.Fatalf("service-UID descendant remains active after supervisor return: pid %d state %q", childPID, state)
	}
}

func TestHiddenAdmissionChildPrivilegeGatesInPrivateNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private NSS and /var/lib admission fixture requires the privileged test invocation")
	}
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
	env, err := exec.LookPath("env")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helperDirectory, err := os.MkdirTemp("/tmp", "ts-admission-gate-helper-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(helperDirectory); err != nil {
			t.Errorf("remove admission gate helper: %v", err)
		}
	})
	if err := os.Chmod(helperDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(helperDirectory, "app.test")
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, err := os.OpenFile(helper, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		_ = destination.Close()
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(helper, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "child-config.json")
	configWire, err := protocol.EncodeJSON(Config{NATS: natscell.Config{Cell: "gru"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configWire, 0o600); err != nil {
		t.Fatal(err)
	}
	script := `
set -eu
helper="$1"
config="$2"
mount_command="$3"
setpriv_command="$4"
mkdir_command="$5"
chmod_command="$6"
env_command="$7"
"$mount_command" --make-rprivate /
"$mount_command" -t tmpfs -o size=8m,mode=0755 tmpfs /etc
if [ -d /run/nscd ]; then "$mount_command" -t tmpfs -o size=1m,mode=0755 tmpfs /run/nscd; fi
printf 'root:x:0:0:root:/root:/sbin/nologin\nterrascale-orchestrator:x:1000:1000:service:/nonexistent:/sbin/nologin\nfixture-wrong:x:1001:1001:wrong:/nonexistent:/sbin/nologin\n' > /etc/passwd
printf 'root:x:0:\nterrascale-orchestrator:x:1000:\nfixture-wrong:x:1001:\n' > /etc/group
printf 'passwd: files\ngroup: files\n' > /etc/nsswitch.conf
"$chmod_command" 0644 /etc/passwd /etc/group /etc/nsswitch.conf
"$mkdir_command" -p /etc/terrascale-orchestrator/bootstrap
printf 'invalid fixture\n' > /etc/terrascale-orchestrator/bootstrap/identity.json
"$chmod_command" 0444 /etc/terrascale-orchestrator/bootstrap/identity.json
"$mount_command" -t tmpfs -o size=8m,mode=0755 tmpfs /var/lib
"$mkdir_command" -p /var/lib/terrascale-orchestrator-bootstrap
"$chmod_command" 0755 /var/lib/terrascale-orchestrator-bootstrap
run_case() {
  uid="$1"
  gid="$2"
  command_name="$3"
  expected="$4"
  if [ "$uid" = 0 ]; then
    TS_ADMISSION_GATE_HELPER=1 TS_ADMISSION_GATE_COMMAND="$command_name" TS_ADMISSION_GATE_EXPECT="$expected" TS_ADMISSION_GATE_CLOCK="${5-healthy}" "$helper" -test.run='^TestHiddenAdmissionGateChildHelper$' < "$config"
  else
    "$setpriv_command" --reuid="$uid" --regid="$gid" --clear-groups -- "$env_command" PATH=/usr/bin:/bin TS_ADMISSION_GATE_HELPER=1 TS_ADMISSION_GATE_COMMAND="$command_name" TS_ADMISSION_GATE_EXPECT="$expected" TS_ADMISSION_GATE_CLOCK="${5-healthy}" "$helper" -test.run='^TestHiddenAdmissionGateChildHelper$' < "$config"
  fi
}
run_case 1000 1000 bootstrap-admit-initial 'requires root'
run_case 0 0 bootstrap-admit-initial 'load fixed baked controller bootstrap inputs'
run_case 1001 1001 bootstrap-admit-restart 'requires the dedicated service account'
run_case 1000 1000 bootstrap-admit-restart 'load fixed baked controller bootstrap inputs'
run_case 0 0 bootstrap-admit-initial 'NTP clock health' unhealthy
run_case 1000 1000 bootstrap-admit-restart 'NTP clock health' unhealthy
`
	command := exec.CommandContext(t.Context(), unshare, "--mount", "--fork", "--", "/bin/sh", "-c", script,
		"ts-admission-namespace", helper, configPath, mount, setpriv, mkdir, chmod, env)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("private admission gate fixture failed: %v\n%s", err, output)
	}
}

func TestHiddenAdmissionGateChildHelper(t *testing.T) {
	if os.Getenv("TS_ADMISSION_GATE_HELPER") != "1" {
		return
	}
	priorClock := controllerBrokerClockProbe
	t.Cleanup(func() { controllerBrokerClockProbe = priorClock })
	clock := &fixedControllerClock{bound: brokerauth.ClockBound{SampledAt: time.Now(), MaxError: time.Millisecond}}
	if os.Getenv("TS_ADMISSION_GATE_CLOCK") == "unhealthy" {
		clock.err = errors.New("test NTP clock is unsynchronized")
	}
	controllerBrokerClockProbe = func() brokerauth.ClockProbe { return clock }
	commandName := os.Getenv("TS_ADMISSION_GATE_COMMAND")
	expected := os.Getenv("TS_ADMISSION_GATE_EXPECT")
	err := Run(t.Context(), []string{commandName}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatalf("hidden %s child error = %v, want %q", commandName, err, expected)
	}
}

func TestServiceCredentialChildChecksCredentialsAndTicketKeyAsServiceUser(t *testing.T) {
	if os.Getenv("TS_CREDENTIAL_CHILD_HELPER") == "1" {
		if err := Run(t.Context(), []string{"bootstrap-credential-check"}, io.Discard); err != nil {
			t.Fatalf("same-binary credential validation child: %v", err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("root-to-service credential process requires the privileged test invocation")
	}
	request, _, _, err := serviceCredentialChildFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	runChild := func() ([]byte, error) {
		command := exec.CommandContext(t.Context(), "/proc/self/exe", "-test.run=^TestServiceCredentialChildChecksCredentialsAndTicketKeyAsServiceUser$")
		command.Stdin = bytes.NewReader(wire)
		command.Env = []string{"PATH=/usr/bin:/bin", "TS_CREDENTIAL_CHILD_HELPER=1"}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid: bootstrapAdmissionTestUID, Gid: bootstrapAdmissionTestGID, Groups: []uint32{},
		}}
		return command.CombinedOutput()
	}
	if output, err := runChild(); err != nil {
		t.Fatalf("same-binary service credential child rejected valid material: %v\n%s", err, output)
	}
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := request.Config.Embedded.TicketPublicKeyFile
	if err := os.WriteFile(publicPath, []byte(base64.StdEncoding.EncodeToString(wrongPublic)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(publicPath, bootstrapAdmissionTestUID, bootstrapAdmissionTestGID); err != nil {
		t.Fatal(err)
	}
	if output, err := runChild(); err == nil || !strings.Contains(string(output), "pinned broker ticket key does not match") {
		t.Fatalf("service credential child did not reject mismatched ticket key: %v\n%s", err, output)
	}
}

func serviceCredentialChildFixture(t *testing.T) (bootstrapstart.CredentialChildRequest, string, ed25519.PublicKey, error) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "ts-service-credential-child-")
	if err != nil {
		return bootstrapstart.CredentialChildRequest{}, "", nil, err
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		return bootstrapstart.CredentialChildRequest{}, "", nil, err
	}
	operatorKey, err := nkeys.CreateOperator()
	if err != nil {
		return bootstrapstart.CredentialChildRequest{}, "", nil, err
	}
	systemKey, err := nkeys.CreateAccount()
	if err != nil {
		return bootstrapstart.CredentialChildRequest{}, "", nil, err
	}
	cellKey, err := nkeys.CreateAccount()
	if err != nil {
		return bootstrapstart.CredentialChildRequest{}, "", nil, err
	}
	operatorID, _ := operatorKey.PublicKey()
	systemID, _ := systemKey.PublicKey()
	cellID, _ := cellKey.PublicKey()
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	operatorClaim := jwt.NewOperatorClaims(operatorID)
	operatorClaim.SystemAccount = systemID
	operatorJWT, err := operatorClaim.Encode(operatorKey)
	if err != nil {
		return bootstrapstart.CredentialChildRequest{}, "", nil, err
	}
	systemJWT, err := jwt.NewAccountClaims(systemID).Encode(operatorKey)
	if err != nil {
		return bootstrapstart.CredentialChildRequest{}, "", nil, err
	}
	cellJWT, err := jwt.NewAccountClaims(cellID).Encode(operatorKey)
	if err != nil {
		return bootstrapstart.CredentialChildRequest{}, "", nil, err
	}
	operatorPath := write("operator.jwt", operatorJWT)
	systemPath := write("system.jwt", systemJWT)
	cellPath := write("cell.jwt", cellJWT)
	systemUserID, systemCredentials := testBrokerJWTUser(t, root, "system.creds", systemKey, systemID,
		[]string{"$SYS.REQ.ACCOUNT." + cellID + ".CLAIMS.UPDATE"}, nil)
	systemClaim, err := jwt.DecodeUserClaims(testDecoratedJWT(t, systemCredentials))
	if err != nil {
		return bootstrapstart.CredentialChildRequest{}, "", nil, err
	}
	systemClaim.Sub.Allow = jwt.StringList{"ts.orch.v1.gru.inbox." + systemUserID + ".>"}
	systemCredentials = testBrokerJWTUserWithClaim(t, root, "system.creds", systemKey, systemClaim)
	controllerUserID, controllerCredentials := testBrokerJWTUser(t, root, "controller.creds", cellKey, cellID,
		[]string{"ts.broker.gru.ticket.>", "ts.broker.gru.fence.>"},
		[]string{"ts.broker.gru.ticket.>", "ts.broker.gru.fence.broker-a", "ts.orch.v1.gru.broker.claim.apply",
			"ts.orch.v1.gru.agent.*.observation.*", "ts.orch.v1.gru.delivery.artifact.admit",
			"ts.orch.v1.gru.host.register", "ts.orch.v1.gru.placement.apply"})
	controllerClaim, err := jwt.DecodeUserClaims(testDecoratedJWT(t, controllerCredentials))
	if err != nil {
		return bootstrapstart.CredentialChildRequest{}, "", nil, err
	}
	controllerClaim.Sub.Allow = append(controllerClaim.Sub.Allow,
		"ts.orch.v1.gru.inbox."+controllerUserID+".>", "ts.orch.v1.gru.managed-update.prepare", "ts.orch.v1.gru.backup.operation", "ts.orch.v1.gru.terminal.>")
	controllerClaim.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}
	controllerCredentials = testBrokerJWTUserWithClaim(t, root, "controller.creds", cellKey, controllerClaim)
	tlsFiles, _ := testR3TLSMaterial(t, root)
	ticketPublic, _ := testEd25519(t, root, "ticket.key")
	responsePublic, _ := testEd25519(t, root, "response.key")
	_ = responsePublic
	ticketPublicPath := write("ticket.pub", base64.StdEncoding.EncodeToString(ticketPublic))
	request := bootstrapstart.CredentialChildRequest{
		Config: natscell.Config{Cell: "gru", Instance: "broker-a", Replicas: 1,
			CredentialsFile: controllerCredentials, TLS: tlsFiles,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: 4222, StoreDir: filepath.Join(root, "store"),
				TLS: tlsFiles, RouteTLS: tlsFiles, OperatorJWTFile: operatorPath, SystemJWTFile: systemPath,
				CellJWTFile: cellPath, SystemCredentialsFile: systemCredentials, TicketPublicKeyFile: ticketPublicPath,
				BrokerIDs: []string{"broker-a"}}},
		UID: bootstrapAdmissionTestUID, GID: bootstrapAdmissionTestGID,
		ResponseKeyFile: filepath.Join(root, "response.key"), BrokerTicketKeyFile: filepath.Join(root, "ticket.key"),
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return bootstrapstart.CredentialChildRequest{}, "", nil, err
	}
	for _, entry := range entries {
		if err := os.Chown(filepath.Join(root, entry.Name()), bootstrapAdmissionTestUID, bootstrapAdmissionTestGID); err != nil {
			return bootstrapstart.CredentialChildRequest{}, "", nil, err
		}
	}
	return request, root, ticketPublic, nil
}

func writeAdmissionShell(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admission-child.sh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func bootstrapAdmissionCapabilitiesMatch(t *testing.T, want uint64) bool {
	t.Helper()
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer file.Close()
	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if ok {
			values[key] = strings.TrimSpace(value)
		}
	}
	if err := scanner.Err(); err != nil || values["NoNewPrivs"] != "1" {
		return false
	}
	for _, key := range []string{"CapEff", "CapPrm", "CapBnd"} {
		got, err := strconv.ParseUint(values[key], 16, 64)
		if err != nil || got != want {
			return false
		}
	}
	return true
}

func processState(pid int) (rune, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	end := strings.LastIndex(string(data), ")")
	if end < 0 {
		return 0, errors.New("invalid process stat entry")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) == 0 || len(fields[0]) != 1 {
		return 0, errors.New("invalid process state field")
	}
	return rune(fields[0][0]), nil
}

var _ = ed25519.PrivateKeySize
