package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats.go"
)

const binary = "/usr/local/bin/terrascale-orchestrator"
const unit = "/etc/systemd/system/ts-orch.service"
const dropin = "/etc/systemd/system/ts-orch.service.d/90-e2e-release.conf"

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func command(args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("%v: %v: %s", args, err, out))
	}
	return strings.TrimSpace(string(out))
}

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func read(path string) []byte {
	data, err := os.ReadFile(path)
	check(err)
	return data
}

func encoded(value any) string {
	data, err := json.Marshal(value)
	check(err)
	return base64.RawURLEncoding.EncodeToString(data)
}

func run() {
	fd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_CLASS_CONTENT, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	check(err)
	check(unix.Close(fd))
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	check(err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "e2e-github"},
		DNSNames: []string{"github.com", "token.actions.githubusercontent.com"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	check(err)
	ca := "/var/lib/ts-orch/e2e-release-ca.pem"
	check(os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	var mu sync.RWMutex
	assets := map[string][]byte{}
	jwks, err := json.Marshal(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "alg": "RS256", "kid": "e2e",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
	check(err)
	proxy := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require(r.Method == http.MethodConnect, "expected HTTPS proxy CONNECT")
		conn, _, err := w.(http.Hijacker).Hijack()
		check(err)
		defer conn.Close()
		_, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		check(err)
		secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
		request, err := http.ReadRequest(bufio.NewReader(secure))
		check(err)
		mu.RLock()
		body := assets[request.URL.Path]
		mu.RUnlock()
		if request.URL.Path == "/.well-known/jwks" {
			body = jwks
		}
		status := http.StatusOK
		if body == nil {
			status = http.StatusNotFound
		}
		response := &http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Close: true,
			ContentLength: int64(len(body)), Body: io.NopCloser(bytes.NewReader(body))}
		check(response.Write(secure))
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	check(err)
	go func() { _ = proxy.Serve(listener) }()
	defer proxy.Close()

	original := read(binary)
	embeddedUnit := []byte(command(binary, "release", "unit") + "\n")
	originalUnit := bytes.ReplaceAll(embeddedUnit, []byte("TimeoutStartSec=5min"), []byte("TimeoutStartSec=10s "))
	originalUnit = bytes.ReplaceAll(originalUnit, []byte("TimeoutStopSec=180s"), []byte("TimeoutStopSec=1s  "))
	original = bytes.ReplaceAll(original, embeddedUnit, originalUnit)
	check(os.WriteFile(binary, original, 0o755))
	check(os.MkdirAll("/etc/systemd/system/ts-orch.service.d", 0o755))
	check(os.WriteFile(dropin, []byte(fmt.Sprintf("[Service]\nEnvironment=HTTPS_PROXY=http://%s SSL_CERT_FILE=%s\n", listener.Addr(), ca)), 0o644))
	oldUnit := bytes.Replace(originalUnit, []byte("StartLimitIntervalSec=10min"), []byte("StartLimitIntervalSec=30s"), 1)
	check(os.WriteFile(unit, oldUnit, 0o644))
	command("systemctl", "daemon-reload")
	info, err := buildinfo.ReadFile(binary)
	check(err)
	var revision string
	modified := false
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			revision = setting.Value
		}
		if setting.Key == "vcs.modified" {
			modified = setting.Value == "true"
		}
	}
	require(len(revision) == 40, "missing executable VCS revision")
	ready := func(action func()) {
		cursor := command("journalctl", "-n", "1", "--show-cursor", "--no-pager")
		cursor = strings.TrimSpace(strings.Split(cursor, "-- cursor: ")[1])
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		journal := exec.CommandContext(ctx, "journalctl", "-u", "ts-orch", "--after-cursor="+cursor, "-f", "-o", "cat")
		stdout, err := journal.StdoutPipe()
		check(err)
		check(journal.Start())
		defer func() { cancel(); _ = journal.Wait() }()

		action()
		deadline := time.Now().Add(time.Minute)
		var t struct {
			GuardAfter   time.Time
			StartTimeout time.Duration
		}
		if data, err := os.ReadFile("/var/lib/ts-orch/nats/release-trial"); err == nil {
			check(json.Unmarshal(data, &t))
			if !t.GuardAfter.IsZero() {
				deadline = t.GuardAfter.Add(2*time.Minute + t.StartTimeout)
			}
		}
		expiry := time.AfterFunc(time.Until(deadline), cancel)
		defer expiry.Stop()
		served := false
		lines := bufio.NewScanner(stdout)
		for lines.Scan() {
			if strings.Contains(lines.Text(), "ready; advertise") {
				served = true
				break
			}
		}
		require(served, "released or restored binary did not serve")
		require(command("systemctl", "is-active", "ts-orch") == "active", "unit is not active")
	}
	current := revision
	if modified {
		current += "-dirty"
	}
	invalidUnit := bytes.Replace(originalUnit, []byte("Description=TerraScale Orchestrator single host (milestone 1)"), []byte("Description=Trial"), 1)
	invalidUnit = bytes.Replace(invalidUnit, []byte("ExecStart="), []byte("ExecStart=relative/path "), 1)
	invalidUnit = append(invalidUnit, bytes.Repeat([]byte("\n"), len(originalUnit)-len(invalidUnit))...)
	check(os.WriteFile(binary, bytes.ReplaceAll(original, originalUnit, invalidUnit), 0o755))

	check(os.WriteFile(binary+".prev", original, 0o755))
	check(os.WriteFile("/var/lib/ts-orch/nats/release-trial", []byte(fmt.Sprintf(`{"sha":%q,"run_id":"0","starts":0}`, current)), 0o600))

	ready(func() { command("systemctl", "start", "--no-block", "ts-orch") })
	require(bytes.Equal(read(binary), original) && bytes.Equal(read(unit), oldUnit), "first-rollout verification failure did not retain the previous binary and unit")
	require(bytes.Equal(read(binary+".original.unit"), oldUnit), "refused first rollout did not preserve original unit")
	require(command("systemctl", "show", "ts-orch", "-p", "StartLimitIntervalUSec", "--value") == "30s", "refused first rollout changed loaded unit")
	fmt.Println("ok release: invalid first-rollout unit restores the binary already swapped by the binary-only installer")

	check(os.WriteFile(binary+".prev", original, 0o755))
	check(os.WriteFile("/var/lib/ts-orch/nats/release-trial", []byte(fmt.Sprintf(`{"sha":%q,"run_id":"0","starts":0}`, current)), 0o600))

	guardOutput, guardErr := exec.Command(binary, "release", "guard").CombinedOutput()
	require(guardErr != nil && strings.Contains(string(guardOutput), "missing its recovery deadline"), "guard accepted an unconverted binary-only handoff")
	require(command("systemctl", "is-active", "ts-orch") == "active", "guard stopped agent before first-rollout deadline conversion")
	fmt.Println("ok release: guard leaves a binary-only handoff running until its first-start deadline conversion")

	reconciled := atFilePermission("unit-installed", func(point, path string, pid int) bool {
		if point != "unit-installed" {
			return false
		}
		var t struct{ Starts int }
		check(json.Unmarshal(read("/var/lib/ts-orch/nats/release-trial"), &t))
		require(t.Starts == 0, "unit application restart consumed a trial start")
		return true
	})
	ready(func() { command("systemctl", "restart", "--no-block", "ts-orch") })
	require(<-reconciled == "unit-installed", "first rollout was not observed")
	require(command("systemctl", "show", "ts-orch", "-p", "StartLimitIntervalUSec", "--value") == "10min", "first updated binary did not activate its own unit")
	require(bytes.Equal(read(binary+".original.unit"), oldUnit), "first rollout did not preserve hand-made unit")
	require(command("systemctl", "is-enabled", "ts-orch-release-guard.timer") == "enabled", "guard timer not enabled")
	fmt.Println("ok release: first updated binary reconciles the unit left by a binary-only installer without consuming a trial start")
	check(os.WriteFile(unit, oldUnit, 0o644))
	command("systemctl", "daemon-reload")
	release := func(letter string, run int, mode string) []byte {
		sha := strings.Repeat(letter, 40)
		data := bytes.ReplaceAll(original, []byte("vcs.revision="+revision), []byte("vcs.revision="+sha))
		data = bytes.ReplaceAll(data, []byte("vcs.modified=true\n"), []byte("vcs.modified=fals\n"))

		candidate := originalUnit
		if mode == "verify" || mode == "start" || strings.HasPrefix(mode, "sandbox") || mode == "reboot" || mode == "crash:unit-staged" || mode == "crash:unit-installed" || mode == "guard-crash" {
			candidate = bytes.Replace(candidate, []byte("Description=TerraScale Orchestrator single host (milestone 1)"), []byte("Description=Trial"), 1)
			switch mode {
			case "verify":
				candidate = bytes.Replace(candidate, []byte("ExecStart="), []byte("ExecStart=relative/path "), 1)
			case "start", "reboot", "guard-crash":
				candidate = bytes.Replace(candidate, []byte("[Service]"), []byte("[Service]\nExecStartPre=/bin/sh -c 'exit 1'"), 1)
			case "sandbox-reboot-guard-crash":
				candidate = bytes.Replace(candidate, []byte("[Service]"), []byte("[Service]\nRestrictAddressFamilies=AF_INET AF_INET6"), 1)
			}
			require(len(candidate) <= len(originalUnit), "candidate unit exceeds embedded asset size")
			candidate = append(candidate, bytes.Repeat([]byte("\n"), len(originalUnit)-len(candidate))...)
			data = bytes.ReplaceAll(data, originalUnit, candidate)
		}
		url := releasepush.ReleaseURL(sha, strconv.Itoa(run), runtime.GOARCH)
		path := strings.TrimPrefix(url, "https://github.com")
		mu.Lock()
		clear(assets)
		assets[path] = data
		mu.Unlock()
		claims := map[string]any{"iss": "https://token.actions.githubusercontent.com", "aud": "ts-orch", "exp": time.Now().Add(time.Hour).Unix(),
			"nbf": time.Now().Add(-time.Minute).Unix(), "repository": "TerraScale/ts-orchestrator", "repository_owner": "TerraScale", "ref": "refs/heads/main",
			"sha": sha, "run_id": strconv.Itoa(run), "run_attempt": "1", "event_name": "push",
			"job_workflow_ref": "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main"}
		token := encoded(map[string]string{"alg": "RS256", "kid": "e2e"}) + "." + encoded(claims)
		digest := sha256.Sum256([]byte(token))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		check(err)
		token += "." + base64.RawURLEncoding.EncodeToString(signature)
		certificate, _ := pem.Decode(read("/var/lib/ts-orch/nats/tls.crt"))
		conn, err := nats.Connect("tls://127.0.0.1:4222", nats.Token(token), nats.CustomInboxPrefix(releasepush.Inbox(strconv.Itoa(run))),
			nats.Secure(&tls.Config{InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
				if !bytes.Equal(state.PeerCertificates[0].Raw, certificate.Bytes) {
					return fmt.Errorf("release listener certificate changed")
				}
				return nil
			}}))
		check(err)
		defer conn.Close()
		sum := sha256.Sum256(data)
		request, err := json.Marshal(releasepush.OrchRelease{SHA: sha, Token: token,
			Binaries: map[string]releasepush.Binary{runtime.GOARCH: {URL: url, SHA256: hex.EncodeToString(sum[:])}}})
		check(err)

		var failedRestore <-chan struct{}
		if mode == "sandbox-reboot-guard-crash" {
			failedRestore = observeFailedRestore()
		}
		var interrupted <-chan string
		if strings.HasPrefix(mode, "crash:") {
			interrupted = crashAt(strings.TrimPrefix(mode, "crash:"))
		} else if mode == "guard-crash" || mode == "sandbox-reboot-guard-crash" {
			interrupted = crashGuard()
		}

		send := func() {
			if mode == "slow" {
				command("systemctl", "stop", "ts-orch")
				command("ip", "addr", "add", "169.254.169.254/32", "dev", "lo")
				var metadataAfter time.Time
				metadata := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					require(request.Header.Get("Authorization") == "Bearer Oracle", "missing metadata authentication")
					if metadataAfter.IsZero() {
						metadataAfter = time.Now().Add(125 * time.Second)
					}
					values := map[string]string{"/opc/v2/instance/canonicalRegionName": "us-sanjose-1", "/opc/v2/instance/id": "instance"}
					if time.Now().Before(metadataAfter) {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					if request.URL.Path == "/opc/v2/vnics/" {
						check(json.NewEncoder(w).Encode([]map[string]string{{"privateIp": "127.0.0.1"}}))
						return
					}
					_, err := io.WriteString(w, values[request.URL.Path])
					check(err)
				})}
				metadataListener, err := net.Listen("tcp", "169.254.169.254:80")
				check(err)
				defer metadata.Close()
				command("systemctl", "start", "ts-orch")
				go func() { _ = metadata.Serve(metadataListener) }()
				check(os.WriteFile("/opt/firmware/chassis_asset_tag", []byte("OracleCloud.com\n"), 0o644))
				cert, err := x509.ParseCertificate(certificate.Bytes)
				check(err)
				pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
				region := releasepush.Region{Region: "sjc", NATS: "tls://127.0.0.1:4222", SPKISHA256: hex.EncodeToString(pin[:])}
				var progress bytes.Buffer
				result := releasepush.PushRegion(context.Background(), region, releasepush.OrchRelease{SHA: sha, Token: token, Binaries: map[string]releasepush.Binary{runtime.GOARCH: {URL: url, SHA256: hex.EncodeToString(sum[:])}}}, &progress)
				require(result.Error == "" && result.ServingMS >= 120000, fmt.Sprintf("slow release failed: %+v", result))
				require(strings.Contains(progress.String(), "accepted, still in probation until ") && !strings.Contains(progress.String(), "rolled_back"), "pusher did not report probation truthfully")
				fmt.Println("ok release: slow planning crossed 120s; pusher reported accepted, still in probation until <time>, then success")
				return
			}
			message, err := conn.Request(releasepush.SubjectOrch, request, 30*time.Second)

			if strings.HasPrefix(mode, "crash:") {
				select {
				case point := <-interrupted:
					require(point == strings.TrimPrefix(mode, "crash:"), "did not kill requested release boundary: "+point)
				case <-time.After(30 * time.Second):
					panic("release did not reach requested crash point")
				}
				return
			}
			check(err)
			var reply releasepush.Reply
			check(json.Unmarshal(message.Data, &reply))

			if mode == "verify" {
				require(reply.State == "rejected" && strings.Contains(reply.Error, "verify release units"), fmt.Sprintf("invalid unit was not refused by verifier: %+v", reply))
			} else {
				require(reply.State == "installed" && !reply.Deadline.IsZero(), fmt.Sprintf("release refused: %+v", reply))
			}

			if mode == "reboot" || mode == "sandbox-reboot-guard-crash" {
				if failedRestore != nil {
					expiry := time.NewTimer(time.Until(reply.Deadline))
					defer expiry.Stop()
					select {
					case <-failedRestore:
					case <-expiry.C:
						panic("sandbox did not attempt fast restoration before its guard deadline")
					}
				}
				command("systemctl", "stop", "ts-orch", "ts-orch-release-guard.timer", "ts-orch-release-guard.service", "containerd")
				command("systemctl", "start", "ts-orch-release-guard.timer")
			}
		}
		if mode == "verify" {
			send()
		} else {
			ready(send)
		}

		if mode == "guard-crash" || mode == "sandbox-reboot-guard-crash" {
			require(<-interrupted == "restoring", "guard was not killed while restoring")
		}
		return data
	}
	release("a", 1, "")
	require(command("systemctl", "show", "ts-orch", "-p", "StartLimitIntervalUSec", "--value") == "10min", "new unit setting was not loaded")
	require(bytes.Equal(read(binary+".prev.unit"), oldUnit), "previous unit was not retained")
	fmt.Println("ok release: previous start limit replaced in the service manager")
	before, err := os.Stat(unit)
	check(err)
	reloads := command("systemctl", "show", "-p", "UnitsLoadFinishTimestampMonotonic", "--value")
	previous := release("b", 2, "")
	after, err := os.Stat(unit)
	check(err)
	require(os.SameFile(before, after) && before.ModTime() == after.ModTime(), "matching unit was rewritten")
	require(command("systemctl", "show", "-p", "UnitsLoadFinishTimestampMonotonic", "--value") == reloads, "matching unit reloaded manager")
	fmt.Println("ok release: matching unit changes neither inode, mtime nor manager reload timestamp")

	for index, phase := range []string{"intent", "unit-staged", "unit-installed", "binary-swapped"} {
		next := release(strconv.Itoa(index+1), 3+index, "crash:"+phase)
		if phase == "binary-swapped" {
			previous = next
		}
		require(bytes.Equal(read(binary), previous) && bytes.Equal(read(unit), originalUnit), "phase crash did not restore pair: "+phase)
		require(command("systemctl", "show", "ts-orch", "-p", "StartLimitIntervalUSec", "--value") == "10min", "phase crash did not restore loaded properties")
		require(command("systemctl", "is-active", "ts-orch") == "active", "phase crash left agent stopped")
		fmt.Println("ok release: kill at " + phase + " repaired on next start; unit, binary, properties and agent verified")
	}

	families := command("systemctl", "show", "ts-orch", "-p", "RestrictAddressFamilies", "--value")
	verifyBefore := read(binary)
	verifyUnit := read(unit)
	release("c", 7, "verify")
	require(bytes.Equal(read(binary), verifyBefore) && bytes.Equal(read(unit), verifyUnit), "verification failure changed installed files")
	require(command("systemctl", "is-active", "ts-orch") == "active", "verification failure stopped agent")
	require(command("systemctl", "show", "ts-orch", "-p", "StartLimitIntervalUSec", "--value") == "10min", "verification failure changed loaded unit")
	fmt.Println("ok release: verification failure refused with unchanged unit, binary and loaded properties")
	release("d", 8, "start")
	require(bytes.Equal(read(binary), previous) && bytes.Equal(read(unit), originalUnit), "guard did not restore binary and unit together")
	require(command("systemctl", "show", "ts-orch", "-p", "ExecStartPre", "--value") == "", "failed prestart remains loaded")
	var rollback releasepush.Rollback
	check(json.Unmarshal(read("/var/lib/ts-orch/nats/release-rolled-back"), &rollback))
	require(rollback.SHA == strings.Repeat("d", 40) && strings.Contains(rollback.Reason, "guard deadline"), "unstartable agent was not restored by independent guard")
	require(bytes.Equal(read(dropin), []byte(fmt.Sprintf("[Service]\nEnvironment=HTTPS_PROXY=http://%s SSL_CERT_FILE=%s\n", listener.Addr(), ca))), "release changed drop-ins")
	fmt.Println("ok release: independent timer restores a verified unit whose ExecStartPre prevents every new agent start")
	release("e", 9, "sandbox-reboot-guard-crash")
	require(bytes.Equal(read(binary), previous) && bytes.Equal(read(unit), originalUnit), "sandbox failure did not restore pair")
	require(command("systemctl", "show", "ts-orch", "-p", "RestrictAddressFamilies", "--value") == families, "failed socket sandbox remains loaded")
	check(json.Unmarshal(read("/var/lib/ts-orch/nats/release-rolled-back"), &rollback))
	require(rollback.SHA == strings.Repeat("e", 40) && strings.Contains(rollback.Reason, "guard deadline"), "sandbox restoration did not use guard")
	require(command("systemctl", "is-active", "ts-orch") == "active", "restored agent is not running")
	require(bytes.Equal(read(binary+".original.unit"), oldUnit), "later releases replaced hand-made unit backup")
	fmt.Println("ok release: independent timer repairs a sandbox that blocks in-process root restoration")
	fmt.Println("ok release: guard interrupted after unit restore finishes from retained backups on the next timer activation")
	fmt.Println("ok release: reboot-equivalent stop of agent, runtime and guard resumes recovery from the boot timer")

	command("systemctl", "stop", "ts-orch")
	check(os.WriteFile(unit, originalUnit, 0o644))
	command("systemctl", "daemon-reload")
	_ = os.Remove("/var/lib/ts-orch/nats/release-rolled-back")
	ready(func() { command("systemctl", "start", "--no-block", "ts-orch") })
	require(bytes.Equal(read(binary), previous) && bytes.Equal(read(unit), originalUnit), "previous binary cannot start under candidate unit")
	require(command("systemctl", "show", "ts-orch", "-p", "TimeoutStartUSec", "--value") == "10s", "candidate timeout not loaded")
	fmt.Println("ok release: previous binary starts under the candidate unit")
	slow := release("5", 12, "slow")
	require(bytes.Equal(read(binary), slow) && bytes.Equal(read(unit), originalUnit), "slow good release was replaced")
	require(command("systemctl", "is-active", "ts-orch") == "active", "slow good agent stopped")
	require(command("systemctl", "show", "ts-orch", "-p", "TimeoutStartUSec", "--value") == "10s", "slow release changed loaded unit")
	_, err = os.Stat("/var/lib/ts-orch/nats/release-trial")
	require(os.IsNotExist(err), "slow good release stayed on probation")
	_, err = os.Stat("/var/lib/ts-orch/nats/release-rolled-back")
	require(os.IsNotExist(err), "slow good release rolled back")
	fmt.Println("ok release: slow good release retained unit and binary, confirmed probation, and remains running")

}

func stopReleaseProcesses(agent int) {
	_ = syscall.Kill(agent, syscall.SIGKILL)
	entries, err := os.ReadDir("/proc")
	check(err)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err == nil && bytes.Contains(data, []byte("release\x00unit\x00install\x00")) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

func observeFailedRestore() <-chan struct{} {
	done := make(chan struct{})
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	check(err)
	_, err = syscall.InotifyAddWatch(fd, "/var/lib/ts-orch/nats", syscall.IN_MOVED_TO)
	check(err)
	go func() {
		defer syscall.Close(fd)
		buffer := make([]byte, 4096)
		for {
			_, err := syscall.Read(fd, buffer)
			check(err)
			data, err := os.ReadFile("/var/lib/ts-orch/nats/release-trial")
			if os.IsNotExist(err) {
				continue
			}
			check(err)
			var t struct {
				RestoreFailed bool
				Starts        int
			}
			check(json.Unmarshal(data, &t))
			if t.RestoreFailed && t.Starts == 3 {
				close(done)
				return
			}
		}
	}()
	return done
}

func crashAt(phase string) <-chan string {
	agent, err := strconv.Atoi(command("systemctl", "show", "ts-orch", "-p", "MainPID", "--value"))
	check(err)
	return atFilePermission(phase, func(point, path string, pid int) bool {
		if point != phase {
			return false
		}
		require(pid > 1, "invalid fault target")
		_ = syscall.Kill(pid, syscall.SIGKILL)
		stopReleaseProcesses(agent)
		return true
	})
}

func crashGuard() <-chan string {
	return atFilePermission("restoring", func(point, path string, pid int) bool {
		if point != "restoring" || path != binary+".prev" {
			return false
		}
		var t struct {
			RestoreFailed bool
			Starts        int
		}
		check(json.Unmarshal(read("/var/lib/ts-orch/nats/release-trial"), &t))
		require(t.RestoreFailed && t.Starts == 3, "sandbox did not defer a failed fast restoration to the guard")
		require(pid > 1, "invalid guard fault target")
		check(syscall.Kill(pid, syscall.SIGKILL))
		return true
	})
}

func atFilePermission(phase string, crash func(string, string, int) bool) <-chan string {
	done := make(chan string, 1)
	fd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_CLASS_CONTENT, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	check(err)
	for _, directory := range []string{filepath.Dir(binary), filepath.Dir(unit)} {
		check(unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_OPEN_PERM|unix.FAN_OPEN_EXEC_PERM|unix.FAN_EVENT_ON_CHILD|unix.FAN_ONDIR, unix.AT_FDCWD, directory))
	}
	go func() {
		defer unix.Close(fd)
		buffer := make([]byte, 4096)
		for {
			n, err := unix.Read(fd, buffer)
			if err != nil {
				done <- err.Error()
				return
			}
			for offset := 0; offset+unix.FAN_EVENT_METADATA_LEN <= n; {
				event := *(*unix.FanotifyEventMetadata)(unsafe.Pointer(&buffer[offset]))
				offset += int(event.Event_len)
				if event.Fd < 0 {
					continue
				}
				path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", event.Fd))
				check(err)
				var t struct{ Phase string }
				data, err := os.ReadFile("/var/lib/ts-orch/nats/release-trial")
				hit := err == nil && json.Unmarshal(data, &t) == nil && crash(t.Phase, path, int(event.Pid))
				response := unix.FanotifyResponse{Fd: event.Fd, Response: unix.FAN_ALLOW}
				_, err = unix.Write(fd, unsafe.Slice((*byte)(unsafe.Pointer(&response)), int(unsafe.Sizeof(response))))
				if err != nil && !(hit && errors.Is(err, unix.ENOENT)) {
					check(err)
				}
				check(unix.Close(int(event.Fd)))
				if hit {
					done <- phase
					return
				}
			}
		}
	}()
	return done
}

func main() {
	defer func() {
		if failure := recover(); failure != nil {
			fmt.Fprintln(os.Stderr, failure)
			output, _ := exec.Command("journalctl", "-u", "ts-orch", "-u", "ts-orch-release-guard", "--no-pager", "-n", "80").CombinedOutput()
			fmt.Fprintln(os.Stderr, string(output))
			os.Exit(1)
		}
	}()
	run()
}
