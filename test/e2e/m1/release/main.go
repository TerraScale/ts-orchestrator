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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

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

func main() {
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
	original, originalUnit := read(binary), read(unit)
	check(os.MkdirAll("/etc/systemd/system/ts-orch.service.d", 0o755))
	check(os.WriteFile(dropin, []byte(fmt.Sprintf("[Service]\nEnvironment=HTTPS_PROXY=http://%s SSL_CERT_FILE=%s\n", listener.Addr(), ca)), 0o644))
	defer func() {
		command("systemctl", "stop", "ts-orch")
		check(os.WriteFile(binary, original, 0o755))
		check(os.WriteFile(unit, originalUnit, 0o644))
		check(os.Remove(dropin))
		command("systemctl", "daemon-reload")
		command("systemctl", "start", "ts-orch")
		check(os.Remove(ca))
		for _, path := range []string{binary + ".prev", binary + ".prev.unit", "/var/lib/ts-orch/nats/release-run-id", "/var/lib/ts-orch/nats/release-rolled-back"} {
			if err := os.Remove(path); !errors.Is(err, os.ErrNotExist) {
				check(err)
			}
		}
	}()
	oldUnit := bytes.Replace(originalUnit, []byte("StartLimitIntervalSec=0"), []byte("StartLimitIntervalSec=30s"), 1)
	check(os.WriteFile(unit, oldUnit, 0o644))
	command("systemctl", "daemon-reload")
	command("systemctl", "restart", "ts-orch")
	require(command("systemctl", "show", "ts-orch", "-p", "StartLimitIntervalUSec", "--value") == "30s", "previous unit is not active")
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
		cursor := command("journalctl", "-u", "ts-orch", "-n", "1", "--show-cursor", "--no-pager")
		cursor = strings.TrimSpace(strings.Split(cursor, "-- cursor: ")[1])
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		journal := exec.CommandContext(ctx, "journalctl", "-u", "ts-orch", "--after-cursor="+cursor, "-f", "-o", "cat")
		stdout, err := journal.StdoutPipe()
		check(err)
		check(journal.Start())
		defer func() { cancel(); _ = journal.Wait() }()
		action()
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
	check(os.WriteFile("/var/lib/ts-orch/nats/release-trial", []byte(fmt.Sprintf(`{"sha":%q,"run_id":"0","starts":0}`, current)), 0o600))
	ready(func() { command("systemctl", "restart", "--no-block", "ts-orch") })
	require(command("systemctl", "show", "ts-orch", "-p", "StartLimitIntervalUSec", "--value") == "0", "first updated binary did not activate its own unit")
	fmt.Println("ok release: first updated binary reconciles the unit left by a binary-only installer")
	check(os.WriteFile(unit, oldUnit, 0o644))
	command("systemctl", "daemon-reload")
	release := func(letter string, run int, fail bool) []byte {
		sha := strings.Repeat(letter, 40)
		data := bytes.ReplaceAll(original, []byte("vcs.revision="+revision), []byte("vcs.revision="+sha))
		data = bytes.ReplaceAll(data, []byte("vcs.modified=true\n"), []byte("vcs.modified=fals\n"))
		if fail {
			from := []byte("# Root: the containerd executor, the :80/:443 edge, the :4222 firewall rule and data-dir chown need it.")
			to := []byte("TemporaryFileSystem=/run/containerd")
			require(bytes.Contains(data, from), "missing unit failure insertion point")
			data = bytes.ReplaceAll(data, from, append(to, bytes.Repeat([]byte(" "), len(from)-len(to))...))
		}
		url := releasepush.ReleaseURL(sha, strconv.Itoa(run), runtime.GOARCH)
		path := strings.TrimPrefix(url, "https://github.com")
		mu.Lock()
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
		ready(func() {
			message, err := conn.Request(releasepush.SubjectOrch, request, 30*time.Second)
			check(err)
			var reply releasepush.Reply
			check(json.Unmarshal(message.Data, &reply))
			require(reply.State == "installed", fmt.Sprintf("release refused: %+v", reply))
		})
		return data
	}
	release("a", 1, false)
	require(command("systemctl", "show", "ts-orch", "-p", "StartLimitIntervalUSec", "--value") == "0", "new unit setting was not loaded")
	require(bytes.Equal(read(binary+".prev.unit"), oldUnit), "previous unit was not retained")
	fmt.Println("ok release: previous start limit replaced in the service manager")
	before, err := os.Stat(unit)
	check(err)
	reloads := command("systemctl", "show", "-p", "UnitsLoadFinishTimestampMonotonic", "--value")
	previous := release("b", 2, false)
	after, err := os.Stat(unit)
	check(err)
	require(os.SameFile(before, after) && before.ModTime() == after.ModTime(), "matching unit was rewritten")
	require(command("systemctl", "show", "-p", "UnitsLoadFinishTimestampMonotonic", "--value") == reloads, "matching unit reloaded manager")
	fmt.Println("ok release: matching unit changes neither inode, mtime nor manager reload timestamp")
	release("c", 3, true)
	require(bytes.Equal(read(binary), previous) && bytes.Equal(read(unit), originalUnit), "probation did not restore binary and unit together")
	require(command("systemctl", "show", "ts-orch", "-p", "TemporaryFileSystem", "--value") == "", "failed unit sandbox remains loaded")
	var rollback releasepush.Rollback
	check(json.Unmarshal(read("/var/lib/ts-orch/nats/release-rolled-back"), &rollback))
	require(rollback.SHA == strings.Repeat("c", 40), "missing probation rollback record")
	fmt.Println("ok release: failed probation restores previous binary and loaded unit")
}
