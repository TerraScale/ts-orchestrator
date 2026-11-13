package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

const state = "/var/lib/ts-orch"
const installedUnit = "/etc/systemd/system/ts-orch.service"
const installedBinary = "/usr/local/bin/terrascale-orchestrator"
const laneDropin = "/etc/systemd/system/ts-orch.service.d/90-node-list-lane.conf"

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func encode(value any) []byte {
	data, err := json.Marshal(value)
	must(err)
	return data
}

func run(args ...string) []byte {
	output, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("%s: %v: %s", args[0], err, output))
	}
	return output
}

func write(path string, data []byte) {
	must(os.WriteFile(path, data, 0600))
}

type artifact struct {
	Name string
	SHA  string
	Path string
	List nodelist.List
}

func prepare(work string) {
	inventory := []nodelist.Node{}
	for index := 1; index <= 2; index++ {
		wg, err := ecdh.X25519().GenerateKey(rand.Reader)
		must(err)
		pin := sha256.Sum256([]byte(fmt.Sprint(index)))
		inventory = append(inventory, nodelist.Node{
			Name: fmt.Sprintf("ts-gru-%d", index), Region: "gru",
			PublicIP: fmt.Sprintf("192.0.2.%d", index), PrivateIP: fmt.Sprintf("10.251.0.%d", index),
			MeshIP:      fmt.Sprintf("10.201.1.%d", index),
			WGPublicKey: base64.StdEncoding.EncodeToString(wg.PublicKey().Bytes()), TLSSPKISHA256: hex.EncodeToString(pin[:]),
		})
	}
	base := nodelist.List{Sequence: 1, Nodes: inventory}
	higher := nodelist.List{Sequence: 2, Nodes: inventory}
	conflict := nodelist.List{Sequence: 2, Nodes: append([]nodelist.Node{}, inventory...)}
	conflict.Nodes[0].PublicIP = "192.0.2.20"
	noncanonical := nodelist.List{Sequence: 3, Nodes: append([]nodelist.Node{}, inventory...)}
	noncanonical.Nodes[1].WGPublicKey = inventory[0].WGPublicKey[:4] + "\n" + inventory[0].WGPublicKey[4:]
	duplicate := nodelist.List{Sequence: 3, Nodes: append([]nodelist.Node{}, inventory...)}
	duplicate.Nodes[1].WGPublicKey = inventory[0].WGPublicKey
	items := []artifact{
		{Name: "base", List: base},
		{Name: "higher", List: higher},
		{Name: "conflict", List: conflict},
		{Name: "canonical", List: noncanonical},
		{Name: "duplicate", List: duplicate},
		{Name: "empty", List: nodelist.List{Sequence: 3, Nodes: []nodelist.Node{}}},
	}
	repo, err := os.Getwd()
	must(err)
	source := filepath.Join(repo, "deploy/m1/embed.go")
	original, err := os.ReadFile(source)
	must(err)
	declaration := regexp.MustCompile(`(?m)^const NodeList = .*\n?`)
	revision := strings.TrimSpace(string(run("git", "rev-parse", "HEAD")))
	for index := range items {
		item := &items[index]
		item.SHA = fmt.Sprintf("%040x", index+101)
		item.Path = filepath.Join(work, item.Name)
		embedded := declaration.ReplaceAllFunc(original, func([]byte) []byte {
			return []byte(fmt.Sprintf("const NodeList = %q\n", encode(item.List)))
		})
		overlaySource := filepath.Join(work, "embed.go")
		write(overlaySource, embedded)
		overlay := filepath.Join(work, "overlay.json")
		write(overlay, encode(map[string]any{"Replace": map[string]string{source: overlaySource}}))
		run("nice", "-n", "19", "go", "build", "-p", "2", "-buildvcs=true", "-overlay", overlay, "-o", item.Path, "./cmd/terrascale-orchestrator")
		binary, err := os.ReadFile(item.Path)
		must(err)
		from := []byte("vcs.revision=" + revision)
		require(bytes.Contains(binary, from), "build revision missing")
		binary = bytes.ReplaceAll(binary, from, []byte("vcs.revision="+item.SHA))
		binary = bytes.ReplaceAll(binary, []byte("vcs.modified=true"), []byte("vcs.modified=truE"))
		write(item.Path, binary)
		must(os.Chmod(item.Path, 0700))
	}
	write(filepath.Join(work, "artifacts.json"), encode(items))
	versionFile, err := os.ReadFile("deploy/m1/host-runtime.sh")
	must(err)
	version := regexp.MustCompile(`(?m)^containerd_version=(.*)$`).FindSubmatch(versionFile)
	require(len(version) == 2, "containerd version missing")
	client := &http.Client{Timeout: time.Minute}
	response, err := client.Get(fmt.Sprintf("https://github.com/containerd/containerd/releases/download/v%s/containerd-%s-linux-%s.tar.gz", version[1], version[1], runtime.GOARCH))
	must(err)
	defer response.Body.Close()
	require(response.StatusCode == http.StatusOK, "containerd download refused")
	zipped, err := gzip.NewReader(response.Body)
	must(err)
	defer zipped.Close()
	archive := tar.NewReader(zipped)
	for {
		header, err := archive.Next()
		must(err)
		if header.Name == "bin/containerd" {
			binary, err := io.ReadAll(archive)
			must(err)
			write(filepath.Join(work, "containerd"), binary)
			must(os.Chmod(filepath.Join(work, "containerd"), 0700))
			break
		}
	}
}

type process struct {
	cmd   *exec.Cmd
	mu    sync.Mutex
	log   bytes.Buffer
	ready chan struct{}
	done  chan error
}

func start(needle string, environment []string, args ...string) *process {
	p := &process{cmd: exec.Command(args[0], args[1:]...), ready: make(chan struct{}), done: make(chan error, 1)}
	p.cmd.Env = append(os.Environ(), environment...)
	reader, err := p.cmd.StdoutPipe()
	must(err)
	p.cmd.Stderr = p.cmd.Stdout
	must(p.cmd.Start())
	go func() {
		scanner := bufio.NewScanner(reader)
		found := false
		for scanner.Scan() {
			line := scanner.Text()
			p.mu.Lock()
			p.log.WriteString(line + "\n")
			p.mu.Unlock()
			if !found && strings.Contains(line, needle) {
				close(p.ready)
				found = true
			}
		}
		p.done <- p.cmd.Wait()
	}()
	return p
}

func (p *process) text() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.log.String()
}

func (p *process) wait() error {
	select {
	case err := <-p.done:
		return err
	case <-time.After(30 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
		panic("process did not exit: " + p.text())
	}
}

func (p *process) serving() {
	select {
	case <-p.ready:
	case err := <-p.done:
		panic(fmt.Sprintf("not serving: %v: %s", err, p.text()))
	case <-time.After(30 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
		panic("not ready: " + p.text())
	}
}

func (p *process) stop() {
	must(p.cmd.Process.Signal(syscall.SIGTERM))
	_ = p.wait()
}

func signed(key *rsa.PrivateKey, kid, commit, run string, overrides map[string]any) string {
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString(encode(map[string]string{"alg": "RS256", "kid": kid}))
	claims := map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": "ts-orch",
		"exp": now.Add(time.Hour).Unix(), "nbf": now.Add(-time.Minute).Unix(),
		"repository": "TerraScale/ts-orchestrator", "repository_owner": "TerraScale",
		"ref": "refs/heads/main", "sha": commit, "run_id": run, "event_name": "push",
		"workflow_ref": "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main",
	}
	for name, value := range overrides {
		claims[name] = value
	}
	input := header + "." + base64.RawURLEncoding.EncodeToString(encode(claims))
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	must(err)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func lane(work string) {
	run("mount", "--make-rprivate", "/")
	run("ip", "link", "set", "lo", "up")
	for _, name := range []string{"run", "firmware"} {
		must(os.Mkdir(filepath.Join(work, name), 0700))
	}
	write(filepath.Join(work, "firmware/chassis_asset_tag"), []byte("Local"))
	must(os.MkdirAll("/var/lib/containerd", 0700))
	for _, path := range []string{"/run/containerd", "/run/ts-orch", "/run/ts-orch-observability"} {
		isolated := filepath.Join(work, "run", filepath.Base(path))
		must(os.MkdirAll(isolated, 0700))
		must(os.MkdirAll(path, 0700))
		run("mount", "--bind", isolated, path)
	}
	run("mount", "--bind", filepath.Join(work, "firmware"), "/sys/class/dmi/id")
	runtimeProcess := start("containerd successfully booted", nil, filepath.Join(work, "containerd"),
		"--root", filepath.Join(work, "containerd-root"), "--state", filepath.Join(work, "containerd-state"),
		"--address", "/run/containerd/containerd.sock")
	defer runtimeProcess.stop()
	runtimeProcess.serving()
	var items []artifact
	data, err := os.ReadFile(filepath.Join(work, "artifacts.json"))
	must(err)
	must(json.Unmarshal(data, &items))
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "M1 releases"},
		DNSNames:  []string{"token.actions.githubusercontent.com", "github.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &caKey.PublicKey, caKey)
	must(err)
	caPath := filepath.Join(work, "ca.pem")
	write(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "token.actions.githubusercontent.com" && r.URL.Path == "/.well-known/jwks" {
			must(json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
				"kty": "RSA", "kid": "run-key", "n": base64.RawURLEncoding.EncodeToString(signer.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signer.E)).Bytes()),
			}}}))
			return
		}
		if r.Host == "github.com" {
			for _, item := range items {
				if strings.Contains(r.URL.Path, "/ci-"+item.SHA+"-run-") {
					http.ServeFile(w, r, item.Path)
					return
				}
			}
		}
		http.NotFound(w, r)
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: caKey}}}
	upstream.StartTLS()
	defer upstream.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "token.actions.githubusercontent.com:443" && r.Host != "github.com:443" {
			http.Error(w, "unexpected upstream", http.StatusBadGateway)
			return
		}
		target, err := net.DialTimeout("tcp", upstream.Listener.Addr().String(), 5*time.Second)
		must(err)
		defer target.Close()
		client, buffered, err := w.(http.Hijacker).Hijack()
		must(err)
		defer client.Close()
		_, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		must(err)
		must(buffered.Flush())
		done := make(chan struct{})
		go func() { _, _ = io.Copy(target, buffered); _ = target.Close(); close(done) }()
		_, _ = io.Copy(client, target)
		_ = client.Close()
		<-done
	}))
	defer proxy.Close()
	environment := []string{"HTTPS_PROXY=" + proxy.URL, "SSL_CERT_FILE=" + caPath}
	executable := filepath.Join(work, "agent")
	data, err = os.ReadFile(items[0].Path)
	must(err)
	write(executable, data)
	must(os.Chmod(executable, 0700))
	must(os.RemoveAll(state))
	must(os.MkdirAll(state, 0700))
	must(os.MkdirAll(filepath.Dir(installedUnit), 0755))
	unit, err := exec.Command(executable, "release", "unit").Output()
	must(err)
	must(os.WriteFile(installedUnit, unit, 0644))
	must(os.MkdirAll("/usr/local/bin", 0755))
	must(os.WriteFile(installedBinary, data, 0755))
	must(os.MkdirAll(filepath.Dir(laneDropin), 0755))
	must(os.WriteFile(laneDropin, []byte("[Service]\nExecStart=\nExecStart=/usr/local/bin/terrascale-orchestrator release guard\nRestart=no\n"), 0644))
	defer func() {
		_ = exec.Command("systemctl", "disable", "--now", "ts-orch-release-guard.timer").Run()
		_ = exec.Command("systemctl", "stop", "ts-orch.service").Run()
		_ = os.RemoveAll(filepath.Dir(laneDropin))
		_ = os.Remove("/etc/systemd/system/ts-orch-release-guard.service")
		_ = os.Remove("/etc/systemd/system/ts-orch-release-guard.timer")
		_ = os.Remove(installedUnit)
		_ = os.Remove(installedBinary)
		_ = exec.Command("systemctl", "daemon-reload").Run()
		_ = os.RemoveAll(state)
	}()
	run("systemctl", "daemon-reload")
	launch := func(broken bool) *process {
		env := append([]string{}, environment...)
		if broken {
			env = append(env, "NOTIFY_SOCKET="+filepath.Join(work, "missing.sock"))
		}
		return start("ready; advertise", env, executable, "single-host", "--state", state)
	}
	current := launch(false)
	defer func() {
		if current != nil {
			current.stop()
		}
	}()
	current.serving()
	pin := strings.TrimSpace(string(run(executable, "release", "pin", "--state", state)))
	region := releasepush.Region{Region: "gru", NATS: "tls://127.0.0.1:4222", SPKISHA256: pin}
	token := signed(signer, "run-key", items[0].SHA, "100", nil)
	request := func(subject string, value any) releasepush.Reply {
		conn, err := releasepush.Dial(region, token)
		must(err)
		defer conn.Close()
		message, err := conn.Request(subject, encode(value), 15*time.Second)
		must(err)
		var reply releasepush.Reply
		must(json.Unmarshal(message.Data, &reply))
		return reply
	}
	snapshot := func() []byte {
		data, err := os.ReadFile(state + "/node/nodes.json")
		must(err)
		return data
	}
	baselineHealth := request(releasepush.SubjectHealth, nil).Health
	require(baselineHealth != "", "release health reply missing")
	serves := func() {
		client, conn, err := swarmruntime.DialSingleHost(state)
		must(err)
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
		must(err)
		require(len(nodes.Nodes) == 1 && nodes.Nodes[0].Status.State == api.NodeStatus_READY, "host control API is not serving its ready node")
		require(request(releasepush.SubjectHealth, nil).Health == baselineHealth, "node list changed release health")
	}
	check := func(item artifact, refusal string) {
		reply := request(releasepush.SubjectVersion, nil)
		wire := encode(item.List)
		digest := sha256.Sum256(wire)
		require(reply.NodeList.Sequence == item.List.Sequence, fmt.Sprintf("sequence differs: %+v", reply))
		require(reply.NodeList.Digest == hex.EncodeToString(digest[:]), "status digest differs")
		require(strings.Contains(reply.NodeList.Refused, refusal) && (refusal != "" || reply.NodeList.Refused == ""), fmt.Sprintf("refusal differs: %+v", reply))
		output := run(executable, "status")
		require(bytes.Contains(output, []byte(reply.NodeList.String())), "CLI status did not show daemon decision: "+string(output))
		serves()
	}
	push := func(index, runID int) {
		item := items[index]
		binary, err := os.ReadFile(item.Path)
		must(err)
		sum := sha256.Sum256(binary)
		runText := fmt.Sprint(runID)
		release := releasepush.OrchRelease{SHA: item.SHA, Token: signed(signer, "run-key", item.SHA, runText, nil),
			Binaries: map[string]releasepush.Binary{runtime.GOARCH: {
				URL: releasepush.ReleaseURL(item.SHA, runText, runtime.GOARCH), SHA256: hex.EncodeToString(sum[:]),
			}}}
		reply := request(releasepush.SubjectOrch, release)
		require(reply.State == "installed", fmt.Sprintf("release refused: %+v", reply))
		require(current.wait() != nil, "installed release did not restart")
		current = nil
	}
	check(items[0], "")
	public := run(executable, "node", "keys")
	inventoryPath, listPath := filepath.Join(work, "inventory.json"), filepath.Join(work, "built-list.json")
	write(listPath, []byte("unchanged"))
	for _, invalid := range []struct {
		name   string
		change func([]nodelist.Node)
		reason string
	}{
		{"escaped CRLF", func(nodes []nodelist.Node) {
			nodes[1].WGPublicKey = nodes[0].WGPublicKey[:4] + "\r\n" + nodes[0].WGPublicKey[4:]
		}, "invalid canonical WireGuard"},
		{"decoded WG duplicate", func(nodes []nodelist.Node) { nodes[1].WGPublicKey = nodes[0].WGPublicKey }, "duplicate node wg_public_key"},
		{"uppercase TLS hash", func(nodes []nodelist.Node) { nodes[0].TLSSPKISHA256 = strings.ToUpper(nodes[0].TLSSPKISHA256) }, "invalid canonical TLS"},
		{"decoded TLS duplicate", func(nodes []nodelist.Node) { nodes[1].TLSSPKISHA256 = nodes[0].TLSSPKISHA256 }, "duplicate node tls_spki_sha256"},
		{"parsed cross-field address duplicate", func(nodes []nodelist.Node) { nodes[1].PrivateIP = nodes[0].PublicIP }, "duplicate node address"},
		{"noncanonical address", func(nodes []nodelist.Node) { nodes[0].PublicIP = "192.000.2.1" }, "invalid canonical IPv4"},
		{"uppercase name", func(nodes []nodelist.Node) { nodes[0].Name = "TS-GRU-1" }, "node name must be"},
		{"noncanonical index", func(nodes []nodelist.Node) { nodes[0].Name = "ts-gru-01" }, "node name must be"},
	} {
		nodes := append([]nodelist.Node{}, items[0].List.Nodes...)
		invalid.change(nodes)
		write(inventoryPath, encode(nodes))
		output, err := exec.Command(executable, "node", "list", "build", "4", inventoryPath, listPath).CombinedOutput()
		require(err != nil && bytes.Contains(output, []byte(invalid.reason)), invalid.name+" was not refused: "+string(output))
		data, err := os.ReadFile(listPath)
		must(err)
		require(string(data) == "unchanged", "invalid builder input replaced output")
	}
	write(inventoryPath, []byte("[]"))
	run(executable, "node", "list", "build", "4", inventoryPath, listPath)
	built, err := os.ReadFile(listPath)
	must(err)
	var empty nodelist.List
	must(json.Unmarshal(built, &empty))
	require(empty.Sequence == 4 && len(empty.Nodes) == 0, "builder refused final removal")
	fmt.Println("ok public CLI: canonical keys, decoded key uniqueness, parsed address uniqueness and canonical names enforced; final removal builds")

	keys := []string{state + "/node/tls.key", state + "/node/wg.key"}
	private := make([][]byte, len(keys))
	for index, path := range keys {
		private[index], err = os.ReadFile(path)
		must(err)
		require(!bytes.Contains(public, bytes.TrimSpace(private[index])), "private identity exposed by public CLI")
		info, err := os.Stat(path)
		must(err)
		require(info.Mode().Perm() == 0600 && info.Sys().(*syscall.Stat_t).Uid == 0, "generated identity permissions differ")
	}
	held := snapshot()
	push(1, 101)
	require(bytes.Equal(snapshot(), held), "install adopted before confirmation")
	for attempt := 0; attempt < 3; attempt++ {
		failed := launch(true)
		require(failed.wait() != nil, "unconfirmed release unexpectedly served")
		if attempt < 2 {
			require(strings.Contains(failed.text(), "missing.sock"), "failure did not reach readiness: "+failed.text())
		} else {
			require(strings.Contains(failed.text(), "rolled back release"), "trial did not roll back: "+failed.text())
		}
		require(bytes.Equal(snapshot(), held), "unconfirmed or rolled-back release changed list")
	}
	current = launch(false)
	current.serving()
	check(items[0], "")
	fmt.Println("ok real daemon: unconfirmed higher embedded list and rolled-back release preserve stored list")
	push(1, 102)
	require(bytes.Equal(snapshot(), held), "higher list adopted during installation")
	current = launch(false)
	current.serving()
	check(items[1], "")
	require(!bytes.Equal(snapshot(), held), "confirmed higher sequence not persisted")
	held = snapshot()
	fmt.Println("ok real daemon: higher embedded sequence adopted after confirmation; status sequence and digest converge")
	push(0, 103)
	current = launch(false)
	current.serving()
	check(items[1], "")
	require(bytes.Equal(snapshot(), held), "older binary lowered stored list")
	fmt.Println("ok real daemon: older binary and restart keep higher stored sequence silently")
	for _, refusal := range []struct {
		index  int
		reason string
	}{
		{2, "conflicting node lists at the same sequence"},
		{3, "invalid canonical WireGuard public key"},
		{4, "duplicate node wg_public_key"},
	} {
		push(refusal.index, 104+refusal.index)
		current = launch(false)
		current.serving()
		check(items[1], refusal.reason)
		require(bytes.Equal(snapshot(), held), "refused list changed stored bytes")
		require(strings.Count(current.text(), "node list: refused, ") == 1, "refusal was not logged once: "+current.text())
		require(exec.Command("test", "-e", state+"/nats/release-trial").Run() != nil, "refusal blocked confirmation")
	}
	fmt.Println("ok real daemon: equal-sequence conflict, noncanonical escaped-newline key and decoded duplicate refused once; releases confirm and serve")
	push(5, 110)
	current = launch(false)
	current.serving()
	check(items[5], "")
	held = snapshot()
	fmt.Println("ok real daemon: higher empty list removes final enrolled hosts")
	for index, path := range keys {
		for _, wrong := range []string{"mode", "owner"} {
			current.stop()
			current = nil
			if wrong == "mode" {
				must(os.Chmod(path, 0644))
			} else {
				must(os.Chown(path, 65534, 65534))
			}
			current = launch(false)
			current.serving()
			check(items[5], "")
			require(exec.Command(executable, "node", "keys").Run() != nil, "invalid key metadata accepted")
			actual, err := os.ReadFile(path)
			must(err)
			require(bytes.Equal(actual, private[index]), "existing identity bytes changed")
			info, err := os.Stat(path)
			must(err)
			require(wrong != "mode" || info.Mode().Perm() == 0644, "existing key mode silently changed")
			require(wrong != "owner" || info.Sys().(*syscall.Stat_t).Uid == 65534, "existing key owner silently changed")
			require(strings.Count(current.text(), "node identity unavailable") == 1, "identity failure not reported once")
			must(os.Chown(path, 0, 0))
			must(os.Chmod(path, 0600))
		}
	}
	for index, path := range keys {
		current.stop()
		current = nil
		write(path, []byte("damaged"))
		current = launch(false)
		current.serving()
		check(items[5], "")
		require(exec.Command(executable, "node", "keys").Run() != nil, "damaged identity accepted")
		actual, err := os.ReadFile(path)
		must(err)
		require(string(actual) == "damaged", "damaged identity silently replaced")
		write(path, private[index])
	}
	current.stop()
	current = nil
	must(os.Remove(keys[1]))
	current = launch(false)
	current.serving()
	check(items[5], "")
	_, err = os.Stat(keys[1])
	require(os.IsNotExist(err), "incomplete identity regenerated")
	require(exec.Command(executable, "node", "keys").Run() != nil, "incomplete identity accepted")
	actual, err := os.ReadFile(keys[0])
	must(err)
	require(bytes.Equal(actual, private[0]), "incomplete identity replaced surviving key")
	write(keys[1], private[1])
	current.stop()
	current = nil
	write(state+"/node/nodes.json", []byte("damaged"))
	current = launch(false)
	current.serving()
	reply := request(releasepush.SubjectVersion, nil)
	require(strings.Contains(reply.NodeList.Refused, "stored node list"), "damaged stored list not reported")
	require(string(snapshot()) == "damaged", "damaged stored list overwritten")
	serves()
	current.stop()
	current = nil
	write(state+"/node/nodes.json", held)
	current = launch(false)
	current.serving()
	check(items[5], "")
	require(bytes.Equal(public, run(executable, "node", "keys")), "identity changed over releases and restarts")
	require(exec.Command(executable, "node", "keys", filepath.Join(work, "absent")).Run() != nil, "absent identity accepted")
	_, err = os.Stat(filepath.Join(work, "absent"))
	require(os.IsNotExist(err), "public-key command created state")
	fmt.Println("ok real daemon: both existing keys with wrong owner or mode reported unchanged; damaged and incomplete keys preserve serving and identity")
	fmt.Println("ok real daemon: damaged stored list refused and preserved without blocking serving; public-key CLI remains read-only")
}

func main() {
	require(len(os.Args) == 2, "binary or prepared lane directory required")
	if os.Geteuid() == 0 {
		lane(os.Args[1])
		return
	}
	work, err := os.MkdirTemp("", "node-list-e2e-")
	must(err)
	defer func() { run("sudo", "-n", "rm", "-rf", work) }()
	prepare(work)
	self, err := os.Executable()
	must(err)
	fmt.Print(string(run("sudo", "-n", "env", "PATH="+os.Getenv("PATH"), "unshare", "--mount", "--net", self, work)))
}
