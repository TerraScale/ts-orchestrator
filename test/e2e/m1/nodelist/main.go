package main

import (
	"bytes"
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
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
)

const (
	sha     = "1111111111111111111111111111111111111111"
	nextSHA = "2222222222222222222222222222222222222222"
	state   = "/var/lib/ts-orch"
	dropin  = "/run/systemd/system/ts-orch.service.d/node-list-e2e.conf"
)

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

func run(input []byte, args ...string) []byte {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("%s failed: %v: %s", args[0], err, output))
	}
	return output
}

func main() {
	require(len(os.Args) == 2, "binary argument required")
	bin, err := filepath.Abs(os.Args[1])
	must(err)
	work, err := os.MkdirTemp("", "node-list-e2e-")
	must(err)
	defer os.RemoveAll(work)
	command := func(args ...string) []byte {
		return run(nil, append([]string{bin}, args...)...)
	}
	root := func(args ...string) []byte {
		return run(nil, append([]string{"sudo", "-n"}, args...)...)
	}
	save := func(path string, data []byte) {
		run(data, "sudo", "-n", "install", "-m", "0600", "/dev/stdin", path)
	}
	tlsPath, wgPath := state+"/node/tls.key", state+"/node/wg.key"
	tlsPrivate, wgPrivate := root("cat", tlsPath), root("cat", wgPath)
	defer func() {
		save(tlsPath, tlsPrivate)
		save(wgPath, wgPrivate)
		root("rm", "-f", state+"/node/nodes.json", dropin, "/run/ts-node-list-e2e-ca.pem")
		root("systemctl", "daemon-reload")
		root("systemctl", "restart", "ts-orch")
	}()
	public := root(bin, "node", "keys")
	require(bytes.Equal(public, root(bin, "node", "keys")), "public identity changed across processes")
	require(!bytes.Contains(public, bytes.TrimSpace(tlsPrivate)) && !bytes.Contains(public, bytes.TrimSpace(wgPrivate)), "private key exposed")
	var keys nodelist.PublicKeys
	must(json.Unmarshal(public, &keys))
	var fields map[string]any
	must(json.Unmarshal(public, &fields))
	require(len(fields) == 2 && len(keys.WGPublicKey) == 44 && len(keys.TLSSPKISHA256) == 64, "public identity incomplete")
	for _, path := range []string{tlsPath, wgPath} {
		require(strings.TrimSpace(string(root("stat", "-c", "%a", path))) == "600", "private key mode differs")
	}
	missing := exec.Command(bin, "node", "keys", filepath.Join(work, "absent"))
	require(missing.Run() != nil, "keys command created an absent identity")
	_, err = os.Stat(filepath.Join(work, "absent"))
	require(os.IsNotExist(err), "read-only keys command changed state")
	emptyPath := filepath.Join(work, "empty.json")
	must(os.WriteFile(emptyPath, []byte("{\"sequence\":0,\"nodes\":[]}"), 0600))
	require(len(command("release", "nodes", "publish", sha, emptyPath, "absent-regions")) == 0, "empty list attempted delivery")
	inventory := []nodelist.Node{}
	for index := 1; index <= 3; index++ {
		if index > 1 {
			wg, err := ecdh.X25519().GenerateKey(rand.Reader)
			must(err)
			tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			must(err)
			spki, err := x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
			must(err)
			pin := sha256.Sum256(spki)
			keys = nodelist.PublicKeys{WGPublicKey: base64.StdEncoding.EncodeToString(wg.PublicKey().Bytes()), TLSSPKISHA256: hex.EncodeToString(pin[:])}
		}
		inventory = append(inventory, nodelist.Node{Name: fmt.Sprintf("ts-gru-%d", index), Region: "gru",
			PublicIP: fmt.Sprintf("192.0.2.%d", index), PrivateIP: fmt.Sprintf("10.251.0.%d", index),
			WGPublicKey: keys.WGPublicKey, TLSSPKISHA256: keys.TLSSPKISHA256})
	}
	inventoryPath, listPath := filepath.Join(work, "inventory.json"), filepath.Join(work, "nodes.json")
	must(os.WriteFile(inventoryPath, encode(inventory), 0600))
	command("node", "list", "build", "2", inventoryPath, listPath)
	listWire, err := os.ReadFile(listPath)
	must(err)
	list, err := nodelist.Decode(listWire)
	must(err)
	require(list.Nodes[2].MeshIP == "10.201.1.3", "builder derived wrong mesh IP")
	newer := list
	newer.Sequence = 3
	newerWire := encode(newer)
	commits := map[string][]byte{sha: listWire, nextSHA: newerWire}
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	unknown, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	var token atomic.Value
	var fetchFailed atomic.Bool
	var fetched atomic.Uint64
	token.Store(signed(signer, "run-key", sha, "20", nil))
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "M1 node list"},
		DNSNames:  []string{"token.actions.githubusercontent.com", "raw.githubusercontent.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &caKey.PublicKey, caKey)
	must(err)
	caPath := "/run/ts-node-list-e2e-ca.pem"
	save(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host == "token.actions.githubusercontent.com" && r.URL.Path == "/.well-known/jwks":
			must(json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
				"kty": "RSA", "kid": "run-key", "n": base64.RawURLEncoding.EncodeToString(signer.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signer.E)).Bytes()),
			}}}))
		case r.Host == "raw.githubusercontent.com":
			fetched.Add(1)
			if fetchFailed.Load() {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			for commit, data := range commits {
				if r.URL.Path == "/TerraScale/ts-orchestrator/"+commit+"/deploy/m1/nodes.json" {
					_, err := w.Write(data)
					must(err)
					return
				}
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: caKey}}}
	upstream.StartTLS()
	defer upstream.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		address := r.Host
		if address == "token.actions.githubusercontent.com:443" || address == "raw.githubusercontent.com:443" {
			address = upstream.Listener.Addr().String()
		}
		target, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err != nil {
			http.Error(w, "connection failed", http.StatusBadGateway)
			return
		}
		client, buffered, err := w.(http.Hijacker).Hijack()
		must(err)
		defer client.Close()
		defer target.Close()
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
	mint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require(r.Header.Get("Authorization") == "bearer e2e-only", "unauthenticated mint")
		must(json.NewEncoder(w).Encode(map[string]string{"value": token.Load().(string)}))
	}))
	defer mint.Close()
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", mint.URL+"?request=e2e"))
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "e2e-only"))
	root("install", "-d", filepath.Dir(dropin))
	save(dropin, []byte(fmt.Sprintf("[Service]\nEnvironment=HTTPS_PROXY=%s SSL_CERT_FILE=%s\n", proxy.URL, caPath)))
	root("systemctl", "daemon-reload")
	root("systemctl", "restart", "ts-orch")
	pin := strings.TrimSpace(string(root(bin, "release", "pin", "--state", state)))
	region := releasepush.Region{Region: "gru", NATS: "tls://127.0.0.1:4222", SPKISHA256: pin}
	dial := func() *connection {
		conn, err := releasepush.Dial(region, token.Load().(string))
		must(err)
		return &connection{request: func(subject string, wire []byte) releasepush.Reply {
			message, err := conn.Request(subject, wire, 5*time.Second)
			must(err)
			var reply releasepush.Reply
			must(json.Unmarshal(message.Data, &reply))
			return reply
		}, close: conn.Close}
	}
	conn := dial()
	defer func() { conn.close() }()
	send := func(value releasepush.NodesRelease) releasepush.Reply {
		return conn.request(releasepush.SubjectNodes, encode(value))
	}
	version := conn.request(releasepush.SubjectVersion, nil).Version
	binary, err := os.ReadFile(bin)
	must(err)
	sum := sha256.Sum256(binary)
	binaryRelease := releasepush.OrchRelease{SHA: version, Token: signed(signer, "run-key", version, "22", nil),
		Binaries: map[string]releasepush.Binary{runtime.GOARCH: {URL: releasepush.ReleaseURL(version, "22", runtime.GOARCH), SHA256: hex.EncodeToString(sum[:])}}}
	binaryWorks := func() {
		require(conn.request(releasepush.SubjectOrch, encode(binaryRelease)).State == "current", "current binary release refused")
	}
	binaryWorks()
	sign := func(commit string) releasepush.NodesRelease {
		var release releasepush.NodesRelease
		must(json.Unmarshal(command("release", "nodes", "sign", commit, listPath), &release))
		return release
	}
	release := sign(sha)
	bad := release
	parts := strings.Split(bad.Token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	must(err)
	signature[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	bad.Token = strings.Join(parts, ".")
	require(send(bad).State == "rejected", "bad signature accepted")
	bad.Token = signed(unknown, "unknown-key", sha, "20", nil)
	require(send(bad).State == "rejected", "unknown signer accepted")
	for _, refusal := range []struct {
		name   string
		claims map[string]any
	}{
		{"another workflow", map[string]any{"workflow_ref": "TerraScale/ts-orchestrator/.github/workflows/app-canary.yml@refs/heads/main"}},
		{"pull-request event", map[string]any{"event_name": "pull_request"}},
		{"non-main ref", map[string]any{"ref": "refs/heads/feature"}},
		{"another repository", map[string]any{"repository": "TerraScale/terrascale", "workflow_ref": "TerraScale/terrascale/.github/workflows/ci.yml@refs/heads/main"}},
	} {
		bad.Token = signed(signer, "run-key", sha, "20", refusal.claims)
		require(send(bad).State == "rejected", refusal.name+" accepted")
	}
	require(fetched.Load() == 0, "refused authorization fetched content")
	bad = release
	bad.Artifact.URL = releasepush.NodesURL(nextSHA)
	require(send(bad).State == "rejected", "unsigned commit URL accepted")
	must(os.WriteFile(listPath, newerWire, 0600))
	bad = sign(sha)
	require(send(bad).State == "rejected", "content absent from signed commit accepted")
	must(os.WriteFile(listPath, listWire, 0600))
	require(send(release).State == "updated", "valid signed list refused")
	require(send(release).State == "current", "idempotent publish refused")
	snapshot := func() []byte { return root("cat", state+"/node/nodes.json") }
	held := snapshot()
	fetchFailed.Store(true)
	require(send(release).State == "rejected", "failed commit fetch accepted")
	require(bytes.Equal(held, snapshot()), "failed fetch changed stored list")
	fetchFailed.Store(false)
	must(os.WriteFile(listPath, newerWire, 0600))
	token.Store(signed(signer, "run-key", nextSHA, "21", nil))
	newRelease := sign(nextSHA)
	envelopePath, regionsPath := filepath.Join(work, "envelope.json"), filepath.Join(work, "regions.json")
	must(os.WriteFile(envelopePath, encode(newRelease), 0600))
	must(os.WriteFile(regionsPath, encode([]releasepush.Region{region}), 0600))
	require(bytes.Contains(command("release", "nodes", "push", envelopePath, regionsPath), []byte("\"updated\"")), "external publish failed")
	require(send(release).State == "stale", "older sequence was not stale")
	bad = newRelease
	bad.Token = signed(signer, "run-key", nextSHA, "19", nil)
	require(send(bad).State == "stale", "older run was not stale")
	restart := func() {
		conn.close()
		root("systemctl", "restart", "ts-orch")
		conn = dial()
		require(strings.TrimSpace(string(root(bin, "release", "pin", "--state", state))) == pin, "release pin changed")
		run(nil, "curl", "-fsS", "--max-time", "5", "http://127.0.0.1:18081/health")
	}
	restart()
	require(send(release).State == "stale", "sequence floor lost on restart")
	require(send(bad).State == "stale", "run floor lost on restart")
	held = snapshot()
	require(bytes.Equal(public, root(bin, "node", "keys")), "restart replaced identity")
	root("rm", wgPath)
	restart()
	binaryWorks()
	require(bytes.Equal(root("cat", tlsPath), tlsPrivate), "partial identity replaced surviving key")
	missing = exec.Command("sudo", "-n", bin, "node", "keys")
	require(missing.Run() != nil, "partial keys command succeeded")
	require(exec.Command("sudo", "-n", "test", "-e", wgPath).Run() != nil, "partial identity regenerated")
	save(wgPath, wgPrivate)
	save(tlsPath, []byte("damaged"))
	restart()
	binaryWorks()
	require(string(root("cat", tlsPath)) == "damaged", "damaged key replaced")
	save(tlsPath, tlsPrivate)
	root("chmod", "0644", tlsPath)
	restart()
	binaryWorks()
	require(strings.TrimSpace(string(root("stat", "-c", "%a", tlsPath))) == "644", "invalid mode silently repaired")
	root("chmod", "0600", tlsPath)
	save(state+"/node/nodes.json", []byte("damaged"))
	restart()
	binaryWorks()
	require(send(newRelease).State == "rejected", "unavailable list handler accepted list")
	require(string(snapshot()) == "damaged", "damaged list replaced")
	save(state+"/node/nodes.json", held)
	restart()
	require(send(newRelease).State == "current", "restored list refused")
	fmt.Println("ok real daemon: valid list accepted; signature, signer, workflow, PR event, ref, repository, commit contents, sequence and run checked")
	fmt.Println("ok real daemon: failed fetch preserves list; damaged, incomplete and wrong-mode identities and damaged list preserve serving, release listener and host pin")
	fmt.Println("ok external commands: keys only reads; build, sign and push; persisted floors and identity survive restart")
}

type connection struct {
	request func(string, []byte) releasepush.Reply
	close   func()
}
