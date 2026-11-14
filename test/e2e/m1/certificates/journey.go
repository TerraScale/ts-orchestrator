package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
)

func namespace(cfg configuration, node, address string) error {
	ns := "cert-" + node
	commands := [][]string{
		{"ip", "netns", "add", ns},
		{"ip", "link", "add", "host-" + node, "type", "veth", "peer", "name", "node-" + node},
		{"ip", "link", "set", "node-" + node, "netns", ns},
		{"ip", "link", "set", "host-" + node, "master", "cert-br"},
		{"ip", "link", "set", "host-" + node, "up"},
		{"ip", "-n", ns, "link", "set", "lo", "up"},
		{"ip", "-n", ns, "link", "set", "node-" + node, "name", "wt0"},
		{"ip", "-n", ns, "addr", "add", address + "/24", "dev", "wt0"},
		{"ip", "-n", ns, "link", "set", "wt0", "up"},
		{"ip", "-n", ns, "route", "add", "default", "via", "10.77.0.1"},
	}
	for _, args := range commands {
		if err := command(args...); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/etc/netns/"+ns, 0755); err != nil {
		return err
	}
	hosts := "127.0.0.1 localhost\n10.77.0.1 acme-v02.api.letsencrypt.org\n"
	for index, region := range []string{"gru", "sjc", "fra"} {
		hosts += fmt.Sprintf("10.77.0.%d %s.%s\n", index+2, region, mesh.Domain)
	}
	if err := os.WriteFile("/etc/netns/"+ns+"/hosts", []byte(hosts), 0644); err != nil {
		return err
	}
	return os.WriteFile("/etc/netns/"+ns+"/nsswitch.conf", []byte("hosts: files dns\n"), 0644)
}

func request(ctx context.Context, client *http.Client, address, path string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Host = "shared.e2e.test"
	response, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	return response.StatusCode, data, err
}

func metric(ctx context.Context, client *http.Client, address, name string) (float64, error) {
	status, data, err := request(ctx, client, address+":9108", "/metrics")
	if err != nil || status != 200 {
		return 0, fmt.Errorf("metric response %d: %v", status, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == name {
			return strconv.ParseFloat(fields[1], 64)
		}
	}
	return 0, fmt.Errorf("missing metric %s", name)
}

func inventory(ctx context.Context, client *http.Client, address string) (edge.Inventory, error) {
	status, data, err := request(ctx, client, address+":9108", "/edge/certificates")
	var result edge.Inventory
	if err != nil || status != 200 {
		return result, fmt.Errorf("inventory response %d: %v", status, err)
	}
	err = json.Unmarshal(data, &result)
	return result, err
}

func handshake(address string) (string, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 20 * time.Second}, "tcp", address+":443", &tls.Config{ServerName: "shared.e2e.test", MinVersion: tls.VersionTLS12})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	digest := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].Raw)
	return hex.EncodeToString(digest[:]), nil
}

func checkReady(ctx context.Context, client *http.Client, address string, want int) error {
	status, data, err := request(ctx, client, address, "/edge/ready")
	if err != nil || status != want {
		return fmt.Errorf("readiness %s: status=%d body=%s error=%v", address, status, data, err)
	}
	var ready struct {
		Ready        bool
		Missing      []string `json:"missing"`
		MissingNames []string `json:"missing_names"`
	}
	if err = json.Unmarshal(data, &ready); err != nil {
		return err
	}
	if ready.Ready != (want == 200) {
		return errors.New("readiness verdict mismatch")
	}
	if want == 503 && (len(ready.MissingNames) != 1 || ready.MissingNames[0] != "shared.e2e.test") {
		return errors.New("missing name absent from readiness")
	}
	if want == 503 && len(ready.Missing) != 0 {
		return fmt.Errorf("certificate gap reported as infrastructure condition: %s", data)
	}
	if want == 200 && (len(ready.Missing) != 0 || len(ready.MissingNames) != 0) {
		return errors.New("ready response reports conditions")
	}
	return nil
}

func cli(cfg configuration, node string, want bool) error {
	cmd := exec.Command("ip", "netns", "exec", "cert-"+node, cfg.Work+"/ts-orch", "edge", "certificates", "inventory", "local")
	data, err := cmd.CombinedOutput()
	if (err == nil) != want {
		return fmt.Errorf("inventory CLI success=%t want=%t output=%s", err == nil, want, data)
	}
	if want && (!strings.Contains(string(data), "sha256=") || !strings.Contains(string(data), "valid=true")) {
		return errors.New("inventory CLI omitted certificate")
	}
	return nil
}

func journey(ctx context.Context, cfg configuration) error {
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
		_ = os.Setenv(key, "")
	}
	if err := fixtures(cfg); err != nil {
		return err
	}
	for _, args := range [][]string{
		{"ip", "link", "set", "lo", "up"},
		{"ip", "link", "add", "cert-br", "type", "bridge"},
		{"ip", "addr", "add", "10.77.0.1/24", "dev", "cert-br"},
		{"ip", "addr", "add", "10.89.0.1/24", "dev", "cert-br"},
		{"ip", "addr", "add", "10.90.0.1/24", "dev", "cert-br"},
		{"ip", "addr", "add", "10.91.0.1/24", "dev", "cert-br"},
		{"ip", "link", "set", "cert-br", "up"},
	} {
		if err := command(args...); err != nil {
			return err
		}
	}
	self := cfg.Work + "/certificates"
	env := []string{"SSL_CERT_FILE=" + cfg.Work + "/ca.pem", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "GOMAXPROCS=2"}
	authority, err := launch(ctx, cfg.Work+"/authority", env, self, "authority", cfg.Work+"/lane.json")
	if err != nil {
		return err
	}
	defer authority.stop()
	if err = authority.wait(ctx, "READY authority", 1); err != nil {
		return err
	}
	nodes := map[string]*process{}
	for index, node := range []string{"previous", "b", "c"} {
		if err = namespace(cfg, node, fmt.Sprintf("10.77.0.%d", index+2)); err != nil {
			return err
		}
		defer command("ip", "netns", "del", "cert-"+node)
		var p *process
		if node == "previous" {
			p, err = launch(ctx, cfg.Work+"/"+node, env, "ip", "netns", "exec", "cert-"+node, cfg.Work+"/previous-edge", cfg.Work+"/lane.json")
		} else {
			p, err = launch(ctx, cfg.Work+"/"+node, env, "ip", "netns", "exec", "cert-"+node, self, "node", cfg.Work+"/lane.json", node, []string{"gru", "sjc", "fra"}[index])
		}
		if err != nil {
			return err
		}
		nodes[node] = p
		defer func() { nodes[node].stop() }()
		if err = p.wait(ctx, "READY ", 1); err != nil {
			return err
		}
	}
	os.Setenv("SSL_CERT_FILE", cfg.Work+"/ca.pem")
	roots, err := x509.SystemCertPool()
	if err != nil {
		return err
	}
	rootData, err := os.ReadFile(cfg.Work + "/ca.pem")
	if err != nil {
		return err
	}
	if !roots.AppendCertsFromPEM(rootData) {
		return errors.New("authority root unavailable")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second}
	defer transport.CloseIdleConnections()
	for _, address := range []string{"10.77.0.3", "10.77.0.4"} {
		if err = checkReady(ctx, client, address, 503); err != nil {
			return err
		}
	}
	if err = challengeSyntax(ctx, cfg, client); err != nil {
		return err
	}
	orders, err := metric(ctx, client, "10.77.0.3", `ts_edge_autocert_orders_total{outcome="success"}`)
	if err != nil || orders != 0 {
		return fmt.Errorf("observation placed orders=%g error=%v", orders, err)
	}
	fmt.Println("PASS observation placed zero orders")
	if err = cli(cfg, "b", false); err != nil {
		return err
	}
	for index, node := range []string{"previous", "b", "c"} {
		address := fmt.Sprintf("10.77.0.%d", index+2)
		fingerprint, err := handshake(address)
		if err != nil {
			return fmt.Errorf("%s automatic issuance: %w", node, err)
		}
		if node == "previous" {
			if err = warmCache(ctx, cfg, client, nodes, env, fingerprint); err != nil {
				return err
			}
			fmt.Println("PASS previous binary order validated through both new edges")
			continue
		}
		if err = checkReady(ctx, client, address, 200); err != nil {
			return err
		}
		snapshot, err := inventory(ctx, client, address)
		if err != nil {
			return err
		}
		if len(snapshot.MissingNames) != 0 || len(snapshot.Errors) != 0 {
			return fmt.Errorf("unexpected inventory problems %+v", snapshot)
		}
		found := false
		for _, cert := range snapshot.Certificates {
			if cert.Fingerprint == fingerprint && cert.Valid {
				found = true
			}
		}
		if !found {
			return errors.New("inventory fingerprint does not match TLS")
		}
		if err = cli(cfg, node, true); err != nil {
			return err
		}
		orders, err := metric(ctx, client, address, `ts_edge_autocert_orders_total{outcome="success"}`)
		if err != nil || orders != 1 {
			return fmt.Errorf("automatic order count=%g error=%v", orders, err)
		}
		fmt.Println("PASS", node, "autocert, readiness, public inventory, TLS fingerprint and CLI; one automatic order")
	}

	if err = writeFleetList(); err != nil {
		return err
	}
	for _, selection := range []string{"", "all", "ts-sjc-101"} {
		if err = fleetCLI(cfg, selection, true); err != nil {
			return err
		}
	}
	fmt.Println("PASS default, all and named-node inventory read the persisted fleet list without changing state")
	rsaConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 20 * time.Second}, "tcp", "10.77.0.3:443", &tls.Config{ServerName: "shared.e2e.test", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}})
	if err == nil {
		rsaConn.Close()
		return errors.New("RSA-only handshake succeeded without an RSA certificate")
	}
	unsupported, err := metric(ctx, client, "10.77.0.3", "ts_edge_ecdsa_unsupported_handshakes_total")
	if err != nil || unsupported != 1 {
		return fmt.Errorf("unsupported key handshakes=%g error=%v", unsupported, err)
	}
	rejected, err := metric(ctx, client, "10.77.0.3", `ts_edge_autocert_orders_total{outcome="error"}`)
	if err != nil || rejected != 1 {
		return fmt.Errorf("rejected orders=%g error=%v", rejected, err)
	}
	if _, err = handshake("10.77.0.3"); err != nil {
		return fmt.Errorf("ECDSA serving after RSA refusal: %w", err)
	}
	fmt.Println("PASS RSA-only client refusal increments missing-key and rejected-order counters; ECDSA still serves")
	if err = os.Remove(cfg.Work + "/b/edge-certs/shared.e2e.test"); err != nil {
		return err
	}
	if err = checkReady(ctx, client, "10.77.0.3", 200); err != nil {
		return err
	}
	if err = cli(cfg, "b", true); err != nil {
		return err
	}
	fmt.Println("PASS removing only the disk file preserves readiness for the certificate still held in memory")
	nodes["b"].stop()
	if err = cli(cfg, "b", false); err != nil {
		return err
	}
	fmt.Println("PASS inventory CLI fails when its node cannot be read")
	if err = fleetCLI(cfg, "", false); err != nil {
		return err
	}
	fmt.Println("PASS fleet inventory returns readable certificates and fails for its unreadable node")
	p, err := launch(ctx, cfg.Work+"/b-restarted", env, "ip", "netns", "exec", "cert-b", self, "node", cfg.Work+"/lane.json", "b", "sjc")
	if err != nil {
		return err
	}
	nodes["b"] = p
	if err = p.wait(ctx, "READY node", 1); err != nil {
		return err
	}
	if err = checkReady(ctx, client, "10.77.0.3", 503); err != nil {
		return err
	}
	if err = cli(cfg, "b", false); err != nil {
		return err
	}
	missing, err := metric(ctx, client, "10.77.0.3", "ts_edge_certificate_names_missing")
	if err != nil || missing != 1 {
		return fmt.Errorf("missing names=%g error=%v", missing, err)
	}
	fmt.Println("PASS certificate removed and edge restarted: readiness and CLI fail, missing metric=1")
	rootPEM, err := os.ReadFile(cfg.Work + "/ca.pem")
	if err != nil {
		return err
	}
	rootBlock, _ := pem.Decode(rootPEM)
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return err
	}
	rootKeyPEM, err := os.ReadFile(cfg.Work + "/ca.key")
	if err != nil {
		return err
	}
	rootKeyBlock, _ := pem.Decode(rootKeyPEM)
	rootKey, err := x509.ParseECPrivateKey(rootKeyBlock.Bytes)
	if err != nil {
		return err
	}
	for _, failure := range []string{"expired", "untrusted", "key-mismatch", "wrong-name"} {
		nodes["b"].stop()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		until := time.Now().Add(24 * time.Hour)
		if failure == "expired" {
			until = time.Now().Add(-time.Hour)
		}
		issuer, signer := root, rootKey
		if failure == "untrusted" {
			signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			cert, _, err := fixtureCertificate("journey CA", signer, nil, nil, time.Now().Add(24*time.Hour))
			if err != nil {
				return err
			}
			block, _ := pem.Decode(cert)
			issuer, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return err
			}
		}
		name := "shared.e2e.test"
		if failure == "wrong-name" {
			name = "other.e2e.test"
		}
		cert, keyPEM, err := fixtureCertificate(name, key, issuer, signer, until)
		if err != nil {
			return err
		}
		if failure == "key-mismatch" {
			other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			der, err := x509.MarshalECPrivateKey(other)
			if err != nil {
				return err
			}
			keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		}
		if err = os.WriteFile(cfg.Work+"/b/edge-certs/shared.e2e.test", append(keyPEM, cert...), 0600); err != nil {
			return err
		}
		p, err = launch(ctx, cfg.Work+"/b-"+failure, env, "ip", "netns", "exec", "cert-b", self, "node", cfg.Work+"/lane.json", "b", "sjc")
		if err != nil {
			return err
		}
		nodes["b"] = p
		if err = p.wait(ctx, "READY node", 1); err != nil {
			return err
		}
		if err = checkReady(ctx, client, "10.77.0.3", 503); err != nil {
			return err
		}
		if err = cli(cfg, "b", false); err != nil {
			return err
		}
		missing, err := metric(ctx, client, "10.77.0.3", "ts_edge_certificate_names_missing")
		if err != nil || missing != 1 {
			return fmt.Errorf("%s missing metric=%g error=%v", failure, missing, err)
		}
		fmt.Println("PASS", failure, "certificate rejected by readiness, inventory CLI and missing-name metric")
	}
	nodes["b"].stop()
	if err = os.Remove(cfg.Work + "/b/edge-certs/shared.e2e.test"); err != nil {
		return err
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	rsaCert, rsaPrivate, err := fixtureCertificate("shared.e2e.test", rsaKey, root, rootKey, time.Now().Add(24*time.Hour))
	if err != nil {
		return err
	}
	if err = os.WriteFile(cfg.Work+"/b/edge-certs/shared.e2e.test+rsa", append(rsaPrivate, rsaCert...), 0600); err != nil {
		return err
	}
	p, err = launch(ctx, cfg.Work+"/b-rsa-only", env, "ip", "netns", "exec", "cert-b", self, "node", cfg.Work+"/lane.json", "b", "sjc")
	if err != nil {
		return err
	}
	nodes["b"] = p
	if err = p.wait(ctx, "READY node", 1); err != nil {
		return err
	}
	if err = checkReady(ctx, client, "10.77.0.3", 503); err != nil {
		return err
	}
	if err = cli(cfg, "b", true); err != nil {
		return err
	}
	missing, err = metric(ctx, client, "10.77.0.3", "ts_edge_certificate_names_missing")
	if err != nil || missing != 0 {
		return fmt.Errorf("valid RSA inventory missing metric=%g error=%v", missing, err)
	}
	if err = rsaServing("10.77.0.3", rsaCert); err != nil {
		return err
	}
	fmt.Println("PASS RSA-only certificate serves TLS while readiness reports not ready")

	return nil
}

func writeFleetList() error {
	list := nodelist.List{Sequence: 1, Nodes: []nodelist.Node{}}
	for _, fixture := range []struct{ process, region, address string }{{"b", "sjc", "10.77.0.3"}, {"c", "fra", "10.77.0.4"}} {
		name := "ts-" + fixture.region + "-101"
		address, err := nodelist.MeshIP(name, fixture.region)
		if err != nil {
			return err
		}
		if err = command("ip", "-n", "cert-"+fixture.process, "addr", "add", address+"/32", "dev", "wt0"); err != nil {
			return err
		}
		if err = command("ip", "route", "add", address+"/32", "via", fixture.address, "dev", "cert-br"); err != nil {
			return err
		}
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return err
		}
		pin := sha256.Sum256(key)
		index := len(list.Nodes) + 1
		list.Nodes = append(list.Nodes, nodelist.Node{Name: name, Region: fixture.region, PublicIP: fmt.Sprintf("192.0.2.%d", index), PrivateIP: fmt.Sprintf("172.20.0.%d", index), MeshIP: address, WGPublicKey: base64.StdEncoding.EncodeToString(key), TLSSPKISHA256: hex.EncodeToString(pin[:])})
	}
	if err := list.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if err = os.MkdirAll("/var/lib/ts-orch/node", 0700); err != nil {
		return err
	}
	return os.WriteFile("/var/lib/ts-orch/node/nodes.json", data, 0600)
}

func fleetCLI(cfg configuration, selection string, want bool) error {
	before, err := os.ReadFile("/var/lib/ts-orch/node/nodes.json")
	if err != nil {
		return err
	}
	info, err := os.Stat("/var/lib/ts-orch/node/nodes.json")
	if err != nil {
		return err
	}
	args := []string{"edge", "certificates", "inventory"}
	if selection != "" {
		args = append(args, selection)
	}
	data, callErr := exec.Command(cfg.Work+"/ts-orch", args...).CombinedOutput()
	if (callErr == nil) != want {
		return fmt.Errorf("fleet inventory success=%t want=%t output=%s", callErr == nil, want, data)
	}
	if want {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		count := 2
		if selection == "ts-sjc-101" {
			count = 1
		}
		if len(lines) != count {
			return fmt.Errorf("fleet inventory certificate lines=%d want=%d: %s", len(lines), count, data)
		}
		for _, line := range lines {
			if !strings.Contains(line, "valid=true") {
				return fmt.Errorf("fleet inventory validation missing: %s", line)
			}
		}
	} else if !strings.Contains(string(data), "ts-fra-101 names=") || !strings.Contains(string(data), "ts-sjc-101: inventory unavailable") {
		return fmt.Errorf("partial inventory lost its readable node or failure: %s", data)
	}
	after, err := os.ReadFile("/var/lib/ts-orch/node/nodes.json")
	if err != nil {
		return err
	}
	current, err := os.Stat("/var/lib/ts-orch/node/nodes.json")
	if err != nil {
		return err
	}
	entries, err := os.ReadDir("/var/lib/ts-orch/node")
	if err != nil {
		return err
	}
	if !bytes.Equal(before, after) || !info.ModTime().Equal(current.ModTime()) || len(entries) != 1 {
		return errors.New("inventory changed node state")
	}
	return nil
}
