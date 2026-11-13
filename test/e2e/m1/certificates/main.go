package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go"
)

type configuration struct {
	Work          string
	Binary        string
	MainBinary    string
	MeshSeed      string
	DatabaseToken string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if len(os.Args) < 3 {
		return errors.New("usage: certificates <journey|authority|store|backend> <config.json>")
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		return err
	}
	var cfg configuration
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	switch os.Args[1] {
	case "operator":
		if err := syscall.Sethostname([]byte("ts-gru-1")); err != nil {
			return err
		}
		if err := syscall.Mount(cfg.Work+"/sys-oracle", "/sys", "", syscall.MS_BIND, ""); err != nil {
			return err
		}
		return syscall.Exec(os.Args[3], append([]string{os.Args[3]}, os.Args[4:]...), os.Environ())
	case "node":
		nodeName := map[string]string{"a": "ts-gru-1", "b": "ts-sjc-1"}[os.Args[4]]
		if err := syscall.Sethostname([]byte(nodeName)); err != nil {
			return err
		}
		if err := os.WriteFile(cfg.Work+"/"+os.Args[4]+".pid", []byte(fmt.Sprint(os.Getpid())), 0600); err != nil {
			return err
		}
		if err := syscall.Mount(cfg.Work+"/sys-"+os.Args[5], "/sys", "", syscall.MS_BIND, ""); err != nil {
			return err
		}
		return syscall.Exec(os.Args[3], []string{os.Args[3], "single-host", "--state", cfg.Work + "/" + os.Args[4]}, os.Environ())
	case "authority":
		return authorityMain(ctx, cfg)
	case "store":
		return storeMain(ctx, cfg)
	case "backend":
		return backendMain(ctx)
	case "journey":
		bounded, stop := context.WithTimeout(ctx, 20*time.Minute)
		defer stop()
		return journey(bounded, cfg)
	default:
		return errors.New("unknown lane process")
	}
}

func fixtureCertificate(name string, key crypto.Signer, root *x509.Certificate, signer crypto.Signer, until time.Time) ([]byte, []byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: serial, DNSNames: []string{name}, Subject: pkix.Name{CommonName: name}, NotBefore: until.Add(-90 * 24 * time.Hour), NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if leaf.NotBefore.After(time.Now().Add(-time.Hour)) {
		leaf.NotBefore = time.Now().Add(-time.Hour)
	}
	if name == "journey CA" {
		leaf.IsCA, leaf.BasicConstraintsValid, leaf.KeyUsage = true, true, x509.KeyUsageCertSign
		leaf.NotBefore = time.Now().Add(-time.Hour)
		root, signer = leaf, key
	}
	if name == "identity" {
		leaf.Subject.OrganizationalUnit = []string{"opc-tenant:ocid1.tenancy.oc1..journey"}
		leaf.DNSNames = []string{"auth.sa-saopaulo-1.oraclecloud.com", "secrets.vaults.sa-saopaulo-1.oci.oraclecloud.com", "acme-v02.api.letsencrypt.org"}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, key.Public(), signer)
	if err != nil {
		return nil, nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), nil
}

func fixtures(cfg configuration) error {
	for kind, value := range map[string]string{"local": "Journey", "oracle": "OracleCloud.com"} {
		dir := cfg.Work + "/sys-" + kind + "/class/dmi/id"
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		if err := os.WriteFile(dir+"/chassis_asset_tag", []byte(value), 0644); err != nil {
			return err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	cert, _, err := fixtureCertificate("journey CA", key, nil, nil, time.Now().Add(365*24*time.Hour))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(cert)
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfg.Work+"/ca.pem", cert, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.Work+"/ca.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return err
	}
	identity, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	cert, private, err := fixtureCertificate("identity", identity, root, key, time.Now().Add(24*time.Hour))
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfg.Work+"/identity.pem", cert, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.Work+"/identity.key", private, 0600); err != nil {
		return err
	}
	for _, node := range []string{"a", "b"} {
		region := map[string]string{"a": "gru", "b": "sjc"}[node]
		directory := cfg.Work + "/" + node + "/edge-certs"
		if err := os.MkdirAll(directory, 0700); err != nil {
			return err
		}

		names := []string{"asymmetric.e2e.test", "urgent.e2e.test", "metadata.e2e.test", "repair.e2e.test", "fail-upload.e2e.test", "existing.e2e.test", "rsa.e2e.test", "postgres.e2e.test", "unknown.e2e.test", "unknown-local.e2e.test", "ecdsa-renew.e2e.test", "rsa-renew-rsa.e2e.test", "equal.e2e.test", "barrier.e2e.test", "fenced.e2e.test", "fail-first.e2e.test", "fail-second.e2e.test", "fail-long.e2e.test", region + ".regional.e2e.test"}
		base := append([]string(nil), names...)
		for _, name := range base {
			names = append(names, region+"."+name)
		}
		for _, name := range names {
			var leafKey crypto.Signer
			filename := name
			if strings.HasSuffix(name, "rsa.e2e.test") || (name == "asymmetric.e2e.test" && node == "a") {
				leafKey, err = rsa.GenerateKey(rand.Reader, 2048)
				filename += "+rsa"
			} else {
				leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}
			if err != nil {
				return err
			}
			until := time.Now().UTC().Truncate(time.Second).Add(90 * 24 * time.Hour)
			if node == "b" && name != "equal.e2e.test" {
				until = until.Add(24 * time.Hour)
			}
			if name == "equal.e2e.test" {
				until = time.Now().UTC().Truncate(24 * time.Hour).Add(90 * 24 * time.Hour)
			}
			if strings.HasPrefix(name, "fail-") {
				until = time.Now().Add(10 * 24 * time.Hour)
			}
			if name == "unknown.e2e.test" || name == "fenced.e2e.test" || name == "metadata.e2e.test" || name == "fail-upload.e2e.test" {
				continue
			}
			if name == "ecdsa-renew.e2e.test" || name == "urgent.e2e.test" {
				until = time.Now().Add(10 * 24 * time.Hour)
			}
			if name == "rsa-renew-rsa.e2e.test" {
				until = time.Now().Add(10 * 24 * time.Hour)
			}

			cert, private, err := fixtureCertificate(name, leafKey, root, key, until)
			if err != nil {
				return err
			}
			if err := os.WriteFile(directory+"/"+filename, append(private, cert...), 0600); err != nil {
				return err
			}
			if strings.HasSuffix(name, "rsa.e2e.test") || name == "ecdsa-renew.e2e.test" {
				var extra crypto.Signer
				extraName := name
				extraUntil := time.Now().Add(90 * 24 * time.Hour)
				if strings.HasSuffix(name, "rsa.e2e.test") {
					extra, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				} else {
					extra, err = rsa.GenerateKey(rand.Reader, 2048)
					extraName += "+rsa"
				}
				if err != nil {
					return err
				}
				cert, private, err := fixtureCertificate(name, extra, root, key, extraUntil)
				if err != nil {
					return err
				}
				if err := os.WriteFile(directory+"/"+extraName, append(private, cert...), 0600); err != nil {
					return err
				}
			}

		}
	}
	return nil
}

func namespace(cfg configuration, node, address string) error {
	ns := "cert-" + node
	if err := command("ip", "netns", "add", ns); err != nil {
		return err
	}
	if err := command("ip", "link", "add", "host-"+node, "type", "veth", "peer", "name", "node-"+node); err != nil {
		return err
	}
	if err := command("ip", "link", "set", "node-"+node, "netns", ns); err != nil {
		return err
	}
	if err := command("ip", "link", "set", "host-"+node, "master", "cert-br"); err != nil {
		return err
	}
	if err := command("ip", "link", "set", "host-"+node, "up"); err != nil {
		return err
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"addr", "add", address + "/24", "dev", "node-" + node},
		{"link", "set", "node-" + node, "up"},
		{"route", "add", "169.254.169.254/32", "via", "10.77.0.1"},
	} {
		if err := command(append([]string{"ip", "-n", ns}, args...)...); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/etc/netns/"+ns, 0755); err != nil {
		return err
	}
	hosts := "127.0.0.1 localhost\n10.77.0.1 ts-gru-1.nb.ts.internal\n10.77.0.4 ts-sjc-1.nb.ts.internal\n10.77.0.5 ts-fra-1.nb.ts.internal\n10.77.0.1 acme-v02.api.letsencrypt.org\n"
	if err := os.WriteFile("/etc/netns/"+ns+"/hosts", []byte(hosts), 0644); err != nil {
		return err
	}
	return os.WriteFile("/etc/netns/"+ns+"/nsswitch.conf", []byte("hosts: files dns\n"), 0644)
}

func route(ctx context.Context, cfg configuration, node, service string, names []string) error {
	client, conn, err := swarmruntime.DialSingleHost(cfg.Work + "/" + node)
	if err != nil {
		return err
	}
	defer conn.Close()
	labels := map[string]string{swarmruntime.LabelHostnames: strings.Join(names, ","), swarmruntime.LabelReadyPath: "/readyz", swarmruntime.LabelPostgres: "postgres.e2e.test"}
	spec := &api.ServiceSpec{
		Annotations: api.Annotations{Name: service, Labels: labels},
		Task:        api.TaskSpec{Runtime: &api.TaskSpec_Container{Container: &api.ContainerSpec{Image: "journey.invalid/backend"}}},
		Mode:        &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 0}},
		Endpoint: &api.EndpointSpec{Ports: []*api.PortConfig{
			{Name: "web", Protocol: api.ProtocolTCP, PublishedPort: 18081, TargetPort: 18081, PublishMode: api.PublishModeHost},
			{Name: "postgres", Protocol: api.ProtocolTCP, PublishedPort: 15432, TargetPort: 15432, PublishMode: api.PublishModeHost},
		}},
	}
	_, err = client.CreateService(ctx, &api.CreateServiceRequest{Spec: spec})
	return err
}

func removeRoute(ctx context.Context, cfg configuration, node, name string) error {
	client, conn, err := swarmruntime.DialSingleHost(cfg.Work + "/" + node)
	if err != nil {
		return err
	}
	defer conn.Close()
	services, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return err
	}
	for _, service := range services.Services {
		if service.Spec.Annotations.Name == name {
			_, err := client.RemoveService(ctx, &api.RemoveServiceRequest{ServiceID: service.ID})
			return err
		}
	}
	return errors.New("lane route not found")
}

func fingerprint(cfg configuration, address, name string, postgres bool) (string, error) {
	pemRoots, err := os.ReadFile(cfg.Work + "/ca.pem")
	if err != nil {
		return "", err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemRoots)
	port := "443"
	if postgres {
		port = "5432"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, port), 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return "", err
	}
	if postgres {
		if _, err := conn.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47}); err != nil {
			return "", err
		}
		answer := make([]byte, 1)
		if _, err := io.ReadFull(conn, answer); err != nil || answer[0] != 'S' {
			return "", fmt.Errorf("Postgres SSL response: %q, %v", answer, err)
		}
	}
	settings := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: name}
	if strings.HasSuffix(name, "rsa.e2e.test") {
		settings.MaxVersion = tls.VersionTLS12
		settings.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	}
	secured := tls.Client(conn, settings)
	if err := secured.Handshake(); err != nil {
		return "", err
	}
	digest := sha256.Sum256(secured.ConnectionState().PeerCertificates[0].Raw)
	return hex.EncodeToString(digest[:]), nil
}

func ready(address string) error {
	response, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + address + "/edge/ready")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("readiness on %s: %s", address, response.Status)
	}
	return nil
}

func backendMain(ctx context.Context) error {
	addresses, err := net.LookupHost("ts-gru-1.nb.ts.internal")
	if err != nil || len(addresses) != 1 || addresses[0] != "10.77.0.1" {
		return fmt.Errorf("namespace hosts mapping: %v, %v", addresses, err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:18081")
	if err != nil {
		return err
	}
	defer listener.Close()
	postgres, err := net.Listen("tcp", "127.0.0.1:15432")
	if err != nil {
		return err
	}
	defer postgres.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "journey backend") })}
	go func() { _ = server.Serve(listener) }()
	go func() {
		for {
			conn, err := postgres.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	fmt.Println("READY backend")
	<-ctx.Done()
	return server.Close()
}

func journey(ctx context.Context, cfg configuration) error {
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
		_ = os.Setenv(key, "")
	}
	if err := os.MkdirAll(cfg.Work, 0700); err != nil {
		return err
	}
	if err := fixtures(cfg); err != nil {
		return err
	}
	runtime, err := launch(ctx, cfg.Work+"/containerd", nil, "containerd", "--root", cfg.Work+"/containerd-root", "--state", cfg.Work+"/containerd-state", "--address", "/run/containerd/containerd.sock")
	if err != nil {
		return err
	}
	defer runtime.stop()
	if err := runtime.wait(ctx, "containerd successfully booted", 1); err != nil {
		return err
	}
	if err := command("ip", "link", "set", "lo", "up"); err != nil {
		return err
	}
	if err := command("ip", "link", "add", "cert-br", "type", "bridge"); err != nil {
		return err
	}
	for _, address := range []string{"10.77.0.1/24", "10.77.0.4/24", "10.77.0.5/24", "169.254.169.254/32"} {
		if err := command("ip", "addr", "add", address, "dev", "cert-br"); err != nil {
			return err
		}
	}
	if err := command("ip", "link", "set", "cert-br", "up"); err != nil {
		return err
	}
	for i, node := range []string{"a", "b"} {
		defer func() { _ = command("ip", "netns", "del", "cert-"+node); _ = os.RemoveAll("/etc/netns/cert-" + node) }()
		if err := namespace(cfg, node, fmt.Sprintf("10.77.0.%d", i+2)); err != nil {
			return err
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	authority, err := launch(ctx, cfg.Work+"/authority", nil, self, "authority", os.Args[2])
	if err != nil {
		return err
	}
	defer authority.stop()
	if err := authority.wait(ctx, "READY authority", 1); err != nil {
		return err
	}
	store, err := launch(ctx, cfg.Work+"/store", nil, self, "store", os.Args[2])
	if err != nil {
		return err
	}
	defer store.stop()
	if err := store.wait(ctx, "READY store", 1); err != nil {
		return err
	}
	seedStore, err := nats.Connect("nats://10.77.0.1:4223", nats.UserInfo("orch", "journey"))
	if err != nil {
		return err
	}
	seedAPI, err := seedStore.JetStream(nats.MaxWait(3 * time.Second))
	if err != nil {
		seedStore.Close()
		return err
	}
	unknown, _ := json.Marshal(struct {
		Version string
		Data    []byte
	}{"v999", []byte{0}})
	for _, name := range []string{"unknown.e2e.test", "unknown-local.e2e.test"} {
		if _, err := seedAPI.Publish("$KV.edge-certs."+hex.EncodeToString([]byte(name)), unknown); err != nil {
			return err
		}
	}
	seedStore.Close()

	for _, node := range []string{"a", "b"} {
		backend, err := launch(ctx, cfg.Work+"/backend-"+node, nil, "ip", "netns", "exec", "cert-"+node, self, "backend", os.Args[2])
		if err != nil {
			return err
		}
		defer backend.stop()
		if err := backend.wait(ctx, "READY backend", 1); err != nil {
			return err
		}
	}
	env := []string{"JOURNAL_STREAM=", "HTTPS_PROXY=http://10.77.0.1:8089", "GOMAXPROCS=2", "NO_PROXY=169.254.169.254,127.0.0.1,10.77.0.0/24,acme-v02.api.letsencrypt.org", "SSL_CERT_FILE=" + cfg.Work + "/ca.pem"}
	startNode := func(node, binary, log, platform string) (*process, error) {
		p, err := launch(ctx, cfg.Work+"/"+log, env, "ip", "netns", "exec", "cert-"+node, "unshare", "--uts", self, "node", os.Args[2], binary, node, platform)
		if err != nil {
			return nil, err
		}
		if err := p.wait(ctx, " ready; advertise ", 1); err != nil {
			p.stop()
			return nil, err
		}
		return p, nil
	}
	for _, node := range []string{"a", "b"} {
		bootstrap, err := startNode(node, cfg.MainBinary, "bootstrap-"+node, "local")
		if err != nil {
			return err
		}
		bootstrap.stop()
	}
	old, err := startNode("b", cfg.MainBinary, "old", "oracle")
	if err != nil {
		return err
	}
	oldRunning := true
	defer func() {
		if oldRunning {
			old.stop()
		}
	}()
	current, err := startNode("a", cfg.Binary, "a-process", "oracle")
	if err != nil {
		return err
	}
	defer func() { current.stop() }()
	for _, node := range []string{"a", "b"} {
		if err := route(ctx, cfg, node, "existing", []string{"existing.e2e.test", "rsa.e2e.test", map[string]string{"a": "gru", "b": "sjc"}[node] + ".regional.e2e.test"}); err != nil {
			return err
		}
	}
	if err := current.wait(ctx, "edge readiness changed ready=true", 1); err != nil {
		return err
	}
	for _, address := range []string{"10.77.0.2", "10.77.0.3"} {
		for _, name := range []string{"existing.e2e.test", "rsa.e2e.test"} {
			if _, err := fingerprint(cfg, address, name, false); err != nil {
				return fmt.Errorf("mixed rollout %s %s: %w", address, name, err)
			}
		}
		if _, err := fingerprint(cfg, address, "postgres.e2e.test", true); err != nil {
			return err
		}
	}
	fmt.Println("PASS main and current binaries serve existing ECDSA, RSA and Postgres certificates together")
	if err := route(ctx, cfg, "a", "rollout", []string{"asymmetric.e2e.test", "urgent.e2e.test"}); err != nil {
		return err
	}
	if err := current.wait(ctx, "edge certificate installed name=urgent.e2e.test ", 2); err != nil {
		return err
	}
	if err := waitUntil(ctx, time.Now().Add(11*time.Second)); err != nil {
		return err
	}
	rolloutCounts, err := fetchCounts()
	if err != nil {
		return err
	}
	if rolloutCounts["asymmetric.e2e.test"] != 0 || rolloutCounts["urgent.e2e.test"] != 1 {
		return fmt.Errorf("rollout orders: %v", rolloutCounts)
	}
	fmt.Println("PASS asymmetric missing ECDSA waits for unupgraded peer; 10d urgent certificate renews with missing inventory")
	localB, err := fingerprint(cfg, "10.77.0.3", "existing.e2e.test", false)
	if err != nil {
		return err
	}
	old.stop()
	oldRunning = false
	second, err := startNode("b", cfg.Binary, "b-process", "oracle")
	if err != nil {
		return err
	}
	defer second.stop()
	if err := second.wait(ctx, "edge readiness changed ready=true", 1); err != nil {
		return err
	}
	preserved, err := fingerprint(cfg, "10.77.0.3", "existing.e2e.test", false)
	if err != nil {
		return err
	}
	if preserved != localB {
		return errors.New("newer local certificate replaced by older shared copy")
	}
	if err := current.wait(ctx, "edge certificate installed name=existing.e2e.test", 2); err != nil {
		return err
	}
	adopted, err := fingerprint(cfg, "10.77.0.2", "existing.e2e.test", false)
	if err != nil {
		return err
	}
	if adopted != localB {
		return errors.New("later expiry certificate was not adopted")
	}
	fmt.Println("PASS later-expiring local certificate preserved and adopted on the other node")
	if err := current.wait(ctx, "edge certificate installed name=asymmetric.e2e.test ", 1); err != nil {
		return err
	}
	asymmetric, err := fingerprint(cfg, "10.77.0.2", "asymmetric.e2e.test", false)
	if err != nil {
		return err
	}
	sharedAsymmetric, err := fileFingerprint(cfg.Work + "/b/edge-certs/asymmetric.e2e.test")
	if err != nil || asymmetric != sharedAsymmetric {
		return errors.New("asymmetric peer ECDSA not adopted")
	}
	rolloutCounts, err = fetchCounts()
	if err != nil || rolloutCounts["asymmetric.e2e.test"] != 0 {
		return errors.New("asymmetric rollout spent an order")
	}
	fmt.Println("PASS asymmetric rollout: A adopts B ECDSA after upgrade, zero authority orders")
	conn, err := nats.Connect("nats://10.77.0.1:4223", nats.UserInfo("orch", "journey"))
	if err != nil {
		return err
	}
	defer conn.Close()
	leaseSubject := "$KV.edge-certs." + hex.EncodeToString([]byte("shared.e2e.test"))
	leases, err := conn.SubscribeSync(leaseSubject)
	if err != nil {
		return err
	}
	defer leases.Unsubscribe()
	if err := conn.Flush(); err != nil {
		return err
	}
	for _, node := range []string{"a", "b"} {
		if err := route(ctx, cfg, node, "shared", []string{"shared.e2e.test"}); err != nil {
			return err
		}
	}
	if _, err := leases.NextMsgWithContext(ctx); err != nil {
		return err
	}
	for i, regional := range []struct {
		process *process
		region  string
	}{{current, "gru"}, {second, "sjc"}} {
		if err := regional.process.wait(ctx, "edge certificate installed name="+regional.region+".shared.e2e.test", 1); err != nil {
			return err
		}
		if _, err := fingerprint(cfg, fmt.Sprintf("10.77.0.%d", i+2), regional.region+".shared.e2e.test", false); err != nil {
			return err
		}
	}
	response, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://10.77.0.1:8088/release")
	if err != nil {
		return err
	}
	response.Body.Close()
	for _, p := range []*process{current, second} {
		if err := p.wait(ctx, "edge certificate installed name=shared.e2e.test", 1); err != nil {
			return err
		}
	}

	firstFingerprint, err := fingerprint(cfg, "10.77.0.2", "shared.e2e.test", false)
	if err != nil {
		return err
	}
	secondFingerprint, err := fingerprint(cfg, "10.77.0.3", "shared.e2e.test", false)
	if err != nil {
		return err
	}
	if firstFingerprint != secondFingerprint {
		return errors.New("shared certificate fingerprints differ")
	}
	response, err = (&http.Client{Timeout: 2 * time.Second}).Get("http://10.77.0.1:8088/counts")
	if err != nil {
		return err
	}
	var counts map[string]int
	err = json.NewDecoder(response.Body).Decode(&counts)
	response.Body.Close()
	if err != nil {
		return err
	}
	if len(counts) != 4 || counts["urgent.e2e.test"] != 1 || counts["shared.e2e.test"] != 1 || counts["gru.shared.e2e.test"] != 1 || counts["sjc.shared.e2e.test"] != 1 {
		return fmt.Errorf("authority orders: %v", counts)
	}
	sharedAPI, err := conn.JetStream(nats.MaxWait(3 * time.Second))
	if err != nil {
		return err
	}
	encrypted, err := sharedAPI.GetLastMsg("KV_edge-certs", "$KV.edge-certs."+hex.EncodeToString([]byte("shared.e2e.test")), nats.Context(ctx))
	if err != nil {
		return err
	}
	var envelope struct {
		Version string
		Data    []byte
	}
	if err := json.Unmarshal(encrypted.Data, &envelope); err != nil {
		return err
	}
	if envelope.Version != "v1" || len(envelope.Data) < 32 || bytes.Contains(envelope.Data, []byte("PRIVATE KEY")) {
		return errors.New("certificate envelope is not encrypted and versioned")
	}
	fmt.Println("PASS two production processes use the host seed and account path; two lease contenders, one order per name, HTTP-01 on every eligible node; TLS fingerprint", firstFingerprint)
	if err := recoveryJourney(ctx, cfg, conn, current); err != nil {
		return err
	}
	if err := fixupJourney(ctx, cfg, conn, authority, current, second, store); err != nil {
		return err
	}
	for _, address := range []string{"10.77.0.2", "10.77.0.3"} {
		if err := ready(address); err != nil {
			return err
		}
	}
	if err := store.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		return err
	}
	for _, node := range []string{"a", "b"} {
		if err := route(ctx, cfg, node, "pending", []string{"pending.e2e.test"}); err != nil {
			return err
		}
	}
	for _, p := range []*process{current, second} {
		if err := p.wait(ctx, "edge certificate unavailable name=pending.e2e.test", 1); err != nil {
			return err
		}
	}
	var requests sync.WaitGroup
	failures := make(chan error, 64)
	for range 16 {
		for _, address := range []string{"10.77.0.2", "10.77.0.3"} {
			requests.Go(func() {
				got, err := fingerprint(cfg, address, "shared.e2e.test", false)
				if err == nil && got != firstFingerprint {
					err = errors.New("certificate changed during outage")
				}
				if err != nil {
					failures <- err
				}
				if _, err := fingerprint(cfg, address, "postgres.e2e.test", true); err != nil {
					failures <- err
				}
			})
		}
	}
	requests.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			return err
		}
	}
	for _, address := range []string{"10.77.0.2", "10.77.0.3"} {
		if err := ready(address); err != nil {
			return err
		}
	}
	fmt.Println("PASS SIGSTOP store: 32 fresh HTTPS and 32 Postgres handshakes; both readiness endpoints 200 with a new uncertified hostname")
	for _, node := range []string{"a", "b"} {
		info, err := os.Stat(filepath.Join(cfg.Work, node, "edge-certs", "shared.e2e.test"))
		if err != nil {
			return err
		}
		if info.Mode().Perm() != 0600 {
			return errors.New("certificate file is not owner-only")
		}
	}
	return nil
}
