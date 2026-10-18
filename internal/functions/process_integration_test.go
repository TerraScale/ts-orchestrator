package functions

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func TestFunctionWorkerProcess(t *testing.T) {
	if directory := os.Getenv("TS_FUNCTION_TEST_PROCESS_DIR"); directory != "" {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
		defer cancel()
		if err := runProcess(ctx, directory, "127.0.0.1:0", os.Stdout); err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		return
	}
	artifact := integrationArtifact(t, "echo")
	admitted, deployment, files := signedFunctionFixture(t, artifact)
	ca, serverCertificate, clientCertificate, wrongCertificate := processCertificates(t, "spiffe://terrascale.tech/tenants/"+deployment.TenantID+"/functions/"+deployment.FunctionID,
		deployment.FunctionID+"."+strings.ToLower(deployment.TenantID)+".functions."+strings.ToLower(deployment.Cell)+".terrascale.internal")
	credentials, workerCredentials, operatorID, systemID, resolver := processBrokerCredentials(t, admitted)
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(),
		TLSConfig:   &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate}},
		TrustedKeys: []string{operatorID}, SystemAccount: systemID, AccountResolver: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("broker startup failed")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	deployment.BrokerURL = strings.Replace(srv.ClientURL(), "nats://", "tls://", 1)
	files["deployment.json"], err = json.Marshal(deployment)
	if err != nil {
		t.Fatal(err)
	}
	files["broker-ca.pem"] = ca
	files["broker.creds"] = workerCredentials
	poolForBroker := x509.NewCertPool()
	poolForBroker.AppendCertsFromPEM(ca)
	admin, err := nats.Connect(deployment.BrokerURL, nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: poolForBroker}), nats.UserCredentialBytes(credentials))
	if err != nil {
		t.Fatal(err)
	}
	if err := ProvisionQueue(t.Context(), admin, admitted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	admin.Close()

	files["ingress-ca.pem"] = ca
	files["ingress-cert.pem"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertificate.Certificate[0]})
	key, err := x509.MarshalPKCS8PrivateKey(serverCertificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	files["ingress-key.pem"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	directory := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestFunctionWorkerProcess$")
	cmd.Env = append(os.Environ(), "TS_FUNCTION_TEST_PROCESS_DIR="+directory)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := false
	t.Cleanup(func() {
		if !exited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	lines := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); lines <- line }()
	var ready struct{ State, Address, TenantID, FunctionID, Revision, Digest string }
	select {
	case line := <-lines:
		if err := json.Unmarshal([]byte(line), &ready); err != nil {
			t.Fatalf("worker readiness: %q: %v (%s)", line, err, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("worker process did not become ready")
	}
	if ready.State != "ready" || ready.Digest != deployment.Digest || ready.TenantID != deployment.TenantID {
		t.Fatalf("worker readiness mismatch: %+v", ready)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	client := func(cert tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}}}, Timeout: 5 * time.Second}
	}
	goodClient, badClient := client(clientCertificate), client(wrongCertificate)
	t.Cleanup(goodClient.CloseIdleConnections)
	t.Cleanup(badClient.CloseIdleConnections)
	health, err := goodClient.Get("https://" + ready.Address + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	healthBody, err := io.ReadAll(health.Body)
	health.Body.Close()
	if err != nil || health.StatusCode != http.StatusOK || string(healthBody) != `{"state":"ready"}` {
		t.Fatalf("process health: %d %q %v", health.StatusCode, healthBody, err)
	}

	for _, tc := range []struct {
		client *http.Client
		status int
	}{{badClient, 401}, {goodClient, 200}} {
		req, err := http.NewRequestWithContext(t.Context(), "POST", "https://"+ready.Address, strings.NewReader("process payload"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Idempotency-Key", "process-http")
		resp, err := tc.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != tc.status {
			t.Fatalf("process HTTP status %d: %v", resp.StatusCode, err)
		}
		if tc.status == 200 {
			var got Invocation
			if err := json.Unmarshal(body, &got); err != nil || string(got.Payload) != "process payload" || got.TenantID != deployment.TenantID {
				t.Fatalf("process guest input %s: %v", body, err)
			}
		}
	}
	for _, tc := range []struct {
		client *http.Client
		status int
	}{{badClient, http.StatusUnauthorized}, {goodClient, http.StatusOK}} {
		response, err := tc.client.Get("https://" + ready.Address + "/snapshot")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != tc.status {
			t.Fatalf("snapshot status %d: %v", response.StatusCode, err)
		}
		if tc.status == http.StatusOK {
			var snapshot Snapshot
			if err := json.Unmarshal(body, &snapshot); err != nil || snapshot.SchemaVersion != 1 || snapshot.ObservedAt.IsZero() || time.Since(snapshot.ObservedAt) < 0 || time.Since(snapshot.ObservedAt) > 5*time.Second || snapshot.Manifest.Digest != deployment.Digest || snapshot.RuntimeVersion != RuntimeVersion || snapshot.Architecture == "" || snapshot.Succeeded != 1 || snapshot.Active != 0 || bytes.Contains(body, []byte("process payload")) {
				t.Fatalf("snapshot is missing worker identity/counters or contains invocation data: %s: %v", body, err)
			}
		}
	}
	nc, err := nats.Connect(deployment.BrokerURL, nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}), nats.UserCredentialBytes(credentials))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	address, err := netip.ParseAddrPort(ready.Address)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := ReadSnapshot(t.Context(), admitted, address, clientCertificate, ca)
	if err != nil || observed.Manifest.Digest != deployment.Digest || observed.Succeeded != 1 {
		t.Fatalf("authenticated snapshot collector lost actual worker state: %+v %v", observed, err)
	}
	if _, err := ReadSnapshot(t.Context(), admitted, address, wrongCertificate, ca); err == nil {
		t.Fatal("snapshot collector accepted a different function client identity")
	}
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	subject := "ts.functions." + deployment.TenantID + "." + deployment.FunctionID + "." + deployment.Revision
	publishTransportMessage(t, js, subject, "process-queue", []byte("queue payload"))
	waitTransport(t, func() bool {
		streams, err := js.Stream(t.Context(), "TS_FUNCTION_"+func() string { digest := sha256.Sum256([]byte(subject)); return hex.EncodeToString(digest[:]) }())
		if err != nil {
			return false
		}
		info, err := streams.Info(t.Context())
		return err == nil && info.State.Msgs == 0
	})

	identityDigest := sha256.Sum256([]byte(subject))
	identityHex := hex.EncodeToString(identityDigest[:])
	receipts, err := js.KeyValue(t.Context(), "TS_FUNCTION_RECEIPTS_"+identityHex)
	if err != nil {
		t.Fatal(err)
	}
	before, err := receipts.Get(t.Context(), "process-queue")
	if err != nil {
		t.Fatal(err)
	}
	firstPID := cmd.Process.Pid
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed process unexpectedly succeeded")
	}
	exited = true
	cmd = exec.Command(executable, "-test.run=^TestFunctionWorkerProcess$")
	cmd.Env = append(os.Environ(), "TS_FUNCTION_TEST_PROCESS_DIR="+directory)
	cmd.Stderr = &stderr
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited = false
	if cmd.Process.Pid == firstPID {
		t.Fatal("worker restart reused live process")
	}
	lines = make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); lines <- line }()
	select {
	case line := <-lines:
		if err := json.Unmarshal([]byte(line), &ready); err != nil {
			t.Fatalf("restarted readiness: %q: %v", line, err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("restarted worker did not become ready")
	}
	stream, err := js.Stream(t.Context(), "TS_FUNCTION_"+identityHex)
	if err != nil {
		t.Fatal(err)
	}
	streamInfo, err := stream.Info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	streamInfo.Config.Duplicates = 100 * time.Millisecond
	if _, err := js.UpdateStream(t.Context(), streamInfo.Config); err != nil {
		t.Fatal(err)
	}
	time.Sleep(110 * time.Millisecond)
	publishTransportMessage(t, js, subject, "process-queue", []byte("queue payload"))
	waitTransport(t, func() bool { info, err := stream.Info(t.Context()); return err == nil && info.State.Msgs == 0 })
	after, err := receipts.Get(t.Context(), "process-queue")
	if err != nil || after.Revision() != before.Revision() {
		t.Fatalf("process restart replay receipt: %v", err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		exited = true
		if err != nil {
			t.Fatalf("worker shutdown: %v: %s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker process did not stop")
	}

	proof, materialDeployment, materialFiles := signedFunctionFixture(t, integrationArtifact(t, "echo"))
	materialDeployment.BrokerURL = "tls://127.0.0.1:4222"
	for name, expiry := range map[string]time.Time{"missing": {}, "expired": time.Now().Add(-time.Second), "beyond release": proof.ExpiresAt().Add(time.Second)} {
		t.Run(name, func(t *testing.T) {
			materialDeployment.ExpiresAt = expiry
			wire, err := json.Marshal(materialDeployment)
			if err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			for name, value := range materialFiles {
				if err := os.WriteFile(filepath.Join(directory, name), value, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(directory, "deployment.json"), wire, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, executable, "-test.run=^TestFunctionWorkerProcess$")
			child.Env = append(os.Environ(), "TS_FUNCTION_TEST_PROCESS_DIR="+directory)
			output, err := child.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("material rejection child timed out or was canceled: %v: %s", ctx.Err(), output)
			}
			exit, ok := errors.AsType[*exec.ExitError](err)
			if !ok || exit.ExitCode() != 1 {
				t.Fatalf("material rejection child exit = %v, output = %q", err, output)
			}
			if !bytes.Contains(output, []byte("material authority")) {
				t.Fatalf("invalid material expiry was not rejected by worker: %s", output)
			}
		})
	}
}

func processCertificates(t *testing.T, identityURI, serverDNS string) ([]byte, tls.Certificate, tls.Certificate, tls.Certificate) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "function integration CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, uri string, server bool) tls.Certificate {
		t.Helper()
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			leaf.DNSNames = []string{serverDNS}
			uri = identityURI
		}
		parsed, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		leaf.URIs = []*url.URL{parsed}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, private)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), issue(2, "", true), issue(3, identityURI, false), issue(4, identityURI+"-other", false)
}

func processBrokerCredentials(t *testing.T, admitted release.VerifiedFunction) ([]byte, []byte, string, string, *server.MemAccResolver) {
	t.Helper()
	operator, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	defer operator.Wipe()
	operatorID, err := operator.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	resolver := &server.MemAccResolver{}
	makeAccount := func(js bool) (nkeys.KeyPair, string) {
		key, err := nkeys.CreateAccount()
		if err != nil {
			t.Fatal(err)
		}
		id, err := key.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		claim := jwt.NewAccountClaims(id)
		if js {
			claim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 64 << 20, DiskStorage: 256 << 20, Streams: 4, Consumer: 4}
		}
		encoded, err := claim.Encode(operator)
		if err != nil {
			t.Fatal(err)
		}
		if err := resolver.Store(id, encoded); err != nil {
			t.Fatal(err)
		}
		return key, id
	}
	system, systemID := makeAccount(false)
	defer system.Wipe()
	account, accountID := makeAccount(true)
	defer account.Wipe()
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	userID, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	claim := jwt.NewUserClaims(userID)
	claim.IssuerAccount = accountID
	claim.Expires = time.Now().Add(time.Hour).Unix()
	encoded, err := claim.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := jwt.FormatUserConfig(encoded, seed)
	if err != nil {
		t.Fatal(err)
	}
	accountJWT, err := resolver.Fetch(accountID)
	if err != nil {
		t.Fatal(err)
	}
	workerCredentials, _, err := IssueWorkerCredentials(admitted, accountID, accountJWT, account, nil)
	if err != nil {
		t.Fatal(err)
	}
	return credentials, workerCredentials, operatorID, systemID, resolver
}
