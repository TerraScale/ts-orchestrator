package foundation

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	managerbundle "github.com/TerraScale/ts-orchestrator/deploy/netbird/manager"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/native"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/netbird/protocol"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/netbird/scenario"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var nativeQualificationServe bool

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "serve" {
		nativeQualificationServe = true
		os.Args = []string{os.Args[0], "-test.run=^TestNativeImageQualification$", "-test.timeout=45m"}
		_ = flag.CommandLine.Parse(os.Args[1:])
	}
	os.Exit(m.Run())
}

// The SSH worker is a test binary: production never accepts alternate Vault or storage endpoints.
func TestNativeImageQualification(t *testing.T) {
	if !nativeQualificationServe {
		t.Skip("invoked only by the disposable native image runner")
	}
	worker := &nativeQualification{t: t, vault: newVaultHTTP(t)}
	t.Cleanup(worker.close)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		var command protocol.Command
		var response protocol.Response
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil {
			response.Error = "invalid native qualification request"
		} else {
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
			response, err = worker.execute(ctx, command)
			cancel()
			if err != nil {
				response = protocol.Response{Error: "native qualification " + command.Operation + " failed"}
			}
		}
		wire, err := json.Marshal(response)
		if err != nil {
			t.Fatal("native response encoding failed")
		}
		if _, err = os.Stdout.Write(append(wire, '\n')); err != nil {
			t.Fatal("native response transport failed")
		}
	}
	if scanner.Err() != nil {
		t.Fatal("native request transport failed")
	}
}

type nativeQualification struct {
	t          *testing.T
	vault      *vaultHTTP
	runtime    *foundationRuntime
	target     BootstrapVault
	client     *bootstrapClient
	store      *httptest.Server
	peer       *exec.Cmd
	runID      string
	clientPath string
	private    nativePrivate
}

type nativePrivate struct {
	Endpoint    string            `json:"endpoint"`
	Certificate []byte            `json:"certificate"`
	SigningKey  []byte            `json:"signing_key"`
	Vault       map[string]string `json:"vault"`
	Versions    map[string]int64  `json:"versions"`
	Object      string            `json:"object"`
}

func (w *nativeQualification) execute(ctx context.Context, c protocol.Command) (protocol.Response, error) {
	var response protocol.Response
	if c.RunID == "" || !filepath.IsLocal(c.RunID) || strings.ContainsAny(c.RunID, "/\\") || len(c.RunID) > 64 {
		return response, errors.New("invalid native run")
	}
	if w.runID != "" && w.runID != c.RunID {
		return response, errors.New("native run changed")
	}
	w.runID = c.RunID
	identity, err := native.MeasureIdentity(ctx, c.ContainerdPath, c.RuncPath)
	if err != nil {
		return response, err
	}
	if identity != c.Host.ExpectedIdentity || identity.InstanceID != c.Host.OCID {
		return response, errors.New("native host identity differs")
	}
	response.Observation.Identity = identity
	response.Observation.WorkerSHA256, response.Observation.WorkerSourceRevision, err = nativeBuildIdentity()
	if err != nil {
		return response, err
	}
	if response.Observation.WorkerSourceRevision != c.SourceRevision {
		return response, errors.New("source mismatch")
	}
	switch c.Operation {
	case "identity":
		client, err := containerd.New("/run/containerd/containerd.sock")
		if err != nil {
			return response, err
		}
		containers, err := client.Containers(foundationContext(ctx))
		closeErr := client.Close()
		if err = errors.Join(err, closeErr); err != nil {
			return response, err
		}
		if len(containers) != 0 {
			return response, errors.New("native foundation namespace is not dormant")
		}
		return response, nil
	case "backup-store":
		err = w.startStore(c.Host.Address)
		if err == nil {
			response.Private, err = json.Marshal(w.private)
		}
		return response, err
	case "foundation":
		if w.runtime != nil {
			return response, errors.New("foundation already started")
		}
		if err = w.stage(ctx, c); err != nil {
			return response, err
		}
		w.target = w.vault.clients(w.t)
		if err = w.startFoundation(ctx); err != nil {
			return response, err
		}
		if err = w.seed(ctx, c); err != nil {
			return response, err
		}
	case "restart":
		if w.runtime == nil {
			return response, errors.New("foundation absent")
		}
		container, loadErr := w.runtime.client.LoadContainer(foundationContext(ctx), "netbird-server")
		if loadErr != nil {
			return response, loadErr
		}
		task, taskErr := container.Task(foundationContext(ctx), nil)
		if taskErr != nil {
			return response, taskErr
		}
		exited, waitErr := task.Wait(foundationContext(ctx))
		if waitErr != nil {
			return response, waitErr
		}
		if err = task.Kill(foundationContext(ctx), syscall.SIGKILL, containerd.WithKillAll); err != nil {
			return response, err
		}
		select {
		case <-exited:
		case <-ctx.Done():
			return response, ctx.Err()
		}
		if err = w.ensureFoundation(ctx); err != nil {
			return response, err
		}
		if _, err = Bootstrap(ctx, localOrigin, DataDirectory+"/data/terrascale-identity", w.target); err != nil {
			return response, err
		}
	case "rotate":
		response.Observation.DeniedHTTPStatus, err = w.rotate(ctx)
		if err != nil {
			return response, err
		}
	case "backup":
		if err = json.Unmarshal(c.Private, &w.private); err != nil {
			return response, err
		}
		targets, err := w.backupTargets()
		if err != nil {
			return response, err
		}
		if err = w.stopPeer(); err != nil {
			return response, err
		}
		record, err := Backup(ctx, DataDirectory+"/data", ConfigPath, targets, w.pause)
		peerErr := w.startPeer(c)
		err = errors.Join(err, peerErr)
		if err != nil {
			return response, err
		}
		w.private.Object = record.Object
		w.vault.mu.Lock()
		w.private.Vault = map[string]string{}
		w.private.Versions = map[string]int64{}
		for k, v := range w.vault.values {
			w.private.Vault[k] = v
			w.private.Versions[k] = w.vault.versions[k]
		}
		w.vault.mu.Unlock()
		response.Private, err = json.Marshal(w.private)
		if err != nil {
			return response, err
		}
		response.Observation.BackupObject = record.Object
		response.Observation.BackupSHA256 = strings.TrimSuffix(filepath.Base(record.Object), ".tar")
		response.Observation.BackupBytes = record.Bytes
		response.Observation.BackupRegions = []string{targets[0].Region, targets[1].Region}
		response.Observation.BackupStorage = "signed-sdk-fixture"
		for _, target := range targets {
			hash := sha256.New()
			counter := &nativeCountWriter{Writer: hash}
			if err = target.download(ctx, record.Object, counter); err != nil {
				return response, err
			}
			response.Observation.BackupCopies = append(response.Observation.BackupCopies, protocol.Copy{Region: target.Region, SHA256: hex.EncodeToString(hash.Sum(nil)), Bytes: counter.Bytes})
		}
	case "restore":
		if err = json.Unmarshal(c.Private, &w.private); err != nil {
			return response, err
		}
		targets, err := w.backupTargets()
		if err != nil {
			return response, err
		}
		if _, err = Restore(ctx, targets[1], w.private.Object, DataDirectory); err != nil {
			return response, err
		}
		restored, err := os.ReadFile(DataDirectory + "/config.yaml")
		if err != nil {
			return response, err
		}
		if err = os.MkdirAll(filepath.Dir(ConfigPath), 0700); err != nil {
			return response, err
		}
		if err = os.WriteFile(ConfigPath, restored, 0600); err != nil {
			return response, err
		}
		clear(restored)
		w.vault.mu.Lock()
		w.vault.values = w.private.Vault
		w.vault.versions = w.private.Versions
		w.vault.mu.Unlock()
		w.target = w.vault.clients(w.t)
		if err = w.stage(ctx, c); err != nil {
			return response, err
		}
		if err = w.startFoundation(ctx); err != nil {
			return response, err
		}
		if err = w.startPeer(c); err != nil {
			return response, err
		}
		response.Observation.RestoredSHA256 = strings.TrimSuffix(filepath.Base(w.private.Object), ".tar")
	case "retire", "cleanup":
		return response, w.shutdown(ctx)
	default:
		return response, errors.New("unknown native operation")
	}
	account, err := w.observe(ctx)
	if err != nil {
		return response, err
	}
	response.Observation.Account = account
	response.Observation.TLSProtocol, response.Observation.GRPCStatus, response.Observation.STUNTransaction, err = w.probeProtocols(ctx)
	if err != nil {
		return response, err
	}
	response.Observation.TLSAuthority = "fixture-internal"
	response.Observation.Components, err = w.components(ctx)
	if err != nil {
		return response, err
	}
	w.vault.mu.Lock()
	response.Observation.CredentialVersion = fmt.Sprint(w.vault.versions[ManagementSecretName])
	w.vault.mu.Unlock()
	return response, nil
}

func (w *nativeQualification) stage(ctx context.Context, c protocol.Command) error {
	for _, dir := range []string{DataDirectory, DataDirectory + "/data", DataDirectory + "/data/foundation-tls", filepath.Dir(ConfigPath), stackDirectory} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	for _, name := range []string{"Caddyfile.netbird", "dashboard.environment"} {
		wire, err := fs.ReadFile(managerbundle.Files, name)
		if err != nil {
			return err
		}
		if name == "Caddyfile.netbird" {
			wire = []byte(strings.Replace(string(wire), "netbird.terrascale.tech {", "netbird.terrascale.tech {\n    tls internal", 1))
		}
		if err = os.WriteFile(filepath.Join(stackDirectory, name), wire, 0600); err != nil {
			return err
		}
	}
	hosts, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return err
	}
	if !strings.Contains(string(hosts), "127.0.0.1 netbird.terrascale.tech") {
		hosts = append(hosts, []byte("\n127.0.0.1 netbird.terrascale.tech\n")...)
		if err = os.WriteFile("/etc/hosts", hosts, 0644); err != nil {
			return err
		}
	}
	client, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		return err
	}
	defer client.Close()
	for _, artifact := range c.Artifacts {
		if !slices.Contains([]string{"server", "dashboard", "ingress"}, artifact.Role) {
			return errors.New("invalid native artifact")
		}
		name := "/run/ts-native-" + c.RunID + "/" + artifact.Role + ".oci"
		digest, err := nativeFileDigest(name)
		if err != nil || digest != artifact.ArchiveSHA256 {
			return errors.New("native artifact changed")
		}
		file, err := os.Open(name)
		if err != nil {
			return err
		}
		_, importErr := client.Import(foundationContext(ctx), file)
		closeErr := file.Close()
		if err = errors.Join(importErr, closeErr); err != nil {
			return err
		}
	}
	w.clientPath = "/run/ts-native-" + c.RunID + "/client"
	digest, err := nativeFileDigest(w.clientPath)
	if err != nil || digest != c.ClientSHA256 {
		return errors.New("native peer binary changed")
	}
	return os.Chmod(w.clientPath, 0700)
}

func (w *nativeQualification) startFoundation(ctx context.Context) error {
	if err := (Supervisor{Vault: w.target}).Render(ctx); err != nil {
		return err
	}
	client, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		return err
	}
	w.runtime = &foundationRuntime{client: client, executable: "/usr/local/bin/terrascale-orchestrator", logRoot: DataDirectory + "/runtime-logs"}
	w.client, err = newBootstrapClient(localOrigin)
	if err != nil {
		return err
	}
	return w.ensureFoundation(ctx)
}

func (w *nativeQualification) ensureFoundation(ctx context.Context) error {
	components, err := foundationComponents()
	if err != nil {
		return err
	}
	for _, component := range components[:2] {
		if err = w.runtime.ensure(ctx, component, w.target.Check); err != nil {
			return err
		}
	}
	if err = (Supervisor{Vault: w.target}).wait(ctx, false); err != nil {
		return err
	}
	if _, err = Bootstrap(ctx, localOrigin, DataDirectory+"/data/terrascale-identity", w.target); err != nil {
		return err
	}
	if err = w.runtime.ensure(ctx, components[2], w.target.Check); err != nil {
		return err
	}
	_, _, _, err = w.probeProtocols(ctx)
	return err
}

func (w *nativeQualification) pause(ctx context.Context) (func(context.Context) error, error) {
	if err := w.runtime.stop(ctx, "netbird-ingress", w.target.Check); err != nil {
		return nil, err
	}
	if err := w.runtime.stop(ctx, "netbird-server", w.target.Check); err != nil {
		return nil, err
	}
	return w.ensureFoundation, nil
}

func (w *nativeQualification) token() string {
	w.vault.mu.Lock()
	defer w.vault.mu.Unlock()
	return w.vault.values[ManagementSecretName]
}

func (w *nativeQualification) seed(ctx context.Context, c protocol.Command) error {
	api, err := manager.NewAPI(localOrigin, w.token())
	if err != nil {
		return err
	}
	defer api.Close()
	desired := manager.GRU()
	if _, err = manager.Sync(ctx, api, desired, true); err != nil {
		return err
	}
	name := "gru-1-netbird-setup-key"
	_, err = manager.ReconcileServerEnrollment(ctx, api, desired, DataDirectory+"/data/native-enrollment", manager.EnrollmentVault{Target: w.target.Target, Management: w.target.Management, Bundles: w.target.Bundles, Name: name}, manager.EnrollmentAuthority{Check: w.target.Check, Quiesce: func(ctx context.Context) error {
		resume, err := w.pause(ctx)
		if err != nil {
			return err
		}
		return resume(ctx)
	}})
	if err != nil {
		return err
	}
	w.vault.mu.Lock()
	key := w.vault.values[name]
	w.vault.mu.Unlock()
	if key == "" {
		return errors.New("native enrollment key absent")
	}
	if err = w.launchPeer(c, key); err != nil {
		return err
	}
	if _, err = w.observe(ctx); err != nil {
		return err
	}
	if _, err = manager.Prune(ctx, api, desired, manager.PruneOptions{}, true); err != nil {
		return err
	}
	_, err = manager.Sync(ctx, api, desired, true)
	return err
}

func (w *nativeQualification) startPeer(c protocol.Command) error { return w.launchPeer(c, "") }
func (w *nativeQualification) launchPeer(c protocol.Command, key string) error {
	directory := DataDirectory + "/data/native-peer"
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if _, err := os.Stat(directory + "/default.json"); errors.Is(err, os.ErrNotExist) {
		if err = os.WriteFile(directory+"/default.json", []byte("{}"), 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	w.peer = exec.Command(w.clientPath, "up", "--foreground-mode", "--management-url", publicOrigin, "--hostname", "ts-gru-1", "--config", directory+"/default.json", "--log-file", directory+"/client.log")
	w.peer.Env = append(os.Environ(), "NB_SETUP_KEY="+key, "NB_STATE_DIR="+directory, "SSL_CERT_FILE="+DataDirectory+"/data/foundation-tls/caddy/pki/authorities/local/root.crt")
	return w.peer.Start()
}

func (w *nativeQualification) observe(ctx context.Context) (protocol.Account, error) {
	var result protocol.Account
	auth := "Token " + w.token()
	var accounts []struct {
		ID string `json:"id"`
	}
	if err := w.client.api(ctx, "GET", "/accounts", auth, nil, &accounts); err != nil {
		return result, err
	}
	if len(accounts) != 1 {
		return result, errors.New("native account count changed")
	}
	result.AccountID = accounts[0].ID
	var users []apiUser
	if err := w.client.api(ctx, "GET", "/users", auth, nil, &users); err != nil {
		return result, err
	}
	for _, user := range users {
		if user.Service && user.Name == serviceName {
			result.ServiceID = user.ID
		}
	}
	w.vault.mu.Lock()
	result.OwnerID = w.vault.values[identitySecretName]
	w.vault.mu.Unlock()
	result.StoreID = w.target.StoreGeneration
	var tokens []apiToken
	if err := w.client.api(ctx, "GET", "/users/"+result.ServiceID+"/tokens", auth, nil, &tokens); err != nil {
		return result, err
	}
	if len(tokens) != 1 {
		return result, errors.New("native service tokens differ")
	}
	result.ServiceTokenID = tokens[0].ID
	var policies []struct {
		ID string `json:"id"`
	}
	if err := w.client.api(ctx, "GET", "/policies", auth, nil, &policies); err != nil {
		return result, err
	}
	for _, policy := range policies {
		result.PolicyIDs = append(result.PolicyIDs, policy.ID)
	}
	slices.Sort(result.PolicyIDs)
	for {
		var peers []struct {
			ID        string `json:"id"`
			Hostname  string `json:"hostname"`
			IP        string `json:"ip"`
			Connected bool   `json:"connected"`
		}
		if err := w.client.api(ctx, "GET", "/peers", auth, nil, &peers); err != nil {
			return result, err
		}
		for _, peer := range peers {
			if peer.Hostname == "ts-gru-1" && peer.Connected {
				result.PeerID = peer.ID
				result.PeerAddress = peer.IP
			}
		}
		if result.PeerID != "" {
			break
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	config, err := os.ReadFile(DataDirectory + "/data/native-peer/default.json")
	if err != nil {
		return result, err
	}
	defer clear(config)
	var peerConfig struct {
		PrivateKey string `json:"PrivateKey"`
	}
	if err = json.Unmarshal(config, &peerConfig); err != nil {
		return result, err
	}
	private, err := base64.StdEncoding.DecodeString(peerConfig.PrivateKey)
	if err != nil {
		return result, err
	}
	defer clear(private)
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(key.PublicKey().Bytes())
	result.PeerKeySHA256 = hex.EncodeToString(digest[:])
	_, _, result.SetupHTTPStatus, err = w.client.request(ctx, "POST", "/setup", "", "application/json", strings.NewReader(`{"email":"second@example.test","password":"refused-native-setup-password","name":"second"}`))
	if err != nil {
		return result, err
	}
	_, _, result.ServiceHTTPStatus, err = w.client.request(ctx, "GET", "/users", auth, "", nil)
	if err != nil {
		return result, err
	}
	_, _, result.PeerHTTPStatus, err = w.client.request(ctx, "GET", "/peers/"+result.PeerID, auth, "", nil)
	return result, err
}

func (w *nativeQualification) rotate(ctx context.Context) (int, error) {
	old := w.token()
	w.vault.mu.Lock()
	owner := w.vault.values[ownerSecretName]
	w.vault.mu.Unlock()
	jwt, err := w.client.login(ctx, owner)
	if err != nil {
		return 0, err
	}
	var users []apiUser
	if err = w.client.api(ctx, "GET", "/users", "Bearer "+jwt, nil, &users); err != nil {
		return 0, err
	}
	var service string
	for _, user := range users {
		if user.Service && user.Name == serviceName {
			service = user.ID
		}
	}
	var short struct {
		Plain string `json:"plain_token"`
	}
	if err = w.client.api(ctx, "POST", "/users/"+service+"/tokens", "Bearer "+jwt, map[string]any{"name": serviceName, "expires_in": 1}, &short); err != nil {
		return 0, err
	}
	w.vault.mu.Lock()
	w.vault.values[ManagementSecretName] = short.Plain
	w.vault.loseUpdate = true
	w.vault.mu.Unlock()
	if _, err = Bootstrap(ctx, localOrigin, DataDirectory+"/data/terrascale-identity", w.target); err == nil {
		return 0, errors.New("lost publication not observed")
	}
	if _, err = Bootstrap(ctx, localOrigin, DataDirectory+"/data/terrascale-identity", w.target); err != nil {
		return 0, err
	}
	_, _, status, err := w.client.request(ctx, "GET", "/users", "Token "+old, "", nil)
	return status, err
}

func (w *nativeQualification) components(ctx context.Context) ([]protocol.Component, error) {
	components, err := foundationComponents()
	if err != nil {
		return nil, err
	}
	var observed []protocol.Component
	containers, err := w.runtime.client.Containers(foundationContext(ctx))
	if err != nil {
		return nil, err
	}
	if len(containers) != 3 {
		return nil, errors.New("native component count differs")
	}
	for _, component := range components {
		container, err := w.runtime.client.LoadContainer(foundationContext(ctx), component.ID)
		if err != nil {
			return nil, err
		}
		task, err := container.Task(foundationContext(ctx), nil)
		if err != nil {
			return nil, err
		}
		status, err := task.Status(foundationContext(ctx))
		if err != nil || status.Status != containerd.Running {
			return nil, errors.New("native component stopped")
		}
		observed = append(observed, protocol.Component{Name: component.ID, Image: component.Image, PID: task.Pid(), Containers: 1})
	}
	return observed, nil
}

func (w *nativeQualification) startStore(address string) error {
	if w.store != nil {
		return errors.New("backup fixture already started")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	root := filepath.Join("/run/ts-native-"+w.runID, "protected-backups")
	if err = os.MkdirAll(root, 0700); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(address, "0"))
	if err != nil {
		return err
	}
	server := httptest.NewUnstartedServer(&scenario.ObjectStore{Root: root, PublicKey: &key.PublicKey})
	_ = server.Listener.Close()
	server.Listener = listener
	server.StartTLS()
	w.store = server
	w.private = nativePrivate{Endpoint: server.URL, Certificate: server.Certificate().Raw, SigningKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})}
	return nil
}

func (w *nativeQualification) backupTargets() ([2]BackupTarget, error) {
	var targets [2]BackupTarget
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..fixture", "ocid1.user.oc1..fixture", "sa-saopaulo-1", "fixture", string(w.private.SigningKey), nil)
	pool := x509.NewCertPool()
	certificate, err := x509.ParseCertificate(w.private.Certificate)
	if err != nil {
		return targets, err
	}
	pool.AddCert(certificate)
	for i, region := range []string{"sa-saopaulo-1", "us-sanjose-1"} {
		client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
		if err != nil {
			return targets, err
		}
		ociclient.PinHost(&client.BaseClient, w.private.Endpoint)
		client.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12}}, Timeout: 2 * time.Minute}
		bucket := []string{"netbird-gru", "netbird-sfo"}[i]
		targets[i] = BackupTarget{Client: client, Region: region, Namespace: "tenancy", Bucket: bucket, BucketID: "ocid1.bucket.oc1." + region + "." + bucket, CompartmentID: "ocid1.compartment.oc1..control", KMSKeyID: "ocid1.key.oc1." + region + "." + bucket}
	}
	return targets, nil
}

func (w *nativeQualification) close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := w.shutdown(ctx); err != nil {
		w.t.Error("native fixture cleanup failed")
	}
}

func (w *nativeQualification) shutdown(ctx context.Context) error {
	err := w.stopPeer()
	if w.runtime != nil {
		for _, id := range []string{"netbird-ingress", "netbird-server", "netbird-dashboard"} {
			err = errors.Join(err, w.runtime.stop(ctx, id, func() error { return nil }))
		}
		err = errors.Join(err, w.runtime.client.Close())
		w.runtime = nil
	}
	if w.store != nil {
		w.store.Close()
		w.store = nil
	}
	if w.client != nil {
		w.client.http.CloseIdleConnections()
	}
	return err
}

func nativeFileDigest(name string) (string, error) {
	file, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func nativeBuildIdentity() (string, string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", "", errors.New("native build identity absent")
	}
	revision := ""
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			revision = setting.Value
		}
		if setting.Key == "vcs.modified" && setting.Value != "false" {
			return "", "", errors.New("native build dirty")
		}
	}
	if revision == "" {
		return "", "", errors.New("native source identity absent")
	}
	executable, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	digest, err := nativeFileDigest(executable)
	return digest, revision, err
}

func (w *nativeQualification) probeProtocols(ctx context.Context) (string, string, string, error) {
	var pool *x509.CertPool
	for {
		root, err := os.ReadFile(DataDirectory + "/data/foundation-tls/caddy/pki/authorities/local/root.crt")
		if err == nil {
			pool = x509.NewCertPool()
			if !pool.AppendCertsFromPEM(root) {
				return "", "", "", errors.New("native TLS authority invalid")
			}
			break
		}
		select {
		case <-ctx.Done():
			return "", "", "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "netbird.terrascale.tech", MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:443")
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	request, err := http.NewRequestWithContext(ctx, "POST", "https://netbird.terrascale.tech/management.ManagementService/isHealthy", bytes.NewReader([]byte{0, 0, 0, 0, 0}))
	if err != nil {
		return "", "", "", err
	}
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("TE", "trailers")
	response, err := client.Do(request)
	if err != nil {
		return "", "", "", err
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if err = errors.Join(readErr, closeErr); err != nil {
		return "", "", "", err
	}
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || response.ProtoMajor != 2 {
		return "", "", "", errors.New("native TLS HTTP2 protocol differs")
	}
	status := response.Trailer.Get("Grpc-Status")
	if status == "" {
		status = response.Header.Get("Grpc-Status")
	}
	if status != "0" {
		return "", status, "", errors.New("native management health gRPC failed")
	}
	connection, err := net.DialTimeout("udp", "127.0.0.1:3478", 5*time.Second)
	if err != nil {
		return "", "", "", err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet, 1)
	binary.BigEndian.PutUint32(packet[4:], 0x2112a442)
	if _, err = rand.Read(packet[8:]); err != nil {
		return "", "", "", err
	}
	if _, err = connection.Write(packet); err != nil {
		return "", "", "", err
	}
	reply := make([]byte, 2048)
	size, err := connection.Read(reply)
	if err != nil {
		return "", "", "", err
	}
	if size < 20 || binary.BigEndian.Uint16(reply) != 0x0101 || !bytes.Equal(reply[4:20], packet[4:20]) {
		return "", "", "", errors.New("native STUN transaction differs")
	}
	return "TLSv1.3", status, hex.EncodeToString(packet[8:]), nil
}

func (w *nativeQualification) stopPeer() error {
	if w.peer == nil || w.peer.Process == nil {
		return nil
	}
	process := w.peer
	w.peer = nil
	if err := process.Process.Signal(os.Interrupt); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	select {
	case err := <-done:
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil
		}
		return err
	case <-time.After(10 * time.Second):
		_ = process.Process.Kill()
		<-done
		return errors.New("native peer failed graceful stop")
	}
}

type nativeCountWriter struct {
	io.Writer
	Bytes int64
}

func (w *nativeCountWriter) Write(wire []byte) (int, error) {
	count, err := w.Writer.Write(wire)
	w.Bytes += int64(count)
	return count, err
}
