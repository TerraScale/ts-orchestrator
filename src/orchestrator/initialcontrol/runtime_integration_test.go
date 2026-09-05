//go:build linux

package initialcontrol_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
)

// These tests use the actual root-owned publication in a private mount
// namespace. Ordinary go test skips them; no production trust override exists.
func namespace(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("TS_INITIALCONTROL_TEST_NAMESPACE") != "1" {
		t.Skip("requires root in a private mount namespace")
	}
	self, _ := os.Readlink("/proc/self/ns/mnt")
	init, _ := os.Readlink("/proc/1/ns/mnt")
	if self == init {
		t.Fatal("refusing to mount over the host namespace")
	}
	// The participant inherits the parent's protected credentials under /var/lib.
	// Isolate only its own admission publication; mounting all of /var/lib
	// would hide those credentials before initialcontrol.Start can read them.
	mountPath := "/var/lib"
	if os.Getenv("TS_INITIALCONTROL_PARTICIPANT_CONFIG") != "" {
		mountPath = "/var/lib/terrascale"
		if err := os.MkdirAll(mountPath, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mount("tmpfs", mountPath, "tmpfs", 0, "mode=0755"); err != nil {
		t.Fatal(err)
	}
	network, _ := os.Readlink("/proc/self/ns/net")
	hostNetwork, _ := os.Readlink("/proc/1/ns/net")
	if network == hostNetwork {
		t.Fatal("requires private network namespace")
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"address", "replace", "10.77.0.10/32", "dev", "lo"}} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("isolated test address: %v %s", err, output)
		}
	}
	t.Cleanup(func() {
		if err := unix.Unmount(mountPath, 0); err != nil {
			t.Error(err)
		}
	})
}
func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func memberKey(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), base64.StdEncoding.EncodeToString(public)
}

type fixture struct {
	config    initialgrant.Config
	proof     *initialgrant.Proof
	epochs    *nodeauthority.EpochStore
	admission *initialgrant.Admission
	owner     *security.CommandSignatureSigner
}

func fixtureConfig(t *testing.T) (initialgrant.Config, initialgrant.Config) {
	return fixtureConfigCapture(t, false)
}

func fixtureConfigCapture(t *testing.T, capture bool) (initialgrant.Config, initialgrant.Config) {
	t.Helper()
	var declaration *vmcontrolseed.PreliminaryCaptureDeclaration
	if capture {
		declaration = &vmcontrolseed.PreliminaryCaptureDeclaration{MaxSnapshotBytes: 32 << 20, MaxTotalBytes: 128 << 20}
	}
	return fixtureConfigCaptureDeclaration(t, declaration)
}

func fixtureConfigCaptureDeclaration(t *testing.T, declaration *vmcontrolseed.PreliminaryCaptureDeclaration) (initialgrant.Config, initialgrant.Config) {
	t.Helper()
	seedKey, seedPublic := memberKey(t)
	peerKey, peerPublic := memberKey(t)
	guests := []vmcontrolseed.Guest{{ID: "gru-one", Address: "10.77.0.10", MembershipPublicKey: seedPublic}, {ID: "gru-two", Address: "10.77.0.11", MembershipPublicKey: peerPublic}}
	var materials map[string]vmcontrolseed.Material
	var err error
	if declaration == nil {
		materials, err = vmcontrolseed.GenerateGRU("runtime-test", guests)
	} else {
		materials, err = vmcontrolseed.GenerateGRUWithPreliminaryCapture("runtime-test", guests, *declaration)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, m := range materials {
			m.Clear()
		}
	}()
	listener, err := net.Listen("tcp", "10.77.0.10:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "tls://" + listener.Addr().String()
	listener.Close()
	root, err := os.MkdirTemp("/var/lib", "receiver-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	var output []initialgrant.Config
	for _, id := range []string{"gru-one", "gru-two"} {
		material := materials[id]
		directory := filepath.Join(root, id)
		for path, data := range material.Files {
			write(t, strings.NewReplacer(vmcontrolseed.Directory, directory, vmcontrolseed.AuthorityDirectory, directory+"/reader").Replace(path), data)
		}
		settings := strings.NewReplacer(vmcontrolseed.Directory, directory, vmcontrolseed.AuthorityDirectory, directory+"/reader").Replace(material.Settings)
		settings = strings.ReplaceAll(settings, vmcontrolseed.StorePath, filepath.Join(root, "nats"))
		settings = strings.ReplaceAll(settings, vmcontrolseed.CaptureOutputPath, filepath.Join(root, "capture"))
		settings = strings.ReplaceAll(settings, vmcontrolseed.PublicationStatePath, filepath.Join(root, "publication"))
		settings = strings.ReplaceAll(settings, "tls://10.77.0.10:4222", endpoint)
		var c initialgrant.Config
		if err = json.Unmarshal([]byte(settings), &c); err != nil {
			t.Fatal(err)
		}
		if c.Role == "seed" {
			var broker map[string]any
			if err = json.Unmarshal([]byte(c.Broker.Configuration), &broker); err != nil {
				t.Fatal(err)
			}
			broker["listen"] = strings.TrimPrefix(endpoint, "tls://")
			delete(broker, "host")
			delete(broker, "port")
			var buffer bytes.Buffer
			encoder := json.NewEncoder(&buffer)
			encoder.SetEscapeHTML(false)
			if err = encoder.Encode(broker); err != nil {
				t.Fatal(err)
			}
			c.Broker.Configuration = strings.TrimSpace(buffer.String())
		}
		key := seedKey
		if id == "gru-two" {
			key = peerKey
		}
		write(t, c.Membership.SigningKeyFile, key)
		pins := map[string]string{"gru-one": seedPublic, "gru-two": peerPublic}
		data, _ := json.Marshal(pins)
		write(t, c.Membership.PinsFile, data)
		// Generation already binds these exact, canonical public pin bytes.
		if err = c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.Role == "seed" {
			options := &server.Options{}
			if err = options.ProcessConfigString(c.Broker.Configuration); err != nil {
				t.Fatalf("fixture broker: %v", err)
			}
		}
		output = append(output, c)
	}
	return output[0], output[1]
}
func admit(t *testing.T, c initialgrant.Config) *fixture {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	spec := hostmanifest.ComponentSpec{Name: "orchestrator", Version: "initial-test", ArtifactURL: "https://releases.example/orchestrator", SignatureURL: "https://releases.example/orchestrator.sig", Sha256: strings.Repeat("a", 64), User: "terrascale-orchestrator", DataVolume: "/var/lib/terrascale/orchestrator", CPUWeight: 100, MemoryMaxBytes: 1 << 30, IOWeight: 100, Arguments: initialgrant.Arguments, Configuration: string(raw)}
	manifest, err := hostmanifest.CanonicalHostManifestJSON(hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Close() })
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	signed, err := nodebootstrap.SignBootstrapGrant(signer, nodebootstrap.BootstrapGrant{Version: 1, GrantID: "owner-initial-test", NodeID: c.NodeID, Manifest: manifest, IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := initialgrant.VerifyProof(c.NodeID, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), signed)
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(t.TempDir(), "epochs")
	if err = os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	epochs, err := nodeauthority.NewEpochStore(private, c.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { epochs.Close() })
	identity := proof.Identity()
	if err = epochs.AdmitBootstrap(identity.GrantSHA256, identity.ManifestSHA256); err != nil {
		t.Fatal(err)
	}
	if err = initialgrant.Publish(t.Context(), epochs, proof); err != nil {
		t.Fatal(err)
	}
	admission, err := initialgrant.AdmitConfiguration(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{config: c, proof: proof, epochs: epochs, admission: admission, owner: signer}
}
func client(t *testing.T, c initialgrant.Config, identity initialgrant.Connection) *nats.Conn {
	t.Helper()
	option, err := nats.NkeyOptionFromSeed(identity.NKeySeedFile)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := nats.Connect(c.Broker.Endpoint, option, nats.RootCAs(identity.TLS.CAFile), nats.ClientCert(identity.TLS.CertificateFile, identity.TLS.KeyFile), nats.Timeout(time.Second), nats.NoReconnect(), nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func TestInitialRuntimeBlankDiskRetryAndRetirement(t *testing.T) {
	namespace(t)
	config, _ := fixtureConfig(t)
	f := admit(t, config)
	runtime, err := initialcontrol.Start(t.Context(), f.admission)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close() })
	if !runtime.RegionalAuthority().Ready() || !runtime.GlobalAuthority().Ready() {
		t.Fatal("real authority leases not ready")
	}
	nc := client(t, config, config.Regional.Runtime)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	members, err := js.KeyValue(t.Context(), "ORCH_RUNTIME")
	if err != nil {
		t.Fatal(err)
	}
	entry, err := members.Get(t.Context(), "controller."+config.Instance)
	if err != nil {
		t.Fatal(err)
	}
	var member struct{ Signature string }
	if err = json.Unmarshal(entry.Value(), &member); err != nil {
		t.Fatal(err)
	}
	snapshot := runtime.Membership()
	if len(snapshot.Members) != 1 || !snapshot.Members[0].VerifySignedIdentity() {
		t.Fatal("actual runtime membership is not signed")
	}
	// A runtime identity cannot turn a profile conflict into infrastructure work.
	denied, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	_, err = js.CreateStream(denied, jetstream.StreamConfig{Name: "ESCAPE", Subjects: []string{"escape"}, Storage: jetstream.FileStorage})
	cancel()
	if err == nil {
		t.Fatal("restricted runtime provisioned a stream")
	}
	nc.Close()
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Err(); err != nil {
		t.Fatalf("normal shutdown reported a component failure: %v", err)
	}
	runtime, err = initialcontrol.Start(t.Context(), f.admission)
	if err != nil {
		t.Fatalf("exact retained-profile restart: %v", err)
	}
	// Retirement consumes the actual coordinator's durable lease, including its
	// generated epoch and lease identity, rather than fabricating an epoch.
	nc = client(t, config, config.Regional.Runtime)
	js, _ = jetstream.New(nc)
	leaders, err := js.KeyValue(t.Context(), "ORCH_LEADERS")
	if err != nil {
		t.Fatal(err)
	}
	leaseEntry, err := leaders.Get(t.Context(), "authority.regional")
	if err != nil {
		t.Fatal(err)
	}
	var lease struct {
		AuthorityId          string
		Epoch                int64
		CandidateId, LeaseId string
		IssuedAt             time.Time
		DurationMilliseconds int64
	}
	if err = json.Unmarshal(leaseEntry.Value(), &lease); err != nil {
		t.Fatal(err)
	}
	replacement := hostmanifest.HostManifest{}
	command, err := hostmanifest.NewApplyManifestCommand("retire-real-runtime", f.proof.Identity().ManifestSHA256, replacement)
	if err != nil {
		t.Fatal(err)
	}
	commandBytes, _ := json.Marshal(command)
	authorization := nodeauthority.CommandAuthorization{NodeID: config.NodeID, AuthorityID: lease.AuthorityId, Epoch: lease.Epoch, CandidateID: lease.CandidateId, LeaseID: lease.LeaseId, ExpiresAt: lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds) * time.Millisecond), Command: commandBytes}
	if err = f.epochs.Admit(authorization); err != nil {
		t.Fatal(err)
	}
	replacementHash, _ := hostmanifest.HostManifestSha256(replacement)
	if err = f.epochs.RetireInitialR1(t.Context(), nodeauthority.InitialR1AdmissionDirectory, f.proof.Identity(), authorization, command.CommandId, f.proof.Identity().ManifestSHA256, replacementHash); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runtime.Completion():
	case <-time.After(5 * time.Second):
		t.Fatal("retirement did not shut down runtime")
	}
	if _, err = initialcontrol.Start(t.Context(), f.admission); err == nil {
		t.Fatal("retired admission restarted initial control")
	}
}

func TestInitialRuntimeInsufficientBudgetBeforeBroker(t *testing.T) {
	namespace(t)
	c, _ := fixtureConfig(t)
	c.Broker.StorageBudgetBytes = 256 << 20
	f := admit(t, c)
	if runtime, err := initialcontrol.Start(t.Context(), f.admission); err == nil {
		runtime.Close()
		t.Fatal("insufficient budget admitted")
	}
	if _, err := os.Stat(c.Broker.StoreDir); !os.IsNotExist(err) {
		t.Fatal("rejected budget created storage")
	}
}

func TestInitialRuntimeRejectsConflictingRetainedProfile(t *testing.T) {
	namespace(t)
	c, _ := fixtureConfig(t)
	f := admit(t, c)
	runtime, err := initialcontrol.Start(t.Context(), f.admission)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close() })
	nc := client(t, c, *c.Regional.Provisioner)
	js, _ := jetstream.New(nc)
	stream, err := js.Stream(t.Context(), "CELL_EVENTS")
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	info.Config.MaxBytes++
	if _, err = js.UpdateStream(t.Context(), info.Config); err != nil {
		t.Fatal(err)
	}
	nc.Close()
	runtime.Close()
	if r, err := initialcontrol.Start(t.Context(), f.admission); err == nil {
		r.Close()
		t.Fatal("conflicting existing profile was silently updated")
	}
}

func TestInitialParticipantProcess(t *testing.T) {
	path := os.Getenv("TS_INITIALCONTROL_PARTICIPANT_CONFIG")
	if path == "" {
		t.Skip("subprocess helper")
	}
	namespace(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := initialgrant.ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Role != "participant" || c.Global != nil || c.Regional.Provisioner != nil || c.Broker.Configuration != "" {
		t.Fatal("participant has seed privileges")
	}
	f := admit(t, c)
	runtime, err := initialcontrol.Start(t.Context(), f.admission)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if !runtime.RegionalAuthority().Ready() || runtime.GlobalAuthority().Epoch != 0 {
		t.Fatal("participant authority composition differs")
	}
	nc := client(t, c, c.Regional.Runtime)
	js, _ := jetstream.New(nc)
	denied, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	_, err = js.CreateStream(denied, jetstream.StreamConfig{Name: "PARTICIPANT_ESCAPE", Subjects: []string{"escape"}, Storage: jetstream.FileStorage})
	cancel()
	if err == nil {
		t.Fatal("participant provisioned a stream")
	}
	write(t, path+".ready", []byte("ready"))
	stopped := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); close(stopped) }()
	select {
	case <-stopped:
	case <-runtime.Completion():
		if os.Getenv("TS_INITIALCONTROL_EXPECT_DISCONNECT") == "1" && runtime.Err() != nil && !runtime.RegionalAuthority().Ready() {
			return
		}
		t.Fatalf("participant stopped unexpectedly: %v", runtime.Err())
	case <-time.After(30 * time.Second):
		t.Fatal("participant parent did not stop")
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInitialSeedAndParticipantUseOneBroker(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		name := "participant-stops-independently"
		if disconnect {
			name = "broker-loss-stops-participant"
		}
		t.Run(name, func(t *testing.T) { initialSeedAndParticipant(t, disconnect) })
	}
}

func initialSeedAndParticipant(t *testing.T, disconnect bool) {
	t.Helper()
	namespace(t)
	seed, peer := fixtureConfig(t)
	f := admit(t, seed)
	runtime, err := initialcontrol.Start(t.Context(), f.admission)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	path := filepath.Join(t.TempDir(), "participant.json")
	data, _ := json.Marshal(peer)
	write(t, path, data)
	command := exec.Command("unshare", "-m", "--propagation", "private", os.Args[0], "-test.run=^TestInitialParticipantProcess$", "-test.v", "-test.timeout=35s")
	command.Env = append(os.Environ(), "TS_INITIALCONTROL_PARTICIPANT_CONFIG="+path)
	if disconnect {
		command.Env = append(command.Env, "TS_INITIALCONTROL_EXPECT_DISCONNECT=1")
	}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		stdin.Close()
		if !waited {
			command.Process.Kill()
			command.Wait()
		}
	}()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err = os.Stat(path + ".ready"); err == nil && len(runtime.Membership().Members) == 2 {
			break
		}
		select {
		case <-deadline.C:
			stdin.Close()
			command.Process.Kill()
			command.Wait()
			waited = true
			t.Fatalf("second signed member absent: %s", output.String())
		case <-ticker.C:
		}
	}
	for _, member := range runtime.Membership().Members {
		if !member.VerifySignedIdentity() {
			t.Fatal("unsigned member in real two-process composition")
		}
	}
	if !runtime.GlobalAuthority().IsLeader {
		t.Fatal("seed global authority unavailable")
	}
	if disconnect {
		if err = runtime.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		stdin.Close()
	}
	if err = command.Wait(); err != nil {
		waited = true
		t.Fatalf("participant failed: %v %s", err, output.String())
	}
	waited = true
	if !disconnect && !runtime.GlobalAuthority().Ready() {
		t.Fatal("participant shutdown stopped seed broker")
	}
}

func TestInitialSignedBrokerRejectsPlaintextBeforeListener(t *testing.T) {
	namespace(t)
	c, _ := fixtureConfig(t)
	var broker map[string]any
	if err := json.Unmarshal([]byte(c.Broker.Configuration), &broker); err != nil {
		t.Fatal(err)
	}
	broker["tls"].(map[string]any)["allow_non_tls"] = true
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(broker); err != nil {
		t.Fatal(err)
	}
	c.Broker.Configuration = strings.TrimSpace(buffer.String())
	f := admit(t, c)
	if r, err := initialcontrol.Start(t.Context(), f.admission); err == nil {
		r.Close()
		t.Fatal("mixed plaintext listener admitted")
	}
	if _, err := os.Stat(c.Broker.StoreDir); !os.IsNotExist(err) {
		t.Fatal("rejected broker created storage")
	}
	address := strings.TrimPrefix(c.Broker.Endpoint, "tls://")
	connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
	if err == nil {
		connection.Close()
		t.Fatal("rejected broker opened a listener")
	}
}

func TestInitialSwappedMaterialAfterAdmissionBeforeEffects(t *testing.T) {
	namespace(t)
	c, _ := fixtureConfig(t)
	f := admit(t, c)
	ca, err := os.ReadFile(c.Broker.TLS.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	write(t, c.Broker.TLS.CAFile, append(ca, '\n'))
	if r, err := initialcontrol.Start(t.Context(), f.admission); err == nil {
		r.Close()
		t.Fatal("changed captured credential accepted")
	}
	if _, err := os.Stat(c.Broker.StoreDir); !os.IsNotExist(err) {
		t.Fatal("changed credential created storage")
	}
}
