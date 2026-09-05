package initialgrant

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func preliminaryConfigFixture(t *testing.T) Config {
	t.Helper()
	c := configFixture(t)
	other := configFixture(t)
	c.PreliminaryCapture = &PreliminaryCaptureConfig{RequestFile: "/var/lib/terrascale/capture-request.json", OutputDir: "/var/lib/terrascale/capture", MaxSnapshotBytes: 1 << 30, MaxTotalBytes: 256 << 30, Regional: other.Regional.Runtime, Global: other.Global.Runtime}
	return c
}

func TestPreliminaryCaptureConfiguration(t *testing.T) {
	legacy := configFixture(t)
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("preliminaryCapture")) {
		t.Fatal("optional capability changed legacy configuration")
	}
	if parsed, err := ParseConfig(raw); err != nil || parsed.PreliminaryCapture != nil {
		t.Fatalf("legacy configuration: %v", err)
	}
	participant := configFixture(t)
	self := configFixture(t)
	participant.Role, participant.NodeID, participant.Instance = "participant", "gru-2", "gru-2"
	participant.Global, participant.Regional.Provisioner = nil, nil
	participant.Broker.Configuration, participant.Broker.TLS = "", TLSFiles{}
	participant.Regional.Runtime = self.Regional.Runtime
	participant.AuthorityReader = self.AuthorityReader
	participant.Membership = self.Membership
	peer := self.Peers[0]
	peer.Instance, peer.GlobalPublicNKey = "gru-2", ""
	participant.Peers = append(participant.Peers, peer)
	if err := participant.Validate(); err != nil {
		t.Fatalf("participant baseline: %v", err)
	}
	participant.PreliminaryCapture = preliminaryConfigFixture(t).PreliminaryCapture
	if participant.Validate() == nil {
		t.Fatal("participant admitted seed-only capture")
	}
	valid := preliminaryConfigFixture(t)
	raw, err = json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseConfig(raw); err != nil {
		t.Fatalf("bounded capture configuration: %v", err)
	}
	cases := map[string]func(*Config){
		"participant":              func(c *Config) { c.Role = "participant" },
		"missing regional":         func(c *Config) { c.PreliminaryCapture.Regional = Connection{} },
		"missing global":           func(c *Config) { c.PreliminaryCapture.Global = Connection{} },
		"paired key collision":     func(c *Config) { c.PreliminaryCapture.Global.PublicNKey = c.PreliminaryCapture.Regional.PublicNKey },
		"runtime collision":        func(c *Config) { c.PreliminaryCapture.Regional.PublicNKey = c.Regional.Runtime.PublicNKey },
		"global runtime collision": func(c *Config) { c.PreliminaryCapture.Regional.PublicNKey = c.Global.Runtime.PublicNKey },
		"reader collision":         func(c *Config) { c.PreliminaryCapture.Regional.PublicNKey = c.AuthorityReader.PublicNKey },
		"provisioner collision":    func(c *Config) { c.PreliminaryCapture.Global.PublicNKey = c.Global.Provisioner.PublicNKey },
		"relative request":         func(c *Config) { c.PreliminaryCapture.RequestFile = "request.json" },
		"unclean output":           func(c *Config) { c.PreliminaryCapture.OutputDir = "/var/lib/../capture" },
		"root output":              func(c *Config) { c.PreliminaryCapture.OutputDir = "/" },
		"output in broker":         func(c *Config) { c.PreliminaryCapture.OutputDir = c.Broker.StoreDir + "/capture" },
		"broker in output":         func(c *Config) { c.PreliminaryCapture.OutputDir = "/data" },
		"request in output":        func(c *Config) { c.PreliminaryCapture.RequestFile = c.PreliminaryCapture.OutputDir + "/request" },
		"output at request":        func(c *Config) { c.PreliminaryCapture.OutputDir = c.PreliminaryCapture.RequestFile },
		"output below request":     func(c *Config) { c.PreliminaryCapture.OutputDir = c.PreliminaryCapture.RequestFile + "/output" },
		"snapshot too small":       func(c *Config) { c.PreliminaryCapture.MaxSnapshotBytes = 1023 },
		"snapshot too large":       func(c *Config) { c.PreliminaryCapture.MaxSnapshotBytes = 1<<30 + 1 },
		"total below snapshot":     func(c *Config) { c.PreliminaryCapture.MaxTotalBytes = c.PreliminaryCapture.MaxSnapshotBytes - 1 },
		"total over 256 GiB":       func(c *Config) { c.PreliminaryCapture.MaxTotalBytes = 256<<30 + 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := preliminaryConfigFixture(t)
			mutate(&c)
			if c.Validate() == nil {
				t.Fatal("accepted invalid capture configuration")
			}
		})
	}
}

func TestReadPreliminaryRequestProtectedFile(t *testing.T) {
	privatePublicationNamespace(t)
	root := "/var/lib/preliminary-request-test"
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "request")
	if _, err := ReadPreliminaryRequest(path); !os.IsNotExist(err) {
		t.Fatalf("missing request: %v", err)
	}
	check := func(want bool) {
		t.Helper()
		_, err := ReadPreliminaryRequest(path)
		if (err == nil) != want {
			t.Fatalf("read success=%v, want %v: %v", err == nil, want, err)
		}
	}
	write := func(raw []byte) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	write([]byte("signed-request"))
	raw, err := ReadPreliminaryRequest(path)
	if err != nil || string(raw) != "signed-request" {
		t.Fatalf("protected request: %q, %v", raw, err)
	}
	must(os.Chmod(root, 0770))
	check(false)
	must(os.Chmod(root, 0700))
	must(os.Chown(root, 65534, 65534))
	check(false)
	must(os.Chown(root, 0, 0))
	must(os.Chmod(path, 0660))
	check(false)
	must(os.Chmod(path, 0600))
	must(os.Chown(path, 65534, 65534))
	check(false)
	must(os.Chown(path, 0, 0))
	must(os.Link(path, path+".link"))
	check(false)
	must(os.Remove(path + ".link"))
	write(nil)
	check(false)
	write(bytes.Repeat([]byte("x"), 64<<10))
	check(true)
	write(bytes.Repeat([]byte("x"), (64<<10)+1))
	check(false)
	must(os.Remove(path))
	must(os.Symlink("/etc/passwd", path))
	check(false)
	must(os.Remove(path))
	must(unix.Mkfifo(path, 0600))
	check(false)
	must(os.Remove(path))
	must(os.Mkdir(path, 0700))
	check(false)
	must(os.Remove(path))
	write([]byte("request"))
	alias := root + "-alias"
	must(os.Symlink(root, alias))
	if _, err := ReadPreliminaryRequest(filepath.Join(alias, "request")); err == nil {
		t.Fatal("symlink ancestry accepted")
	}
	for _, bad := range []string{"relative", root + "/../request", path + "\n"} {
		if _, err := ReadPreliminaryRequest(bad); err == nil {
			t.Fatalf("unsafe path %q accepted", bad)
		}
	}
}

func TestPreliminaryRequestUsesAdmittedOwnerAndScope(t *testing.T) {
	privatePublicationNamespace(t)
	cfg := preliminaryConfigFixture(t)
	base := proofFixture(t)
	spec := base.Component()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	spec.Configuration = string(raw)
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
	defer signer.Close()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	signed, err := nodebootstrap.SignBootstrapGrant(signer, nodebootstrap.BootstrapGrant{Version: 1, GrantID: "capture-owner", NodeID: cfg.NodeID, Manifest: manifest, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyProof(cfg.NodeID, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), signed)
	if err != nil {
		t.Fatal(err)
	}
	epochDir := "/var/lib/preliminary-request-epochs"
	if err := os.Mkdir(epochDir, 0700); err != nil {
		t.Fatal(err)
	}
	epochs, err := nodeauthority.NewEpochStore(epochDir, cfg.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer epochs.Close()
	if err := epochs.AdmitBootstrap(p.identity.GrantSHA256, p.identity.ManifestSHA256); err != nil {
		t.Fatal(err)
	}
	if err := Publish(t.Context(), epochs, p); err != nil {
		t.Fatal(err)
	}
	a, err := AdmitComponent(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	request := preliminarycapture.Request{Version: 1, TransitionID: "capture-1", SourceNodeID: cfg.NodeID, InitialGrantSHA256: p.identity.GrantSHA256, StoreScopeSHA256: p.identity.StoreScopeSHA256, ProfileSHA256: cfg.ProfileSHA256, Accounts: []preliminarycapture.AccountInventory{{Account: cfg.Regional.Account, Streams: []string{"EVENTS"}}, {Account: cfg.Global.Account, Streams: []string{"SPEC"}}}, ControlEpoch: 1, IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute)}
	sign := func(r preliminarycapture.Request, s *security.CommandSignatureSigner) []byte {
		t.Helper()
		raw, err := preliminarycapture.SignRequest(s, r)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err := a.VerifyPreliminaryRequest(t.Context(), sign(request, signer)); err != nil {
		t.Fatalf("admitted owner request: %v", err)
	}
	cases := map[string]func(*preliminarycapture.Request){
		"foreign node":         func(r *preliminarycapture.Request) { r.SourceNodeID = "gru-other" },
		"foreign grant":        func(r *preliminarycapture.Request) { r.InitialGrantSHA256 = strings.Repeat("b", 64) },
		"foreign store":        func(r *preliminarycapture.Request) { r.StoreScopeSHA256 = strings.Repeat("b", 64) },
		"foreign profile":      func(r *preliminarycapture.Request) { r.ProfileSHA256 = strings.Repeat("b", 64) },
		"foreign account":      func(r *preliminarycapture.Request) { r.Accounts[0].Account = "OTHER" },
		"reordered accounts":   func(r *preliminarycapture.Request) { r.Accounts[0], r.Accounts[1] = r.Accounts[1], r.Accounts[0] },
		"before initial grant": func(r *preliminarycapture.Request) { r.IssuedAt = now.Add(-2 * time.Minute) },
		"beyond initial grant": func(r *preliminarycapture.Request) { r.ExpiresAt = now.Add(2 * time.Hour) },
		"expired": func(r *preliminarycapture.Request) {
			r.IssuedAt = now.Add(-30 * time.Second)
			r.ExpiresAt = now.Add(-time.Second)
		},
		"future": func(r *preliminarycapture.Request) { r.IssuedAt = now.Add(time.Minute) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := request
			r.Accounts = append([]preliminarycapture.AccountInventory(nil), request.Accounts...)
			mutate(&r)
			if _, err := a.VerifyPreliminaryRequest(t.Context(), sign(r, signer)); err == nil {
				t.Fatal("accepted request outside admitted scope")
			}
		})
	}
	foreignKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := security.NewCommandSignatureSignerFromKey(foreignKey)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	if _, err := a.VerifyPreliminaryRequest(t.Context(), sign(request, foreign)); err == nil {
		t.Fatal("request-nominated owner accepted")
	}
	var absent *Admission
	if _, err := absent.VerifyPreliminaryRequest(t.Context(), sign(request, signer)); err == nil {
		t.Fatal("missing admission accepted")
	}
}
