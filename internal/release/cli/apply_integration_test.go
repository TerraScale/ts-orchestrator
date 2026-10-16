package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// This scenario crosses the real artifact/crypto, Git, OCI SDK and HTTP boundaries.
// The endpoint simulates regional Object Storage; it does not qualify live OCI.
func TestSignedApplyRegionalHTTPRecovery(t *testing.T) {
	fixture := newApplyHTTPFixture(t)
	for _, failure := range []string{"unreachable", "missing", "stale", "environment", "architecture", "storage", "qualification"} {
		t.Run(failure, func(t *testing.T) {
			fixture.reset(failure)
			qualificationPath := filepath.Join(filepath.Dir(filepath.Dir(fixture.binaryPath)), "production", "SFO", "amd64", "production.json")
			var qualificationWire []byte
			if failure == "qualification" {
				var err error
				qualificationWire, err = os.ReadFile(qualificationPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(qualificationPath); err != nil {
					t.Fatal(err)
				}
			}
			var output bytes.Buffer
			c := command{ctx: t.Context(), output: &output}
			err := c.applyWith(fixture.args, fixture.env)
			if err == nil || !strings.Contains(err.Error(), "SFO") {
				t.Fatalf("missing regional failure: %v\n%s", err, output.String())
			}
			fixture.mu.Lock()
			for _, cell := range []string{"FRA", "GRU"} {
				if fixture.channelWrites[cell] != 1 {
					t.Errorf("healthy %s did not publish independently: %v", cell, fixture.channelWrites)
				}
			}
			if fixture.channelWrites["SFO"] != 0 {
				t.Errorf("failed region published a channel: %v", fixture.channelWrites)
			}
			fixture.failure = ""
			fixture.mu.Unlock()
			if failure == "qualification" {
				if err := os.WriteFile(qualificationPath, qualificationWire, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if fixture.inspections.Load() != 1 {
				t.Fatalf("same digest inspected %d times", fixture.inspections.Load())
			}
			if err := c.applyWith(fixture.args, fixture.env); err != nil {
				t.Fatalf("retry did not recover: %v\n%s", err, output.String())
			}
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			for _, cell := range []string{"FRA", "GRU", "SFO"} {
				if fixture.binaryCreates[cell] != 1 || len(fixture.objects[cell]) != 2 {
					t.Errorf("retry lost/duplicated %s immutable bytes: creates=%v objects=%d", cell, fixture.binaryCreates, len(fixture.objects[cell]))
				}
			}
		})
	}
	t.Run("tampered local bytes block every write", func(t *testing.T) {
		fixture.reset("")
		if err := os.WriteFile(fixture.binaryPath, []byte("tampered"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := (command{ctx: t.Context(), output: io.Discard}).applyWith(fixture.args, fixture.env); err == nil {
			t.Fatal("tampered bundle admitted")
		}
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		if len(fixture.channelWrites) != 0 || len(fixture.binaryCreates) != 0 {
			t.Fatal("bundle failed local validation after remote mutation")
		}
	})
}

type applyHTTPFixture struct {
	mu             sync.Mutex
	failure        string
	objects        map[string]map[string][]byte
	channelWrites  map[string]int
	binaryCreates  map[string]int
	inspections    atomic.Int64
	binaryPath     string
	releaseDir     string
	rootPath       string
	rootPrivate    ed25519.PrivateKey
	leafPath       string
	delegationPath string
	sourceDir      string
	binary         binaryReceipt
	args           []string
	env            deployEnv
	roots          trust.Keyring
}

func (f *applyHTTPFixture) reset(failure string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failure = failure
	f.objects = make(map[string]map[string][]byte)
	f.channelWrites = make(map[string]int)
	f.binaryCreates = make(map[string]int)
	f.inspections.Store(0)
}

func newApplyHTTPFixture(t *testing.T) *applyHTTPFixture {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", []byte("module release-fixture\n\ngo 1.27.1\n"))
	write("main.go", []byte("package main\nfunc main() {}\n"))
	applyFixtureCommand(t, dir, "git", "init", "-q", "--initial-branch=main")
	applyFixtureCommand(t, dir, "git", "add", "go.mod", "main.go")
	applyFixtureCommand(t, dir, "git", "-c", "user.name=Release fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
	revision := strings.TrimSpace(applyFixtureCommand(t, dir, "git", "rev-parse", "HEAD"))
	binaryPath := filepath.Join(t.TempDir(), "binary")
	applyFixtureCommand(t, dir, "go", "build", "-buildvcs=true", "-o", binaryPath, ".")
	c := command{ctx: t.Context(), output: io.Discard}
	goVersion := strings.TrimSpace(applyFixtureCommand(t, dir, "go", "env", "GOVERSION"))
	binary, err := c.inspectBinary(binaryPath, goVersion, revision)
	if err != nil {
		t.Fatal(err)
	}
	armPath := filepath.Join(t.TempDir(), "arm64")
	applyFixtureCommand(t, dir, "env", "GOARCH=arm64", "go", "build", "-buildvcs=true", "-o", armPath, ".")
	arm, err := c.inspectBinary(armPath, goVersion, revision)
	if err != nil {
		t.Fatal(err)
	}
	qualification := release.Qualification{
		Schema: release.QualificationSchema, Repository: release.QualificationRepository,
		SourceRevision: revision, SourceTree: revision, GoVersion: goVersion,
		GoModSHA256: binary.SHA256, GoSumSHA256: binary.SHA256,
		Verification: release.QualificationCheck{Workflow: release.QualificationWorkflow, Job: release.QualificationJob,
			RunID: 4001, RunNumber: 620, Conclusion: "success"},
		Artifacts: []release.QualifiedArtifact{
			{Architecture: "amd64", Name: "terrascale-orchestrator-linux-amd64", Bytes: binary.Bytes, SHA256: binary.SHA256},
			{Architecture: "arm64", Name: "terrascale-orchestrator-linux-arm64", Bytes: arm.Bytes, SHA256: arm.SHA256},
		},
	}
	wire, err := trust.EncodePayload(qualification)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := release.DecodeQualification(wire)
	if err != nil {
		t.Fatal(err)
	}
	binary.QualificationSHA256 = digest
	retainedDir := t.TempDir()
	for _, artifact := range []struct{ name, path string }{
		{"terrascale-orchestrator-linux-amd64", binaryPath},
		{"terrascale-orchestrator-linux-arm64", armPath},
	} {
		data, err := os.ReadFile(artifact.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(retainedDir, artifact.name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(retainedDir, "qualification.json"), wire, 0o600); err != nil {
		t.Fatal(err)
	}
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := trust.KeyID(leafPublic)
	public, _ := trust.EncodeDelegatedPublicKey(leafPublic)
	now := time.Now().UTC()
	delegation, err := release.SignUpdateDelegation(release.BinaryUpdateDelegation{
		Schema: release.UpdateDelegationSchema, SubjectKeyID: keyID, SubjectPublicKey: public,
		Environment: "production", Architectures: []string{"amd64"}, Repository: release.QualificationRepository,
		Workflow: release.QualificationWorkflow, Ref: release.LineageRef, LineageBase: revision,
	}, now.Add(-time.Minute), now.Add(time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, _ := trust.EncodeEnvelope(delegation)
	write("update-delegation.json", delegationWire)
	leafDER, _ := x509.MarshalPKCS8PrivateKey(leafPrivate)
	write("leaf.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafDER}))
	bundle := t.TempDir()
	if err := os.Mkdir(filepath.Join(bundle, "binaries"), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	binaryPath = filepath.Join(bundle, "binaries", binary.SHA256)
	if err := os.WriteFile(binaryPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cell := range []string{"FRA", "GRU", "SFO"} {
		envelope, err := release.SignBinaryUpdateReceipt(binary, qualification, digest, cell, "production",
			applyFixtureLineage{t, dir}, delegation, roots, leafPrivate, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		receiptWire, _ := trust.EncodeEnvelope(envelope)
		channel := releasechannel.Channel{Schema: releasechannel.ChannelSchema, Cell: cell, Environment: "production",
			SourceRevision: revision, RunNumber: 620, Delegation: delegationWire, Receipts: []jsontext.Value{receiptWire}}
		wire, err := json.Marshal(channel)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(bundle, cell), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundle, cell, "channel.json"), wire, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, evidenceDir := range []string{filepath.Join(bundle, "production"), filepath.Join(retainedDir, "production")} {
			record := writeProductionEvidence(t, evidenceDir, productionCandidate(binary, cell))
			writeProductionRecord(t, filepath.Join(evidenceDir, cell, "amd64", "production.json"), record, rootPrivate,
				now.Add(-time.Minute), now.Add(time.Hour))
		}
	}
	rootDER, _ := x509.MarshalPKIXPublicKey(rootPublic)
	write("root.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rootDER}))
	f := &applyHTTPFixture{binaryPath: binaryPath, roots: roots, releaseDir: retainedDir,
		rootPath: filepath.Join(dir, "root.pub"), rootPrivate: rootPrivate,
		leafPath: filepath.Join(dir, "leaf.key"), delegationPath: filepath.Join(dir, "update-delegation.json"),
		sourceDir: dir, binary: binary,
		args: []string{"--dir", bundle, "--root-key", filepath.Join(dir, "root.pub"), "--namespace", "ns"}}
	f.reset("")
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(common.NewRawConfigurationProvider(
		"tenancy", "user", "sa-saopaulo-1", "fingerprint", string(keyPEM), nil))
	if err != nil {
		t.Fatal(err)
	}
	client.Host = server.URL
	client.HTTPClient = applyHTTPDispatcher{server}
	policy := common.NoRetryPolicy()
	client.SetCustomClientConfiguration(common.CustomClientConfiguration{RetryPolicy: &policy})
	f.env = deployEnv{timeout: 500 * time.Millisecond,
		storage: func(string) (releasechannel.ObjectClient, error) { return client, nil },
		inspect: func(path, version, revision string) (binaryReceipt, error) {
			f.inspections.Add(1)
			return c.inspectBinary(path, version, revision)
		},
	}
	return f
}

func (f *applyHTTPFixture) serve(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(r.URL.Path, "/", 7)
	if len(parts) != 7 || parts[1] != "n" || parts[3] != "b" || parts[5] != "o" || r.Header.Get("Authorization") == "" {
		http.Error(w, "invalid OCI request", http.StatusBadRequest)
		return
	}
	cell, _, _ := strings.Cut(strings.ToUpper(parts[4]), "-")
	name := parts[6]
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.objects[cell] == nil {
		f.objects[cell] = make(map[string][]byte)
	}
	if cell == "SFO" && f.failure == "unreachable" && name == releasechannel.StatusObject {
		f.mu.Unlock()
		<-r.Context().Done()
		f.mu.Lock()
		return
	}
	if cell == "SFO" && f.failure == "storage" && r.Method == http.MethodPut {
		http.Error(w, "unavailable", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPut {
		old, exists := f.objects[cell][name]
		if r.Header.Get("If-None-Match") == "*" && exists || r.Header.Get("If-Match") != "" && r.Header.Get("If-Match") != fmt.Sprintf("%x", len(old)) {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.objects[cell][name] = data
		if name == releasechannel.ChannelObject {
			f.channelWrites[cell]++
		} else {
			f.binaryCreates[cell]++
		}
		w.Header().Set("etag", fmt.Sprintf("%x", len(data)))
		return
	}
	data, exists := f.objects[cell][name]
	if name == releasechannel.StatusObject {
		status := releasechannel.Status{Schema: releasechannel.StatusSchema, Cell: cell, Environment: "production",
			Architectures: []string{"amd64"}, UpdatedAt: time.Now().UTC()}
		if cell == "SFO" {
			switch f.failure {
			case "missing":
				w.WriteHeader(http.StatusNotFound)
				return
			case "stale":
				status.UpdatedAt = status.UpdatedAt.Add(-time.Hour)
			case "environment":
				status.Environment = "canary"
			case "architecture":
				status.Architectures = []string{"arm64"}
			}
		}
		if wire, ok := f.objects[cell][releasechannel.ChannelObject]; ok {
			var channel releasechannel.Channel
			if err := json.Unmarshal(wire, &channel); err == nil {
				_, err := channel.Verify(f.roots, cell, "production", time.Now().UTC())
				status.SourceRevision, status.RunNumber = channel.SourceRevision, channel.RunNumber
				status.State = releasechannel.StateComplete
				if err != nil {
					status.State, status.Reason = releasechannel.StateFailed, err.Error()
				}
			}
		}
		data, _ = json.Marshal(status)
		exists = true
	}
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("etag", fmt.Sprintf("%x", len(data)))
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func applyFixtureCommand(t *testing.T, dir, program string, args ...string) string {
	t.Helper()
	name := program
	if os.Getenv("CI") != "true" {
		name, args = "nice", append([]string{"-n", "19", program}, args...)
	}
	command := exec.CommandContext(t.Context(), name, args...)
	command.Dir = dir
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", program, err, output)
	}
	return string(output)
}

type applyFixtureLineage struct {
	t   *testing.T
	dir string
}

func (l applyFixtureLineage) CheckLineage(base, revision, ref string) error {
	applyFixtureCommand(l.t, l.dir, "git", "merge-base", "--is-ancestor", base, revision)
	applyFixtureCommand(l.t, l.dir, "git", "merge-base", "--is-ancestor", revision, ref)
	return nil
}

// OCI SDK endpoint selection runs per operation; force all fixture traffic local.
type applyHTTPDispatcher struct{ server *httptest.Server }

func (d applyHTTPDispatcher) Do(request *http.Request) (*http.Response, error) {
	local, err := url.Parse(d.server.URL)
	if err != nil {
		return nil, err
	}
	request = request.Clone(request.Context())
	request.URL = request.URL.Clone()
	request.URL.Scheme, request.URL.Host = local.Scheme, local.Host
	request.Host = local.Host
	return d.server.Client().Do(request)
}
