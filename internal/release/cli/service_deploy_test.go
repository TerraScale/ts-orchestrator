package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
)

// serviceBucket is a region's head bucket whose leader admits the role's
// claim as a controller would, then reports outcome for it.
type serviceBucket struct {
	mu      sync.Mutex
	cell    string
	signer  ed25519.PublicKey
	outcome releasechannel.State
	objects map[string][]byte
	log     *[]string
	logMu   *sync.Mutex
}

func (bucket *serviceBucket) PutObject(_ context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	data, err := io.ReadAll(request.PutObjectBody)
	if err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	name := *request.ObjectName
	if _, exists := bucket.objects[name]; exists && request.IfNoneMatch != nil {
		return objectstorage.PutObjectResponse{}, httpError(412)
	}
	bucket.objects[name] = data
	bucket.logMu.Lock()
	*bucket.log = append(*bucket.log, "put "+bucket.cell+" "+name)
	bucket.logMu.Unlock()
	return objectstorage.PutObjectResponse{}, nil
}

func (bucket *serviceBucket) GetObject(_ context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	name := *request.ObjectName
	data, ok := bucket.objects[name]
	if name == releasechannel.ServiceStatusObject("ts-auth") {
		data, ok = bucket.status()
	}
	if !ok {
		return objectstorage.GetObjectResponse{}, httpError(404)
	}
	sum := sha256.Sum256(data)
	return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader(data)), ETag: new(hex.EncodeToString(sum[:]))}, nil
}

// status fails a claim that does not verify for the bucket's cell, or whose
// binary is missing or differs.
func (bucket *serviceBucket) status() ([]byte, bool) {
	claim, ok := bucket.objects[releasechannel.ServiceReleaseObject("ts-auth")]
	if !ok {
		return nil, false
	}
	issued, _ := releasechannel.ClaimIssuedAt(claim)
	cell := strings.ToLower(bucket.cell)
	keyID, _ := protocol.KeyID(bucket.signer)
	codec := delivery.Ed25519Codec{Cell: cell, MaxLifetime: 5 * time.Minute, Trusted: map[string]delivery.TrustedSigner{
		keyID: {Actor: "ci-release", PublicKey: bucket.signer}}}
	status := releasechannel.ServiceStatus{Cell: bucket.cell, Role: "ts-auth", IssuedAt: issued, State: bucket.outcome}
	record, actor, err := codec.VerifyArchivedArtifact(context.Background(), claim)
	if err == nil {
		status.Digest = record.Digest
		binary := bucket.objects[releasechannel.ServiceBinaryObject("ts-auth", record.Digest)]
		sum := sha256.Sum256(binary)
		if actor != "ci-release" || record.Role != "ts-auth" || hex.EncodeToString(sum[:]) != record.Digest || int64(len(binary)) != record.Size {
			err = errors.New("the binary is not the claimed one")
		}
	}
	if err != nil {
		status.State, status.Reason = releasechannel.StateFailed, err.Error()
	}
	encoded, _ := json.Marshal(status)
	return encoded, true
}

type serviceDeployFixture struct {
	binary, checkout, commit, key string
	buckets                       map[string]*serviceBucket
	log                           []string
	logMu                         sync.Mutex
	env                           deployEnv
}

func newServiceDeployFixture(t *testing.T) *serviceDeployFixture {
	t.Helper()
	directory := t.TempDir()
	fixture := &serviceDeployFixture{buckets: map[string]*serviceBucket{}, checkout: filepath.Join(directory, "source")}
	if err := os.Mkdir(fixture.checkout, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(fixture.checkout, "README"), []byte("ts-auth\n"), 0o644)
	for _, args := range [][]string{{"init", "-q"}, {"add", "README"},
		{"-c", "user.name=ci", "-c", "user.email=ci@example.com", "commit", "-q", "-m", "release"}} {
		if out, err := exec.Command("git", append([]string{"-C", fixture.checkout}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	out, err := exec.Command("git", "-C", fixture.checkout, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	fixture.commit = strings.TrimSpace(string(out))
	fixture.binary = filepath.Join(directory, "ts-auth-linux-arm64")
	writeFixtureFile(t, fixture.binary, []byte("ts-auth release"), 0o755)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture.key = filepath.Join(directory, "release.key")
	writePrivateKey(t, fixture.key, private)
	for _, cell := range []string{"GRU", "SFO"} {
		fixture.buckets[cell] = &serviceBucket{cell: cell, signer: public, outcome: releasechannel.StateComplete,
			objects: map[string][]byte{}, log: &fixture.log, logMu: &fixture.logMu}
	}
	fixture.env = deployEnv{
		storage: func(cell string) (releasechannel.ObjectClient, error) { return fixture.buckets[cell], nil },
		secret:  func(context.Context, string, string) ([]byte, error) { return nil, errors.New("no Vault in this test") },
	}
	return fixture
}

func (fixture *serviceDeployFixture) args(cells ...string) []string {
	args := []string{"--role", "ts-auth", "--binary", fixture.binary,
		"--repository", "https://git.terrascale.tech/TerraScale/ts-auth", "--commit", fixture.commit,
		"--source-checkout", fixture.checkout, "--environment", "canary", "--actor", "ci-release",
		"--signing-key", fixture.key, "--namespace", "ns", "--poll", "1ms", "--region-timeout", "2s"}
	for _, cell := range cells {
		args = append(args, "--cell", cell)
	}
	return args
}

func TestServiceDeployReleasesEveryRegion(t *testing.T) {
	fixture := newServiceDeployFixture(t)
	var output bytes.Buffer
	c := command{ctx: t.Context(), output: &output}
	if err := c.serviceDeployWith(fixture.args("GRU", "SFO"), fixture.env); err != nil {
		t.Fatalf("%v\n%s", err, output.String())
	}
	sum := sha256.Sum256([]byte("ts-auth release"))
	digest := hex.EncodeToString(sum[:])
	want := []string{
		"put GRU " + releasechannel.ServiceBinaryObject("ts-auth", digest),
		"put GRU " + releasechannel.ServiceReleaseObject("ts-auth"),
		"put SFO " + releasechannel.ServiceBinaryObject("ts-auth", digest),
		"put SFO " + releasechannel.ServiceReleaseObject("ts-auth"),
	}
	slices.Sort(fixture.log)
	slices.Sort(want)
	if !slices.Equal(fixture.log, want) {
		t.Fatalf("writes %q, want %q", fixture.log, want)
	}
	if !strings.Contains(output.String(), "ts-auth complete: "+digest) {
		t.Fatalf("output:\n%s", output.String())
	}
	// The claim binds the source tree CI built from.
	tree, err := exec.Command("sh", "-c", "git -C '"+fixture.checkout+"' archive --format=tar HEAD | sha256sum").Output()
	if err != nil {
		t.Fatal(err)
	}
	var envelope protocol.Envelope
	var record delivery.ArtifactRecord
	if err := json.Unmarshal(fixture.buckets["GRU"].objects[releasechannel.ServiceReleaseObject("ts-auth")], &envelope); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(envelope.Payload, &record); err != nil {
		t.Fatal(err)
	}
	if record.Cell != "gru" || record.Environment != "canary" || record.Source.Commit != fixture.commit ||
		record.Source.TreeDigest != strings.Fields(string(tree))[0] {
		t.Fatalf("claim %+v", record)
	}
}

func TestServiceDeployFinishesOtherRegionsWhenOneRollsBack(t *testing.T) {
	fixture := newServiceDeployFixture(t)
	fixture.buckets["GRU"].outcome = releasechannel.StateFailed
	c := command{ctx: t.Context(), output: io.Discard}
	err := c.serviceDeployWith(fixture.args("GRU", "SFO"), fixture.env)
	if !errors.Is(err, releasechannel.ErrFailed) {
		t.Fatalf("a rolled-back canary: %v", err)
	}
	if !slices.Contains(fixture.log, "put SFO "+releasechannel.ServiceReleaseObject("ts-auth")) {
		t.Fatalf("SFO did not receive its independent release: %q", fixture.log)
	}
}

func TestServiceDeployRefusesIncompleteArguments(t *testing.T) {
	fixture := newServiceDeployFixture(t)
	c := command{ctx: t.Context(), output: io.Discard}
	both := append(fixture.args("GRU"), "--signing-key-secret", "release", "--vault-id", "v")
	if err := c.serviceDeployWith(both, fixture.env); err == nil {
		t.Fatal("service-deploy accepted two key sources")
	}
	if err := c.serviceDeployWith(fixture.args("NOPE"), fixture.env); err == nil {
		t.Fatal("service-deploy accepted an unknown cell")
	}
	if err := c.serviceDeployWith(fixture.args(), fixture.env); err == nil {
		t.Fatal("service-deploy accepted no cell")
	}
	if len(fixture.log) != 0 {
		t.Fatalf("a refused deployment wrote %q", fixture.log)
	}
}
