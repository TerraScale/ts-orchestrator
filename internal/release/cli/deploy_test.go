package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"testing"

	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type httpError int

func (err httpError) Error() string          { return fmt.Sprintf("HTTP %d", int(err)) }
func (err httpError) GetHTTPStatusCode() int { return int(err) }

// regionBucket is a region's head bucket whose leader verifies the channel
// as a controller would and then reports outcome for it.
type regionBucket struct {
	mu      sync.Mutex
	cell    string
	roots   trust.Keyring
	outcome releasechannel.State
	objects map[string][]byte
	scope   *releasechannel.Status
	log     *[]string
	logMu   *sync.Mutex
	wait    func(context.Context) error
}

func (bucket *regionBucket) PutObject(_ context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
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

func (bucket *regionBucket) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	if *request.ObjectName == releasechannel.StatusObject && bucket.wait != nil {
		if err := bucket.wait(ctx); err != nil {
			return objectstorage.GetObjectResponse{}, err
		}
	}
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	name := *request.ObjectName
	data, ok := bucket.objects[name]
	if name == releasechannel.StatusObject && !ok {
		data, ok = bucket.status()
		if !ok && bucket.scope != nil {
			data, _ = json.Marshal(bucket.scope)
			ok = true
		}
	}
	if !ok {
		return objectstorage.GetObjectResponse{}, httpError(404)
	}
	return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader(data)), ETag: new(fmt.Sprintf("%x", len(data)))}, nil
}

// status is what the region's leader reports once it read the channel: it
// fails the release if the channel does not verify for its own cell.
func (bucket *regionBucket) status() ([]byte, bool) {
	wire, ok := bucket.objects[releasechannel.ChannelObject]
	if !ok {
		return nil, false
	}
	var channel releasechannel.Channel
	if err := json.Unmarshal(wire, &channel); err != nil {
		return nil, false
	}
	status := releasechannel.Status{Schema: releasechannel.StatusSchema, Cell: bucket.cell,
		SourceRevision: channel.SourceRevision, RunNumber: channel.RunNumber, State: bucket.outcome, UpdatedAt: time.Now()}
	verified, err := channel.Verify(bucket.roots, bucket.cell, "production", time.Now())
	if err == nil {
		for _, binary := range verified {
			if _, ok := bucket.objects[releasechannel.BinaryObject(binary.Receipt().SHA256)]; !ok {
				err = errors.New("binary missing")
			}
		}
	}
	if err != nil {
		status.State, status.Reason = releasechannel.StateFailed, err.Error()
	}
	encoded, _ := json.Marshal(status)
	return encoded, true
}

type deployFixture struct {
	delegationFixture
	releaseDir string
	delegation string
	leafKey    string
	buckets    map[string]*regionBucket
	log        []string
	logMu      sync.Mutex
	env        deployEnv
}

func newDeployFixture(t *testing.T) *deployFixture {
	t.Helper()
	fixture := &deployFixture{delegationFixture: newDelegationFixture(t), buckets: map[string]*regionBucket{}}
	c := command{ctx: t.Context(), output: io.Discard}
	fixture.delegation = filepath.Join(fixture.directory, "update-delegation.json")
	if err := c.signUpdateDelegation([]string{"--subject-public-key", fixture.leafPath, "--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath, "--environment", "production", "--lineage-base", testLineageBase,
		"--service", "terrabase=https://github.com/TerraScale/terrabase", "--arch", "amd64",
		"--issued-at", fixture.now.Add(-time.Minute).Format(time.RFC3339),
		"--expires-at", fixture.now.Add(24 * time.Hour).Format(time.RFC3339), "--out", fixture.delegation}); err != nil {
		t.Fatal(err)
	}
	fixture.leafKey = filepath.Join(fixture.directory, "leaf.key")
	writePrivateKey(t, fixture.leafKey, fixture.leafPrivate)
	fixture.releaseDir = filepath.Join(fixture.directory, "release")
	if err := os.Mkdir(fixture.releaseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(fixture.releaseDir, "qualification.json"), testQualificationWire(t), 0o644)
	writeFixtureFile(t, filepath.Join(fixture.releaseDir, "terrascale-orchestrator-linux-amd64"), []byte("static binary"), 0o644)
	roots, err := trust.ParseKeyring(fixture.rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	rootPrivate, err := readDelegatedPrivateKey(fixture.privatePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range []string{"GRU", "SJC", "FRA"} {
		fixture.buckets[cell] = &regionBucket{cell: cell, roots: roots, outcome: releasechannel.StateComplete,
			objects: map[string][]byte{}, log: &fixture.log, logMu: &fixture.logMu,
			scope: &releasechannel.Status{Schema: releasechannel.StatusSchema, Cell: cell, Environment: "production",
				Architectures: []string{"amd64"}, UpdatedAt: time.Now().UTC()}}
		evidenceDir := filepath.Join(fixture.releaseDir, "production")
		record := writeProductionEvidence(t, evidenceDir, productionCandidate(testBinaryReceipt(), cell))
		writeProductionRecord(t, filepath.Join(evidenceDir, cell, "amd64", "production.json"), record, rootPrivate,
			time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	}
	fixture.env = deployEnv{
		timeout:  2 * time.Second,
		discover: func(context.Context) ([]string, error) { return []string{"GRU", "SJC"}, nil },
		check:    func(release.Qualification, string) error { return nil },
		inspect:  func(string, string, string) (binaryReceipt, error) { return testBinaryReceipt(), nil },
		git: func(_ context.Context, args ...string) (string, error) {
			if strings.HasSuffix(strings.Join(args, " "), "remote get-url origin") {
				return "https://github.com/TerraScale/ts-orchestrator.git\n", nil
			}
			return "", nil
		},
		storage: func(cell string) (releasechannel.ObjectClient, error) { return fixture.buckets[cell], nil },
		secret: func(context.Context, string, string) ([]byte, error) {
			return nil, errors.New("no Vault in this test")
		},
	}
	return fixture
}

func (fixture *deployFixture) args(cells ...string) []string {
	args := []string{"--dir", fixture.releaseDir, "--source-revision", testRevision,
		"--update-delegation", fixture.delegation, "--root-key", fixture.rootPath, "--signing-key", fixture.leafKey,
		"--environment", "production", "--source-checkout", "/srv/checkout", "--namespace", "ns",
		"--arch", "amd64", "--poll", "1ms"}
	for _, cell := range cells {
		args = append(args, "--cell", cell)
	}
	return args
}

func (fixture *deployFixture) touched(cell string) bool {
	for _, entry := range fixture.log {
		if strings.HasPrefix(entry, "put "+cell+" ") {
			return true
		}
	}
	return false
}

func TestDeployRollsOutEveryRegion(t *testing.T) {
	fixture := newDeployFixture(t)
	var output bytes.Buffer
	c := command{ctx: t.Context(), output: &output}
	if err := c.deployWith(fixture.args("GRU", "SJC"), fixture.env); err != nil {
		t.Fatalf("deploy: %v\n%s", err, output.String())
	}
	binary := releasechannel.BinaryObject(testBinaryReceipt().SHA256)
	want := []string{"put GRU " + binary, "put GRU " + releasechannel.ChannelObject,
		"put SJC " + binary, "put SJC " + releasechannel.ChannelObject}
	slices.Sort(fixture.log)
	slices.Sort(want)
	if !slices.Equal(fixture.log, want) {
		t.Fatalf("writes = %q, want %q", fixture.log, want)
	}
	text := output.String()
	if !strings.Contains(text, "GRU complete") || !strings.Contains(text, "SJC complete") ||
		!strings.Contains(text, "fleet complete: run 620") {
		t.Fatalf("output:\n%s", text)
	}

	// Deploying the same run again only renews the channels' receipts.
	fixture.log = nil
	err := c.deployWith(fixture.args("GRU", "SJC"), fixture.env)
	slices.Sort(fixture.log)
	if err != nil || !slices.Equal(fixture.log, []string{"put GRU " + releasechannel.ChannelObject, "put SJC " + releasechannel.ChannelObject}) {
		t.Fatalf("repeated deploy: %v, writes %q", err, fixture.log)
	}

	output.Reset()
	if err := c.fleetStatusWith([]string{"--namespace", "ns"}, fixture.env); err != nil {
		t.Fatalf("fleet-status: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"cell":"GRU"`) || !strings.Contains(lines[0], `"state":"complete"`) ||
		!strings.Contains(lines[0], `"run_number":620`) {
		t.Fatalf("fleet-status:\n%s", output.String())
	}

	// --role reads only that role's service status, as the release
	// retention job does with the role's own scoped key.
	fixture.buckets["SJC"].objects[releasechannel.ServiceStatusObject("terrabase")] =
		[]byte(`{"cell":"SJC","role":"terrabase","digest":"` + strings.Repeat("ab", 32) + `","state":"complete"}`)
	output.Reset()
	if err := c.fleetStatusWith([]string{"--namespace", "ns", "--cell", "GRU", "--cell", "SJC", "--role", "terrabase"},
		fixture.env); err != nil {
		t.Fatalf("fleet-status --role: %v", err)
	}
	lines = strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 || lines[0] != `{"cell":"GRU"}` || !strings.Contains(lines[1], strings.Repeat("ab", 32)) ||
		strings.Contains(lines[1], "channel") {
		t.Fatalf("fleet-status --role:\n%s", output.String())
	}
}

func TestDeployFinishesOtherRegionsWhenOneRollsBack(t *testing.T) {
	fixture := newDeployFixture(t)
	fixture.buckets["GRU"].outcome = releasechannel.StateFailed
	var output bytes.Buffer
	c := command{ctx: t.Context(), output: &output}
	err := c.deployWith(fixture.args("GRU", "SJC"), fixture.env)
	if !errors.Is(err, releasechannel.ErrFailed) || !strings.Contains(err.Error(), "GRU rolled back run 620") {
		t.Fatalf("deploy = %v", err)
	}
	if !fixture.touched("SJC") || !strings.Contains(output.String(), "SJC complete") {
		t.Fatalf("the healthy region did not finish: %q\n%s", fixture.log, output.String())
	}
}

func TestDeployReadsTheLeafFromVault(t *testing.T) {
	fixture := newDeployFixture(t)
	der, err := x509.MarshalPKCS8PrivateKey(fixture.leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	fixture.env.secret = func(_ context.Context, vaultID, name string) ([]byte, error) {
		asked = append(asked, vaultID+" "+name)
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}
	args := fixture.args("GRU")
	for index, arg := range args {
		if arg == "--signing-key" {
			args = append(args[:index], args[index+2:]...)
			break
		}
	}
	c := command{ctx: t.Context(), output: io.Discard}
	both := append(append([]string{}, fixture.args("GRU")...), "--signing-key-secret", "leaf", "--vault-id", "v")
	if err := c.deployWith(both, fixture.env); err == nil {
		t.Fatal("deploy accepted two leaf sources")
	}
	vault := "ocid1.vault.oc1.sa-saopaulo-1.example"
	if err := c.deployWith(append(args, "--signing-key-secret", "global-release-update-leaf"), fixture.env); err == nil {
		t.Fatal("deploy accepted a Vault secret without its Vault")
	}
	if err := c.deployWith(append(args, "--signing-key-secret", "global-release-update-leaf", "--vault-id", vault), fixture.env); err != nil {
		t.Fatalf("deploy with the Vault leaf: %v", err)
	}
	if len(asked) != 1 || asked[0] != vault+" global-release-update-leaf" || !fixture.touched("GRU") {
		t.Fatalf("Vault reads %q, writes %q", asked, fixture.log)
	}
}
