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
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
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
		"--cell", "GRU", "--cell", "SFO", "--arch", "amd64",
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
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		fixture.buckets[cell] = &regionBucket{cell: cell, roots: roots, outcome: releasechannel.StateComplete,
			objects: map[string][]byte{}, log: &fixture.log, logMu: &fixture.logMu}
	}
	fixture.env = deployEnv{
		check:   func(release.Qualification, string) error { return nil },
		inspect: func(string, string, string) (binaryReceipt, error) { return testBinaryReceipt(), nil },
		git: func(_ context.Context, args ...string) (string, error) {
			if strings.HasSuffix(strings.Join(args, " "), "remote get-url origin") {
				return "https://git.terrascale.tech/TerraScale/ts-orchestrator.git\n", nil
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
		"--arch", "amd64", "--poll", "1ms", "--region-timeout", "2s"}
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
	if err := c.deployWith(fixture.args("GRU", "SFO"), fixture.env); err != nil {
		t.Fatalf("deploy: %v\n%s", err, output.String())
	}
	binary := releasechannel.BinaryObject(testBinaryReceipt().SHA256)
	want := []string{"put GRU " + binary, "put GRU " + releasechannel.ChannelObject,
		"put SFO " + binary, "put SFO " + releasechannel.ChannelObject}
	slices.Sort(fixture.log)
	slices.Sort(want)
	if !slices.Equal(fixture.log, want) {
		t.Fatalf("writes = %q, want %q", fixture.log, want)
	}
	text := output.String()
	if !strings.Contains(text, "GRU complete") || !strings.Contains(text, "SFO complete") ||
		!strings.Contains(text, "fleet complete: run 620") {
		t.Fatalf("output:\n%s", text)
	}

	// Deploying the same run again only renews the channels' receipts.
	fixture.log = nil
	err := c.deployWith(fixture.args("GRU", "SFO"), fixture.env)
	slices.Sort(fixture.log)
	if err != nil || !slices.Equal(fixture.log, []string{"put GRU " + releasechannel.ChannelObject, "put SFO " + releasechannel.ChannelObject}) {
		t.Fatalf("repeated deploy: %v, writes %q", err, fixture.log)
	}

	output.Reset()
	if err := c.fleetStatusWith([]string{"--namespace", "ns"}, fixture.env.storage); err != nil {
		t.Fatalf("fleet-status: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"cell":"GRU"`) || !strings.Contains(lines[0], `"state":"complete"`) ||
		!strings.Contains(lines[0], `"run_number":620`) || strings.Contains(lines[2], "status") {
		t.Fatalf("fleet-status:\n%s", output.String())
	}

	// --role reads only that role's service status, as the release
	// retention job does with the role's own scoped key.
	fixture.buckets["SFO"].objects[releasechannel.ServiceStatusObject("terrabase")] =
		[]byte(`{"cell":"SFO","role":"terrabase","digest":"` + strings.Repeat("ab", 32) + `","state":"complete"}`)
	output.Reset()
	if err := c.fleetStatusWith([]string{"--namespace", "ns", "--cell", "GRU", "--cell", "SFO", "--role", "terrabase"},
		fixture.env.storage); err != nil {
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
	err := c.deployWith(fixture.args("GRU", "SFO"), fixture.env)
	if !errors.Is(err, releasechannel.ErrFailed) || !strings.Contains(err.Error(), "GRU rolled back run 620") {
		t.Fatalf("deploy = %v", err)
	}
	if !fixture.touched("SFO") || !strings.Contains(output.String(), "SFO complete") {
		t.Fatalf("the healthy region did not finish: %q\n%s", fixture.log, output.String())
	}
}

func TestDeployWaitsForRegionsConcurrently(t *testing.T) {
	fixture := newDeployFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	reading := make(chan string, 2)
	proceed := make(chan struct{})
	for _, cell := range []string{"GRU", "SFO"} {
		fixture.buckets[cell].wait = func(ctx context.Context) error {
			reading <- cell
			select {
			case <-proceed:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	done := make(chan error, 1)
	go func() {
		done <- (command{ctx: ctx, output: io.Discard}).deployWith(fixture.args("GRU", "SFO"), fixture.env)
	}()
	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case cell := <-reading:
			seen[cell] = true
		case <-ctx.Done():
			close(proceed)
			<-done
			t.Fatal("regions waited sequentially")
		}
	}
	close(proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDeployMissingDelegationDoesNotBlockOtherRegions(t *testing.T) {
	fixture := newDeployFixture(t)
	var output bytes.Buffer
	c := command{ctx: t.Context(), output: &output}
	if err := c.deployWith(fixture.args("GRU", "FRA"), fixture.env); !errors.Is(err, trust.ErrCapabilityDenied) {
		t.Fatalf("deploy outside the delegation = %v", err)
	}
	if !fixture.touched("GRU") || fixture.touched("FRA") ||
		!strings.Contains(output.String(), "GRU complete") || !strings.Contains(output.String(), "FRA failed:") {
		t.Fatalf("regional signing failure blocked a healthy cell: %q\n%s", fixture.log, output.String())
	}
}

func TestDeployStorageFailuresAreRegionalAndAllReported(t *testing.T) {
	for _, failBoth := range []bool{false, true} {
		t.Run(fmt.Sprint(failBoth), func(t *testing.T) {
			fixture := newDeployFixture(t)
			storage := fixture.env.storage
			gruError, sfoError := errors.New("GRU storage unavailable"), errors.New("SFO storage unavailable")
			fixture.env.storage = func(cell string) (releasechannel.ObjectClient, error) {
				if cell == "GRU" {
					return nil, gruError
				}
				if failBoth && cell == "SFO" {
					return nil, sfoError
				}
				return storage(cell)
			}
			var output bytes.Buffer
			err := (command{ctx: t.Context(), output: &output}).deployWith(fixture.args("GRU", "SFO"), fixture.env)
			if !errors.Is(err, gruError) || errors.Is(err, sfoError) != failBoth ||
				fixture.touched("SFO") == failBoth || !strings.Contains(output.String(), "GRU failed:") ||
				strings.Contains(output.String(), "SFO failed:") != failBoth {
				t.Fatalf("deploy = %v, writes %q\n%s", err, fixture.log, output.String())
			}
		})
	}
}

func TestDeploySharesLineageFetchAcrossRegions(t *testing.T) {
	fixture := newDeployFixture(t)
	git := fixture.env.git
	var fetches atomic.Int32
	fixture.env.git = func(ctx context.Context, args ...string) (string, error) {
		if slices.Contains(args, "fetch") {
			fetches.Add(1)
		}
		return git(ctx, args...)
	}
	if err := (command{ctx: t.Context(), output: io.Discard}).deployWith(fixture.args("GRU", "SFO"), fixture.env); err != nil {
		t.Fatal(err)
	}
	if fetches.Load() != 1 {
		t.Fatalf("parallel regions fetched the same main ref %d times", fetches.Load())
	}
}

func TestDeployRefusesUnqualifiedOrInvalidSource(t *testing.T) {
	fixture := newDeployFixture(t)
	c := command{ctx: t.Context(), output: io.Discard}
	unqualified := fixture.env
	unqualified.check = func(release.Qualification, string) error { return errors.New("run failed") }
	if err := c.deployWith(fixture.args("GRU"), unqualified); err == nil {
		t.Fatal("deployed an unqualified run")
	}
	offMain := fixture.env
	offMain.git = func(ctx context.Context, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "origin/main") && strings.Contains(strings.Join(args, " "), "merge-base") {
			return "", errors.New("not an ancestor")
		}
		return fixture.env.git(ctx, args...)
	}
	if err := c.deployWith(fixture.args("GRU"), offMain); !errors.Is(err, release.ErrLineage) {
		t.Fatalf("deployed a revision outside main = %v", err)
	}
	// The delegation expires in a day: receipts capped at it would lapse
	// while a region still rolls them out.
	if err := c.deployWith(append(fixture.args("GRU"), "--region-timeout", "25h"), fixture.env); err == nil ||
		!strings.Contains(err.Error(), "renew the update delegation") {
		t.Fatalf("deployed receipts that expire mid-rollout: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixture.releaseDir, "terrascale-orchestrator-linux-amd64"), []byte("tampered bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.deployWith(fixture.args("GRU"), fixture.env); err == nil {
		t.Fatal("deployed a binary that differs from the inspected one")
	}
	if len(fixture.log) != 0 {
		t.Fatalf("rejected deployments wrote %q", fixture.log)
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

func TestFleetStatusRequiresLeaderPinsBeforePruning(t *testing.T) {
	f := newDeployFixture(t)
	var output bytes.Buffer
	c := command{ctx: t.Context(), output: &output}
	rollback, bad := strings.Repeat("a", 64), strings.Repeat("b", 64)
	updated := time.Now().UTC().Format(time.RFC3339Nano)
	for _, role := range []string{"", "terrabase"} {
		t.Run("role="+role, func(t *testing.T) {
			args := []string{"--namespace", "ns", "--cell", "GRU", "--require-pins"}
			name, schema := releasechannel.StatusObject, releasechannel.StatusSchema
			if role != "" {
				args = append(args, "--role", role)
				name, schema = releasechannel.ServiceStatusObject(role), releasechannel.ServiceStatusSchema
			}
			statuses := []string{
				"",
				fmt.Sprintf(`{"schema":%q,"cell":"GRU","role":%q,"state":"complete"}`, schema, role),
				fmt.Sprintf(`{"schema":%q,"cell":"SFO","role":%q,"pins":{}}`, schema, role),
				fmt.Sprintf(`{"schema":%q,"cell":"GRU","role":%q,"updated_at":%q,"pins":{"rollback":[%q],"known_bad":[%q]}}`, schema, role, updated, rollback, bad),
				fmt.Sprintf(`{"schema":%q,"cell":"GRU","role":%q,"updated_at":%q,"pins":{"rollback":[],"known_bad":[]}}`, schema, role, updated),
			}
			for i, status := range statuses {
				delete(f.buckets["GRU"].objects, name)
				if status != "" {
					f.buckets["GRU"].objects[name] = []byte(status)
				}
				output.Reset()
				err := c.fleetStatusWith(args, f.env.storage)
				if (err != nil) != (i < 3) {
					t.Fatalf("status %d: err=%v output=%s", i, err, output.String())
				}
				if i == 3 && (!strings.Contains(output.String(), rollback) || !strings.Contains(output.String(), bad)) {
					t.Fatalf("pins lost: %s", output.String())
				}
			}
		})
	}
}

func TestFleetStatusRejectsStaleLeaderPins(t *testing.T) {
	f := newDeployFixture(t)
	c := command{ctx: t.Context(), output: io.Discard}
	now := time.Now().UTC()
	for _, role := range []string{"", "terrabase"} {
		for _, tc := range []struct {
			name string
			at   time.Time
			bad  bool
		}{
			{"fresh", now, false},
			{"missing timestamp", time.Time{}, true},
			{"stale", now.Add(-releasechannel.MaxPinAge - time.Second), true},
			{"future", now.Add(releasechannel.PinRefreshInterval + time.Minute), true},
		} {
			t.Run(role+"/"+tc.name, func(t *testing.T) {
				name, schema := releasechannel.StatusObject, releasechannel.StatusSchema
				args := []string{"--namespace", "ns", "--cell", "GRU", "--cell", "SFO"}
				if role != "" {
					name, schema = releasechannel.ServiceStatusObject(role), releasechannel.ServiceStatusSchema
					args = append(args, "--role", role)
				}
				for _, cell := range []string{"GRU", "SFO"} {
					at := now
					if cell == "SFO" {
						at = tc.at
					}
					f.buckets[cell].objects[name] = []byte(fmt.Sprintf(`{"schema":%q,"cell":%q,"role":%q,"updated_at":%q,"pins":{"rollback":[],"known_bad":[]}}`,
						schema, cell, role, at.Format(time.RFC3339Nano)))
				}
				if err := c.fleetStatusWith(args, f.env.storage); err != nil {
					t.Fatalf("ordinary status read: %v", err)
				}
				if err := c.fleetStatusWith(append(args, "--require-pins"), f.env.storage); (err != nil) != tc.bad {
					t.Fatalf("strict status read = %v, invalid timestamp = %v", err, tc.bad)
				}
			})
		}
	}
}
