package region

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// All discovery requests cross the actual OCI SDK's signed HTTP boundary.
// Only the remote Object Storage service and root ceremony are local fixtures.
type currentDiscoveryScenario struct {
	client  foundationDiscoveryObjects
	genesis trust.Keyring
	root    ed25519.PrivateKey
	anchor  bootstrap.BootstrapAnchor
	grant   FoundationGrant
	chain   trust.RootChain
	objects map[string][]byte
	mu      sync.Mutex
	config  string
	test    *testing.T
	now     time.Time
}

func newCurrentDiscoveryScenario(t *testing.T) *currentDiscoveryScenario {
	t.Helper()
	f := &currentDiscoveryScenario{test: t, objects: map[string][]byte{}, config: t.TempDir(), chain: trust.RootChain{Version: 1}, now: time.Now().UTC().Truncate(time.Second)}
	t.Setenv("XDG_CONFIG_HOME", f.config)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.root = private
	f.genesis, err = trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
			t.Error("discovery did not use authenticated SDK request")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			t.Error("ordinary discovery attempted a cloud mutation")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/n" {
			if r.URL.Query().Get("compartmentId") != f.grant.TenancyID {
				t.Error("namespace discovery omitted authenticated tenancy")
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `"ns"`)
			return
		}
		prefix := "/n/ns/b/" + foundationDiscoveryBucket + "/o/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			t.Errorf("discovery escaped fixed home location: %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		wire, found := f.objects[strings.TrimPrefix(r.URL.Path, prefix)]
		wire = bytes.Clone(wire)
		f.mu.Unlock()
		if !found {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"code":"ObjectNotFound","message":"absent"}`)
			return
		}
		w.Write(wire)
	}))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", foundationHomeRegion, "test",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	client.Host = server.URL
	f.client = &client
	deployment, installation, cluster := entityid.New(), entityid.New(), entityid.New()
	domain := bootstrap.StorageDomain{Namespace: "ns", HeadBucket: foundationDiscoveryBucket, LedgerBucket: "gru-1-ledger", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", Prefix: "bootstrap"}
	f.grant = FoundationGrant{InstallationID: installation, SchemaVersion: 1, Generation: 1, TenancyID: "ocid1.tenancy.oc1..test", ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "scenario"}
	f.grant.Regions = []FoundationIntent{{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": foundationHomeRegion, "tenancy_id": f.grant.TenancyID,
		"parent_compartment_id": f.grant.ParentCompartmentID, "shared_compartment_id": f.grant.SharedCompartmentID, "resource_ids": map[string]any{}}}}
	intentWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: foundationHomeRegion}}})
	if err != nil {
		t.Fatal(err)
	}
	intentDigest := sha256.Sum256(intentWire)
	slots := []string{"controller-a", "controller-b", "controller-c"}
	f.anchor = bootstrap.BootstrapAnchor{SchemaVersion: 1, DeploymentID: deployment, Environment: "production", ClusterID: cluster, Cell: oci.RegionGRU, OCIRegion: foundationHomeRegion,
		StorageDomain: domain, ControllerSlots: slots, InitialRegionIntentGeneration: 1, InitialRegionIntentSHA256: hex.EncodeToString(intentDigest[:]), InitialRegionIntentWire: intentWire,
		FoundationScope: &bootstrap.FoundationScope{InstallationID: installation, DeploymentID: deployment, ClusterID: cluster, TenancyID: f.grant.TenancyID, OCIRegion: foundationHomeRegion, StorageDomain: domain, GrantGeneration: 1},
		InitialSourceRegistration: &bootstrap.InitialSourceRegistration{InstallationID: installation, DeploymentID: deployment, Environment: "production", ClusterID: cluster, Cell: oci.RegionGRU,
			Generation: 1, PlanSHA256: strings.Repeat("a", 64), SeedSlot: slots[0], ControllerSlots: slots, StorageDomain: domain, LedgerRecordDomains: bootstrap.BootstrapLedgerCapabilityDomains()}}
	f.publish()
	return f
}

func (f *currentDiscoveryScenario) publish() {
	f.test.Helper()
	now := f.now
	payload, err := trust.EncodePayload(f.grant)
	if err != nil {
		f.test.Fatal(err)
	}
	scope := trust.Scope{Domain: foundationGrantDomain, DeploymentID: f.anchor.DeploymentID, Cell: "GRU", Environment: "production", Role: "foundation", Slot: f.anchor.ClusterID}
	envelope, err := trust.Sign(payload, scope, now.Add(-time.Minute), now.Add(time.Hour), f.root)
	if err != nil {
		f.test.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		f.test.Fatal(err)
	}
	f.anchor.FoundationScope.GrantGeneration = f.grant.Generation
	f.anchor.InitialSourceRegistration.Generation = f.grant.Generation
	digest := sha256.Sum256(grantWire)
	f.anchor.FoundationScope.GrantSHA256 = hex.EncodeToString(digest[:])
	anchor, err := bootstrap.SignBootstrapAnchor(f.anchor, now.Add(-time.Minute), now.Add(time.Hour), f.root)
	if err != nil {
		f.test.Fatal(err)
	}
	anchorWire, err := trust.EncodeEnvelope(anchor)
	if err != nil {
		f.test.Fatal(err)
	}
	chainWire, err := trust.EncodeRootChain(f.chain)
	if err != nil {
		f.test.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[foundationDiscoveryObject] = anchorWire
	f.objects[foundationRootChainObject] = chainWire
	f.objects["bootstrap/"+foundationGrantObject] = grantWire
}

func (f *currentDiscoveryScenario) rotate() {
	f.test.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.test.Fatal(err)
	}
	identity := foundationChainIdentity(f.anchor.DeploymentID)
	verified, err := trust.VerifyRootChain(f.genesis, identity, f.chain)
	if err != nil {
		f.test.Fatal(err)
	}
	rotation, err := trust.NextRotation(verified, public)
	if err != nil {
		f.test.Fatal(err)
	}
	now := f.now
	signed := trust.SignedRotation{}
	for _, key := range []ed25519.PrivateKey{f.root, private} {
		signature, err := trust.SignRotation(rotation, identity, now.Add(-time.Minute), now.Add(time.Hour), key)
		if err != nil {
			f.test.Fatal(err)
		}
		signed.Signatures = append(signed.Signatures, signature)
	}
	f.root = private
	f.chain.Rotations = append(f.chain.Rotations, signed)
}

func (f *currentDiscoveryScenario) discover(ctx context.Context) (FoundationResolver, error) {
	return discoverCurrentFoundation(ctx, f.client, f.grant.TenancyID, f.genesis)
}

func (f *currentDiscoveryScenario) floorPath() string {
	digest := sha256.Sum256([]byte(f.grant.TenancyID))
	return filepath.Join(f.config, "terrascale-orchestrator", "foundation", hex.EncodeToString(digest[:])+".json")
}

func TestCurrentFoundationDiscoveryHTTPDurableAuthority(t *testing.T) {
	t.Run("mandatory chain even on fresh installation", func(t *testing.T) {
		f := newCurrentDiscoveryScenario(t)
		delete(f.objects, foundationRootChainObject)
		if _, err := f.discover(t.Context()); !errors.Is(err, ErrFoundationDiscoveryPending) {
			t.Fatalf("absent explicit chain: %v", err)
		}
		if _, err := os.Stat(f.floorPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed discovery created floor: %v", err)
		}
	})
	t.Run("rotation persisted before resolver and survives restart", func(t *testing.T) {
		f := newCurrentDiscoveryScenario(t)
		initialRoot := f.root
		f.now = f.now.Add(-48 * time.Hour)
		f.rotate()
		if err := trust.RotationCurrent(f.chain.Rotations[0], time.Now()); !errors.Is(err, trust.ErrExpired) {
			t.Fatalf("fixture rotation must be historical: %v", err)
		}
		f.now = f.now.Add(48 * time.Hour)
		f.publish()
		resolver, err := f.discover(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		wire, err := os.ReadFile(f.floorPath())
		if err != nil {
			t.Fatal(err)
		}
		var floor foundationFloor
		if err := json.Unmarshal(wire, &floor); err != nil {
			t.Fatal(err)
		}
		exactChain, err := trust.EncodeRootChain(f.chain)
		if err != nil || !bytes.Equal(floor.ChainWire, exactChain) || floor.InstallationID != f.grant.InstallationID || floor.Generation != f.grant.Generation {
			t.Fatalf("floor differs from adopted authority: %+v %v", floor, err)
		}
		for path, mode := range map[string]os.FileMode{f.floorPath(): 0600, filepath.Dir(f.floorPath()): 0700} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("unsafe floor permission: %s %v", path, err)
			}
		}
		if _, err := resolver.Footprint.AuthorizedRegions(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := f.discover(t.Context()); err != nil {
			t.Fatalf("restart: %v", err)
		}
		delete(f.objects, foundationRootChainObject)
		if _, err := f.discover(t.Context()); !errors.Is(err, ErrFoundationDiscoveryPending) {
			t.Fatalf("adopted chain omission: %v", err)
		}
		f.chain = trust.RootChain{Version: 1}
		f.root = initialRoot
		f.publish()
		if _, err := f.discover(t.Context()); err == nil {
			t.Fatal("restarted client accepted retired genesis")
		}
		f.rotate()
		f.publish()
		if _, err := f.discover(t.Context()); err == nil {
			t.Fatal("restarted client accepted rival rotation")
		}
	})
	t.Run("generation and exact grant wire remain monotonic", func(t *testing.T) {
		f := newCurrentDiscoveryScenario(t)
		if _, err := f.discover(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.grant.MonthlyLimitMinor++
		f.publish()
		if _, err := f.discover(t.Context()); err == nil {
			t.Fatal("adopted generation accepted altered grant")
		}
		f.grant.Generation = 2
		f.grant.Regions[0].Generation = 2
		f.publish()
		if _, err := f.discover(t.Context()); err != nil {
			t.Fatalf("new generation: %v", err)
		}
		f.grant.Generation = 1
		f.grant.Regions[0].Generation = 1
		f.publish()
		if _, err := f.discover(t.Context()); err == nil {
			t.Fatal("restarted client accepted lower grant generation")
		}
	})
	t.Run("identity and anchor authority cannot switch", func(t *testing.T) {
		f := newCurrentDiscoveryScenario(t)
		if _, err := f.discover(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.anchor.InitialSourceRegistration.PlanSHA256 = strings.Repeat("b", 64)
		f.publish()
		if _, err := f.discover(t.Context()); err == nil {
			t.Fatal("same chain and grant accepted changed anchor authority")
		}
		f.grant.Generation = 2
		f.grant.Regions[0].Generation = 2
		f.grant.InstallationID = entityid.New()
		f.anchor.FoundationScope.InstallationID = f.grant.InstallationID
		f.anchor.InitialSourceRegistration.InstallationID = f.grant.InstallationID
		f.publish()
		if _, err := f.discover(t.Context()); err == nil {
			t.Fatal("new generation switched installed identity")
		}
	})
	t.Run("untrusted roots and foreign location remain rejected", func(t *testing.T) {
		f := newCurrentDiscoveryScenario(t)
		original := f.root
		_, attacker, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.root = attacker
		f.publish()
		if _, err := f.discover(t.Context()); err == nil {
			t.Fatal("self-declared locator signer became trusted")
		}
		f.root = original
		f.anchor.StorageDomain.Namespace = "foreign"
		f.anchor.FoundationScope.StorageDomain.Namespace = "foreign"
		f.anchor.InitialSourceRegistration.StorageDomain.Namespace = "foreign"
		f.publish()
		if _, err := f.discover(t.Context()); err == nil {
			t.Fatal("signed locator redirected authenticated storage namespace")
		}
		if _, err := DiscoverCurrentFoundation(t.Context(), nil); !errors.Is(err, ErrFoundationDiscoveryPending) {
			t.Fatalf("missing authenticated factory: %v", err)
		}
	})
	t.Run("absent grant never adopts incomplete authority", func(t *testing.T) {
		f := newCurrentDiscoveryScenario(t)
		delete(f.objects, "bootstrap/"+foundationGrantObject)
		if _, err := f.discover(t.Context()); !errors.Is(err, ErrFoundationGrantPending) {
			t.Fatalf("missing grant: %v", err)
		}
		if _, err := os.Stat(f.floorPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("incomplete authority persisted: %v", err)
		}
	})
	t.Run("another process fences adoption and cancellation", func(t *testing.T) {
		f := newCurrentDiscoveryScenario(t)
		if _, err := f.discover(t.Context()); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(os.Args[0], "-test.run=^TestCurrentFoundationDiscoveryLockProcess$")
		command.Env = append(os.Environ(), "TS_TEST_FOUNDATION_LOCK="+f.floorPath()+".lock")
		output, err := command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		input, err := command.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			input.Close()
			if err := command.Wait(); err != nil {
				t.Error(err)
			}
		})
		var marker [1]byte
		if _, err := io.ReadFull(output, marker[:]); err != nil || marker[0] != 'L' {
			t.Fatalf("child did not acquire floor lock: %q %v", marker, err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
		defer cancel()
		if _, err := f.discover(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("waiting discovery ignored lock/cancellation: %v", err)
		}
	})
	t.Run("unsafe or damaged durable state never resets trust", func(t *testing.T) {
		f := newCurrentDiscoveryScenario(t)
		if _, err := f.discover(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.floorPath(), []byte(`{`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.discover(t.Context()); err == nil {
			t.Fatal("corrupt floor became first-install fallback")
		}
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(f.floorPath()); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, f.floorPath()); err != nil {
			t.Fatal(err)
		}
		if _, err := f.discover(t.Context()); err == nil {
			t.Fatal("symlink floor accepted")
		}
		if wire, err := os.ReadFile(outside); err != nil || string(wire) != "unchanged" {
			t.Fatalf("symlink target changed: %q %v", wire, err)
		}
	})
}

func TestCurrentFoundationDiscoveryLockProcess(t *testing.T) {
	path := os.Getenv("TS_TEST_FOUNDATION_LOCK")
	if path == "" {
		return
	}
	lock, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.Write([]byte("L")); err != nil {
		t.Fatal(err)
	}
	var done [1]byte
	_, _ = os.Stdin.Read(done[:])
}
