package rootociread

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
)

const readScenarioRegion = "sa-saopaulo-1"
const readScenarioTenancy = "ocid1.tenancy.oc1..root-read-scenario"

// The test binary embeds testdata/genesis.pem through the documented Go overlay.
// Production genesis, discovery, signature verification and floor code stay intact.
func TestRootReleaseChannelThroughSignedSDK(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("root backend qualification requires an isolated root test process")
	}
	for _, outcome := range []string{"current", "grant changes during read", "canceled after channel"} {
		t.Run(outcome, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			f := newReadScenario(t)
			if outcome == "grant changes during read" {
				initial := maps.Clone(f.objects)
				f.publish(2)
				successor := maps.Clone(f.objects)
				f.mu.Lock()
				f.objects = initial
				f.afterChannel = func() {
					f.mu.Lock()
					f.objects = successor
					f.mu.Unlock()
				}
				f.mu.Unlock()
			}
			if outcome == "canceled after channel" {
				f.mu.Lock()
				f.afterChannel = cancel
				f.mu.Unlock()
			}
			call, err := rootoci.RootCall(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var reader rootoci.Reader = f.backend
			observed, err := reader.ReleaseChannel(ctx, call)
			f.mu.Lock()
			channels, requests := f.channelReads, f.requests
			f.mu.Unlock()
			if channels != 1 || requests < 8 || requests > 32 {
				t.Fatalf("unexpected SDK boundary counts: channel=%d total=%d", channels, requests)
			}
			if outcome == "current" {
				if err != nil || !observed.Found || observed.Channel.SourceRevision != "signed-sdk-observation" || observed.Channel.Cell != "gru" {
					t.Fatalf("typed channel observation = %+v, %v", observed, err)
				}
				return
			}
			if err == nil || observed.Found || observed.Channel.SourceRevision != "" {
				t.Fatalf("invalidated read returned an observation: %+v, %v", observed, err)
			}
		})
	}
}

type readScenario struct {
	test         *testing.T
	backend      *Backend
	root         ed25519.PrivateKey
	anchor       bootstrap.BootstrapAnchor
	grant        region.FoundationGrant
	objects      map[string][]byte
	mu           sync.Mutex
	requests     int
	channelReads int
	afterChannel func()
	responses    map[string][]byte
	afterRead    func(*http.Request)
}

func newReadScenario(t *testing.T) *readScenario {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	seed := sha256.Sum256([]byte("rootociread integration genesis; never production"))
	f := &readScenario{test: t, root: ed25519.NewKeyFromSeed(seed[:]), objects: map[string][]byte{}, responses: map[string][]byte{}}
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := trust.ParseKeyring(f.root.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !maps.EqualFunc(genesis, expected, func(left, right ed25519.PublicKey) bool { return left.Equal(right) }) {
		t.Fatal("test binary must embed only the test genesis using testdata/README.md")
	}
	deployment, installation, cluster := entityid.New(), entityid.New(), entityid.New()
	domain := bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "gru-1-head", LedgerBucket: "gru-1-ledger",
		HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", Prefix: "bootstrap"}
	f.grant = region.FoundationGrant{InstallationID: installation, SchemaVersion: 1, Generation: 1, TenancyID: readScenarioTenancy,
		ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "scenario",
		Regions: []region.FoundationIntent{{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": readScenarioRegion, "tenancy_id": readScenarioTenancy,
			"parent_compartment_id": "ocid1.compartment.oc1..parent", "shared_compartment_id": "ocid1.compartment.oc1..shared", "resource_ids": map[string]any{}}}}}
	intentWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU,
		Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: readScenarioRegion}}})
	if err != nil {
		t.Fatal(err)
	}
	intentDigest := sha256.Sum256(intentWire)
	slots := []string{"controller-a", "controller-b", "controller-c"}
	f.anchor = bootstrap.BootstrapAnchor{SchemaVersion: 1, DeploymentID: deployment, Environment: "production", ClusterID: cluster, Cell: oci.RegionGRU, OCIRegion: readScenarioRegion,
		StorageDomain: domain, ControllerSlots: slots, InitialRegionIntentGeneration: 1, InitialRegionIntentSHA256: hex.EncodeToString(intentDigest[:]), InitialRegionIntentWire: intentWire,
		FoundationScope: &bootstrap.FoundationScope{InstallationID: installation, DeploymentID: deployment, ClusterID: cluster, TenancyID: readScenarioTenancy,
			OCIRegion: readScenarioRegion, StorageDomain: domain, GrantGeneration: 1},
		InitialSourceRegistration: &bootstrap.InitialSourceRegistration{InstallationID: installation, DeploymentID: deployment, Environment: "production", ClusterID: cluster, Cell: oci.RegionGRU,
			Generation: 1, PlanSHA256: strings.Repeat("a", 64), SeedSlot: slots[0], ControllerSlots: slots, StorageDomain: domain, LedgerRecordDomains: bootstrap.BootstrapLedgerCapabilityDomains()}}
	f.publish(1)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := verifyReadSignature(r, &key.PublicKey); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		response, found := f.responses[r.Method+" "+r.Host+r.URL.Path]
		afterRead := f.afterRead
		if found {
			f.requests++
		}
		f.mu.Unlock()
		if found {
			if afterRead != nil {
				afterRead(r)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", "financial-observation")
			w.Write(response)
			return
		}
		if r.Method != http.MethodGet || r.Host != "objectstorage."+readScenarioRegion+".oraclecloud.com" {
			t.Errorf("root read escaped its finite SDK scope: %s %s %s", r.Method, r.Host, r.URL)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.mu.Lock()
		f.requests++
		f.mu.Unlock()
		if r.URL.Path == "/n" {
			if compartment := r.URL.Query().Get("compartmentId"); compartment != "" && compartment != readScenarioTenancy {
				t.Errorf("namespace used caller-derived tenancy %q", compartment)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `"ns"`)
			return
		}
		const prefix = "/n/ns/b/gru-1-head/o/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			t.Errorf("read escaped root-derived bucket: %s", r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, prefix)
		if name == releasechannel.ChannelObject {
			f.mu.Lock()
			f.channelReads++
			afterChannel := f.afterChannel
			f.mu.Unlock()
			if afterChannel != nil {
				afterChannel()
			}
			w.Header().Set("ETag", "channel-observation")
			fmt.Fprint(w, `{"cell":"gru","source_revision":"signed-sdk-observation"}`)
			return
		}
		f.mu.Lock()
		wire, found := f.objects[name]
		f.mu.Unlock()
		if !found {
			t.Errorf("read escaped fixed foundation objects: %s", name)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", "protected-observation")
		w.Write(wire)
	}))
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	previous := http.DefaultTransport
	http.DefaultTransport = confinedReadTransport{next: server.Client().Transport, endpoint: endpoint}
	t.Cleanup(func() { http.DefaultTransport = previous })
	provider := common.NewRawConfigurationProvider(readScenarioTenancy, "ocid1.user.oc1..root-read-scenario", readScenarioRegion, "test",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: readScenarioRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	f.backend, err = New(factory)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *readScenario) publish(generation uint64) {
	f.test.Helper()
	f.grant.Generation = generation
	f.grant.Regions[0].Generation = generation
	payload, err := trust.EncodePayload(f.grant)
	if err != nil {
		f.test.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	envelope, err := trust.Sign(payload, trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: f.anchor.DeploymentID,
		Cell: "GRU", Environment: "production", Role: "foundation", Slot: f.anchor.ClusterID}, now.Add(-time.Minute), now.Add(time.Hour), f.root)
	if err != nil {
		f.test.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		f.test.Fatal(err)
	}
	digest := sha256.Sum256(grantWire)
	f.anchor.FoundationScope.GrantSHA256 = hex.EncodeToString(digest[:])
	f.anchor.FoundationScope.GrantGeneration = generation
	f.anchor.InitialSourceRegistration.Generation = generation
	anchor, err := bootstrap.SignBootstrapAnchor(f.anchor, now.Add(-time.Minute), now.Add(time.Hour), f.root)
	if err != nil {
		f.test.Fatal(err)
	}
	anchorWire, err := trust.EncodeEnvelope(anchor)
	if err != nil {
		f.test.Fatal(err)
	}
	chainWire, err := trust.EncodeRootChain(trust.RootChain{Version: 1})
	if err != nil {
		f.test.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects["orchestrator/foundation/v1/anchor.json"] = anchorWire
	f.objects["orchestrator/foundation/v1/root-chain.json"] = chainWire
	f.objects["bootstrap/foundation-scope-v1.json"] = grantWire
}

type confinedReadTransport struct {
	next     http.RoundTripper
	endpoint *url.URL
}

func (transport confinedReadTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || !slices.Contains([]string{
		"objectstorage." + readScenarioRegion + ".oraclecloud.com",
		"identity." + readScenarioRegion + ".oci.oraclecloud.com",
		"iaas." + readScenarioRegion + ".oraclecloud.com",
		"query." + readScenarioRegion + ".oci.oraclecloud.com",
	}, request.URL.Host) {
		return nil, errors.New("test transport rejected noncanonical OCI destination")
	}
	request = request.Clone(request.Context())
	request.Host = request.URL.Host
	request.URL.Scheme, request.URL.Host = transport.endpoint.Scheme, transport.endpoint.Host
	return transport.next.RoundTrip(request)
}

func verifyReadSignature(request *http.Request, public *rsa.PublicKey) error {
	value, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Signature ")
	if !ok {
		return errors.New("root read did not cross the SDK signing boundary")
	}
	fields := map[string]string{}
	for part := range strings.SplitSeq(value, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return errors.New("invalid OCI signature header")
		}
		fields[key] = strings.Trim(value, `"`)
	}
	headers := "date (request-target) host"
	if request.Method == http.MethodPost {
		headers += " content-length content-type x-content-sha256"
	}
	if fields["algorithm"] != "rsa-sha256" || fields["headers"] != headers {
		return fmt.Errorf("unexpected SDK signature algorithm or headers: %q %q", fields["algorithm"], fields["headers"])
	}
	signature, err := base64.StdEncoding.DecodeString(fields["signature"])
	if err != nil {
		return err
	}
	signed := "date: " + request.Header.Get("Date") + "\n(request-target): " + strings.ToLower(request.Method) + " " + request.URL.RequestURI() + "\nhost: " + request.Host
	if request.Method == http.MethodPost {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		digest := sha256.Sum256(body)
		if request.Header.Get("X-Content-Sha256") != base64.StdEncoding.EncodeToString(digest[:]) || request.ContentLength != int64(len(body)) {
			return errors.New("SDK body differs from its signed digest or length")
		}
		signed += fmt.Sprintf("\ncontent-length: %d\ncontent-type: %s\nx-content-sha256: %s", request.ContentLength, request.Header.Get("Content-Type"), request.Header.Get("X-Content-Sha256"))
	}
	digest := sha256.Sum256([]byte(signed))
	return rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature)
}
