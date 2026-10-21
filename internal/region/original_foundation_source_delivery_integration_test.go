package region

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// This is only a transport principal fixture. Real root-signed public bundles
// still pass the production verifier; no verified source authority is invented.
type originalDeliveryProvider struct {
	*provisionProvider
	token string
	kind  common.AuthenticationType
}

func (p originalDeliveryProvider) KeyID() (string, error) { return p.token, nil }
func (p originalDeliveryProvider) KeyIDContext(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return p.KeyID()
}
func (p originalDeliveryProvider) AuthType() (common.AuthConfig, error) {
	return common.AuthConfig{AuthType: p.kind}, nil
}

func originalDeliveryToken(t *testing.T, instance, tenancy string, expiry int64) string {
	t.Helper()
	payload, err := protocol.EncodeJSON(map[string]any{"sub": instance, "opc-instance": instance, "ptype": "instance", "tenant": tenancy, "exp": expiry})
	if err != nil {
		t.Fatal(err)
	}
	return "ST$e30." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

func TestOriginalFoundationPublicDeliverySDK(t *testing.T) {
	// Vendor DefaultTransport otherwise replaces the fixture's proxy with environment routing.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	f := newOriginalActorReadsSDKFixture(t, "", 0)
	instance := "ocid1.instance.oc1.sa-saopaulo-1.local"
	tenancy := f.approval.TenancyID
	key, err := release.WorkloadGenesisObject(tenancy, "GRU", "production", "ts-auth")
	if err != nil {
		t.Fatal(err)
	}
	token := originalDeliveryToken(t, instance, tenancy, time.Now().Add(time.Hour).Unix())
	wire, namespace, status := f.publicBundle, "ns", http.StatusOK
	var responseMu sync.Mutex
	var requests []string
	setResponse := func(body []byte, ns string, code int) {
		responseMu.Lock()
		defer responseMu.Unlock()
		wire, namespace, status = body, ns, code
	}
	requestCount := func() int {
		responseMu.Lock()
		defer responseMu.Unlock()
		return len(requests)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responseMu.Lock()
		defer responseMu.Unlock()
		requests = append(requests, r.Method+" "+r.Host+r.URL.RequestURI())
		if r.Method != http.MethodGet || r.Host != "objectstorage.sa-saopaulo-1.oraclecloud.com" ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") || !strings.Contains(r.Header.Get("Authorization"), `keyId="`+token+`"`) {
			t.Error("delivery left authenticated fixed home SDK GET boundary")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path == "/n" && r.URL.RawQuery == "" {
			json.MarshalWrite(w, namespace)
			return
		}
		if r.URL.Path != "/n/"+namespace+"/b/gru-1-head/o/"+key || r.URL.RawQuery != "" {
			t.Errorf("delivery selected unexpected object %s", r.URL)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(status)
		w.Write(wire)
	}))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("delivery fixture requires literal loopback TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("delivery fixture refuses plaintext dialing")
	}
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig
	if tlsConfig == nil || tlsConfig.InsecureSkipVerify || tlsConfig.RootCAs == nil {
		t.Fatal("delivery fixture requires verified TLS")
	}
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("fixture refuses network %q", network)
		}
		return (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, "tcp", listener.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	newFactory := func(provider originalDeliveryProvider) *ociclient.Factory {
		factory, err := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
		if err != nil {
			t.Fatal(err)
		}
		return factory
	}
	provider := originalDeliveryProvider{provisionProvider: f.provider, token: token, kind: common.InstancePrincipal}
	got, err := readOriginalFoundationPublic(t.Context(), newFactory(provider), instance, "GRU", digestSource(wire), f.roots)
	if err != nil || !bytes.Equal(got, f.publicBundle) || requestCount() != 2 {
		t.Fatalf("genuine signed SDK delivery = %d bytes, %d requests, %v", len(got), requestCount(), err)
	}
	if f.cloud.creates != 0 || f.cloud.launchPosts != 0 || f.cloud.materialPosts != 0 || f.cloud.hasAnchor() {
		t.Fatal("public delivery created resources, material or published an anchor")
	}
	for _, fault := range []string{"wrong digest", "foreign namespace", "unavailable", "oversized", "corrupt signature"} {
		t.Run(fault, func(t *testing.T) {
			wire, namespace, status := f.publicBundle, "ns", http.StatusOK
			digest := digestSource(wire)
			switch fault {
			case "wrong digest":
				digest = strings.Repeat("0", 64)
			case "foreign namespace":
				namespace = "foreign"
			case "unavailable":
				status = http.StatusForbidden
			case "oversized":
				wire = bytes.Repeat([]byte("x"), bootstrapstart.MaxOriginalFoundationPublicBytes+1)
			case "corrupt signature":
				bundle := f.bundle.clone()
				envelope, decodeErr := trust.DecodeEnvelope(bundle.GrantWire)
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				first := "A"
				if strings.HasPrefix(envelope.Signature, first) {
					first = "B"
				}
				envelope.Signature = first + envelope.Signature[1:]
				bundle.GrantWire, err = trust.EncodeEnvelope(envelope)
				if err != nil {
					t.Fatal(err)
				}
				wire, err = protocol.EncodeJSON(bundle)
				if err != nil {
					t.Fatal(err)
				}
				digest = digestSource(wire)
			}
			setResponse(wire, namespace, status)
			if got, err := readOriginalFoundationPublic(t.Context(), newFactory(provider), instance, "GRU", digest, f.roots); !errors.Is(err, ErrOriginalFoundationDelivery) || got != nil {
				t.Fatalf("invalid public delivery accepted: %d bytes %v", len(got), err)
			}
		})
	}
	for _, fault := range []string{"user principal", "foreign instance", "foreign tenancy", "expired token", "wrong cell"} {
		t.Run(fault, func(t *testing.T) {
			bad, cell := provider, "GRU"
			switch fault {
			case "user principal":
				bad.kind = common.UserPrincipal
			case "foreign instance":
				bad.token = originalDeliveryToken(t, "ocid1.instance.oc1.sa-saopaulo-1.foreign", tenancy, time.Now().Add(time.Hour).Unix())
			case "foreign tenancy":
				bad.token = originalDeliveryToken(t, instance, "ocid1.tenancy.oc1..foreign", time.Now().Add(time.Hour).Unix())
			case "expired token":
				bad.token = originalDeliveryToken(t, instance, tenancy, time.Now().Add(-time.Hour).Unix())
			case "wrong cell":
				cell = "FRA"
			}
			before := requestCount()
			if _, err := readOriginalFoundationPublic(t.Context(), newFactory(bad), instance, cell, digestSource(f.publicBundle), f.roots); !errors.Is(err, ErrOriginalFoundationDelivery) || requestCount() != before {
				t.Fatal("wrong local principal or region reached OCI public delivery")
			}
		})
	}
	for _, fault := range []string{"whitespace", "unknown field", "tenancy", "namespace", "signed environment", "regional cell", "regional environment", "origin missing", "origin namespace", "origin role", "origin duplicate"} {
		t.Run(fault, func(t *testing.T) {
			bundle := f.bundle.clone()
			grant, err := decodeOriginalMaterialGrant(bundle)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "tenancy":
				bundle.TenancyID = "ocid1.tenancy.oc1..foreign"
			case "namespace":
				bundle.Namespace = "foreign"
			case "regional cell":
				grant.Regions[0].BootstrapMaterial.Config.Cell = "fra"
			case "regional environment":
				grant.Regions[0].BootstrapMaterial.Config.Environment = "canary"
			case "origin missing":
				grant.WorkloadGenesis = nil
			case "origin namespace", "origin role", "origin duplicate":
				for i, origin := range grant.WorkloadGenesis {
					if origin.Cell != "GRU" || origin.Role != "ts-auth" {
						continue
					}
					switch fault {
					case "origin namespace":
						grant.WorkloadGenesis[i].Namespace = "foreign"
					case "origin role":
						grant.WorkloadGenesis[i].Role = "terrabase"
					case "origin duplicate":
						grant.WorkloadGenesis = append(grant.WorkloadGenesis, origin)
					}
					break
				}
			}
			if fault == "signed environment" || strings.HasPrefix(fault, "regional ") || strings.HasPrefix(fault, "origin ") {
				prepared := f.prepared
				prepared.Grant = grant
				if fault == "signed environment" {
					prepared.Anchor.Environment = "canary"
					// The anchor must stay self-consistent so the delivery verifier, not signing, refuses it.
					if registration := prepared.Anchor.InitialSourceRegistration; registration != nil {
						changed := *registration
						changed.Environment = "canary"
						prepared.Anchor.InitialSourceRegistration = &changed
					}
				}
				bundle = signProvisionFoundation(t, prepared, bundle.RootChainWire, f.root, f.now)
			}
			wire, err := protocol.EncodeJSON(bundle)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "whitespace" {
				wire = append(wire, '\n')
			}
			if fault == "unknown field" {
				wire = append([]byte(`{"foreign":1,`), wire[1:]...)
			}
			setResponse(wire, "ns", http.StatusOK)
			before := requestCount()
			if got, err := readOriginalFoundationPublic(t.Context(), newFactory(provider), instance, "GRU", digestSource(wire), f.roots); !errors.Is(err, ErrOriginalFoundationDelivery) || got != nil || requestCount() != before+2 {
				t.Fatal("wrong canonical/authenticated/regional/origin scope reached full verifier")
			}
		})
	}
}

func TestOriginalFoundationLaunchMetadataNeverRetrofitsRetainedActors(t *testing.T) {
	f := newOriginalActorSDKFixture(t, "", 0)
	if err := f.run(t); err != nil {
		t.Fatal(err)
	}
	before := f.wire(t)
	store := f.store(t)
	record, etag, err := store.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	actor := record.OriginalFoundationCompartments.Regions[0].Actor
	if actor == nil || actor.Pending == nil || actor.Provenance == nil || actor.VerifiedAt.IsZero() {
		t.Fatal("metadata immutability control lacks genuinely retained actual actor")
	}
	actor.Request.Metadata = foundationWriterMetadata("controller-a")
	if err := record.validateOriginalFoundationActors(); err == nil {
		t.Fatal("legacy slot-only retained launch was treated as the new bundle-scoped request")
	}
	if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil || !bytes.Equal(before, f.wire(t)) {
		t.Fatal("protected CAS rewrote immutable original launch metadata")
	}
}
