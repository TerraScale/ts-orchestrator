package region

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// Source reservations cross signed SDK HTTP and disk CAS, including restart,
// stale checkpoints and rejection of widened IAM read from durable bytes.
func TestSourcePolicyJournalPreservesOriginalRecipientAndRejectsWidening(t *testing.T) {
	store, client, raw := foundationProtocolStore(t)
	now := time.Now().UTC()
	object := "owned/bootstrap/v2/material-source/" + strings.Repeat("a", 64) + ".json"
	mapKey := sourcePolicyKey("ns", "heads", object)
	escrow := bootstrap.StartupVaultTarget{CompartmentOCID: "ocid1.compartment.oc1..home", VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.home", KMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.home"}
	pending := SourcePolicyRecord{Namespace: "ns", Bucket: "heads", Object: object, InstallationID: "installation", InstanceID: "ocid1.instance.oc1.us-sanjose-1.seed", GrantDigest: strings.Repeat("b", 64), TemplateDigest: strings.Repeat("c", 64), GrantGeneration: 1, FirstAttemptAt: now, Escrow: escrow, BucketCompartment: escrow.CompartmentOCID, SecretName: "ts-bootstrap-source-" + strings.Repeat("a", 32)}
	statements, err := ociregion.BootstrapSourceStatements(pending.InstanceID, pending.SecretName, vaultsecret.Target{CompartmentID: escrow.CompartmentOCID, VaultID: escrow.VaultOCID, KeyID: escrow.KMSKeyOCID})
	if err != nil {
		t.Fatal(err)
	}
	statements = append(statements, fmt.Sprintf("Allow any-user to manage objects in compartment id %s where all {request.principal.type='instance', request.principal.id='%s', target.bucket.name='heads', target.object.name='%s', any {request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE', request.permission='OBJECT_READ'}}", escrow.CompartmentOCID, pending.InstanceID, object))
	pending.Request = identity.CreatePolicyDetails{CompartmentId: new(escrow.CompartmentOCID), Name: new("ts-bootstrap-source-" + mapKey[:32]), Description: new("Exact founder source escrow and registration"), Statements: statements}
	requestWire, err := json.Marshal(pending.Request, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	pending.RequestDigest = digestSource(requestWire)
	pending.RetryToken = digestSource([]byte(mapKey + "\x00" + pending.InstanceID + "\x00" + pending.GrantDigest + "\x00" + pending.RequestDigest))
	record := FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: "sa-saopaulo-1", TenancyID: "ocid1.tenancy.oc1..test", ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Generation: 1, IntentDigest: strings.Repeat("0", 64), OperationID: entityid.New(), Epoch: 1, Stage: "reconciled", StartedAt: now, UpdatedAt: now, CompletedAt: now, ResourceIDs: map[string]string{}, SourcePolicyIDs: map[string]SourcePolicyRecord{mapKey: pending}}
	etag, err := store.CompareAndSwap(t.Context(), record, "")
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewObjectFoundationStore(client, "ns", "heads")
	if err != nil {
		t.Fatal(err)
	}
	saved, savedETag, err := restarted.Load(t.Context(), "GRU")
	if err != nil || savedETag != etag || saved.SourcePolicyIDs[mapKey].RetryToken != pending.RetryToken {
		t.Fatalf("pending reservation lost: %v", err)
	}
	// A later signed generation retains the first recipient's exact original bindings.
	saved.Generation = 2
	saved.SourcePolicyIDs = maps.Clone(saved.SourcePolicyIDs)
	established := saved.SourcePolicyIDs[mapKey]
	established.PolicyID = "ocid1.policy.oc1..source"
	established.ProtectionEstablishedAt = now.Add(time.Second)
	saved.SourcePolicyIDs[mapKey] = established
	if _, err = restarted.CompareAndSwap(t.Context(), saved, savedETag); err != nil {
		t.Fatal(err)
	}
	if _, err = store.CompareAndSwap(t.Context(), record, etag); !errors.Is(err, ErrFoundationConflict) {
		t.Fatalf("stale policy checkpoint accepted: %v", err)
	}
	loaded, _, err := restarted.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	original := loaded.SourcePolicyIDs[mapKey]
	if original.InstanceID != pending.InstanceID || original.GrantDigest != pending.GrantDigest || original.TemplateDigest != pending.TemplateDigest || original.GrantGeneration != 1 || original.PolicyID != established.PolicyID {
		t.Fatal("renewal transferred original source binding")
	}
	// Corrupt an authenticated record at rest: no broad policy may become replay authority.
	original.Request.Statements = append(original.Request.Statements, "Allow any-user to manage objects in tenancy")
	loaded.SourcePolicyIDs[mapKey] = original
	wire, err := json.Marshal(loaded, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	raw(foundationObjectPrefix+"GRU.json", wire)
	if _, _, err := restarted.Load(t.Context(), "GRU"); err == nil {
		t.Fatal("durable widened policy accepted")
	}
}

func paginationSDKFactory(t *testing.T, handler http.HandlerFunc) *ociclient.Factory {
	t.Helper()
	// Preserve the test-only proxy and dialers when the SDK clones its transport.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
			t.Errorf("unsigned or mutating pagination request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("pagination SDK fixture requires literal TCP loopback")
	}
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	if tlsConfig.InsecureSkipVerify || tlsConfig.RootCAs == nil {
		t.Fatal("pagination SDK fixture requires verified TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("pagination SDK fixture refuses plaintext connections")
	}
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("pagination SDK fixture refuses network %q", network)
		}
		return (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, network, listener.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", foundationHomeRegion, "fixture", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

func TestSourcePolicyDiscoverySDKPagination(t *testing.T) {
	for _, scenario := range []struct {
		name                     string
		cycle                    string
		emptyTerminal, duplicate bool
	}{
		{name: "finite pages"},
		{name: "empty terminal page", emptyTerminal: true},
		{name: "self cycle", cycle: "self"},
		{name: "two token cycle", cycle: "two"},
		{name: "duplicate policy remains ambiguous", duplicate: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var requests atomic.Int32
			factory := paginationSDKFactory(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/20160918/policies" || r.URL.Query().Get("name") != "wanted" || r.URL.Query().Get("compartmentId") != "ocid1.compartment.oc1..home" {
					t.Errorf("policy listing escaped exact scope: %s", r.URL)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if requests.Add(1) > 3 {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				items := []identity.Policy{}
				switch r.URL.Query().Get("page") {
				case "":
					w.Header().Set("opc-next-page", "page-a")
					items = append(items, identity.Policy{Id: new("ocid1.policy.oc1..source"), Name: new("wanted")})
				case "page-a":
					next := "page-b"
					if scenario.cycle == "self" {
						next = "page-a"
					}
					w.Header().Set("opc-next-page", next)
					if scenario.duplicate {
						items = append(items, identity.Policy{Id: new("ocid1.policy.oc1..source"), Name: new("wanted")})
					}
				case "page-b":
					if scenario.cycle == "two" {
						w.Header().Set("opc-next-page", "page-a")
					} else if scenario.emptyTerminal {
						w.Header().Set("opc-next-page", "")
					}
				default:
					t.Errorf("unexpected policy page: %s", r.URL)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if err := json.MarshalWrite(w, items); err != nil {
					t.Error(err)
				}
			})
			iam, err := factory.Identity()
			if err != nil {
				t.Fatal(err)
			}
			actor := &SourceFounder{iam: iam}
			id, err := actor.findPolicy(t.Context(), identity.CreatePolicyDetails{CompartmentId: new("ocid1.compartment.oc1..home"), Name: new("wanted")})
			wantRequests := int32(3)
			if scenario.cycle == "self" || scenario.duplicate {
				wantRequests = 2
			}
			if requests.Load() != wantRequests {
				t.Fatalf("requests=%d, want%d", requests.Load(), wantRequests)
			}
			if scenario.cycle != "" || scenario.duplicate {
				want := "repeated its page"
				if scenario.duplicate {
					want = "ambiguous"
				}
				if err == nil || !strings.Contains(err.Error(), want) || id != "" {
					t.Fatalf("partial policy discovery id=%q error=%v, want%s and no ID", id, err, want)
				}
			} else if err != nil || id != "ocid1.policy.oc1..source" {
				t.Fatalf("finite policy discovery id=%q error=%v", id, err)
			}
		})
	}
}
