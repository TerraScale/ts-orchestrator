package teardown

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/vault"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

func sdkProvider(t *testing.T, server *httptest.Server) *SDKProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	config := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..t", "ocid1.user.oc1..u", "sa-saopaulo-1", "fp",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(config, ociclient.Options{Region: "sa-saopaulo-1"})
	if err != nil {
		t.Fatal(err)
	}
	p := &SDKProvider{factory: factory}
	if p.vaults, err = keymanagement.NewKmsVaultClientWithConfigurationProvider(config); err != nil {
		t.Fatal(err)
	}
	if p.secrets, err = vault.NewVaultsClientWithConfigurationProvider(config); err != nil {
		t.Fatal(err)
	}
	if p.identity, err = factory.Identity(); err != nil {
		t.Fatal(err)
	}
	p.vaults.Host, p.secrets.Host, p.identity.Host = server.URL, server.URL, server.URL
	return p
}

func TestSDKPreservesAmbiguous404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"code":"NotAuthorizedOrNotFound","message":"unreadable or absent"}`)
	}))
	t.Cleanup(server.Close)
	p := sdkProvider(t, server)
	for _, r := range gruPlan().Delete {
		o, err := p.Get(t.Context(), r)
		if err != nil || o.State != NotFound {
			t.Fatalf("Get(%s): state %s, err %v", r.Kind, o.State, err)
		}
	}
	if _, err := p.VaultContents(t.Context(), Resource{ID: "vault"}); err == nil {
		t.Fatal("unreadable vault treated as empty")
	}
	if err := p.Delete(t.Context(), Resource{Kind: "kms-key", ID: "key", VaultID: "vault"}); err == nil {
		t.Fatal("key deletion reported success through an unreadable vault")
	}
}

func TestSDKVaultContentsAcrossCompartmentsAndPages(t *testing.T) {
	for _, unreadable := range []bool{false, true} {
		t.Run(fmt.Sprint(unreadable), func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				page := r.URL.Query().Get("page")
				compartment := r.URL.Query().Get("compartmentId")
				switch {
				case strings.HasSuffix(r.URL.Path, "/vaults/vault"):
					_, _ = fmt.Fprintf(w, `{"id":"vault","lifecycleState":"ACTIVE","managementEndpoint":%q}`, server.URL)
				case strings.HasSuffix(r.URL.Path, "/compartments"):
					if r.URL.Query().Get("accessLevel") != "ANY" || r.URL.Query().Get("compartmentIdInSubtree") != "true" {
						t.Errorf("incomplete compartment query: %s", r.URL.RawQuery)
					}
					if page == "" {
						w.Header().Set("opc-next-page", "next")
						_, _ = io.WriteString(w, `[{"id":"control","lifecycleState":"ACTIVE"}]`)
					} else {
						_, _ = io.WriteString(w, `[{"id":"shared","lifecycleState":"ACTIVE"}]`)
					}
				case compartment == "shared" && unreadable:
					w.WriteHeader(http.StatusForbidden)
					_, _ = io.WriteString(w, `{"code":"NotAuthorized","message":"cannot inspect shared compartment"}`)
				case strings.HasSuffix(r.URL.Path, "/keys") && compartment == "shared":
					if page == "" {
						w.Header().Set("opc-next-page", "next")
						_, _ = io.WriteString(w, `[{"id":"key-1","lifecycleState":"ENABLED"}]`)
					} else {
						_, _ = io.WriteString(w, `[{"id":"key-2","lifecycleState":"PENDING_DELETION"}]`)
					}
				case strings.HasSuffix(r.URL.Path, "/secrets") && compartment == "shared":
					if r.URL.Query().Get("vaultId") != "vault" {
						t.Error("secret list missing vault filter")
					}
					if page == "" {
						w.Header().Set("opc-next-page", "next")
						_, _ = io.WriteString(w, `[{"id":"secret-1","lifecycleState":"ACTIVE"}]`)
					} else {
						_, _ = io.WriteString(w, `[{"id":"secret-2","lifecycleState":"PENDING_DELETION"}]`)
					}
				default:
					_, _ = io.WriteString(w, `[]`)
				}
			}))
			t.Cleanup(server.Close)
			contents, err := sdkProvider(t, server).VaultContents(t.Context(), Resource{ID: "vault"})
			if unreadable {
				if err == nil {
					t.Fatal("unreadable compartment treated as empty")
				}
				return
			}
			if err != nil || !slices.Equal(contents, []string{"key-1", "key-2", "secret-1", "secret-2"}) {
				t.Fatalf("contents %v, err %v", contents, err)
			}
		})
	}
}

type recordingIdentityClient struct {
	server *httptest.Server
	host   string
}

func (c *recordingIdentityClient) Do(r *http.Request) (*http.Response, error) {
	c.host = r.URL.Host
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = "http", strings.TrimPrefix(c.server.URL, "http://")
	r.Host = r.URL.Host
	return c.server.Client().Do(r)
}

func TestSDKCompartmentDeletionUsesTenancyHomeRegion(t *testing.T) {
	for _, homeKey := range []string{"sJc", "", "unknown"} {
		t.Run(homeKey, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/tenancies/ocid1.tenancy.oc1..t"):
					_, _ = fmt.Fprintf(w, `{"id":"ocid1.tenancy.oc1..t","homeRegionKey":%q}`, homeKey)
				case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/compartments/"+cellCompartment):
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusForbidden)
				}
			}))
			t.Cleanup(server.Close)
			p := sdkProvider(t, server)
			p.vaults.SetRegion(p.factory.Region())
			p.secrets.SetRegion(p.factory.Region())
			vaultHost, secretHost := p.vaults.Host, p.secrets.Host
			client := &recordingIdentityClient{server: server}
			p.identity.HTTPClient = client
			err := p.useHomeIdentity(t.Context())
			if homeKey != "sJc" {
				if err == nil {
					t.Fatal("unresolved home region accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Delete(t.Context(), Resource{Kind: "compartment", ID: cellCompartment}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(client.host, "us-sanjose-1") || p.vaults.Host != vaultHost || p.secrets.Host != secretHost ||
				p.factory.Region() != "sa-saopaulo-1" {
				t.Fatalf("identity host %s, vault host %s, secret host %s, cell region %s", client.host, p.vaults.Host, p.secrets.Host, p.factory.Region())
			}
		})
	}
}
