package imagequalification

import (
	"context"
	"crypto/ed25519"
	"crypto/md5" // OCI API-key fingerprints use MD5 over public SPKI DER.
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/principal"
)

func TestSealedSDKPrincipalRefinesExactHostApproval(t *testing.T) {
	f := fixture(t)
	a := f.prepared.Approval()
	payload, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var p principal.Preparation
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	p.Schema = principal.PreparationSchema
	p.IssuerPrincipal = "ocid1.user.oc1..issuer"
	p.PrincipalName, p.GroupName, p.PolicyName = "ts-qualification-"+a.RunID+"-user", "ts-qualification-"+a.RunID+"-group", "ts-qualification-"+a.RunID+"-policy"
	p.Object = "qualification/" + a.RunID + "/" + a.Candidate.ArtifactSHA256 + ".qcow2"
	p.ExpiresAt = f.prepared.expires
	escrow := filepath.Join(t.TempDir(), "escrow")
	p.PublicKeyPEM, p.PublicKeyFingerprint, err = principal.GenerateKey(escrow)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := md5.Sum(der)
	parts := make([]string, len(digest))
	for i, b := range digest {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	p.IssuerFingerprint = strings.Join(parts, ":")
	p.PolicyTemplate = principal.RequiredTemplate(p)
	sign := func(preparation principal.Preparation) []byte {
		t.Helper()
		payload, err := trust.EncodePayload(preparation)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, principal.PreparationScope(p.RunID, p.Candidate), f.now.Add(-time.Minute), p.CleanupUntil, f.private)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	wire := sign(p)
	verified, err := principal.VerifyPreparation(wire, nil, f.roots, p.RunID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	user, group, policy, membership := "ocid1.user.oc1..created", "ocid1.group.oc1..created", "ocid1.policy.oc1..created", "ocid1.groupmembership.oc1..created"
	description := "Disposable image qualification " + verified.SHA256()
	statements := confinement.RequiredStatements(confinement.Scope{RunID: p.RunID, Group: group, Compartment: p.Compartment, Bucket: p.Bucket, Object: p.Object, ExpiresAt: p.ExpiresAt, CleanupUntil: p.CleanupUntil})
	resources := map[string]any{
		"/users/" + user:                      identity.User{Id: new(user), CompartmentId: new(p.Tenancy), Name: new(p.PrincipalName), Description: new(description), LifecycleState: identity.UserLifecycleStateActive},
		"/groups/" + group:                    identity.Group{Id: new(group), CompartmentId: new(p.Tenancy), Name: new(p.GroupName), Description: new(description), LifecycleState: identity.GroupLifecycleStateActive},
		"/policies/" + policy:                 identity.Policy{Id: new(policy), CompartmentId: new(p.Tenancy), Name: new(p.PolicyName), Description: new(description), Statements: statements, LifecycleState: identity.PolicyLifecycleStateActive},
		"/userGroupMemberships/" + membership: identity.UserGroupMembership{Id: new(membership), CompartmentId: new(p.Tenancy), UserId: new(user), GroupId: new(group), LifecycleState: identity.UserGroupMembershipLifecycleStateActive},
	}
	apiKey := identity.ApiKey{UserId: new(user), Fingerprint: new(p.PublicKeyFingerprint), KeyValue: new(p.PublicKeyPEM), LifecycleState: identity.ApiKeyLifecycleStateActive}
	var mu sync.Mutex
	creates := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !authenticatedFixtureRequest(r, &key.PublicKey, p.Tenancy) || !strings.Contains(r.Header.Get("Authorization"), `keyId="`+p.Tenancy+"/"+p.IssuerPrincipal+"/"+p.IssuerFingerprint+`"`) {
			http.Error(w, "invalid exact issuer signature", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/20160918")
		var result any
		if r.Method == http.MethodGet {
			switch path {
			case "/tenancies/" + p.Tenancy:
				result = identity.Tenancy{Id: new(p.Tenancy), HomeRegionKey: new("GRU")}
			case "/users/" + p.IssuerPrincipal:
				result = identity.User{Id: new(p.IssuerPrincipal), CompartmentId: new(p.Tenancy), LifecycleState: identity.UserLifecycleStateActive}
			case "/users/" + p.IssuerPrincipal + "/apiKeys":
				result = []identity.ApiKey{{UserId: new(p.IssuerPrincipal), Fingerprint: new(p.IssuerFingerprint), LifecycleState: identity.ApiKeyLifecycleStateActive}}
			case "/users/" + user + "/apiKeys":
				result = []identity.ApiKey{apiKey}
			default:
				result = resources[path]
			}
		} else if r.Method == http.MethodPost {
			creates++
			switch path {
			case "/users":
				result = resources["/users/"+user]
			case "/groups":
				result = resources["/groups/"+group]
			case "/policies":
				var details identity.CreatePolicyDetails
				if err := json.UnmarshalRead(r.Body, &details); err != nil || !reflect.DeepEqual(details.Statements, statements) || details.CompartmentId == nil || *details.CompartmentId != p.Tenancy {
					t.Error("SDK policy differs from exact tenancy-attached policy", err)
				}
				result = resources["/policies/"+policy]
			case "/users/" + user + "/apiKeys":
				result = apiKey
			case "/userGroupMemberships":
				result = resources["/userGroupMemberships/"+membership]
			}
		}
		if result == nil {
			t.Errorf("unexpected principal SDK request: %s %s", r.Method, path)
			http.Error(w, "unexpected SDK request", http.StatusBadRequest)
			return
		}
		if err := json.MarshalWrite(w, result); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	fixtureURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "identity.sa-saopaulo-1.oci.oraclecloud.com:443" {
			return nil, fmt.Errorf("unapproved principal fixture origin %s", address)
		}
		return (&tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: fixtureURL.Hostname(), MinVersion: tls.VersionTLS13}}).DialContext(ctx, network, fixtureURL.Host)
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	provider := common.NewRawConfigurationProvider(p.Tenancy, p.IssuerPrincipal, p.IAMRegion, p.IssuerFingerprint, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	issuer, err := ociclient.New(provider, ociclient.Options{Region: p.IAMRegion, Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceIdentity: {PerSecond: 10000, Burst: 1000}}, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := principal.New(issuer).Prepare(t.Context(), verified, escrow)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	count := creates
	mu.Unlock()
	if count != 5 || !result.Prepared() {
		t.Fatalf("actual SDK preparation incomplete: creates=%d prepared=%t", count, result.Prepared())
	}
	prepared, hostWire, err := PrepareFromPrincipal(wire, nil, f.roots, result, f.private, p.RunID, f.disk, f.qualification, f.now)
	if err != nil {
		t.Fatal(err)
	}
	a.Principal, a.Group, a.PolicyID, a.PolicyStatements = user, group, policy, statements
	if !reflect.DeepEqual(prepared.Approval(), a) || !prepared.expires.Equal(p.ExpiresAt) {
		t.Fatal("sealed principal consumer changed finite signed approval fields or renewed expiry")
	}
	envelope, err := trust.DecodeEnvelope(hostWire)
	if err != nil || !envelope.ExpiresAt.Equal(p.ExpiresAt) {
		t.Fatal("host approval envelope expiry differs from original create authority", err)
	}
	if _, err := Prepare(hostWire, nil, f.roots, p.Candidate, p.RunID, f.disk, f.qualification, f.now); err != nil {
		t.Fatal("actual emitted host signature did not verify", err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	changed := p
	changed.MaxSpendMicros++
	for _, tc := range []struct {
		name, want string
		wire       []byte
		signer     ed25519.PrivateKey
		now        time.Time
	}{
		{"different-qualifier", "original preparation qualifier", wire, other, f.now},
		{"different-preparation", "exact finite preparation", sign(changed), f.private, f.now},
		{"expired-create-authority", "exact finite preparation", wire, f.private, p.ExpiresAt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, emitted, err := PrepareFromPrincipal(tc.wire, nil, f.roots, result, tc.signer, p.RunID, f.disk, f.qualification, tc.now)
			if err == nil || !strings.Contains(err.Error(), tc.want) || len(emitted) != 0 || prepared.approvalSHA256 != "" {
				t.Fatalf("invalid refinement emitted authority: bytes=%d err=%v", len(emitted), err)
			}
		})
	}
	for _, path := range []string{f.disk, f.qualification} {
		t.Run("changed-bytes/"+filepath.Base(path), func(t *testing.T) {
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(original, '!'), 0600); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Error(err)
				}
			}()
			prepared, emitted, err := PrepareFromPrincipal(wire, nil, f.roots, result, f.private, p.RunID, f.disk, f.qualification, f.now)
			if err == nil || len(emitted) != 0 || prepared.approvalSHA256 != "" {
				t.Fatalf("changed artifact emitted authority: bytes=%d err=%v", len(emitted), err)
			}
		})
	}
}
