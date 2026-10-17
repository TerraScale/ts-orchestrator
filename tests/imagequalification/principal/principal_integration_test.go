package principal

import (
	"crypto"
	"crypto/ed25519"
	"crypto/md5" // OCI's required public-key fingerprint format.
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
)

var issuerKey = sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 3072) })

type sdkFixture struct {
	t                *testing.T
	dir              string
	prep             Preparation
	verified         VerifiedPreparation
	root             ed25519.PrivateKey
	roots            trust.Keyring
	producer         *Producer
	clock            atomic.Int64
	server           *httptest.Server
	key              *rsa.PrivateKey
	mu               sync.Mutex
	resources        map[string]any
	tokens           map[string]string
	creates          map[string]int
	writes           []string
	failCreate       string
	failDelete       string
	wrongObservation bool
	wrongIAMHome     bool
	expireAfterUser  bool
}

func newFixture(t *testing.T) *sdkFixture {
	t.Helper()
	f := &sdkFixture{t: t, dir: filepath.Join(t.TempDir(), "escrow"), resources: map[string]any{}, tokens: map[string]string{}, creates: map[string]int{}}
	f.clock.Store(time.Now().UTC().Truncate(time.Second).UnixNano())
	public, fingerprint, err := GenerateKey(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	f.key, err = issuerKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	md := md5.Sum(der)
	parts := make([]string, len(md))
	for i, b := range md {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	issuerFingerprint := strings.Join(parts, ":")
	now := f.now()
	f.prep = Preparation{Schema: PreparationSchema, RunID: "testrun", Candidate: release.ProductionExpectation{SourceRevision: strings.Repeat("a", 40), ArtifactSHA256: strings.Repeat("b", 64), QualificationSHA256: strings.Repeat("c", 64), Cell: "GRU", Environment: "production", Runtime: release.ProductionRuntime, Architecture: "arm64", Role: "orchestrator"},
		Tenancy: "ocid1.tenancy.oc1..test", IssuerPrincipal: "ocid1.user.oc1..issuer", IssuerFingerprint: issuerFingerprint, OCIRegion: "sa-saopaulo-1", IAMRegion: "sa-saopaulo-1",
		PrincipalName: "ts-qualification-testrun-user", GroupName: "ts-qualification-testrun-group", PolicyName: "ts-qualification-testrun-policy", PublicKeyPEM: public, PublicKeyFingerprint: fingerprint,
		Compartment: "ocid1.compartment.oc1..disposable", Subnet: "ocid1.subnet.oc1..disposable", Namespace: "qualification", Bucket: "disposable",
		Object: "qualification/testrun/" + strings.Repeat("b", 64) + ".qcow2", RunnerCIDR: "10.72.0.1/32", PeerCIDR: "10.72.1.0/24", VCNCIDR: "10.72.0.0/16",
		WorkloadImage: "registry.example.test/qualification/workload@sha256:" + strings.Repeat("d", 64), WorkloadArchiveSHA256: strings.Repeat("e", 64), ImageBytes: 1 << 20, MaxSpendMicros: 5_000_000,
		BinarySHA256: strings.Repeat("1", 64), KernelSHA256: strings.Repeat("2", 64), ContainerdSHA256: strings.Repeat("3", 64), RuncSHA256: strings.Repeat("4", 64), RunnerSHA256: strings.Repeat("5", 64), ExpiresAt: now.Add(47 * time.Hour), CleanupUntil: now.Add(60 * time.Hour)}
	f.prep.ProfileIdentity = cellspec.Identity{DeploymentID: entityid.Derive("qualification-profile", f.prep.RunID), Cell: f.prep.Candidate.Cell, Environment: f.prep.Candidate.Environment}
	f.prep.KernelRelease = "6.12.57-terrascale"
	for _, scenario := range []string{"ready", "after-loss", "after-partition", "unready", "failed-update"} {
		f.prep.MaterialFixtures = append(f.prep.MaterialFixtures, MaterialApproval{Scenario: scenario, SignedProfileSHA256: hash([]byte("profile/" + scenario)), ContainerIntentSHA256: hash([]byte("intent/" + scenario))})
	}
	for i := range 4 {
		role := "manager"
		if i == 3 {
			role = "worker"
		}
		f.prep.Hosts = append(f.prep.Hosts, HostSpec{Name: fmt.Sprintf("host-%d", i), Role: role, AvailabilityDomain: "AD-1", FaultDomain: fmt.Sprintf("FAULT-DOMAIN-%d", i%3+1), Shape: "VM.Standard.A1.Flex", OCPUs: 1, MemoryGB: 6, BootGB: 50})
	}
	f.prep.PolicyTemplate = RequiredTemplate(f.prep)
	_, f.root, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.roots, err = trust.ParseKeyring(f.root.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	f.verified = f.verify(f.prep)
	provider := common.NewRawConfigurationProvider(f.prep.Tenancy, f.prep.IssuerPrincipal, f.prep.IAMRegion, issuerFingerprint, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: f.prep.IAMRegion, Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceIdentity: {PerSecond: 10000, Burst: 10000}}, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	f.producer = New(factory)
	f.producer.now = f.now
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	f.producer.endpoint = f.server.URL
	return f
}

func (f *sdkFixture) now() time.Time          { return time.Unix(0, f.clock.Load()).UTC() }
func (f *sdkFixture) advance(d time.Duration) { f.clock.Add(int64(d)) }

func (f *sdkFixture) wire(p Preparation, scope trust.Scope, key ed25519.PrivateKey) []byte {
	f.t.Helper()
	payload, err := trust.EncodePayload(p)
	if err != nil {
		f.t.Fatal(err)
	}
	e, err := trust.Sign(payload, scope, f.now().Add(-time.Minute), p.CleanupUntil, key)
	if err != nil {
		f.t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(e)
	if err != nil {
		f.t.Fatal(err)
	}
	return wire
}

func (f *sdkFixture) verify(p Preparation) VerifiedPreparation {
	f.t.Helper()
	wire := f.wire(p, PreparationScope(p.RunID, p.Candidate), f.root)
	v, err := VerifyPreparation(wire, nil, f.roots, p.RunID, f.now())
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func (f *sdkFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("etag", "exact-etag")
	write := func(status int, value any) {
		wire, err := json.Marshal(value)
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write(wire)
	}
	failure := func(status int, code string) {
		write(status, map[string]string{"code": code, "message": "local SDK scenario"})
	}
	if !validSDKSignature(r, &f.key.PublicKey, f.prep.Tenancy+"/"+f.prep.IssuerPrincipal+"/"+f.prep.IssuerFingerprint) {
		f.t.Error("SDK request did not carry the exact issuer's valid RSA signature")
		failure(401, "NotAuthenticated")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/20160918")
	if r.Method == http.MethodGet {
		if path == "/tenancies/"+f.prep.Tenancy {
			key := "GRU"
			if f.wrongIAMHome {
				key = "FRA"
			}
			write(200, identity.Tenancy{Id: new(f.prep.Tenancy), HomeRegionKey: new(key)})
			return
		}
		if path == "/users/"+f.prep.IssuerPrincipal {
			write(200, identity.User{Id: new(f.prep.IssuerPrincipal), CompartmentId: new(f.prep.Tenancy), LifecycleState: identity.UserLifecycleStateActive})
			return
		}
		if path == "/users/"+f.prep.IssuerPrincipal+"/apiKeys" {
			write(200, []identity.ApiKey{{UserId: new(f.prep.IssuerPrincipal), Fingerprint: new(f.prep.IssuerFingerprint), LifecycleState: identity.ApiKeyLifecycleStateActive}})
			return
		}
		if strings.HasSuffix(path, "/apiKeys") {
			var keys []identity.ApiKey
			for _, resource := range f.resources {
				if key, ok := resource.(identity.ApiKey); ok && path == "/users/"+value(key.UserId)+"/apiKeys" {
					keys = append(keys, key)
				}
			}
			if keys == nil {
				keys = []identity.ApiKey{}
			}
			write(200, keys)
			return
		}
		id := path[strings.LastIndex(path, "/")+1:]
		if resource, ok := f.resources[id]; ok {
			if user, ok := resource.(identity.User); ok {
				if f.wrongObservation {
					user.Id = new("ocid1.user.oc1..unrelated")
					resource = user
				}
				if f.expireAfterUser {
					f.clock.Store(f.prep.ExpiresAt.UnixNano())
				}
			}
			write(200, resource)
			return
		}
		failure(404, "NotAuthorizedOrNotFound")
		return
	}
	wire, err := os.ReadFile(filepath.Join(f.dir, "journal.json"))
	if err != nil {
		f.t.Error("IAM mutation preceded durable journal", err)
		failure(400, "MissingParameter")
		return
	}
	var j journal
	if err := protocol.DecodeStrict(wire, &j, 256<<10); err != nil {
		f.t.Error(err)
		failure(400, "InvalidParameter")
		return
	}
	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			f.t.Error(err)
			failure(400, "InvalidParameter")
			return
		}
		digest := sha256.Sum256(body)
		if r.Header.Get("x-content-sha256") != base64.StdEncoding.EncodeToString(digest[:]) {
			f.t.Error("SDK signed body digest differs")
			failure(400, "InvalidParameter")
			return
		}
		name := ""
		switch {
		case path == "/users":
			name = "user"
		case path == "/groups":
			name = "group"
		case path == "/policies":
			name = "policy"
		case path == "/userGroupMemberships":
			name = "membership"
		case strings.HasSuffix(path, "/apiKeys"):
			name = "key"
		}
		op := j.Operations[name]
		token := r.Header.Get("opc-retry-token")
		if op == nil || token == "" || token != op.RetryToken || r.Header.Get("opc-request-id") != token || op.FirstAttempt.IsZero() || op.RequestSHA256 != hash(op.Request) || j.PreparationSHA256 != f.verified.digest {
			f.t.Error("mutation lacks exact durable signed request/token intent")
			failure(400, "InvalidParameter")
			return
		}
		var exact createIntent
		if err := json.Unmarshal(op.Request, &exact); err != nil {
			f.t.Error(err)
			failure(400, "InvalidParameter")
			return
		}
		if exact.Method != r.Method || exact.Path != strings.TrimPrefix(r.URL.EscapedPath(), "/20160918") || exact.Body != string(body) {
			f.t.Error("wire request differs from fsynced SDK intent")
			failure(400, "InvalidParameter")
			return
		}

		if existing, ok := f.tokens[token]; ok {
			write(200, f.resources[existing])
			return
		}
		id := "ocid1." + name + ".oc1..created"
		if name == "membership" {
			id = "ocid1.groupmembership.oc1..created"
		}
		if name == "key" {
			id = f.prep.PublicKeyFingerprint
		}
		description := "Disposable image qualification " + f.verified.digest
		var resource any
		switch name {
		case "user":
			resource = identity.User{Id: new(id), CompartmentId: new(f.prep.Tenancy), Name: new(f.prep.PrincipalName), Description: new(description), LifecycleState: identity.UserLifecycleStateActive}
		case "group":
			resource = identity.Group{Id: new(id), CompartmentId: new(f.prep.Tenancy), Name: new(f.prep.GroupName), Description: new(description), LifecycleState: identity.GroupLifecycleStateActive}
		case "policy":
			var details identity.CreatePolicyDetails
			if err := json.Unmarshal(body, &details); err != nil {
				f.t.Error(err)
			}
			resource = identity.Policy{Id: new(id), CompartmentId: new(f.prep.Tenancy), Name: new(f.prep.PolicyName), Description: new(description), Statements: details.Statements, LifecycleState: identity.PolicyLifecycleStateActive}
		case "key":
			resource = identity.ApiKey{UserId: new("ocid1.user.oc1..created"), Fingerprint: new(id), KeyValue: new(f.prep.PublicKeyPEM), LifecycleState: identity.ApiKeyLifecycleStateActive}
		case "membership":
			resource = identity.UserGroupMembership{Id: new(id), CompartmentId: new(f.prep.Tenancy), UserId: new("ocid1.user.oc1..created"), GroupId: new("ocid1.group.oc1..created"), LifecycleState: identity.UserGroupMembershipLifecycleStateActive}
		default:
			f.t.Errorf("unexpected IAM path %s", path)
			failure(400, "InvalidParameter")
			return
		}
		f.resources[id] = resource
		f.tokens[token] = id
		f.creates[name]++
		f.writes = append(f.writes, "create/"+name)
		if f.failCreate == name {
			f.failCreate = ""
			failure(503, "InternalError")
			return
		}
		write(200, resource)
		return
	}
	if r.Method == http.MethodDelete {
		id := path[strings.LastIndex(path, "/")+1:]
		name := ""
		for n, op := range j.Operations {
			if op.ID == id {
				name = n
				if !op.DeleteIntent {
					f.t.Error("delete preceded durable revoke intent")
				}
				break
			}
		}
		if name == "" {
			f.t.Errorf("deleting non-journaled resource %s", id)
			failure(400, "InvalidParameter")
			return
		}
		delete(f.resources, id)
		f.writes = append(f.writes, "delete/"+name)
		if f.failDelete == name {
			f.failDelete = ""
			failure(503, "InternalError")
			return
		}
		w.WriteHeader(204)
		return
	}
	f.t.Errorf("unexpected IAM method %s", r.Method)
	failure(400, "InvalidParameter")
}

var authorizationField = regexp.MustCompile(`([a-zA-Z]+)="([^"]*)"`)

func validSDKSignature(r *http.Request, key *rsa.PublicKey, keyID string) bool {
	fields := map[string]string{}
	for _, match := range authorizationField.FindAllStringSubmatch(r.Header.Get("Authorization"), -1) {
		fields[match[1]] = match[2]
	}
	if fields["keyId"] != keyID || fields["algorithm"] != "rsa-sha256" {
		return false
	}
	var lines []string
	for header := range strings.FieldsSeq(fields["headers"]) {
		v := r.Header.Get(header)
		if header == "host" {
			v = r.Host
		}
		if header == "(request-target)" {
			v = strings.ToLower(r.Method) + " " + r.URL.RequestURI()
		}
		lines = append(lines, header+": "+v)
	}
	signature, err := base64.StdEncoding.DecodeString(fields["signature"])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil
}

func TestSDKPrepareRestartAndCleanup(t *testing.T) {
	f := newFixture(t)
	result, err := f.producer.Prepare(t.Context(), f.verified, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt().Principal != "ocid1.user.oc1..created" || result.Receipt().Group != "ocid1.group.oc1..created" || result.Receipt().PolicyID != "ocid1.policy.oc1..created" || result.CandidateFactory() == nil {
		t.Fatalf("missing actual prepared identities: %+v", result)
	}
	if err := result.ValidatePreparation(f.verified, f.now()); err != nil {
		t.Fatal(err)
	}
	other := f.prep
	other.MaxSpendMicros++
	if err := result.ValidatePreparation(f.verify(other), f.now()); err == nil {
		t.Fatal("sealed result accepted a different signed finite preparation")
	}
	if err := (Result{}).ValidatePreparation(f.verified, f.now()); err == nil {
		t.Fatal("empty result manufactured prepared authority")
	}
	if user, _ := result.CandidateFactory().Provider().UserOCID(); user != result.Receipt().Principal {
		t.Fatal("candidate factory did not use newly created principal")
	}
	private, err := os.ReadFile(filepath.Join(f.dir, "private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	wire, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	journalWire, err := os.ReadFile(filepath.Join(f.dir, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "PRIVATE KEY") || strings.Contains(string(journalWire), "PRIVATE KEY") || strings.Contains(string(journalWire), string(private)) {
		t.Fatal("public result or journal disclosed private key")
	}
	reopened := New(f.producer.issuer)
	reopened.endpoint = f.server.URL
	reopened.now = f.now
	if _, err := reopened.Prepare(t.Context(), f.verified, f.dir); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	for name, count := range f.creates {
		if count != 1 {
			t.Errorf("restart duplicated %s: %d", name, count)
		}
	}
	f.resources["ocid1.user.oc1..unrelated"] = identity.User{Id: new("ocid1.user.oc1..unrelated")}
	f.mu.Unlock()
	// Cleanup still uses current signatures after creation has expired.
	f.advance(49 * time.Hour)
	if err := result.ValidatePreparation(f.verified, f.now()); err == nil {
		t.Fatal("sealed result renewed expired creation authority")
	}
	cleaned, err := reopened.Cleanup(t.Context(), f.verified, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cleaned.Receipt().Cleaned || cleaned.CandidateFactory() != nil {
		t.Fatal("cleanup did not return a public-only complete receipt")
	}
	if _, err := os.Stat(filepath.Join(f.dir, "private.pem")); !os.IsNotExist(err) {
		t.Fatal("private escrow retained after confirmed complete revocation")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resources) != 1 || f.resources["ocid1.user.oc1..unrelated"] == nil {
		t.Fatal("cleanup touched unrelated resources or left prepared resources")
	}
	want := []string{"delete/policy", "delete/key", "delete/membership", "delete/user", "delete/group"}
	var deleted []string
	for _, op := range f.writes {
		if strings.HasPrefix(op, "delete/") {
			deleted = append(deleted, op)
		}
	}
	if !slices.Equal(deleted, want) {
		t.Fatalf("revoke order %v", deleted)
	}
}

func TestSDKUnknownCreateReplayUsesExactDurableToken(t *testing.T) {
	for _, name := range []string{"user", "group", "policy", "key", "membership"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.failCreate = name
			if _, err := f.producer.Prepare(t.Context(), f.verified, f.dir); err == nil {
				t.Fatal("ambiguous applied create did not surface")
			}
			reopened := New(f.producer.issuer)
			reopened.endpoint = f.server.URL
			reopened.now = f.now
			if _, err := reopened.Prepare(t.Context(), f.verified, f.dir); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			for op, count := range f.creates {
				if count != 1 {
					t.Errorf("duplicated %s after unknown outcome: %d", op, count)
				}
			}
			f.mu.Unlock()
			if _, err := reopened.Cleanup(t.Context(), f.verified, f.dir); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSDKUnknownDeleteRecoveryRetainsOtherResources(t *testing.T) {
	for _, name := range []string{"policy", "key", "membership", "user", "group"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if _, err := f.producer.Prepare(t.Context(), f.verified, f.dir); err != nil {
				t.Fatal(err)
			}
			f.failDelete = name
			if result, err := f.producer.Cleanup(t.Context(), f.verified, f.dir); err == nil || result.Receipt().Cleaned {
				t.Fatal("ambiguous delete claimed full cleanup")
			}
			if _, err := os.Stat(filepath.Join(f.dir, "private.pem")); err != nil {
				t.Fatal("recovery key removed before confirmed complete cleanup")
			}
			if result, err := f.producer.Cleanup(t.Context(), f.verified, f.dir); err != nil || !result.Receipt().Cleaned {
				t.Fatalf("restart cleanup: %+v %v", result, err)
			}
		})
	}
}

func TestSDKExpiredAmbiguousCreateNeverAdoptsByName(t *testing.T) {
	f := newFixture(t)
	f.failCreate = "group"
	if _, err := f.producer.Prepare(t.Context(), f.verified, f.dir); err == nil {
		t.Fatal("missing unknown group outcome")
	}
	f.advance(24 * time.Hour)
	if _, err := f.producer.Prepare(t.Context(), f.verified, f.dir); err == nil || !strings.Contains(err.Error(), "retry window expired") {
		t.Fatalf("expired replay: %v", err)
	}
	result, err := f.producer.Cleanup(t.Context(), f.verified, f.dir)
	if err == nil || result.Receipt().Cleaned {
		t.Fatal("unknown group was adopted or reported cleaned")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.creates["group"] != 1 || f.resources["ocid1.group.oc1..created"] == nil || f.resources["ocid1.user.oc1..created"] != nil {
		t.Fatal("cleanup failed to revoke known user while retaining unresolved group evidence")
	}
	if _, err := os.Stat(filepath.Join(f.dir, "private.pem")); err != nil {
		t.Fatal("unresolved recovery material lost")
	}
}

func TestSDKScopeAndObservationDriftStopBeforeNextMutation(t *testing.T) {
	for _, mode := range []string{"wrong-observed-id", "creation-expired", "issuer-mismatch", "wrong-iam-home", "policy-change", "escrow-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			switch mode {
			case "wrong-iam-home":
				f.wrongIAMHome = true
			case "wrong-observed-id":
				f.wrongObservation = true
			case "creation-expired":
				f.expireAfterUser = true
			case "issuer-mismatch":
				p := f.prep
				p.IssuerPrincipal = "ocid1.user.oc1..other"
				f.verified = f.verify(p)
			case "policy-change":
				p := f.prep
				p.PolicyTemplate = append(p.PolicyTemplate, "Allow group admins to manage all-resources in tenancy")
				wire := f.wire(p, PreparationScope(p.RunID, p.Candidate), f.root)
				if _, err := VerifyPreparation(wire, nil, f.roots, p.RunID, f.now()); err == nil {
					t.Fatal("noncanonical policy authorized")
				}
				return
			case "escrow-mismatch":
				key, err := rsa.GenerateKey(rand.Reader, 3072)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.dir, "private.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.producer.Prepare(t.Context(), f.verified, f.dir); err == nil {
				t.Fatal("drift accepted")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.creates["group"] != 0 || f.creates["policy"] != 0 || f.creates["key"] != 0 || f.creates["membership"] != 0 {
				t.Fatal("later mutation escaped observation or authority fence")
			}
			if (mode == "issuer-mismatch" || mode == "escrow-mismatch" || mode == "wrong-iam-home") && f.creates["user"] != 0 {
				t.Fatal("mutation preceded issuer/key verification")
			}
		})
	}
}

func TestPreparationRequiresOriginalExactQualifierRoles(t *testing.T) {
	f := newFixture(t)
	_, delegate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subject := delegate.Public().(ed25519.PublicKey)
	keyID, _ := trust.KeyID(subject)
	public, _ := trust.EncodeDelegatedPublicKey(subject)
	for _, mode := range []string{"both-roles", "principal-only", "production-domain", "wrong-host-slot", "tampered-payload"} {
		t.Run(mode, func(t *testing.T) {
			scope := PreparationScope(f.prep.RunID, f.prep.Candidate)
			capability := func(role string) trust.Capability {
				return trust.Capability{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}
			}
			caps := []trust.Capability{capability("disposable-principal"), capability("disposable-host")}
			switch mode {
			case "principal-only":
				caps = caps[:1]
			case "production-domain":
				for i := range caps {
					caps[i].Domain = "terrascale.release.production-qualification"
				}
			case "wrong-host-slot":
				caps[1].Slots = []string{"other/linux-arm64"}
			}
			delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: public, Capabilities: caps}, f.now().Add(-time.Hour), f.prep.CleanupUntil, f.root)
			if err != nil {
				t.Fatal(err)
			}
			delegationWire, err := trust.EncodeEnvelope(delegation)
			if err != nil {
				t.Fatal(err)
			}
			wire := f.wire(f.prep, scope, delegate)
			if mode == "tampered-payload" {
				wire = []byte(strings.Replace(string(wire), "testrun-user", "different-user", 1))
			}
			v, err := VerifyPreparation(wire, delegationWire, f.roots, f.prep.RunID, f.now())
			if mode == "both-roles" {
				if err != nil || v.SHA256() == "" {
					t.Fatalf("exact roles rejected: %v", err)
				}
			} else if err == nil {
				t.Fatal("unapproved qualifier authority accepted")
			}
		})
	}
}

func TestSDKPreparationRejectsChangedJournalAndUnsafeEscrow(t *testing.T) {
	for _, mode := range []string{"journal-token", "journal-request", "symlink-key", "hardlink-key", "public-directory", "missing-key"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			if mode == "journal-token" || mode == "journal-request" {
				f.failCreate = "user"
				if _, err := f.producer.Prepare(t.Context(), f.verified, f.dir); err == nil {
					t.Fatal("missing pending operation")
				}
				path := filepath.Join(f.dir, "journal.json")
				wire, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var j journal
				if err := json.Unmarshal(wire, &j); err != nil {
					t.Fatal(err)
				}
				if mode == "journal-token" {
					j.Operations["user"].RetryToken = "new-token"
				} else {
					j.Operations["user"].Request = []byte(`{"name":"unrelated"}`)
				}
				wire, err = json.Marshal(j)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, wire, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				path := filepath.Join(f.dir, "private.pem")
				switch mode {
				case "symlink-key":
					target := filepath.Join(t.TempDir(), "key")
					if err := os.Rename(path, target); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, path); err != nil {
						t.Fatal(err)
					}
				case "hardlink-key":
					if err := os.Link(path, filepath.Join(t.TempDir(), "alias")); err != nil {
						t.Fatal(err)
					}
				case "public-directory":
					if err := os.Chmod(f.dir, 0755); err != nil {
						t.Fatal(err)
					}
				case "missing-key":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := f.producer.Prepare(t.Context(), f.verified, f.dir); err == nil {
				t.Fatal("unsafe journal/escrow accepted")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.creates["group"] != 0 || f.creates["user"] > 1 {
				t.Fatal("unsafe recovery mutated cloud")
			}
		})
	}
}

func TestSDKFixedRoleMaterialAndProductionGroupBindings(t *testing.T) {
	for _, mode := range []string{"netbird-valid", "netbird-wrong-cell", "netbird-extra-swarm-material", "missing-kernel-release", "material-hash", "profile-cell", "production-group-overlap", "production-group-duplicate", "tagged-workload", "unqualified-role"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			p := f.prep
			if strings.HasPrefix(mode, "netbird-") {
				p.Candidate.Role = "netbird-manager"
				p.Candidate.Runtime = "netbird-containerd"
				p.ProfileIdentity = cellspec.Identity{}
				p.MaterialFixtures = nil
				p.WorkloadImage = ""
				p.WorkloadArchiveSHA256 = ""
				p.ClientSHA256 = strings.Repeat("6", 64)
				p.Hosts = slices.Clone(p.Hosts[:2])
				p.Hosts[0].Role = "netbird-primary"
				p.Hosts[1].Role = "netbird-replacement"
				for _, role := range []string{"server", "dashboard", "ingress"} {
					p.ContainerArtifacts = append(p.ContainerArtifacts, ContainerArtifactApproval{Role: role, Image: "registry.example.test/netbird/" + role + "@sha256:" + hash([]byte(role)), ArchiveSHA256: hash([]byte("archive/" + role))})
				}
			}
			switch mode {
			case "netbird-wrong-cell":
				p.Candidate.Cell = "FRA"
				p.OCIRegion = "eu-frankfurt-1"
			case "netbird-extra-swarm-material":
				p.MaterialFixtures = []MaterialApproval{f.prep.MaterialFixtures[0]}
			case "missing-kernel-release":
				p.KernelRelease = ""
			case "material-hash":
				p.MaterialFixtures = slices.Clone(p.MaterialFixtures)
				p.MaterialFixtures[0].SignedProfileSHA256 = "changed"
			case "profile-cell":
				p.ProfileIdentity.Cell = "FRA"
			case "production-group-overlap":
				p.ProductionDynamicGroups = []confinement.ProductionDynamicGroup{{ID: "ocid1.dynamicgroup.oc1..production", Name: "Production", InstanceCompartment: p.Compartment}}
			case "production-group-duplicate":
				group := confinement.ProductionDynamicGroup{ID: "ocid1.dynamicgroup.oc1..production", Name: "Production", InstanceCompartment: "ocid1.compartment.oc1..production"}
				p.ProductionDynamicGroups = []confinement.ProductionDynamicGroup{group, group}
			case "tagged-workload":
				p.WorkloadImage = "registry.example.test/workload:latest@sha256:" + strings.Repeat("d", 64)
			case "unqualified-role":
				p.Candidate.Role = "other"
			}
			wire := f.wire(p, PreparationScope(p.RunID, p.Candidate), f.root)
			v, err := VerifyPreparation(wire, nil, f.roots, p.RunID, f.now())
			if mode != "netbird-valid" {
				if err == nil {
					t.Fatal("changed signed finite role/material scope accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			f.prep = p
			f.verified = v
			result, err := f.producer.Prepare(t.Context(), v, f.dir)
			if err != nil || !result.Prepared() {
				t.Fatalf("actual NetBird principal preparation: %v", err)
			}
			if err := result.ValidatePreparation(v, f.now()); err != nil {
				t.Fatal(err)
			}
			receipt := result.Receipt()
			receipt.Principal = "unrelated"
			receipt.PolicyStatements[0] = "altered"
			if result.Receipt().Principal == "unrelated" || result.Receipt().PolicyStatements[0] == "altered" || (Result{}).Prepared() {
				t.Fatal("public receipt can alter sealed producer result")
			}
			if _, err := f.producer.Cleanup(t.Context(), v, f.dir); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type rotatingIssuer struct {
	common.ConfigurationProvider
	calls atomic.Int32
}

func (r *rotatingIssuer) KeyID() (string, error) {
	if r.calls.Add(1) == 1 {
		return r.ConfigurationProvider.KeyID()
	}
	return "ocid1.tenancy.oc1..test/ocid1.user.oc1..unrelated/other", nil
}

func TestSDKFreezesExactIssuerBeforeDispatch(t *testing.T) {
	f := newFixture(t)
	rotating := &rotatingIssuer{ConfigurationProvider: f.producer.issuer.Provider()}
	factory, err := ociclient.New(rotating, ociclient.Options{Region: f.prep.IAMRegion, Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceIdentity: {PerSecond: 10000, Burst: 10000}}, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	f.producer.issuer = factory
	if result, err := f.producer.Prepare(t.Context(), f.verified, f.dir); err != nil || !result.Prepared() {
		t.Fatalf("frozen issuer preparation: %v", err)
	}
	if rotating.calls.Load() != 1 {
		t.Fatal("mutable issuer provider was consulted after exact identity freeze")
	}
}
