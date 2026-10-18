package region

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/oracle/oci-go-sdk/v65/common"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

type originalMaterialIAMDispatch struct {
	body    []byte
	token   string
	pending PendingFoundationCreate
}

type originalMaterialIAMSDKFixture struct {
	*originalPublicationSDKFixture
	materialMu  sync.Mutex
	fault       string
	faulted     bool
	posts       []originalMaterialIAMDispatch
	rows        map[string]map[string]any
	gets        map[string]int
	journalPuts int
}

func newOriginalMaterialIAMSDKFixture(t *testing.T, fault string) *originalMaterialIAMSDKFixture {
	t.Helper()
	// Preserve pinned loopback TLS instead of the OCI SDK's proxy transport clone.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	reads := newOriginalActorReadsSDKFixture(t, "", 0)
	if reads.prepared.Grant.OriginalMaterialPublicationIAM == nil {
		t.Fatal("prospective preparation omitted material IAM")
	}
	admission := originalAdmissionReadsSDKFixtureFor(t, reads, "")
	publication := originalPublicationSDKFixtureFor(t, admission, "")
	f := &originalMaterialIAMSDKFixture{originalPublicationSDKFixture: publication, fault: fault, rows: map[string]map[string]any{}, gets: map[string]int{}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("material IAM requires literal loopback TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("material IAM fixture refuses plaintext and proxies")
	}
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("unexpected network %q", network)
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	return f
}

func originalMaterialIAMSnapshot(t *testing.T, cloud *provisionCloud) []byte {
	t.Helper()
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	entries, err := os.ReadDir(cloud.directory)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		wire, err := os.ReadFile(filepath.Join(cloud.directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = wire
	}
	wire, err := json.Marshal(files, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (f *originalMaterialIAMSDKFixture) expectedMaterialPolicy(t *testing.T, record FoundationRecord, index int) map[string]any {
	t.Helper()
	regional := record.OriginalFoundationCompartments.Regions[index]
	entry := regional.MaterialPublicationIAM
	cfg := f.prepared.Grant.Regions[index].BootstrapMaterial.Config
	names, err := bootstrapmaterial.OriginalPublicationSecretNames(cfg)
	if err != nil || len(names) != 33 {
		t.Fatal("actual material naming roster unavailable", err)
	}
	principal := fmt.Sprintf("request.principal.type='instance', request.principal.id='%s'", regional.Actor.Provenance.ResourceID)
	control := originalCompartmentID(regional.Compartments[0])
	vault := originalVaultID(regional.Vault.Vault.OriginalFoundationKMSCreate)
	key := originalVaultID(regional.Vault.Key.OriginalFoundationKMSCreate)
	conditions := make([]string, len(names))
	for i, name := range names {
		conditions[i] = "target.secret.name='" + name + "'"
	}
	statement := func(verb, resource, operation, permission, extra string) string {
		return fmt.Sprintf("Allow any-user to %s %s in compartment id %s where all {%s, request.operation='%s', request.permission='%s'%s}", verb, resource, control, principal, operation, permission, extra)
	}
	finite := fmt.Sprintf(", target.vault.id='%s', any {%s}", vault, strings.Join(conditions, ", "))
	statements := []string{
		statement("inspect", "secrets", "ListSecrets", "SECRET_INSPECT", ""),
		statement("manage", "secrets", "CreateSecret", "SECRET_CREATE", finite),
		statement("read", "secrets", "GetSecret", "SECRET_READ", finite),
		statement("read", "secret-bundles", "GetSecretBundle", "SECRET_BUNDLE_READ", finite),
		statement("use", "vaults", "CreateSecret", "VAULT_CREATE_SECRET", fmt.Sprintf(", target.vault.id='%s'", vault)),
		statement("use", "keys", "CreateSecret", "KEY_ENCRYPT", fmt.Sprintf(", target.key.id='%s'", key)),
		statement("use", "keys", "CreateSecret", "KEY_DECRYPT", fmt.Sprintf(", target.key.id='%s'", key)),
	}
	return map[string]any{"compartmentId": control, "name": "ts-original-material-iam-" + entry.IdentitySHA256[:32], "description": "Prospectively authorized finite original material publication", "statements": statements, "freeformTags": map[string]any{}, "definedTags": map[string]any{}}
}

func (f *originalMaterialIAMSDKFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.materialMu.Lock()
	defer f.materialMu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
		f.cloud.test.Error("material IAM request lacks actual SDK signing")
	}
	record := f.record(f.cloud.test)
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/"+foundationObjectPrefix+"GRU.json") {
		wire, err := io.ReadAll(io.LimitReader(r.Body, foundationJournalLimit+1))
		var next FoundationRecord
		if err != nil || json.Unmarshal(wire, &next) != nil {
			f.cloud.test.Error("invalid material checkpoint")
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		f.journalPuts++
		phase := ""
		for index, regional := range next.OriginalFoundationCompartments.Regions {
			before, after := record.OriginalFoundationCompartments.Regions[index].MaterialPublicationIAM, regional.MaterialPublicationIAM
			if after == nil {
				continue
			}
			if before == nil {
				phase = "scope checkpoint"
			} else if before.Pending == nil && after.Pending != nil {
				phase = "reservation checkpoint"
			} else if before.Provenance == nil && after.Provenance != nil {
				phase = "receipt checkpoint"
			} else if before.VerifiedAt.IsZero() && !after.VerifiedAt.IsZero() {
				phase = "completion checkpoint"
			}
		}
		if phase != "" && !f.faulted && (f.fault == phase || f.fault == "lost "+phase) {
			f.faulted = true
			if strings.HasPrefix(f.fault, "lost ") {
				r.Body = io.NopCloser(bytes.NewReader(wire))
				recorder := httptest.NewRecorder()
				f.originalPublicationSDKFixture.serveHTTP(recorder, r)
				if recorder.Code >= 300 {
					f.cloud.test.Error("lost material acknowledgement did not follow accepted CAS")
				}
			}
			originalCompartmentFailure(w, 503, "InternalError")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(wire))
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 2 && parts[1] == "policies" {
		if r.Host != "identity.sa-saopaulo-1.oci.oraclecloud.com" {
			f.cloud.test.Error("material policy escaped HOME IAM")
		}
		if r.Method == http.MethodPost && len(parts) == 2 {
			body, canonical, err := originalNetworkBody(r)
			if err != nil {
				f.cloud.test.Error(err)
				originalCompartmentFailure(w, 400, "InvalidParameter")
				return
			}
			if name, _ := body["name"].(string); strings.HasPrefix(name, "ts-original-material-iam-") {
				index := slices.IndexFunc(record.OriginalFoundationCompartments.Regions[:], func(regional OriginalFoundationCompartmentRegion) bool {
					return regional.MaterialPublicationIAM != nil && deref(regional.MaterialPublicationIAM.Request.Name) == name
				})
				if index < 0 || completeOriginalMaterialIAMPrerequisites(record) != nil {
					f.cloud.test.Error("material effect lacks genuine completed prerequisites")
					originalCompartmentFailure(w, 400, "InvalidParameter")
					return
				}
				entry := record.OriginalFoundationCompartments.Regions[index].MaterialPublicationIAM
				if entry.Pending == nil || entry.Provenance != nil || entry.Pending.Request.RequestDigest != digestSource(canonical) || entry.Pending.Request.RetryToken != r.Header.Get("opc-retry-token") || !sameOriginalSourceValue(body, f.expectedMaterialPolicy(f.cloud.test, record, index)) {
					f.cloud.test.Error("material create escaped signed finite policy or acknowledged request")
					originalCompartmentFailure(w, 400, "InvalidParameter")
					return
				}
				wire, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + homeIAMObject))
				var lease homeIAMRecord
				if err != nil || json.Unmarshal(wire, &lease) != nil || !lease.ReleasedAt.IsZero() || !time.Now().Before(lease.ExpiresAt) || lease.OperatorID != record.OriginalFoundationCompartments.UserID {
					f.cloud.test.Error("material effect lacks actual live HomeWrite")
				}
				f.posts = append(f.posts, originalMaterialIAMDispatch{body: bytes.Clone(canonical), token: r.Header.Get("opc-retry-token"), pending: *entry.Pending})
				if f.fault == "create refused" {
					originalCompartmentFailure(w, 409, "Conflict")
					return
				}
				id := fmt.Sprintf("ocid1.policy.oc1..originalmaterial%d", index+1)
				row := maps.Clone(body)
				row["id"], row["lifecycleState"] = id, "ACTIVE"
				if old := f.rows[id]; old != nil && !sameOriginalSourceValue(old, row) {
					f.cloud.test.Error("retry changed material policy or created another identity")
				}
				f.rows[id] = row
				if f.fault == "lost create response" && !f.faulted {
					f.faulted = true
					originalCompartmentFailure(w, 503, "InternalError")
					return
				}
				json.MarshalWrite(w, row)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(canonical))
		}
		if r.Method == http.MethodGet && len(parts) == 3 {
			if row := f.rows[parts[2]]; row != nil {
				index := slices.IndexFunc(record.OriginalFoundationCompartments.Regions[:], func(regional OriginalFoundationCompartmentRegion) bool {
					return regional.MaterialPublicationIAM != nil && regional.MaterialPublicationIAM.Provenance != nil && regional.MaterialPublicationIAM.Provenance.ResourceID == parts[2]
				})
				if index < 0 {
					f.cloud.test.Error("material policy read preceded actual durable provider ID")
				}
				f.gets[parts[2]]++
				if f.fault == "readback missing" {
					originalCompartmentFailure(w, 404, "NotAuthorizedOrNotFound")
					return
				}
				if f.fault == "readback unavailable" {
					originalCompartmentFailure(w, 503, "InternalError")
					return
				}
				row = maps.Clone(row)
				if f.fault == "readback conflict" {
					row["statements"] = []string{"Allow any-user to manage all-resources in tenancy"}
				}
				if f.fault == "readback compartment" {
					row["compartmentId"] = "ocid1.compartment.oc1..foreign"
				}
				if f.fault == "readback pending deletion" {
					row["lifecycleState"] = "DELETING"
				}
				wire, err := json.Marshal(row, json.Deterministic(true))
				if err != nil {
					f.cloud.test.Error(err)
				}
				etag := digestSource(wire)
				if f.fault == "readback ETag changed" {
					etag = "different-current-etag"
				}
				if f.fault != "readback ETag missing" {
					w.Header().Set("etag", etag)
				}
				w.Write(wire)
				return
			}
		}
	}
	f.originalPublicationSDKFixture.serveHTTP(w, r)
}

func (f *originalMaterialIAMSDKFixture) assertMaterialIAM(t *testing.T) {
	t.Helper()
	f.assertPublished(t)
	record := f.record(t)
	if record.Stage != "original-foundation" || f.cloud.hasAnchor() || len(f.rows) != 3 {
		t.Fatal("material IAM fabricated ordinary startup or omitted policies")
	}
	for index, regional := range record.OriginalFoundationCompartments.Regions {
		entry := regional.MaterialPublicationIAM
		if entry == nil || entry.Pending == nil || entry.Provenance == nil || entry.PolicyETag == "" || entry.ReadbackSHA256 == "" || entry.VerifiedAt.IsZero() || entry.HoldReason != "" || f.gets[entry.Provenance.ResourceID] == 0 {
			t.Fatal("material IAM lacks acknowledged policy and actual independent ETag readback")
		}
		expected := f.expectedMaterialPolicy(t, record, index)
		expected["id"], expected["lifecycleState"] = entry.Provenance.ResourceID, "ACTIVE"
		if !sameOriginalSourceValue(f.rows[entry.Provenance.ResourceID], expected) {
			t.Fatal("retained material policy differs from exact finite actual instance and regional Vault target")
		}
	}
}

func TestOriginalFoundationMaterialIAMSDK(t *testing.T) {
	t.Run("automatic completion and unchanged restart", func(t *testing.T) {
		f := newOriginalMaterialIAMSDKFixture(t, "")
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
			t.Fatal(err)
		}
		f.assertMaterialIAM(t)
		before, posts, puts := bytes.Clone(f.wire(t)), len(f.posts), f.journalPuts
		public := f.puts
		if posts != 3 {
			t.Fatal("material IAM did not create exactly one finite policy per original actor")
		}
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) || len(f.posts) != posts || f.journalPuts != puts || f.puts != public || !bytes.Equal(before, f.wire(t)) {
			t.Fatal("completed material IAM replay changed history or repeated effects", err)
		}
	})
	t.Run("unknown create outcome keeps body and retry token", func(t *testing.T) {
		f := newOriginalMaterialIAMSDKFixture(t, "lost create response")
		if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) || !f.faulted || len(f.posts) != 1 {
			t.Fatal("unknown material create outcome became completion", err)
		}
		pending := f.posts[0]
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
			t.Fatal(err)
		}
		f.assertMaterialIAM(t)
		if len(f.posts) != 4 || f.posts[1].token != pending.token || !bytes.Equal(f.posts[1].body, pending.body) || !sameOriginalSourceValue(f.posts[1].pending, pending.pending) {
			t.Fatal("unknown material create outcome changed immutable retry identity")
		}
	})
	for _, fault := range []string{"scope checkpoint", "reservation checkpoint", "receipt checkpoint", "completion checkpoint", "lost reservation checkpoint", "lost receipt checkpoint", "lost completion checkpoint"} {
		t.Run(fault+" resumes", func(t *testing.T) {
			f := newOriginalMaterialIAMSDKFixture(t, fault)
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) || !f.faulted {
				t.Fatal("failed material checkpoint became completed authority", err)
			}
			if strings.Contains(fault, "scope") || strings.Contains(fault, "reservation") {
				if len(f.posts) != 0 {
					t.Fatal("material effect preceded acknowledged protected reservation")
				}
			}
			var pending *PendingFoundationCreate
			if entry := f.record(t).OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM; entry != nil && entry.Pending != nil {
				value := *entry.Pending
				pending = &value
			}
			if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
				t.Fatal(err)
			}
			f.assertMaterialIAM(t)
			if pending != nil && !sameOriginalSourceValue(pending, f.record(t).OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM.Pending) {
				t.Fatal("checkpoint recovery changed reserved material request")
			}
		})
	}
	for _, fault := range []string{"readback missing", "readback unavailable", "readback conflict", "readback compartment", "readback pending deletion", "readback ETag missing"} {
		t.Run(fault+" cannot complete", func(t *testing.T) {
			f := newOriginalMaterialIAMSDKFixture(t, fault)
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
				t.Fatal("missing or changed material policy became completion", err)
			}
			entry := f.record(t).OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM
			if entry == nil || entry.Provenance == nil || !entry.VerifiedAt.IsZero() || entry.ReadbackSHA256 != "" || entry.PolicyETag != "" || len(f.posts) != 1 || f.cloud.hasAnchor() {
				t.Fatal("uncertain policy readback fabricated completion or ordinary admission")
			}
		})
	}
	t.Run("permanent create refusal retains HOLD", func(t *testing.T) {
		f := newOriginalMaterialIAMSDKFixture(t, "create refused")
		if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
			t.Fatal("refused material create became completion", err)
		}
		entry := f.record(t).OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM
		if entry == nil || entry.Pending == nil || entry.Provenance != nil || entry.HoldReason != "create-refused" || len(f.posts) != 1 {
			t.Fatal("permanent refusal lost reserved history")
		}
		before := bytes.Clone(f.wire(t))
		if err := f.run(t); err == nil || len(f.posts) != 1 || !bytes.Equal(before, f.wire(t)) {
			t.Fatal("permanent refusal recreated or reset material policy")
		}
	})
	t.Run("retained ETag does not replace current provider policy", func(t *testing.T) {
		f := newOriginalMaterialIAMSDKFixture(t, "")
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
			t.Fatal(err)
		}
		before, posts, puts := bytes.Clone(f.wire(t)), len(f.posts), f.journalPuts
		f.materialMu.Lock()
		f.fault = "readback ETag changed"
		f.materialMu.Unlock()
		if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) || !bytes.Equal(before, f.wire(t)) || len(f.posts) != posts || f.journalPuts != puts {
			t.Fatal("retained receipt replaced current exact policy ETag or recreated policy", err)
		}
	})
	t.Run("signed historical absence retains old HOLD", func(t *testing.T) {
		f := newOriginalPublicationSDKFixture(t, "")
		if f.prepared.Grant.OriginalMaterialPublicationIAM != nil {
			t.Fatal("historical fixture has new prospective material permission")
		}
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
			t.Fatal("historical signed absence changed existing HOLD", err)
		}
		f.assertPublished(t)
		for _, regional := range f.record(t).OriginalFoundationCompartments.Regions {
			if regional.MaterialPublicationIAM != nil {
				t.Fatal("historical absence acquired material IAM effects")
			}
		}
	})
}

func TestOriginalFoundationMaterialIAMSignedContract(t *testing.T) {
	// Preserve the fixture's literal loopback transport through SDK client construction.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	for _, change := range []string{"purpose", "name", "owner name", "vault", "key", "control", "actor recipe", "permission", "key encrypt operation", "key decrypt operation", "LIST scope"} {
		t.Run(change, func(t *testing.T) {
			f := newOriginalActorReadsSDKFixture(t, "", 0)
			prepared := f.prepared
			if prepared.Grant.OriginalMaterialPublicationIAM == nil {
				t.Fatal("prospective preparation omitted material IAM")
			}
			recipes := *prepared.Grant.OriginalMaterialPublicationIAM
			for index := range recipes {
				recipes[index].SecretNames = slices.Clone(recipes[index].SecretNames)
			}
			prepared.Grant.OriginalMaterialPublicationIAM = &recipes
			switch change {
			case "purpose":
				recipes[0].Purpose = "publish-arbitrary-material"
			case "name":
				recipes[0].SecretNames[0] += "-foreign"
			case "owner name":
				recipes[0].SecretNames = append(recipes[0].SecretNames, "issuer-operator-seed")
			case "vault":
				recipes[1].Vault = recipes[0].Vault
			case "key":
				recipes[1].Key = recipes[0].Key
			case "control":
				recipes[1].ControlCompartment = recipes[0].ControlCompartment
			case "actor recipe":
				recipes[0].ActorRecipeSHA256 = strings.Repeat("0", 64)
			case "permission":
				recipes[0].Operations[1].Permission = "SECRET_UPDATE"
			case "key encrypt operation":
				recipes[0].Operations[5].Operation = "Encrypt"
			case "key decrypt operation":
				recipes[0].Operations[6].Operation = "Decrypt"
			case "LIST scope":
				recipes[0].Operations[0].Scope = "material-names-vault"
			}
			if validateOriginalMaterialIAMIntents(prepared.Grant, f.approval.HomeStorageDomain) == nil {
				t.Fatal("changed finite recipe passed direct validation")
			}
			f.bundle = signProvisionFoundation(t, prepared, f.bundle.RootChainWire, f.root, f.now)
			f.cloud.bundle = f.bundle.clone()
			var err error
			f.publicBundle, err = json.Marshal(f.bundle, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			before := originalMaterialIAMSnapshot(t, f.cloud)
			if f.cloud.creates != 0 || f.cloud.materialPosts != 0 || f.cloud.launchPosts != 0 {
				t.Fatal("signed recipe mutation began after adoption")
			}
			if err := provisionOriginalFoundationCompartments(t.Context(), f.factoryFor(), f.roots, f.bundle); err == nil {
				t.Fatal("actual coordinator accepted altered signed material recipe")
			}
			if !bytes.Equal(before, originalMaterialIAMSnapshot(t, f.cloud)) || f.cloud.creates != 0 || f.cloud.materialPosts != 0 || f.cloud.launchPosts != 0 || len(f.dispatches()) != 0 || f.cloud.hasAnchor() {
				t.Fatal("altered signed recipe changed durable objects or dispatched effects")
			}
		})
	}
}

func TestOriginalFoundationMaterialIAMRetainedContract(t *testing.T) {
	f := newOriginalMaterialIAMSDKFixture(t, "")
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
		t.Fatal(err)
	}
	f.assertMaterialIAM(t)
	store := f.store(t)
	for _, change := range []string{"remove", "actor", "vault", "name", "statement", "token", "receipt", "ETag", "completion"} {
		t.Run(change, func(t *testing.T) {
			current, etag, err := store.Load(t.Context(), "GRU")
			if err != nil || etag == "" {
				t.Fatal("missing actual current store ETag", err)
			}
			previous := f.record(t)
			entry := current.OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM
			switch change {
			case "remove":
				current.OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM = nil
			case "actor":
				entry.ActorID = current.OriginalFoundationCompartments.Regions[1].Actor.Provenance.ResourceID
			case "vault":
				entry.Target.VaultOCID = current.OriginalFoundationCompartments.Regions[1].MaterialPublicationIAM.Target.VaultOCID
			case "name":
				entry.Recipe.SecretNames[0] += "-different"
			case "statement":
				entry.Request.Statements = append(entry.Request.Statements, "Allow any-user to manage all-resources in tenancy")
			case "token":
				entry.Pending.Request.RetryToken = "different"
			case "receipt":
				entry.Provenance.ResourceID = current.OriginalFoundationCompartments.Regions[1].MaterialPublicationIAM.Provenance.ResourceID
			case "ETag":
				entry.PolicyETag = "different"
			case "completion":
				entry.VerifiedAt = entry.VerifiedAt.Add(time.Nanosecond)
			}
			if current.validate() == nil && current.retainOriginalFoundationMaterialIAM(previous) == nil {
				t.Fatal("changed retained material policy passed direct contract")
			}
			before, posts, puts, public := originalMaterialIAMSnapshot(t, f.cloud), len(f.posts), f.journalPuts, f.puts
			if _, err := store.CompareAndSwap(t.Context(), current, etag); err == nil {
				t.Fatal("actual protected CAS changed retained material identity")
			}
			if !bytes.Equal(before, originalMaterialIAMSnapshot(t, f.cloud)) || len(f.posts) != posts || f.journalPuts != puts || f.puts != public {
				t.Fatal("rejected retained mutation changed durable objects or effects")
			}
		})
	}
}

func TestOriginalFoundationMaterialIAMEffectPredecessors(t *testing.T) {
	for _, fault := range []string{"reservation checkpoint", "receipt checkpoint"} {
		t.Run(fault, func(t *testing.T) {
			f := newOriginalMaterialIAMSDKFixture(t, fault)
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
				t.Fatal("fixture did not stop at actual effect predecessor")
			}
			store := f.store(t)
			current, etag, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			entry := current.OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM
			if entry == nil || entry.Provenance != nil {
				t.Fatal("unexpected receipt predecessor")
			}
			if fault == "receipt checkpoint" && (entry.Pending == nil || len(f.posts) != 1 || f.rows["ocid1.policy.oc1..originalmaterial1"] == nil) {
				t.Fatal("receipt predecessor lacks genuine provider create")
			}
			if entry.Pending == nil {
				body, err := foundationWriterPolicyBody(entry.Request)
				if err != nil {
					t.Fatal(err)
				}
				regional := current.OriginalFoundationCompartments.Regions[0]
				entry.Pending = &PendingFoundationCreate{OperationID: regional.OperationID, IntentDigest: regional.IntentSHA256, FirstAttemptAt: time.Now().UTC(), Request: originalMaterialIAMCreateIdentity(regional, digestSource(body))}
			}
			// These rejected DATA claims cannot create authority or replace a real predecessor.
			entry.Provenance = &FoundationResourceProvenance{Create: *entry.Pending, ResourceID: "ocid1.policy.oc1..originalmaterial1", Generation: entry.Generation, GrantSHA256: entry.GrantSHA256}
			if fault == "receipt checkpoint" {
				wire, err := json.Marshal(f.rows[entry.Provenance.ResourceID], json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				entry.PolicyETag = digestSource(wire)
				entry.ReadbackSHA256, err = originalMaterialIAMReadback(*entry)
				if err != nil {
					t.Fatal(err)
				}
				entry.VerifiedAt = time.Now().UTC()
			}
			current.UpdatedAt = time.Now().UTC()
			if err := current.validate(); err != nil {
				t.Fatal("candidate must be structurally valid before predecessor refusal", err)
			}
			before, posts, puts := originalMaterialIAMSnapshot(t, f.cloud), len(f.posts), f.journalPuts
			if _, err := store.CompareAndSwap(t.Context(), current, etag); !errors.Is(err, ErrOriginalSourceProducerHold) || !bytes.Equal(before, originalMaterialIAMSnapshot(t, f.cloud)) || len(f.posts) != posts || f.journalPuts != puts {
				t.Fatal("actual protected CAS skipped acknowledged material effect predecessor")
			}
		})
	}
}

func TestOriginalFoundationMaterialIAMRequiresOwningLease(t *testing.T) {
	if err := provisionOriginalFoundationMaterialIAM(t.Context(), nil); err == nil {
		t.Fatal("nil original operator acquired material IAM")
	}
	if _, _, _, _, err := originalMaterialIAMPrerequisites(nil, nil); err == nil {
		t.Fatal("nil context acquired material IAM")
	}
	f := newOriginalMaterialIAMSDKFixture(t, "")
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
		t.Fatal(err)
	}
	authority, _, err := newOperatorHomeIAMAuthority(t.Context(), f.factoryFor(), f.roots, f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	before, posts := originalMaterialIAMSnapshot(t, f.cloud), len(f.posts)
	if err := provisionOriginalFoundationMaterialIAM(t.Context(), authority); err == nil || !bytes.Equal(before, originalMaterialIAMSnapshot(t, f.cloud)) || len(f.posts) != posts {
		t.Fatal("missing genuine HomeWrite lease acquired material IAM")
	}
}

func TestOriginalMaterialPublicationNamesMatchActualProducer(t *testing.T) {
	// The existing vendor setting keeps factory transports within literal loopback TLS.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	f := newOriginalActorReadsSDKFixture(t, "", 0)
	material := f.prepared.Grant.Regions[0].BootstrapMaterial
	directory := filepath.Join(t.TempDir(), "candidate")
	record, err := bootstrapmaterial.GenerateAdmissionCandidate(directory, material.Config, *material.AdmissionAttestor, f.now)
	if err != nil {
		t.Fatal(err)
	}
	names, err := bootstrapmaterial.OriginalPublicationSecretNames(material.Config)
	if err != nil || len(names) != 33 {
		t.Fatal(err)
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(f.provider)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := ocisecrets.NewSecretsClientWithConfigurationProvider(f.provider)
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop after actual publication journal, before SDK effects")
	var selected []string
	var files []string
	_, err = bootstrapmaterial.ProvisionDurable(t.Context(), directory, material.SourceVaultTarget, management, bundles, f.now, func(wire []byte) error {
		var journal struct {
			Entries []struct {
				Name     string `json:"name"`
				FileName string `json:"fileName"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(wire, &journal); err != nil {
			t.Fatal(err)
		}
		for _, entry := range journal.Entries {
			selected = append(selected, entry.Name)
			files = append(files, entry.FileName)
		}
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatal("actual producer did not expose initial journal before effect", err)
	}
	slices.Sort(selected)
	if !slices.Equal(names, selected) {
		t.Fatal("IAM helper roster differs from actual publication naming")
	}
	for _, file := range record.Files {
		if slices.Contains(files, file.Name) != (file.Purpose != "owner-only") {
			t.Fatal("closed IAM roster omitted publishable material or admitted owner-only keys")
		}
	}
	for _, name := range []string{"terrabase-member-ca.pem", "terrabase-member-ca.key", "controller-a-admission.key", "controller-b-admission.key", "controller-c-admission.key"} {
		if !slices.Contains(files, name) {
			t.Fatal("actual closed roster omitted member CA or dedicated admission key")
		}
	}
	invalid := material.Config
	invalid.Cell = "foreign"
	if _, err := bootstrapmaterial.OriginalPublicationSecretNames(invalid); err == nil {
		t.Fatal("invalid material configuration produced an IAM roster")
	}
}
